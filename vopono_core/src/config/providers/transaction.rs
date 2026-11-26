//! Stage provider updates without exposing partial downloads or credentials.
use super::VpnProvider;
use crate::config::vpn::Protocol;
use anyhow::{Context, ensure};
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

struct ConfigRoot(Option<std::path::PathBuf>);
impl Drop for ConfigRoot {
    fn drop(&mut self) {
        crate::util::set_config_dir_override(self.0.take());
    }
}

/// Existing generators run against an isolated copy of the provider tree.
/// `metadata` runs after validation, against exactly the files being published.
pub fn run(
    provider: &VpnProvider,
    protocols: &[Protocol],
    generate: impl FnOnce() -> anyhow::Result<()>,
    metadata: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    ensure!(
        provider.supports_sync(),
        "Provider does not support synchronization"
    );
    let previous_override = crate::util::config_dir_override();
    let root = crate::util::vopono_dir()?;
    fs::create_dir_all(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let alias = provider.get_dyn_provider().alias();
    let live = root.join(&alias);
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(format!(".{alias}.sync.lock")))?;
    // The file descriptor releases the lock on every return, including panic.
    loop {
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(error).context("Could not lock provider synchronization");
    }
    let replacing = match fs::symlink_metadata(&live) {
        Ok(meta) => {
            ensure!(
                !meta.file_type().is_symlink() && meta.is_dir(),
                "Provider directory {} must be a real directory, not a symlink",
                live.display()
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let stage = tempfile::Builder::new()
        .prefix(".sync-")
        .tempdir_in(&root)?;
    let staged = stage.path().join("vopono").join(&alias);
    fs::create_dir_all(&staged)?;
    let parent = File::open(&root)?;
    if replacing {
        copy_tree(&live, &staged)?;
    }
    let _restore = ConfigRoot(previous_override);
    crate::util::set_config_dir_override(Some(stage.path().to_owned()));
    generate()?;
    for protocol in protocols {
        let directory = staged.join(protocol.id());
        let configs = crate::util::get_configs_from_alias(&directory, "");
        ensure!(!configs.is_empty(), "Provider generated no configurations");
        for path in configs {
            if *protocol == Protocol::Wireguard && *provider == VpnProvider::PrivateInternetAccess {
                // PIA intentionally provisions the server key and addresses at connect time.
                crate::diagnostics::validate_pia_template(&path)?;
            } else {
                crate::diagnostics::validate_config(&path, protocol)?;
            }
        }
    }
    // Validate referenced inputs in staging before relocating absolute paths.
    relocate(&staged, &staged, &live)?;
    metadata()?;
    sync_tree(&staged)?;
    let exchanged = if live.try_exists()? {
        match exchange(&staged, &live, stage.path()) {
            Ok(()) => true,
            Err(ExchangeError::Clean(error)) => return Err(error),
            Err(ExchangeError::RetainStage(error)) => {
                // Keep the staging directory so the displaced previous live
                // generation in `swap-backup` is never deleted on error.
                let _retained = stage.keep();
                return Err(error);
            }
        }
    } else {
        fs::rename(&staged, &live)?;
        false
    };
    if let Err(error) = parent.sync_all() {
        let rollback = if exchanged {
            exchange(&staged, &live, stage.path()).map_err(|err| err.into_error())
        } else {
            fs::rename(&live, &staged).map_err(Into::into)
        };
        if rollback.is_err() {
            // Preserve both generations if a filesystem failure prevents
            // rollback; deleting the staging directory could lose the old one.
            let _retained = stage.keep();
            anyhow::bail!(
                "Provider publish durability and rollback failed; retained staging data for recovery"
            );
        }
        let _ = parent.sync_all();
        return Err(error)
            .context("Provider publication was rolled back after a durability failure");
    }
    let stamp = stage.path().join("vopono/.last-sync");
    if stamp.is_file()
        && let Err(error) = fs::rename(stamp, root.join(".last-sync"))
    {
        // The authoritative per-provider metadata was committed with the files.
        log::warn!("Provider sync committed, but completion notification failed: {error}");
    }
    Ok(())
}

enum ExchangeError {
    Clean(anyhow::Error),
    RetainStage(anyhow::Error),
}

impl ExchangeError {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Clean(error) | Self::RetainStage(error) => error,
        }
    }
}

fn exchange(left: &Path, right: &Path, stage_dir: &Path) -> Result<(), ExchangeError> {
    let left_c = std::ffi::CString::new(left.as_os_str().as_bytes())
        .map_err(|e| ExchangeError::Clean(e.into()))?;
    let right_c = std::ffi::CString::new(right.as_os_str().as_bytes())
        .map_err(|e| ExchangeError::Clean(e.into()))?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            left_c.as_ptr(),
            libc::AT_FDCWD,
            right_c.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
    ) {
        // Fallback for filesystems without RENAME_EXCHANGE (e.g., eCryptfs, FUSE, CIFS).
        // Keep the temporary swap path inside the private 0700 staging directory on the
        // same filesystem so it is never orphaned in `root` and is preserved if rollback fails.
        let backup = stage_dir.join("swap-backup");
        if backup
            .try_exists()
            .map_err(|e| ExchangeError::Clean(e.into()))?
        {
            fs::remove_dir_all(&backup).map_err(|e| ExchangeError::Clean(e.into()))?;
        }
        fs::rename(right, &backup)
            .context("Moving existing provider directory aside")
            .map_err(ExchangeError::Clean)?;
        if let Err(move_err) = fs::rename(left, right) {
            let err = anyhow::Error::new(move_err).context("Publishing provider configurations");
            if fs::rename(&backup, right).is_err() {
                return Err(ExchangeError::RetainStage(err.context(
                    "Restoring previous provider directory failed; retained staging data for recovery",
                )));
            }
            return Err(ExchangeError::Clean(err));
        }
        if let Err(backup_err) = fs::rename(&backup, left) {
            let err = anyhow::Error::new(backup_err)
                .context("Preserving previous provider generation for rollback");
            // `left` has already replaced `right`; try to restore the prior generation
            // cleanly, and retain staging if rollback cannot complete.
            if fs::rename(right, left).is_ok() && fs::rename(&backup, right).is_ok() {
                return Err(ExchangeError::Clean(err));
            }
            return Err(ExchangeError::RetainStage(err.context(
                "Could not restore previous provider directory; retained staging data for recovery",
            )));
        }
        return Ok(());
    }
    Err(ExchangeError::Clean(
        anyhow::Error::new(err).context("Atomically publishing provider configurations"),
    ))
}

fn copy_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    ensure!(
        fs::symlink_metadata(source)?.is_dir(),
        "Provider tree must be a directory"
    );
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
            copy_tree(&entry.path(), &target)?;
        } else {
            ensure!(
                kind.is_file(),
                "Provider tree contains a symlink or special file"
            );
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn relocate(directory: &Path, staged: &Path, live: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            relocate(&entry.path(), staged, live)?;
        } else {
            ensure!(
                entry.file_type()?.is_file(),
                "Generator produced a symlink or special file"
            );
            if let Ok(content) = fs::read_to_string(entry.path())
                && content.contains(staged.to_str().context("Non-UTF8 staging path")?)
            {
                fs::write(
                    entry.path(),
                    content.replace(
                        staged.to_str().unwrap(),
                        live.to_str().context("Non-UTF8 provider path")?,
                    ),
                )?;
            }
        }
    }
    Ok(())
}

fn sync_tree(directory: &Path) -> anyhow::Result<()> {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            File::open(entry.path())?.sync_all()?;
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write_config(value: &str) -> anyhow::Result<()> {
        let directory = VpnProvider::Mullvad
            .get_dyn_wireguard_provider()?
            .wireguard_dir()?;
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("test.conf"), value)?;
        Ok(())
    }
    const VALID: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n";
    #[test]
    fn concurrent_syncs_wait_and_copy_the_last_committed_generation() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().to_owned();
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let first_root = root.clone();
        let first = std::thread::spawn(move || {
            crate::util::set_config_dir_override(Some(first_root));
            run(
                &VpnProvider::Mullvad,
                &[Protocol::Wireguard],
                || {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    write_config(VALID)
                },
                || Ok(()),
            )
            .unwrap();
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let (started, starting) = std::sync::mpsc::channel();
        let (generated, generating) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            crate::util::set_config_dir_override(Some(root));
            started.send(()).unwrap();
            run(
                &VpnProvider::Mullvad,
                &[Protocol::Wireguard],
                || {
                    let directory = VpnProvider::Mullvad
                        .get_dyn_wireguard_provider()?
                        .wireguard_dir()?;
                    assert_eq!(fs::read_to_string(directory.join("test.conf"))?, VALID);
                    generated.send(()).unwrap();
                    Ok(())
                },
                || Ok(()),
            )
            .unwrap();
        });
        starting.recv().unwrap();
        assert!(
            generating
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        release.send(()).unwrap();
        generating
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }
    #[test]
    fn failed_generation_validation_and_metadata_preserve_installed_tree_then_retry_commits() {
        let base = tempfile::tempdir().unwrap();
        crate::util::set_config_dir_override(Some(base.path().to_owned()));
        write_config(VALID).unwrap();
        let directory = VpnProvider::Mullvad
            .get_dyn_wireguard_provider()
            .unwrap()
            .wireguard_dir()
            .unwrap();
        let provider = directory.parent().unwrap();
        fs::write(provider.join(".sync.json"), "old metadata").unwrap();
        for failure in 0..3 {
            let result = run(
                &VpnProvider::Mullvad,
                &[Protocol::Wireguard],
                || {
                    write_config(if failure == 1 { "invalid" } else { VALID })?;
                    if failure == 0 {
                        anyhow::bail!("simulated failed download");
                    }
                    Ok(())
                },
                || {
                    if failure == 2 {
                        anyhow::bail!("metadata failure");
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read_to_string(directory.join("test.conf")).unwrap(),
                VALID
            );
            assert_eq!(
                fs::read_to_string(provider.join(".sync.json")).unwrap(),
                "old metadata"
            );
        }
        run(
            &VpnProvider::Mullvad,
            &[Protocol::Wireguard],
            || write_config(&VALID.replace("192.0.2.1", "192.0.2.2")),
            || {
                fs::write(
                    VpnProvider::Mullvad
                        .get_dyn_provider()
                        .provider_dir()?
                        .join(".sync.json"),
                    "new metadata",
                )?;
                Ok(())
            },
        )
        .unwrap();
        assert!(
            fs::read_to_string(directory.join("test.conf"))
                .unwrap()
                .contains("192.0.2.2")
        );
        assert_eq!(
            fs::read_to_string(provider.join(".sync.json")).unwrap(),
            "new metadata"
        );
        crate::util::set_config_dir_override(None);
    }
}
