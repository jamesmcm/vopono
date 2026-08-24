//! Privilege-dropped writes into the connecting user's configuration tree.
//!
//! The root daemon adopts a client-supplied base directory (the client's
//! `XDG_CONFIG_HOME`) and then writes lockfiles and logs beneath it. Doing
//! those writes as root would both create root-owned files inside a
//! user-controlled tree and require post-hoc recursive `chown` walks - the
//! latter being the local privilege escalation primitive fixed here.
//!
//! Instead, every write into the adopted tree is performed by a short-lived
//! subprocess that drops privileges to the connecting user before touching
//! the filesystem (`__write-user-file` hidden verb, see `src/main.rs`). The
//! kernel therefore rejects any write the client's own user could not make:
//! an attacker-pointed `XDG_CONFIG_HOME` simply yields `EACCES`, files are
//! natively owned by the client, and no ownership fixups are needed.

use anyhow::{Context, anyhow};
use log::debug;
use nix::unistd::{Gid, Uid, User};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

thread_local! {
    /// Path of the vopono binary used to spawn dropped-privilege helpers.
    /// Set per daemon client thread; absent in CLI/sudo contexts.
    static HELPER_EXE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Upper bound for the JSON payload handed to the helper subprocess.
pub const OWNER_WRITE_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

pub fn set_helper_exe_override(exe: Option<PathBuf>) {
    HELPER_EXE.with(|ov| *ov.borrow_mut() = exe);
}

fn helper_exe_override() -> Option<PathBuf> {
    HELPER_EXE.with(|ov| ov.borrow().clone())
}

/// A single filesystem operation for the dropped-privilege helper.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerWriteRequest {
    /// Create parent directories and atomically write `contents` to `path`.
    ///
    /// `mode` (when set) is applied to the final file, e.g. `Some(0o640)` to
    /// preserve the historic lockfile permissions.
    File {
        path: PathBuf,
        contents: String,
        #[serde(default)]
        mode: Option<u32>,
    },
    /// `create_dir_all` for `path`; `mode` applies to the leaf directory.
    Dir {
        path: PathBuf,
        #[serde(default)]
        mode: Option<u32>,
    },
}

/// Child-side implementation of the hidden `vopono __write-user-file` verb.
///
/// Refuses to run as root: the whole point is that these operations run with
/// the connecting user's credentials, so a misconfigured spawn fails loudly
/// instead of silently recreating the root-owned-write bug.
pub fn perform_owner_write(request: &OwnerWriteRequest) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if nix::unistd::geteuid().is_root() {
        anyhow::bail!("refusing privileged write helper invocation as root");
    }
    match request {
        OwnerWriteRequest::File {
            path,
            contents,
            mode,
        } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create parent directories for {}", path.display())
                })?;
            }
            // Atomic replace so readers never observe a partial lockfile.
            let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
            {
                let mut file = std::fs::File::create(&temporary)
                    .with_context(|| format!("Failed to create {}", temporary.display()))?;
                file.write_all(contents.as_bytes())?;
                if let Some(mode) = mode {
                    file.set_permissions(PermissionsExt::from_mode(*mode))?;
                }
            }
            std::fs::rename(&temporary, path).with_context(|| {
                format!(
                    "Failed to move {} into place at {}",
                    temporary.display(),
                    path.display()
                )
            })?;
        }
        OwnerWriteRequest::Dir { path, mode } => {
            std::fs::create_dir_all(path)
                .with_context(|| format!("Failed to create {}", path.display()))?;
            if let Some(mode) = mode {
                std::fs::set_permissions(path, PermissionsExt::from_mode(*mode))?;
            }
        }
    }
    Ok(())
}

/// Read and execute a helper request from stdin (bounded).
pub fn run_owner_write_from_stdin() -> anyhow::Result<()> {
    let mut payload = Vec::new();
    std::io::stdin()
        .take(OWNER_WRITE_MAX_PAYLOAD as u64 + 1)
        .read_to_end(&mut payload)?;
    anyhow::ensure!(
        payload.len() <= OWNER_WRITE_MAX_PAYLOAD,
        "Helper payload too large"
    );
    let request: OwnerWriteRequest =
        serde_json::from_slice(&payload).context("Invalid write helper request payload")?;
    perform_owner_write(&request)
}

/// Spawn the helper binary with the given user identity to apply `request`.
fn spawn_owner_write(request: &OwnerWriteRequest, uid: Uid, gid: Gid) -> anyhow::Result<()> {
    let exe = helper_exe_override().ok_or_else(|| {
        anyhow!("No helper executable configured for dropped-privilege config writes")
    })?;
    let user = User::from_uid(uid)?.ok_or_else(|| anyhow!("Unknown uid {uid}"))?;
    let payload = serde_json::to_vec(request)?;
    let name_cstr = std::ffi::CString::new(user.name.clone())?;
    let mut child = unsafe {
        let mut command = Command::new(&exe);
        command
            .arg("__write-user-file")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // Full credential transition in the child before exec: supplementary
        // groups, primary group, then user. Ordering matters - setuid last.
        command.pre_exec(move || {
            nix::unistd::initgroups(&name_cstr, gid)?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;
            Ok(())
        });
        command
            .spawn()
            .with_context(|| format!("Failed to spawn write helper {}", exe.display()))?
    };
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload)?;
    }
    let output = child
        .wait_with_output()
        .context("Failed to wait for write helper")?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "Write helper failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Write `contents` to `path` as the configured config owner.
///
/// Returns `Ok(false)` when no config-owner override is set (CLI/sudo
/// context): callers should fall back to their legacy in-process write.
/// Returns an error when the override is set but the dropped-privilege write
/// fails - notably when the target is not writable by that user, which is
/// the intended hard failure for attacker-influenced paths.
pub fn write_file_as_config_owner(
    path: &Path,
    contents: &str,
    mode: Option<u32>,
) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_owner_override() else {
        return Ok(false);
    };
    debug!(
        "Dropped-privilege write to {} for uid {uid}",
        path.display()
    );
    spawn_owner_write(
        &OwnerWriteRequest::File {
            path: path.to_path_buf(),
            contents: contents.to_string(),
            mode,
        },
        uid,
        gid,
    )?;
    Ok(true)
}

/// Ensure `dir` (and parents) exists, created as the configured config owner.
///
/// Same contract as [`write_file_as_config_owner`]; `mode` applies to the
/// leaf directory when provided.
pub fn ensure_dir_as_config_owner(dir: &Path, mode: Option<u32>) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_owner_override() else {
        return Ok(false);
    };
    debug!("Dropped-privilege mkdir at {} for uid {uid}", dir.display());
    spawn_owner_write(
        &OwnerWriteRequest::Dir {
            path: dir.to_path_buf(),
            mode,
        },
        uid,
        gid,
    )?;
    Ok(true)
}

/// Canonicalize `path` and require it to resolve to an existing directory
/// owned by exactly `uid`.
///
/// Used by the daemon before adopting a client-supplied base directory:
/// symlinks are resolved first (so a link into a root-owned location fails
/// the ownership check), and root-owned or foreign-owned directories are
/// rejected outright.
pub fn validated_user_owned_dir(path: &Path, uid: Uid) -> anyhow::Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Failed to resolve {}", path.display()))?;
    let metadata = std::fs::metadata(&canonical)
        .with_context(|| format!("Failed to inspect {}", canonical.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{} is not a directory",
        canonical.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == uid.as_raw(),
            "{} is owned by uid {}, not the authenticated uid {}",
            canonical.display(),
            metadata.uid(),
            uid.as_raw()
        );
    }
    Ok(canonical)
}

/// Validate a network namespace name supplied by a caller.
///
/// Namespace names end up as argv elements for `ip netns ...` (option
/// injection via leading `-`) and as path components under `/etc/netns/<name>`
/// and `/run/netns/<name>` (traversal). Restrict to a conservative charset.
pub fn validate_netns_name(name: &str) -> anyhow::Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.ends_with('.');
    anyhow::ensure!(
        valid,
        "Invalid network namespace name '{name}': must be 1-64 ASCII alphanumeric characters, dots, underscores or hyphens, starting alphanumerically"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vopono-owner-write-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn performs_atomic_file_write() {
        let base = tempdir("file");
        let target = base.join("nested").join("lock");
        perform_owner_write(&OwnerWriteRequest::File {
            path: target.clone(),
            contents: "hello".into(),
            mode: None,
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        assert!(target.is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn creates_directories() {
        let base = tempdir("dir");
        let target = base.join("a").join("b");
        perform_owner_write(&OwnerWriteRequest::Dir {
            path: target.clone(),
            mode: Some(0o750),
        })
        .unwrap();
        assert!(target.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o750);
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let base = tempdir("overwrite");
        let target = base.join("f");
        std::fs::write(&target, "old").unwrap();
        perform_owner_write(&OwnerWriteRequest::File {
            path: target.clone(),
            contents: "new".into(),
            mode: None,
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn validates_user_owned_dirs() {
        let uid = nix::unistd::getuid();
        let base = tempdir("validate");

        // Owned directory passes and is canonicalized.
        let nested = base.join("cfg");
        std::fs::create_dir_all(&nested).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&nested, &link).unwrap();
        let canonical = validated_user_owned_dir(&link, uid).unwrap();
        assert_eq!(canonical, nested.canonicalize().unwrap());

        // Missing path is rejected.
        assert!(validated_user_owned_dir(&base.join("missing"), uid).is_err());

        // Non-directory is rejected.
        std::fs::write(base.join("plain"), "x").unwrap();
        assert!(validated_user_owned_dir(&base.join("plain"), uid).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn netns_names_are_constrained() {
        assert!(validate_netns_name("vo_mu_se").is_ok());
        assert!(validate_netns_name("vo_p_se-sth").is_ok());
        assert!(validate_netns_name("a.b_c-d").is_ok());
        assert!(validate_netns_name("").is_err());
        assert!(validate_netns_name("-flag").is_err());
        assert!(validate_netns_name(".hidden").is_err());
        assert!(validate_netns_name("trailing.").is_err());
        assert!(validate_netns_name("has space").is_err());
        assert!(validate_netns_name("../etc").is_err());
        assert!(validate_netns_name("slash/es").is_err());
        assert!(validate_netns_name(&"x".repeat(65)).is_err());
    }
}
