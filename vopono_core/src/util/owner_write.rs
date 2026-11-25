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
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
    /// `mode` (when set) is applied when the temporary inode is created and
    /// preserved on the final file.
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
    /// Apply permissions throughout an existing tree without following
    /// symlinks. This runs as the config owner so a concurrent path swap can
    /// never turn permission maintenance into a privileged write.
    TreePermissions {
        path: PathBuf,
        file_mode: u32,
        dir_mode: u32,
    },
    /// Clean known lockfiles with the config owner's filesystem permissions.
    CleanLocks {
        config_dir: PathBuf,
    },
    RemoveFile {
        path: PathBuf,
    },
    RemoveDir {
        path: PathBuf,
    },
}

/// Resolve a user's supplementary groups before `fork()` so `pre_exec` only
/// executes async-signal-safe syscalls (`setgroups`, `setgid`, `setuid`).
pub fn supplementary_groups(user_name: &str, gid: Gid) -> anyhow::Result<Vec<Gid>> {
    let name_cstr = std::ffi::CString::new(user_name)?;
    let groups = nix::unistd::getgrouplist(&name_cstr, gid)
        .with_context(|| format!("Failed to resolve supplementary groups for '{user_name}'"))?;
    Ok(groups)
}

/// Child-side implementation of the hidden `vopono __write-user-file` verb.
///
/// Refuses to run as root: the whole point is that these operations run with
/// the connecting user's credentials, so a misconfigured spawn fails loudly
/// instead of silently recreating the root-owned-write bug.
pub fn perform_owner_write(request: &OwnerWriteRequest) -> anyhow::Result<()> {
    if nix::unistd::geteuid().is_root() {
        anyhow::bail!("refusing privileged write helper invocation as root");
    }
    match request {
        OwnerWriteRequest::RemoveFile { path } => match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
        OwnerWriteRequest::RemoveDir { path } => match std::fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
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
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                if let Some(mode) = mode {
                    options.mode(*mode);
                }
                let mut file = options
                    .open(&temporary)
                    .with_context(|| format!("Failed to create {}", temporary.display()))?;
                if let Some(mode) = mode {
                    file.set_permissions(PermissionsExt::from_mode(*mode))?;
                }
                file.write_all(contents.as_bytes())?;
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
        // Only permissions are adjusted here, never ownership: under the
        // dropped-privilege model every file is natively created by the config
        // owner, so ownership is already correct. This does not repair
        // pre-existing root-owned files left over from earlier versions.
        OwnerWriteRequest::TreePermissions {
            path,
            file_mode,
            dir_mode,
        } => {
            for entry in walkdir::WalkDir::new(path) {
                let entry = entry.with_context(|| format!("Failed to walk {}", path.display()))?;
                let metadata = std::fs::symlink_metadata(entry.path())
                    .with_context(|| format!("Failed to stat {}", entry.path().display()))?;
                if metadata.file_type().is_symlink() {
                    continue;
                }
                let mode = if metadata.is_dir() {
                    *dir_mode
                } else {
                    *file_mode
                };
                std::fs::set_permissions(entry.path(), PermissionsExt::from_mode(mode))
                    .with_context(|| {
                        format!("Failed to set permissions on {}", entry.path().display())
                    })?;
            }
        }
        OwnerWriteRequest::CleanLocks { config_dir } => {
            super::lock_cleanup::clean_dead_locks(config_dir)?;
        }
    }
    Ok(())
}

/// Privilege-drop state captured before starting a background worker.
///
/// The daemon's authenticated config owner and helper path are thread-local,
/// so workers that update user-owned state must explicitly inherit them.
#[derive(Clone, Debug)]
pub struct OwnerWriteContext {
    owner: Option<(Uid, Gid)>,
    helper_exe: Option<PathBuf>,
}

pub fn capture_owner_write_context() -> anyhow::Result<OwnerWriteContext> {
    let owner = super::config_write_owner()?;
    let helper_exe = match (owner, helper_exe_override()) {
        (Some(_), None) => Some(std::env::current_exe().context("Failed to locate write helper")?),
        (_, helper_exe) => helper_exe,
    };
    Ok(OwnerWriteContext { owner, helper_exe })
}

pub fn install_owner_write_context(context: &OwnerWriteContext) {
    super::set_config_owner_override(context.owner);
    set_helper_exe_override(context.helper_exe.clone());
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
    let groups = supplementary_groups(&user.name, gid)?;
    let payload = serde_json::to_vec(request)?;
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
        // Only async-signal-safe syscalls are called inside pre_exec.
        command.pre_exec(move || {
            nix::unistd::setgroups(&groups)?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;
            Ok(())
        });
        command
            .spawn()
            .with_context(|| format!("Failed to spawn write helper {}", exe.display()))?
    };
    let write_result = if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload)
    } else {
        Ok(())
    };
    // Always reap the child even if stdin hit EPIPE so we never leak a zombie
    // and can report any stderr from the helper.
    let output = child
        .wait_with_output()
        .context("Failed to wait for write helper")?;
    if output.status.success() {
        write_result?;
        Ok(())
    } else {
        Err(anyhow!(
            "Write helper failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn remove_file_as_config_owner(path: &Path) -> anyhow::Result<()> {
    if remove_file_as_config_owner_if_needed(path)? {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn remove_file_as_config_owner_if_needed(path: &Path) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
        return Ok(false);
    };
    spawn_owner_write(
        &OwnerWriteRequest::RemoveFile {
            path: path.to_owned(),
        },
        uid,
        gid,
    )?;
    Ok(true)
}

pub fn remove_dir_as_config_owner_if_needed(path: &Path) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
        return Ok(false);
    };
    spawn_owner_write(
        &OwnerWriteRequest::RemoveDir {
            path: path.to_owned(),
        },
        uid,
        gid,
    )?;
    Ok(true)
}

/// Write `contents` to `path` as the configured config owner.
///
/// The daemon uses its authenticated owner override; a privileged sudo process
/// resolves the invoking account through NSS. Returns `Ok(false)` only when
/// no privilege drop is needed (an unprivileged process or direct root use),
/// allowing callers to perform their normal in-process write. A failed helper
/// is a hard error, notably for attacker-influenced paths the owner cannot
/// write.
pub fn write_file_as_config_owner(
    path: &Path,
    contents: &str,
    mode: Option<u32>,
) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
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
/// Same privilege-selection contract as [`write_file_as_config_owner`];
/// `mode` applies to the leaf directory when provided.
pub fn ensure_dir_as_config_owner(dir: &Path, mode: Option<u32>) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
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

/// Apply file and directory modes recursively as the configured config owner.
///
/// Symlinks are skipped, and the helper runs without privilege. Consequently,
/// even a path swapped after inspection cannot affect a root-owned target.
pub fn set_tree_permissions_as_config_owner(
    path: &Path,
    file_mode: u32,
    dir_mode: u32,
) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
        return Ok(false);
    };
    debug!(
        "Dropped-privilege permission repair at {} for uid {uid}",
        path.display()
    );
    spawn_owner_write(
        &OwnerWriteRequest::TreePermissions {
            path: path.to_path_buf(),
            file_mode,
            dir_mode,
        },
        uid,
        gid,
    )?;
    Ok(true)
}

pub(super) fn clean_locks_as_config_owner(config_dir: &Path) -> anyhow::Result<bool> {
    let Some((uid, gid)) = super::config_write_owner()? else {
        return Ok(false);
    };
    spawn_owner_write(
        &OwnerWriteRequest::CleanLocks {
            config_dir: config_dir.to_path_buf(),
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
    anyhow::ensure!(
        metadata.uid() == uid.as_raw(),
        "{} is owned by uid {}, not the authenticated uid {}",
        canonical.display(),
        metadata.uid(),
        uid.as_raw()
    );
    Ok(canonical)
}

/// Read a regular configuration file with the authenticated user's permissions.
/// Runs a separate executable so daemon threads never change process credentials.
pub fn read_file_as_config_owner(path: &Path) -> anyhow::Result<Vec<u8>> {
    if !super::is_daemon_mode() {
        return read_regular_file(path)
            .with_context(|| format!("Could not read {}", path.display()));
    }
    let (uid, gid) =
        super::config_owner_override().context("Missing authenticated config owner")?;
    if uid.is_root() {
        return read_regular_file(path)
            .with_context(|| format!("Could not read {}", path.display()));
    }
    let exe = helper_exe_override().context("Missing config reader executable")?;
    let user = User::from_uid(uid)?.context("Unknown config owner")?;
    let groups = supplementary_groups(&user.name, gid)?;
    let output = unsafe {
        let mut command = Command::new(exe);
        command
            .arg("__read-user-file")
            .arg("--")
            .arg(path)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.pre_exec(move || {
            nix::unistd::setgroups(&groups)?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;
            Ok(())
        });
        command.output()?
    };
    anyhow::ensure!(
        output.status.success(),
        "Could not read configuration file {} as the connecting user: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

pub fn read_regular_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    read_bounded_regular_file(path, 4 * 1024 * 1024)
}

pub fn read_regular_file_nofollow(path: &Path) -> anyhow::Result<Vec<u8>> {
    read_bounded_regular_file_nofollow(path, 4 * 1024 * 1024)
}

pub fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    read_bounded_regular_file_with_flags(path, max_bytes, libc::O_NONBLOCK)
}

pub fn read_bounded_regular_file_nofollow(
    path: &Path,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    read_bounded_regular_file_with_flags(path, max_bytes, libc::O_NONBLOCK | libc::O_NOFOLLOW)
}

fn read_bounded_regular_file_with_flags(
    path: &Path,
    max_bytes: usize,
    flags: libc::c_int,
) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "Configuration input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "Configuration file exceeds size limit"
    );
    Ok(bytes)
}

pub fn run_owner_read(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !nix::unistd::geteuid().is_root(),
        "Refusing privileged configuration reader"
    );
    std::io::stdout().write_all(&read_regular_file(path)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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
            mode: Some(0o600),
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        assert!(target.is_file());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn creates_directories() {
        let base = tempdir("dir");
        let target = base.join("a").join("b");
        perform_owner_write(&OwnerWriteRequest::Dir {
            path: target.clone(),
            mode: Some(0o700),
        })
        .unwrap();
        assert!(target.is_dir());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn tree_permissions_skip_symlinks() {
        let base = tempdir("tree-permissions");
        let target = base.with_extension("outside");
        std::fs::write(&target, "outside").unwrap();
        std::fs::set_permissions(&target, PermissionsExt::from_mode(0o644)).unwrap();
        let nested = base.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let regular = nested.join("regular");
        std::fs::write(&regular, "inside").unwrap();
        symlink(&target, nested.join("link")).unwrap();

        perform_owner_write(&OwnerWriteRequest::TreePermissions {
            path: base.clone(),
            file_mode: 0o600,
            dir_mode: 0o700,
        })
        .unwrap();

        assert_eq!(
            std::fs::metadata(&regular).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_file(&target);
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
    fn root_config_owner_override_does_not_spawn_unprivileged_write_helper() {
        let previous = crate::util::config_owner_override();
        crate::util::set_config_owner_override(Some((Uid::from_raw(0), Gid::from_raw(0))));
        let write_owner = crate::util::config_write_owner().unwrap();
        crate::util::set_config_owner_override(previous);
        assert_eq!(write_owner, None);
    }
}
