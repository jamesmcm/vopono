use crate::status::{self, FORWARDED_PORT_SIDECAR, LockfileKind};
use anyhow::Context;
use nix::dir::{Dir, Entry, Type};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::ffi::CStr;
use std::path::Path;

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NOFOLLOW);

// Directory handles and relative unlinks prevent a concurrent symlink swap
// from redirecting cleanup. Never recurse: unknown files and nested directories
// are preserved even when the named network namespace has disappeared.
pub(super) fn clean_dead_locks(config_base: &Path) -> anyhow::Result<()> {
    // The selected config base may itself be a symlink (for example ~/.config).
    // Pin that directory, then reject symlinks at every level below it.
    let Some(config) = optional_directory(Dir::open(
        config_base,
        DIR_FLAGS & !OFlag::O_NOFOLLOW,
        Mode::empty(),
    ))?
    else {
        return Ok(());
    };
    let Some(vopono) =
        optional_directory(Dir::openat(&config, "vopono", DIR_FLAGS, Mode::empty()))?
    else {
        return Ok(());
    };
    let Some(mut locks) =
        optional_directory(Dir::openat(&vopono, "locks", DIR_FLAGS, Mode::empty()))?
    else {
        return Ok(());
    };
    let running_processes = super::get_all_running_pids();
    for entry in entries(&mut locks)? {
        let Ok(namespace) = entry.file_name().to_str() else {
            continue;
        };
        if crate::network::netns::validate_netns_name(namespace).is_err() {
            continue;
        }
        let Some(mut dir) = optional_directory(Dir::openat(
            &locks,
            entry.file_name(),
            DIR_FLAGS,
            Mode::empty(),
        ))?
        else {
            continue;
        };
        // Permission or inspection failures do not establish absence.
        let namespace_missing = std::fs::metadata(Path::new("/var/run/netns").join(namespace))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        for file in entries(&mut dir)? {
            if file.file_type() != Some(Type::File) {
                continue;
            }
            let Ok(filename) = file.file_name().to_str() else {
                continue;
            };
            let path = Path::new(filename);
            let stale = match LockfileKind::from_path(path) {
                Some(LockfileKind::Primary) => filename
                    .parse::<u32>()
                    .is_ok_and(|pid| namespace_missing || !running_processes.contains(&pid)),
                Some(LockfileKind::Client) => {
                    namespace_missing || status::client_lockfile_is_stale(path, namespace)
                }
                None => false,
            };
            if stale {
                log::debug!("Removing stale lockfile: {namespace}/{filename}");
                remove_file(&dir, file.file_name())?;
            }
        }

        let remaining = entries(&mut dir)?;
        if remaining.iter().all(|file| {
            file.file_name().to_bytes() == FORWARDED_PORT_SIDECAR.as_bytes()
                && file.file_type() == Some(Type::File)
        }) {
            for file in remaining {
                remove_file(&dir, file.file_name())?;
            }
            match unlinkat(&locks, entry.file_name(), UnlinkatFlags::RemoveDir) {
                // Another session may have removed or populated the directory.
                Ok(()) | Err(Errno::ENOENT | Errno::ENOTEMPTY | Errno::EEXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn optional_directory(result: nix::Result<Dir>) -> anyhow::Result<Option<Dir>> {
    match result {
        Ok(dir) => Ok(Some(dir)),
        // Missing entries and symlinks are deliberately left untouched.
        Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn entries(dir: &mut Dir) -> nix::Result<Vec<Entry>> {
    dir.iter()
        .filter(|entry| match entry {
            Ok(entry) => !matches!(entry.file_name().to_bytes(), b"." | b".."),
            Err(_) => true,
        })
        .collect()
}

fn remove_file(dir: &Dir, filename: &CStr) -> anyhow::Result<()> {
    match unlinkat(dir, filename, UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Could not remove lockfile {}", filename.to_string_lossy())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn ignores_symlinks_at_each_level_of_the_lock_tree() {
        for component in ["vopono", "locks", "namespace"] {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().join("config");
            let outside = temp.path().join("outside");
            fs::create_dir_all(base.join("vopono/locks")).unwrap();
            let outside_lock_dir = match component {
                "vopono" => outside.join("locks/vo_symlink_test"),
                "locks" => outside.join("vo_symlink_test"),
                _ => outside.clone(),
            };
            fs::create_dir_all(&outside_lock_dir).unwrap();
            let sentinel = outside_lock_dir.join("4294967295");
            fs::write(&sentinel, "unrelated data").unwrap();
            let link = match component {
                "vopono" => base.join("vopono"),
                "locks" => base.join("vopono/locks"),
                _ => base.join("vopono/locks/vo_symlink_test"),
            };
            if link.exists() {
                fs::remove_dir_all(&link).unwrap();
            }
            symlink(&outside, &link).unwrap();

            clean_dead_locks(&base).unwrap();

            assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unrelated data");
            assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        }
    }

    #[test]
    fn supports_a_symlinked_config_base() {
        let temp = tempfile::tempdir().unwrap();
        let real_config = temp.path().join("real-config");
        let config_link = temp.path().join("config");
        let dir = real_config.join("vopono/locks/vo_cleanup_config_link");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("4294967295"), "stale").unwrap();
        symlink(&real_config, &config_link).unwrap();

        clean_dead_locks(&config_link).unwrap();

        assert!(!dir.exists());
        assert!(config_link.is_dir());
    }

    #[test]
    fn cleans_missing_namespace_locks_but_preserves_unknown_state() {
        let temp = tempfile::tempdir().unwrap();
        let namespace = "vo_cleanup_missing";
        assert!(!Path::new("/var/run/netns").join(namespace).exists());
        let dir = temp.path().join("vopono/locks").join(namespace);
        fs::create_dir_all(dir.join("nested")).unwrap();
        let primary = dir.join(std::process::id().to_string());
        let client = dir.join(format!("client-{}", std::process::id()));
        for path in [&primary, &client, &dir.join(FORWARDED_PORT_SIDECAR)] {
            fs::write(path, "state").unwrap();
        }
        fs::write(dir.join("notes.txt"), "keep").unwrap();
        fs::write(dir.join("nested/4294967295"), "keep").unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, "keep").unwrap();
        let link = dir.join("client-4294967295");
        symlink(&outside, &link).unwrap();

        clean_dead_locks(temp.path()).unwrap();

        assert!(!primary.exists());
        assert!(!client.exists());
        assert!(dir.join(FORWARDED_PORT_SIDECAR).exists());
        assert_eq!(fs::read_to_string(dir.join("notes.txt")).unwrap(), "keep");
        assert_eq!(
            fs::read_to_string(dir.join("nested/4294967295")).unwrap(),
            "keep"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");

        fs::remove_file(dir.join("notes.txt")).unwrap();
        fs::remove_dir_all(dir.join("nested")).unwrap();
        fs::remove_file(link).unwrap();
        clean_dead_locks(temp.path()).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn relative_unlink_stays_in_open_directory_after_a_symlink_swap() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("locks");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(original.join("4294967295"), "stale").unwrap();
        fs::write(outside.join("4294967295"), "keep").unwrap();
        let dir = Dir::open(&original, DIR_FLAGS, Mode::empty()).unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(&outside, &original).unwrap();

        remove_file(&dir, c"4294967295").unwrap();

        assert!(!moved.join("4294967295").exists());
        assert_eq!(
            fs::read_to_string(outside.join("4294967295")).unwrap(),
            "keep"
        );
    }
}
