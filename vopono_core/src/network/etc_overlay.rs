use anyhow::{Context, ensure};
use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const TRUSTED_RUNTIME_ROOT: &str = "/run/vopono/runtime";
const VOPONO_RUNTIME_PARENT: &str = "/run/vopono";

/// Create a private directory for files later consumed by privileged code.
///
/// Unlike `tempdir()`, this does not honor an ambient `TMPDIR`. The parent is
/// root-owned and inaccessible to unprivileged users, preventing symlink and
/// path-replacement attacks between preparation and mount/exec.
pub(crate) fn trusted_runtime_dir(prefix: &str) -> anyhow::Result<tempfile::TempDir> {
    let parent = Path::new(VOPONO_RUNTIME_PARENT);
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create {}", parent.display()))?;
    secure_root_directory(parent)?;
    let root = Path::new(TRUSTED_RUNTIME_ROOT);
    std::fs::create_dir(root).or_else(|error| {
        (error.kind() == std::io::ErrorKind::AlreadyExists)
            .then_some(())
            .ok_or(error)
    })?;
    secure_root_directory(root)?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .with_context(|| format!("Failed to create private directory in {}", root.display()))
}

fn secure_root_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_dir(),
        "{} is not a directory",
        path.display()
    );
    ensure!(
        metadata.uid() == 0,
        "{} is not owned by root",
        path.display()
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.mode() & 0o077 == 0,
        "{} is accessible by non-root users",
        path.display()
    );
    Ok(())
}

/// Prepared, inert overlay inputs retained for the lifetime of the child.
pub(crate) struct EtcOverlay {
    namespace: String,
    directory: Option<tempfile::TempDir>,
    pub(crate) source: CString,
    pub(crate) filesystem_type: CString,
    pub(crate) target: CString,
    pub(crate) options: CString,
}

impl EtcOverlay {
    pub(crate) fn prepare(namespace: &str) -> anyhow::Result<Self> {
        let prefix = format!("etc-{namespace}-");
        let directory = trusted_runtime_dir(&prefix)?;
        let upper = directory.path().join("upper");
        let work = directory.path().join("work");
        std::fs::create_dir(&upper)?;
        std::fs::create_dir(&work)?;
        // Overlayfs inherits the upperdir mode onto the mounted /etc root;
        // enforce 0755 so a restrictive daemon UMask never blocks unprivileged apps.
        std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o755))?;
        let namespace_etc = PathBuf::from("/etc/netns").join(namespace);
        for name in ["resolv.conf", "hosts", "nsswitch.conf"] {
            let source = namespace_etc.join(name);
            if source.is_file() {
                let target = upper.join(name);
                std::fs::copy(&source, &target).with_context(|| {
                    format!(
                        "Failed to stage {} for namespace {namespace}",
                        source.display()
                    )
                })?;
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
            }
        }

        Ok(Self {
            namespace: namespace.to_owned(),
            options: CString::new(format!(
                "lowerdir=/etc,upperdir={},workdir={}",
                upper.display(),
                work.display()
            ))?,
            source: CString::new("vopono-etc")?,
            filesystem_type: CString::new("overlay")?,
            target: CString::new("/etc")?,
            directory: Some(directory),
        })
    }
}

impl Drop for EtcOverlay {
    fn drop(&mut self) {
        let Some(directory) = self.directory.take() else {
            return;
        };
        // If detached/forked processes are still running inside the namespace,
        // keep the overlay upperdir/workdir alive so their mounted /etc view
        // does not hit ESTALE/ENOENT. Namespace teardown cleans them up.
        let ns_still_has_processes =
            super::netns::namespace_has_any_process(&self.namespace).unwrap_or(false);
        if ns_still_has_processes {
            let _ = directory.keep();
        }
    }
}

/// Remove any retained overlay backing directories for `namespace` once the
/// namespace itself is torn down.
pub(crate) fn cleanup_namespace_overlays(namespace: &str) {
    let root = Path::new(TRUSTED_RUNTIME_ROOT);
    let prefix = format!("etc-{namespace}-");
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(&prefix))
        {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}
