use anyhow::Context;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vopono_core::network::netns::NetworkNamespace;

const OWNER_DIR: &str = "/run/vopono/namespace-owners";
static OWNER_RECORD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Serialize, Deserialize)]
struct OwnerRecord {
    uid: u32,
    device: u64,
    inode: u64,
    namespace: String,
    #[serde(default)]
    persistent: bool,
    #[serde(default)]
    stopping: bool,
}

impl OwnerRecord {
    fn is_persistent(&self) -> bool {
        self.persistent && !self.stopping
    }

    fn mark_persistent(&mut self, name: &str) -> anyhow::Result<()> {
        anyhow::ensure!(!self.stopping, "Namespace {name} is being stopped");
        self.persistent = true;
        Ok(())
    }

    fn mark_stopping(&mut self) {
        self.persistent = false;
        self.stopping = true;
    }
}

fn namespace_path(name: &str) -> PathBuf {
    Path::new("/run/netns").join(name)
}

fn record_path(name: &str) -> PathBuf {
    Path::new(OWNER_DIR).join(name)
}

/// Give daemon-created namespace names a stable per-user identity while
/// retaining the familiar provider/server prefix.
pub fn name_for_uid(base: &str, uid: Uid) -> anyhow::Result<String> {
    vopono_core::network::netns::validate_netns_name(base)?;
    let suffix = format!("-u{}", uid.as_raw());
    anyhow::ensure!(suffix.len() < 64, "UID suffix is too long");
    let prefix_len = (64 - suffix.len()).min(base.len());
    let name = format!("{}{}", &base[..prefix_len], suffix);
    vopono_core::network::netns::validate_netns_name(&name)?;
    Ok(name)
}

/// Persist ownership outside the user-writable config tree. Device/inode bind
/// the record to this exact namespace rather than merely its reusable name.
pub fn tag(namespace_state: &NetworkNamespace, uid: Uid) -> anyhow::Result<()> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let name = &namespace_state.name;
    vopono_core::network::netns::validate_netns_name(name)?;
    let namespace = std::fs::metadata(namespace_path(name))
        .with_context(|| format!("Failed to inspect namespace {name}"))?;
    std::fs::create_dir_all(OWNER_DIR)?;
    std::fs::set_permissions(OWNER_DIR, std::fs::Permissions::from_mode(0o700))?;

    // Re-tagging happens whenever an existing namespace is reused. Preserve a
    // previous keep-alive/create-only decision rather than silently reverting
    // it to ordinary last-client teardown semantics.
    let (persistent, stopping) = validated_record(name, uid)
        .map(|record| (record.persistent, record.stopping))
        .unwrap_or((false, false));
    let record = OwnerRecord {
        uid: uid.as_raw(),
        device: namespace.dev(),
        inode: namespace.ino(),
        namespace: serde_json::to_string(namespace_state)?,
        persistent,
        stopping,
    };
    persist_record(name, &record)
}

fn persist_record(name: &str, record: &OwnerRecord) -> anyhow::Result<()> {
    let path = record_path(name);
    let mut file = tempfile::NamedTempFile::new_in(OWNER_DIR)?;
    serde_json::to_writer(&mut file, record)?;
    file.as_file().sync_all()?;
    file.persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to persist ownership tag for {name}"))?;
    Ok(())
}

pub fn authorize(name: &str, uid: Uid) -> anyhow::Result<()> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    validated_record(name, uid).map(|_| ())
}

pub fn load(name: &str, uid: Uid) -> anyhow::Result<NetworkNamespace> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let record = validated_record(name, uid)?;
    let namespace: NetworkNamespace = serde_json::from_str(&record.namespace)
        .context("Invalid root-owned namespace state snapshot")?;
    anyhow::ensure!(namespace.name == name, "Namespace snapshot name mismatch");
    Ok(namespace)
}

pub fn is_persistent(name: &str, uid: Uid) -> anyhow::Result<bool> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let record = validated_record(name, uid)?;
    Ok(record.is_persistent())
}

pub fn mark_persistent(name: &str, uid: Uid) -> anyhow::Result<()> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let mut record = validated_record(name, uid)?;
    record.mark_persistent(name)?;
    persist_record(name, &record)
}

pub fn mark_stopping(name: &str, uid: Uid) -> anyhow::Result<()> {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let mut record = validated_record(name, uid)?;
    record.mark_stopping();
    persist_record(name, &record)
}

fn validated_record(name: &str, uid: Uid) -> anyhow::Result<OwnerRecord> {
    vopono_core::network::netns::validate_netns_name(name)?;
    let record_path = record_path(name);
    let record_meta = std::fs::symlink_metadata(&record_path)
        .with_context(|| format!("Namespace {name} has no daemon ownership tag"))?;
    anyhow::ensure!(
        record_meta.file_type().is_file() && record_meta.uid() == 0,
        "Namespace {name} ownership tag is not a root-owned regular file"
    );
    let record: OwnerRecord = serde_json::from_reader(std::fs::File::open(&record_path)?)?;
    let namespace = std::fs::metadata(namespace_path(name))
        .with_context(|| format!("Failed to inspect namespace {name}"))?;
    validate_record(name, &record, uid, namespace.dev(), namespace.ino())?;
    Ok(record)
}

fn validate_record(
    name: &str,
    record: &OwnerRecord,
    uid: Uid,
    device: u64,
    inode: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        record.device == device && record.inode == inode,
        "Namespace {name} ownership tag is stale"
    );
    anyhow::ensure!(
        record.uid == uid.as_raw(),
        "Namespace {name} belongs to uid {}, not authenticated uid {}",
        record.uid,
        uid.as_raw()
    );
    Ok(())
}

pub fn remove(name: &str) {
    let _guard = OWNER_RECORD_LOCK
        .lock()
        .expect("owner record lock poisoned");
    let _ = std::fs::remove_file(record_path(name));
}

#[cfg(test)]
mod tests {
    use super::{NetworkNamespace, OwnerRecord, name_for_uid, validate_record};
    use nix::unistd::Uid;

    #[test]
    fn per_user_names_are_distinct_and_bounded() {
        assert_eq!(
            name_for_uid("vo_m_se", Uid::from_raw(1000)).unwrap(),
            "vo_m_se-u1000"
        );
        assert_ne!(
            name_for_uid("vo_m_se", Uid::from_raw(1000)).unwrap(),
            name_for_uid("vo_m_se", Uid::from_raw(1001)).unwrap()
        );
        let name = name_for_uid(&"a".repeat(64), Uid::from_raw(u32::MAX)).unwrap();
        assert_eq!(name.len(), 64);
    }

    #[test]
    fn records_bind_uid_and_namespace_identity() {
        let record = OwnerRecord {
            uid: 1000,
            device: 7,
            inode: 11,
            namespace: "snapshot".to_string(),
            persistent: false,
            stopping: false,
        };
        assert!(validate_record("vo_test", &record, Uid::from_raw(1000), 7, 11).is_ok());
        assert!(
            validate_record("vo_test", &record, Uid::from_raw(1001), 7, 11)
                .unwrap_err()
                .to_string()
                .contains("belongs to uid 1000")
        );
        assert!(
            validate_record("vo_test", &record, Uid::from_raw(1000), 7, 12)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }

    #[test]
    fn old_owner_records_default_to_non_persistent() {
        let record: OwnerRecord =
            serde_json::from_str(r#"{"uid":1000,"device":7,"inode":11,"namespace":"snapshot"}"#)
                .unwrap();
        assert!(!record.persistent);
        assert!(!record.stopping);
    }

    #[test]
    fn stopping_state_cannot_be_reversed_by_keep_alive() {
        let mut record = OwnerRecord {
            uid: 1000,
            device: 7,
            inode: 11,
            namespace: "snapshot".to_string(),
            persistent: false,
            stopping: false,
        };
        record.mark_persistent("vo_test").unwrap();
        assert!(record.is_persistent());
        record.mark_stopping();
        assert!(!record.is_persistent());
        assert!(record.mark_persistent("vo_test").is_err());
    }

    #[test]
    fn namespace_snapshots_round_trip_without_user_lockfiles() {
        let namespace = NetworkNamespace::attach_unmanaged("vo_test".to_string()).unwrap();
        let snapshot = serde_json::to_string(&namespace).unwrap();
        let restored: NetworkNamespace = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(restored.name, "vo_test");
        assert!(restored.unmanaged);
    }
}
