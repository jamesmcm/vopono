use crate::network::netns::LockfileStatus;
use crate::util::config_dir;
use log::debug;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub type LockNamespaces = HashMap<String, Vec<LockfileStatus>>;

#[derive(Clone, Debug, Default)]
pub struct LockNamespacesStatus {
    pub namespaces: LockNamespaces,
    pub errors: Vec<String>,
}

pub fn read_lock_namespaces() -> anyhow::Result<LockNamespacesStatus> {
    let mut dir = config_dir()?;
    dir.push("vopono");
    dir.push("locks");
    read_lock_namespaces_from_dir(dir)
}

pub fn read_lock_namespaces_from_dir(
    dir: impl Into<PathBuf>,
) -> anyhow::Result<LockNamespacesStatus> {
    let dir = dir.into();
    let mut grouped_locks: HashMap<String, LockGroup> = HashMap::new();
    let mut errors = Vec::new();
    if !dir.exists() {
        return Ok(LockNamespacesStatus::default());
    }

    for entry in WalkDir::new(dir) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        if !entry.path().is_file() {
            continue;
        }
        let Some(lockfile_kind) = LockfileKind::from_path(entry.path()) else {
            continue;
        };

        match File::open(entry.path()) {
            Ok(lockfile) => match ron::de::from_reader::<_, LockfileStatus>(lockfile) {
                Ok(lock) => {
                    let locks = grouped_locks.entry(lock.ns.name.clone()).or_default();
                    match lockfile_kind {
                        LockfileKind::Primary => locks.primary.push(lock),
                        LockfileKind::Client => locks.client.push(lock),
                    }
                }
                Err(error) => {
                    if lockfile_kind == LockfileKind::Client {
                        debug!(
                            "Skipping unreadable client lockfile {}: {error}",
                            entry.path().display()
                        );
                        continue;
                    }
                    errors.push(format!("{}: {error}", entry.path().display()));
                }
            },
            Err(error) => {
                errors.push(format!("{}: {error}", entry.path().display()));
            }
        }
    }

    Ok(LockNamespacesStatus {
        namespaces: grouped_locks
            .into_iter()
            .map(|(namespace, locks)| {
                if locks.client.is_empty() {
                    (namespace, locks.primary)
                } else {
                    // In daemon mode the numeric daemon PID lock is namespace metadata, not an
                    // application. Keep only per-client locks for status/list output.
                    (namespace, locks.client)
                }
            })
            .collect(),
        errors,
    })
}

#[derive(Default)]
struct LockGroup {
    primary: Vec<LockfileStatus>,
    client: Vec<LockfileStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockfileKind {
    Primary,
    Client,
}

impl LockfileKind {
    pub fn from_path(path: &Path) -> Option<Self> {
        let filename = path.file_name()?.to_str()?;
        if filename.chars().all(|c| c.is_ascii_digit()) {
            Some(Self::Primary)
        } else if filename
            .strip_prefix("client-")
            .is_some_and(|pid| pid.chars().all(|c| c.is_ascii_digit()))
        {
            Some(Self::Client)
        } else {
            None
        }
    }
}

pub fn has_client_lockfiles(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .any(|entry| LockfileKind::from_path(&entry.path()) == Some(LockfileKind::Client))
}

pub fn strict_namespaces(status: LockNamespacesStatus) -> anyhow::Result<LockNamespaces> {
    if let Some(error) = status.errors.first() {
        anyhow::bail!("{error}");
    }
    Ok(status.namespaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::VpnProvider;
    use crate::config::vpn::Protocol;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moved backwards")
            .as_nanos();
        dir.push(format!("vopono-status-test-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn status_lock(namespace: &str, command: &str, start: u64) -> String {
        format!(
            r#"(ns:(name:"{namespace}",provider:Mullvad,protocol:Wireguard),start:{start},command:"{command}")"#
        )
    }

    #[test]
    fn classifies_lockfile_names() {
        assert_eq!(
            LockfileKind::from_path(Path::new("12345")),
            Some(LockfileKind::Primary)
        );
        assert_eq!(
            LockfileKind::from_path(Path::new("client-12345")),
            Some(LockfileKind::Client)
        );
        assert_eq!(LockfileKind::from_path(Path::new("client-pid")), None);
        assert_eq!(
            LockfileKind::from_path(Path::new("provider-port-status")),
            None
        );
    }

    #[test]
    fn lockfile_status_deserializes_full_primary_lockfile_shape() {
        let raw = r#"(
            ns: (
                name: "vopono_mullvad_se",
                veth_pair: None,
                dns_config: None,
                openvpn: None,
                wireguard: None,
                host_masquerade: None,
                firewall_exception: None,
                shadowsocks: None,
                veth_pair_ips: None,
                openconnect: None,
                openfortivpn: None,
                warp: None,
                provider: Mullvad,
                protocol: Wireguard,
                firewall: NfTables,
                predown: None,
                predown_user: None,
                predown_group: None,
                config_file: None,
                trojan: None,
            ),
            start: 123,
            command: "firefox --private-window",
        )"#;

        let lock: LockfileStatus = ron::from_str(raw).expect("status lockfile should parse");
        assert_eq!(lock.ns.name, "vopono_mullvad_se");
        assert_eq!(lock.ns.provider, VpnProvider::Mullvad);
        assert_eq!(lock.ns.protocol, Protocol::Wireguard);
        assert_eq!(lock.start, 123);
        assert_eq!(lock.command, "firefox --private-window");
    }

    #[test]
    fn client_locks_take_precedence_over_daemon_primary_lock() {
        let dir = unique_temp_dir("client-precedence");
        let ns_dir = dir.join("vo_m_se");
        fs::create_dir_all(&ns_dir).expect("failed to create namespace dir");
        fs::write(ns_dir.join("100"), status_lock("vo_m_se", "daemon-app", 1)).unwrap();
        fs::write(
            ns_dir.join("client-200"),
            status_lock("vo_m_se", "firefox", 2),
        )
        .unwrap();
        fs::write(
            ns_dir.join("client-300"),
            status_lock("vo_m_se", "transmission", 3),
        )
        .unwrap();

        let status = read_lock_namespaces_from_dir(&dir).expect("status should read");
        let locks = status.namespaces.get("vo_m_se").expect("namespace missing");
        let mut commands = locks
            .iter()
            .map(|lock| lock.command.as_str())
            .collect::<Vec<_>>();
        commands.sort();

        assert!(status.errors.is_empty());
        assert_eq!(commands, vec!["firefox", "transmission"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unreadable_old_client_locks_are_ignored() {
        let dir = unique_temp_dir("old-client");
        let ns_dir = dir.join("vo_m_se");
        fs::create_dir_all(&ns_dir).expect("failed to create namespace dir");
        fs::write(ns_dir.join("100"), status_lock("vo_m_se", "daemon-app", 1)).unwrap();
        fs::write(ns_dir.join("client-200"), "").unwrap();

        let status = read_lock_namespaces_from_dir(&dir).expect("status should read");
        let locks = status.namespaces.get("vo_m_se").expect("namespace missing");

        assert!(status.errors.is_empty());
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].command, "daemon-app");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_client_lockfiles_for_daemon_drop_guard() {
        let dir = unique_temp_dir("client-detect");
        fs::write(dir.join("100"), status_lock("vo_m_se", "daemon-app", 1)).unwrap();
        assert!(!has_client_lockfiles(&dir));
        fs::write(dir.join("client-200"), status_lock("vo_m_se", "firefox", 2)).unwrap();
        assert!(has_client_lockfiles(&dir));
        let _ = fs::remove_dir_all(dir);
    }
}
