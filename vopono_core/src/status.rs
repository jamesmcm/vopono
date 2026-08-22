use crate::network::netns::LockfileStatus;
use crate::util::config_dir;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

/// Sidecar file next to a namespace's lockfiles holding the latest
/// provider-assigned forwarded port, refreshed by the forwarder thread.
const FORWARDED_PORT_SIDECAR: &str = "port-forwarding.json";

#[derive(Serialize, Deserialize, Debug)]
struct ForwardedPortSidecar {
    port: u16,
    updated: u64,
}

/// Record the latest provider-assigned forwarded port for a namespace.
///
/// Written to a sidecar file rather than by rewriting the RON lockfile:
/// primary lockfiles embed namespace handles that must never be deserialized
/// on background threads (dropping such a copy would tear down the live
/// namespace).
pub fn record_forwarded_port(locks_dir: &Path, ns_name: &str, port: u16) -> anyhow::Result<()> {
    let updated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sidecar = ForwardedPortSidecar { port, updated };
    let dir = locks_dir.join(ns_name);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{FORWARDED_PORT_SIDECAR}.tmp"));
    let path = dir.join(FORWARDED_PORT_SIDECAR);
    std::fs::write(&tmp, serde_json::to_vec(&sidecar)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Replace the reported forwarded port with the sidecar value when present.
/// Provider and automatic flag still come from the embedded lockfile state.
fn overlay_forwarded_port(locks_root: &Path, ns_name: &str, locks: &mut [LockfileStatus]) {
    let Ok(raw) = std::fs::read(locks_root.join(ns_name).join(FORWARDED_PORT_SIDECAR)) else {
        return;
    };
    let Ok(sidecar) = serde_json::from_slice::<ForwardedPortSidecar>(&raw) else {
        debug!("Ignoring malformed forwarded-port sidecar for {ns_name}");
        return;
    };
    for lock in locks.iter_mut() {
        if let Some(status) = lock.ns.state.port_forwarding.as_mut()
            && status.port != sidecar.port
        {
            debug!(
                "Forwarded port for {ns_name} renewed: {} -> {}",
                status.port, sidecar.port
            );
            status.port = sidecar.port;
        }
    }
}

pub type LockNamespaces = HashMap<String, Vec<LockfileStatus>>;

#[derive(Clone, Debug, Default)]
pub struct LockNamespacesStatus {
    /// Effective status/application view. In daemon mode, numeric primary
    /// locks are hidden here when per-client locks exist, so the daemon itself
    /// is not reported as an extra application. Without client locks, the
    /// primary lock is also the application record used by direct CLI runs.
    pub namespaces: LockNamespaces,
    /// The authoritative numeric lock for each namespace, retained for
    /// metadata such as creation time, provider, server, and port forwarding.
    /// Its on-disk form contains the full serialized NetworkNamespace needed
    /// to reconstruct an existing namespace; `client-*` locks are temporary,
    /// per-application status/reference locks and cannot do that.
    ///
    /// Private on purpose: consumers should use [`Self::metadata_for`] instead
    /// of deciding which map holds applications versus metadata.
    primary_namespaces: LockNamespaces,
    pub errors: Vec<String>,
}

impl LockNamespacesStatus {
    /// Namespace-state metadata (creation time, provider, server, ports) for a
    /// namespace, taken from its primary lockfile when one exists.
    pub fn metadata_for(&self, namespace: &str) -> Option<&LockfileStatus> {
        self.primary_namespaces
            .get(namespace)
            .and_then(|locks| locks.first())
    }
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

    for entry in WalkDir::new(&dir) {
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
                    let lock = if lock.application_pid.is_none()
                        && lockfile_kind == LockfileKind::Client
                    {
                        let filename = entry.path().file_name().and_then(|name| name.to_str());
                        match filename.and_then(client_pid_from_lockfile_name) {
                            Some(pid) => LockfileStatus {
                                application_pid: Some(pid),
                                ..lock
                            },
                            None => lock,
                        }
                    } else {
                        lock
                    };
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

    // Forwarder renewals update the sidecar, not the RON lockfiles, so
    // reflect the latest forwarded port in every derived view.
    for (namespace, locks) in grouped_locks.iter_mut() {
        overlay_forwarded_port(&dir, namespace, &mut locks.primary);
        overlay_forwarded_port(&dir, namespace, &mut locks.client);
    }

    Ok(LockNamespacesStatus {
        primary_namespaces: grouped_locks
            .iter()
            .filter_map(|(namespace, locks)| {
                locks
                    .primary
                    .first()
                    .cloned()
                    .map(|lock| (namespace.clone(), vec![lock]))
            })
            .collect(),
        namespaces: grouped_locks
            .into_iter()
            .map(|(namespace, locks)| {
                if locks.client.is_empty() {
                    (namespace, locks.primary)
                } else {
                    // In daemon mode the numeric primary lock is namespace
                    // state/lifecycle metadata, while client-* locks represent
                    // the applications and keep the namespace alive.
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

/// Extract the application PID encoded in a `client-<pid>` lockfile name.
///
/// Named so the naming convention shared with the daemon's client lockfile
/// writer has a single, testable definition.
fn client_pid_from_lockfile_name(filename: &str) -> Option<u32> {
    filename.strip_prefix("client-")?.parse::<u32>().ok()
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
    fn extracts_client_pids_from_lockfile_names() {
        assert_eq!(client_pid_from_lockfile_name("client-4242"), Some(4242));
        assert_eq!(client_pid_from_lockfile_name("client-pid"), None);
        assert_eq!(client_pid_from_lockfile_name("12345"), None);
    }

    fn forwarding_lock(namespace: &str, port: u16) -> String {
        format!(
            r#"(ns:(name:"{namespace}",provider:ProtonVPN,protocol:Wireguard,state:(port_forwarding:Some((provider:ProtonVPN,port:{port},automatic:true)))),start:1,command:"curl")"#
        )
    }

    #[test]
    fn forwarded_port_sidecar_overlays_renewed_port() {
        let dir = unique_temp_dir("forwarded-port");
        let ns_dir = dir.join("vo_p_se");
        fs::create_dir_all(&ns_dir).unwrap();
        fs::write(ns_dir.join("100"), forwarding_lock("vo_p_se", 1111)).unwrap();

        // No sidecar yet: the embedded port is reported as-is.
        let status = read_lock_namespaces_from_dir(&dir).unwrap();
        assert_eq!(
            status.namespaces["vo_p_se"][0]
                .ns
                .state
                .port_forwarding
                .as_ref()
                .unwrap()
                .port,
            1111
        );

        record_forwarded_port(&dir, "vo_p_se", 2222).unwrap();
        let status = read_lock_namespaces_from_dir(&dir).unwrap();
        let forwarding = status.namespaces["vo_p_se"][0]
            .ns
            .state
            .port_forwarding
            .as_ref()
            .unwrap();
        assert_eq!(forwarding.port, 2222);
        // Provider/automatic still come from the lockfile state.
        assert_eq!(forwarding.provider, VpnProvider::ProtonVPN);
        assert!(forwarding.automatic);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_forwarded_port_sidecar_is_ignored() {
        let dir = unique_temp_dir("forwarded-port-bad");
        let ns_dir = dir.join("vo_p_se");
        fs::create_dir_all(&ns_dir).unwrap();
        fs::write(ns_dir.join("100"), forwarding_lock("vo_p_se", 1111)).unwrap();
        fs::write(ns_dir.join("port-forwarding.json"), "not json").unwrap();

        let status = read_lock_namespaces_from_dir(&dir).unwrap();
        assert_eq!(
            status.namespaces["vo_p_se"][0]
                .ns
                .state
                .port_forwarding
                .as_ref()
                .unwrap()
                .port,
            1111
        );
        assert!(status.errors.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn metadata_for_exposes_primary_lock_without_leaking_the_map() {
        let dir = unique_temp_dir("metadata-for");
        let ns_dir = dir.join("vo_m_se");
        fs::create_dir_all(&ns_dir).expect("failed to create namespace dir");
        fs::write(ns_dir.join("100"), status_lock("vo_m_se", "daemon-app", 1)).unwrap();
        fs::write(
            ns_dir.join("client-200"),
            status_lock("vo_m_se", "firefox", 2),
        )
        .unwrap();

        let status = read_lock_namespaces_from_dir(&dir).expect("status should read");
        let metadata = status.metadata_for("vo_m_se").expect("metadata missing");
        assert_eq!(metadata.start, 1);
        assert_eq!(metadata.command, "daemon-app");
        // The application view keeps only the client lock while client locks exist.
        let applications = status.namespaces.get("vo_m_se").expect("namespace missing");
        assert_eq!(applications.len(), 1);
        assert_eq!(applications[0].command, "firefox");
        assert!(status.metadata_for("missing").is_none());
        let _ = fs::remove_dir_all(dir);
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
