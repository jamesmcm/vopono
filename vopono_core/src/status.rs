use crate::network::netns::LockfileStatus;
use crate::util::{
    check_process_running, chown_to_config_owner, config_dir, create_private_file,
    ensure_dir_as_config_owner, write_file_as_config_owner,
};
use anyhow::Context;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

/// Sidecar file next to a namespace's lockfiles holding the latest
/// provider-assigned forwarded port, refreshed by the forwarder thread.
pub(crate) const FORWARDED_PORT_SIDECAR: &str = "port-forwarding.json";

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
    let path = dir.join(FORWARDED_PORT_SIDECAR);
    let contents = serde_json::to_string(&sidecar)?;
    if ensure_dir_as_config_owner(&dir, Some(0o700))? {
        anyhow::ensure!(
            write_file_as_config_owner(&path, &contents, Some(0o600))?,
            "Config-owner writer unexpectedly unavailable"
        );
        return Ok(());
    }

    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    chown_to_config_owner(&dir)?;
    let tmp = dir.join(format!("{FORWARDED_PORT_SIDECAR}.tmp"));
    let mut file = create_private_file(&tmp)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())?;
    drop(file);
    std::fs::rename(&tmp, &path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    chown_to_config_owner(&path)
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

/// Whether the directory contains any client lockfile.
///
/// This is a raw existence check: stale locks left behind by a previous
/// session count too. Callers deciding whether a namespace is still in use
/// must prune stale locks first with [`prune_stale_client_lockfiles`].
pub fn has_client_lockfiles(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .any(|entry| LockfileKind::from_path(&entry.path()) == Some(LockfileKind::Client))
}

/// Whether a lock directory contains no session state.
///
/// The forwarded-port sidecar is ignored because it is metadata rather than a
/// session. Any other file (including a temporary file left by an interrupted
/// writer) is treated as state that must be preserved.
pub fn lock_dir_has_no_session_state(dir: &Path) -> anyhow::Result<bool> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_str() != Some(FORWARDED_PORT_SIDECAR) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether the application recorded in the `client-<pid>` lockfile at `path`
/// is stale for `namespace`.
///
/// A lock is stale when its PID has exited, is a zombie, or now belongs to a
/// process outside the namespace (PID reuse). If membership cannot be
/// established the lock is treated as live, so an unprivileged caller never
/// removes state it cannot verify.
pub fn client_lockfile_is_stale(path: &Path, namespace: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(client_pid_from_lockfile_name)
        .is_some_and(|pid| application_pid_is_stale(pid, namespace))
}

/// Whether the application recorded in `lock` is still alive inside the
/// namespace it names. Metadata-only locks (no PID) are treated as live.
pub fn lockfile_application_is_live(lock: &LockfileStatus) -> bool {
    lock.application_pid
        .is_none_or(|pid| !application_pid_is_stale(pid, &lock.ns.name))
}

/// Remove client lockfiles whose application is no longer running in the
/// namespace named by `dir` (the directory below `vopono/locks`).
///
/// Returns the number of stale locks removed. A missing directory is not an
/// error: it simply has no locks to prune.
pub fn prune_stale_client_lockfiles(dir: &Path) -> anyhow::Result<usize> {
    prune_stale_client_lockfiles_with(dir, client_lockfile_is_stale)
}

fn prune_stale_client_lockfiles_with(
    dir: &Path,
    mut is_stale: impl FnMut(&Path, &str) -> bool,
) -> anyhow::Result<usize> {
    let Some(namespace) = dir.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    if crate::network::netns::validate_netns_name(namespace).is_err() {
        debug!(
            "Ignoring lock directory with invalid namespace name: {}",
            dir.display()
        );
        return Ok(0);
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut removed = 0;
    for entry in entries {
        let path = entry?.path();
        if LockfileKind::from_path(&path) != Some(LockfileKind::Client) {
            continue;
        }
        if is_stale(&path, namespace) {
            debug!("Removing stale client lockfile: {}", path.display());
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                // The client guard or another cleanup may have removed it.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Could not remove stale client lockfile {}", path.display())
                    });
                }
            }
        }
    }
    Ok(removed)
}

/// Remove the forwarded-port sidecar from a namespace lock directory.
///
/// The sidecar is not session state, but it would otherwise keep the
/// directory non-empty and block namespace teardown.
pub(crate) fn remove_forwarded_port_sidecar(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FORWARDED_PORT_SIDECAR));
}

fn application_pid_is_stale(pid: u32, namespace: &str) -> bool {
    if !check_process_running(pid) || process_is_zombie(pid) {
        return true;
    }
    // Lockfiles cannot outlive their namespace: when the netns handle is gone
    // no recorded process can still be attached to it.
    if !Path::new("/var/run/netns").join(namespace).exists() {
        return true;
    }
    matches!(process_namespace_matches(pid, namespace), Some(false))
}

/// `/proc/<pid>/stat` state is `Z` for a zombie awaiting reaping.
fn process_is_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().next())
        .is_some_and(|state| state == "Z")
}

/// Compare the process and namespace `(device, inode)` pairs. Returns `None`
/// when either handle cannot be inspected.
fn process_namespace_matches(pid: u32, namespace: &str) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;

    let process_namespace = std::fs::metadata(format!("/proc/{pid}/ns/net")).ok()?;
    let target_namespace = std::fs::metadata(Path::new("/var/run/netns").join(namespace)).ok()?;
    Some(
        process_namespace.dev() == target_namespace.dev()
            && process_namespace.ino() == target_namespace.ino(),
    )
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
        assert_eq!(
            fs::metadata(ns_dir.join(FORWARDED_PORT_SIDECAR))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&ns_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
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

    fn status_lock_with_pid(namespace: &str, command: &str, start: u64, pid: u32) -> String {
        format!(
            r#"(ns:(name:"{namespace}",provider:Mullvad,protocol:Wireguard),start:{start},command:"{command}",application_pid:Some({pid}))"#
        )
    }

    #[test]
    fn sidecar_is_not_session_state_but_unknown_files_are() {
        let dir = unique_temp_dir("lockfile-presence");
        let namespace = "vo_presence_test";
        let ns_dir = dir.join(namespace);
        fs::create_dir_all(&ns_dir).unwrap();

        assert!(lock_dir_has_no_session_state(&ns_dir).unwrap());
        fs::write(ns_dir.join("port-forwarding.json"), "{}").unwrap();
        assert!(lock_dir_has_no_session_state(&ns_dir).unwrap());
        fs::write(ns_dir.join("100"), status_lock(namespace, "daemon-app", 1)).unwrap();
        assert!(!lock_dir_has_no_session_state(&ns_dir).unwrap());
        fs::remove_file(ns_dir.join("100")).unwrap();
        fs::write(ns_dir.join("client-123.tmp-456"), "partial").unwrap();
        assert!(!lock_dir_has_no_session_state(&ns_dir).unwrap());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn prunes_dead_client_lockfiles_but_keeps_primary_and_sidecar() {
        let dir = unique_temp_dir("prune-stale");
        let namespace = "vo_prune_test";
        let ns_dir = dir.join(namespace);
        fs::create_dir_all(&ns_dir).unwrap();
        fs::write(ns_dir.join("100"), status_lock(namespace, "daemon-app", 1)).unwrap();
        fs::write(
            ns_dir.join(format!("client-{}", u32::MAX)),
            status_lock_with_pid(namespace, "dead-app", 2, u32::MAX),
        )
        .unwrap();
        fs::write(ns_dir.join("port-forwarding.json"), "{}").unwrap();

        assert_eq!(prune_stale_client_lockfiles(&ns_dir).unwrap(), 1);
        assert!(ns_dir.join("100").exists());
        assert!(ns_dir.join("port-forwarding.json").exists());
        assert!(!ns_dir.join(format!("client-{}", u32::MAX)).exists());
        assert!(!has_client_lockfiles(&ns_dir));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_pruning_tolerates_locks_removed_by_another_session() {
        let dir = tempfile::tempdir().unwrap();
        let ns_dir = dir.path().join("vo_concurrent_prune");
        fs::create_dir(&ns_dir).unwrap();
        fs::write(ns_dir.join(format!("client-{}", u32::MAX)), "lock").unwrap();
        let barrier = std::sync::Barrier::new(8);

        std::thread::scope(|scope| {
            let workers = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        prune_stale_client_lockfiles_with(&ns_dir, |path, namespace| {
                            let stale = client_lockfile_is_stale(path, namespace);
                            // Force every caller to inspect the same lock before
                            // any one of them can remove it.
                            barrier.wait();
                            stale
                        })
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            let removed = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>();
            assert_eq!(removed, 1);
        });
        assert!(!has_client_lockfiles(&ns_dir));
    }

    #[test]
    fn pruning_preserves_errors_other_than_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let ns_dir = dir.path().join("vo_prune_error");
        fs::create_dir_all(ns_dir.join(format!("client-{}", u32::MAX))).unwrap();
        assert!(prune_stale_client_lockfiles(&ns_dir).is_err());
    }

    #[test]
    fn removes_live_pid_recycled_outside_a_missing_namespace() {
        let dir = unique_temp_dir("prune-recycled");
        let namespace = "vo_prune_recycled";
        let ns_dir = dir.join(namespace);
        fs::create_dir_all(&ns_dir).unwrap();
        let live_pid = std::process::id();
        fs::write(
            ns_dir.join(format!("client-{live_pid}")),
            status_lock_with_pid(namespace, "recycled", 1, live_pid),
        )
        .unwrap();

        // The namespace does not exist, so the record cannot be live.
        assert_eq!(prune_stale_client_lockfiles(&ns_dir).unwrap(), 1);
        assert!(!has_client_lockfiles(&ns_dir));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lockfile_liveness_hides_dead_apps_but_keeps_pid_less_metadata() {
        let dead: LockfileStatus = ron::from_str(&status_lock_with_pid(
            "vo_prune_live",
            "firefox",
            1,
            u32::MAX,
        ))
        .unwrap();
        assert!(!lockfile_application_is_live(&dead));

        let metadata_only: LockfileStatus =
            ron::from_str(&status_lock("vo_prune_live", "daemon-app", 1)).unwrap();
        assert!(lockfile_application_is_live(&metadata_only));
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
