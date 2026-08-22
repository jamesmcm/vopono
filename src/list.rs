use super::args::{ListCommand, ListType};
use anyhow::anyhow;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use vopono_core::network::netns::{LockfileNamespaceStatus, LockfileStatus, PortForwardingStatus};
use vopono_core::status::read_lock_namespaces;
use vopono_core::util::parse_command_str;

use crate::api;
use crate::server_metadata;

#[derive(Debug, Serialize)]
pub struct StatusDocument {
    pub version: u8,
    pub daemon: crate::daemon::DaemonStatus,
    pub namespaces: Vec<NamespaceEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NamespaceEntry {
    pub id: String,
    pub provider: String,
    pub protocol: String,
    pub server: Option<ServerStatus>,
    /// RFC 3339 timestamp of when the namespace was created; `null` when the
    /// recorded epoch value cannot be represented as a calendar timestamp.
    pub created_at: Option<String>,
    pub uptime_seconds: u64,
    pub applications: Vec<ApplicationEntry>,
    pub port_forwarding: Option<PortForwardingEntry>,
    pub open_ports: Vec<u16>,
    pub forwarded_ports: Vec<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerStatus {
    pub id: String,
    pub aliases: Vec<String>,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub hostname: Option<String>,
    pub config_file: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortForwardingEntry {
    pub provider: String,
    pub port: u16,
    pub automatic: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplicationEntry {
    /// PID string when known. Without a recorded PID the id is synthesized
    /// from the command and start time; it is unique within one snapshot but
    /// is not stable across restarts and cannot be used with `stop`.
    pub id: String,
    pub pid: Option<u32>,
    pub command: String,
    pub argv: Vec<String>,
    /// RFC 3339 timestamp; `null` when unrepresentable (see [`NamespaceEntry::created_at`]).
    pub started_at: Option<String>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
struct NamespaceListDocument {
    version: u8,
    namespaces: Vec<NamespaceEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApplicationListDocument {
    version: u8,
    applications: Vec<ApplicationListEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApplicationListEntry {
    id: String,
    pid: Option<u32>,
    namespace_id: String,
    provider: String,
    protocol: String,
    command: String,
    argv: Vec<String>,
    started_at: Option<String>,
    uptime_seconds: u64,
}

pub fn output_status(json: bool) -> anyhow::Result<()> {
    let snapshot = status_snapshot()?;
    if json {
        api::print_json(&snapshot)?;
    } else {
        print_human_status(&snapshot);
    }
    Ok(())
}

pub fn output_list(listcmd: ListCommand) -> anyhow::Result<()> {
    let snapshot = status_snapshot()?;
    match listcmd.list_type.unwrap_or(ListType::Applications) {
        ListType::Namespaces => {
            if listcmd.json {
                api::print_json(&NamespaceListDocument {
                    version: api::SCHEMA_VERSION,
                    namespaces: snapshot.namespaces,
                    errors: snapshot.errors,
                })?;
            } else {
                print_namespaces(&snapshot.namespaces);
            }
        }
        ListType::Applications => {
            let applications = flatten_applications(&snapshot.namespaces);
            if listcmd.json {
                api::print_json(&ApplicationListDocument {
                    version: api::SCHEMA_VERSION,
                    applications,
                    errors: snapshot.errors,
                })?;
            } else {
                print_applications(&snapshot.namespaces);
            }
        }
    }
    Ok(())
}

pub fn status_snapshot() -> anyhow::Result<StatusDocument> {
    let lock_status = read_lock_namespaces()?;
    let now = Utc::now();
    let now_seconds = now.timestamp().max(0) as u64;
    let mut namespaces = lock_status
        .namespaces
        .iter()
        .map(|(id, locks)| namespace_entry(id, locks, lock_status.metadata_for(id), now_seconds))
        .collect::<anyhow::Result<Vec<_>>>()?;
    namespaces.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(StatusDocument {
        version: api::SCHEMA_VERSION,
        daemon: crate::daemon::status(),
        namespaces,
        errors: lock_status.errors,
    })
}

// Status is intentionally a read-only lockfile snapshot. Lifecycle cleanup is
// performed by launch/control paths rather than by a status query.
fn namespace_entry(
    id: &str,
    locks: &[LockfileStatus],
    primary: Option<&LockfileStatus>,
    now_seconds: u64,
) -> anyhow::Result<NamespaceEntry> {
    let first = locks
        .first()
        .ok_or_else(|| anyhow!("Namespace {id} has no lock entries"))?;
    let metadata = primary.unwrap_or(first);
    // Prefer the primary (creator) lock for creation time; fall back to the
    // earliest application lock so direct CLI runs still report sensibly.
    let created = primary.map(|lock| lock.start).unwrap_or_else(|| {
        locks
            .iter()
            .map(|lock| lock.start)
            .min()
            .unwrap_or(first.start)
    });
    let applications = locks
        .iter()
        .map(|lock| application_entry(lock, now_seconds))
        .collect::<Vec<_>>();
    let namespace = &metadata.ns;

    Ok(NamespaceEntry {
        id: id.to_string(),
        provider: namespace.provider.id().to_string(),
        protocol: namespace.protocol.id().to_string(),
        server: server_status(namespace),
        created_at: format_timestamp(created),
        uptime_seconds: now_seconds.saturating_sub(created),
        applications,
        port_forwarding: namespace
            .state
            .port_forwarding
            .as_ref()
            .map(port_forwarding_entry),
        open_ports: namespace.state.open_ports.clone(),
        forwarded_ports: namespace.state.forwarded_ports.clone(),
    })
}

fn application_entry(lock: &LockfileStatus, now_seconds: u64) -> ApplicationEntry {
    let started = lock.application_started_at.unwrap_or(lock.start);
    let argv = parse_command_str(&lock.command).unwrap_or_else(|_| vec![lock.command.clone()]);
    let command = argv
        .first()
        .cloned()
        .unwrap_or_else(|| lock.command.clone());
    let id = lock
        .application_pid
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| format!("{}:{}", lock.command, started));

    ApplicationEntry {
        id,
        pid: lock.application_pid,
        command,
        argv,
        started_at: format_timestamp(started),
        uptime_seconds: now_seconds.saturating_sub(started),
    }
}

fn server_status(namespace: &LockfileNamespaceStatus) -> Option<ServerStatus> {
    let config_id = namespace.config_file.as_ref().and_then(|path| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
    });
    let id = config_id.or_else(|| namespace.state.server.clone())?;
    let aliases = server_metadata::aliases_for(&id, namespace.state.server.as_deref());
    let (country_code, country) = server_metadata::country_from_id(&id);

    Some(ServerStatus {
        id,
        aliases: aliases.into_iter().collect(),
        country_code,
        country,
        hostname: namespace
            .config_file
            .as_deref()
            .and_then(|path| server_metadata::config_hostname(path, &namespace.protocol)),
        config_file: namespace
            .config_file
            .as_ref()
            .map(|path| path.display().to_string()),
    })
}

fn port_forwarding_entry(status: &PortForwardingStatus) -> PortForwardingEntry {
    PortForwardingEntry {
        provider: status.provider.id().to_string(),
        port: status.port,
        automatic: status.automatic,
    }
}

fn flatten_applications(namespaces: &[NamespaceEntry]) -> Vec<ApplicationListEntry> {
    let mut applications = namespaces
        .iter()
        .flat_map(|namespace| {
            namespace
                .applications
                .iter()
                .map(|application| ApplicationListEntry {
                    id: application.id.clone(),
                    pid: application.pid,
                    namespace_id: namespace.id.clone(),
                    provider: namespace.provider.clone(),
                    protocol: namespace.protocol.clone(),
                    command: application.command.clone(),
                    argv: application.argv.clone(),
                    started_at: application.started_at.clone(),
                    uptime_seconds: application.uptime_seconds,
                })
        })
        .collect::<Vec<_>>();
    applications.sort_by(|left, right| {
        left.namespace_id
            .cmp(&right.namespace_id)
            .then_with(|| left.id.cmp(&right.id))
    });
    applications
}

fn print_human_status(status: &StatusDocument) {
    println!("{}", status.daemon.human_line());
    print_namespaces(&status.namespaces);
    if !status.errors.is_empty() {
        for error in &status.errors {
            eprintln!("status warning: {error}");
        }
    }
}

fn print_namespaces(namespaces: &[NamespaceEntry]) {
    if namespaces.is_empty() {
        return;
    }
    println!("namespace\tprovider\tprotocol\tapplications\tuptime");
    for namespace in namespaces {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            namespace.id,
            namespace.provider,
            namespace.protocol,
            namespace.applications.len(),
            compound_duration::format_wdhms(namespace.uptime_seconds),
        );
        for application in &namespace.applications {
            println!(
                "  app {}\t{}\t{}",
                application.id,
                application.command,
                compound_duration::format_wdhms(application.uptime_seconds),
            );
        }
    }
}

fn print_applications(namespaces: &[NamespaceEntry]) {
    let applications = flatten_applications(namespaces);
    if applications.is_empty() {
        return;
    }
    println!("namespace\tprovider\tprotocol\tapplication\tuptime");
    for application in applications {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            application.namespace_id,
            application.provider,
            application.protocol,
            application.command,
            compound_duration::format_wdhms(application.uptime_seconds),
        );
    }
}

/// RFC 3339 rendering of a unix-epoch seconds value; `None` when the value
/// cannot be a valid timestamp so JSON consumers see `null`, never a number
/// masquerading as a date string.
fn format_timestamp(timestamp: u64) -> Option<String> {
    i64::try_from(timestamp)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::{application_entry, format_timestamp, namespace_entry};
    use vopono_core::config::providers::VpnProvider;
    use vopono_core::config::vpn::Protocol;
    use vopono_core::network::netns::{LockfileNamespaceStatus, LockfileStatus};

    fn lock(name: &str, command: &str, start: u64) -> LockfileStatus {
        LockfileStatus {
            ns: LockfileNamespaceStatus {
                name: name.to_string(),
                provider: VpnProvider::Mullvad,
                protocol: Protocol::Wireguard,
                config_file: None,
                state: Default::default(),
            },
            start,
            command: command.to_string(),
            application_pid: None,
            application_started_at: None,
        }
    }

    #[test]
    fn timestamps_render_as_rfc3339_or_null() {
        assert_eq!(format_timestamp(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        // Out-of-range values become null rather than a numeric string.
        assert_eq!(format_timestamp(u64::MAX), None);
    }

    #[test]
    fn synthetic_application_ids_are_deterministic() {
        let entry = application_entry(&lock("vo_m_se", "firefox", 100), 200);
        assert!(entry.pid.is_none());
        assert_eq!(entry.id, "firefox:100");
        assert_eq!(entry.command, "firefox");
        assert_eq!(entry.uptime_seconds, 100);
    }

    #[test]
    fn creation_time_falls_back_to_earliest_lock_without_primary() {
        let mut later = lock("vo_m_se", "transmission", 500);
        later.application_pid = Some(300);
        later.application_started_at = Some(600);
        let earlier = lock("vo_m_se", "firefox", 400);

        let entry = namespace_entry("vo_m_se", &[later, earlier], None, 1000)
            .expect("namespace entry should build");
        assert_eq!(entry.created_at.as_deref(), Some("1970-01-01T00:06:40Z"));
        assert_eq!(entry.uptime_seconds, 600);
        assert_eq!(entry.applications.len(), 2);
    }
}
