use super::args::{ListCommand, ListType};
use anyhow::anyhow;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use std::collections::BTreeSet;
use vopono_core::network::netns::{LockfileNamespaceStatus, LockfileStatus, PortForwardingStatus};
use vopono_core::status::read_lock_namespaces;
use vopono_core::util::parse_command_str;

use crate::providers::SCHEMA_VERSION;
use crate::{daemon, server_metadata};

#[derive(Debug, Serialize)]
pub struct StatusDocument {
    pub version: u8,
    pub daemon: daemon::DaemonStatus,
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
    pub created_at: String,
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
    pub id: String,
    pub pid: Option<u32>,
    pub command: String,
    pub argv: Vec<String>,
    pub started_at: String,
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
    started_at: String,
    uptime_seconds: u64,
}

pub fn output_status(json: bool) -> anyhow::Result<()> {
    let snapshot = status_snapshot()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&NamespaceListDocument {
                        version: SCHEMA_VERSION,
                        namespaces: snapshot.namespaces,
                        errors: snapshot.errors,
                    })?
                );
            } else {
                print_namespaces(&snapshot.namespaces);
            }
        }
        ListType::Applications => {
            let applications = flatten_applications(&snapshot.namespaces);
            if listcmd.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ApplicationListDocument {
                        version: SCHEMA_VERSION,
                        applications,
                        errors: snapshot.errors,
                    })?
                );
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
        .map(|(id, locks)| {
            namespace_entry(
                id,
                locks,
                lock_status
                    .primary_namespaces
                    .get(id)
                    .and_then(|locks| locks.first()),
                now_seconds,
            )
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    namespaces.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(StatusDocument {
        version: SCHEMA_VERSION,
        daemon: daemon::status(),
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
        server: server_status(namespace)?,
        created_at: format_timestamp(created),
        uptime_seconds: now_seconds.saturating_sub(created),
        applications,
        port_forwarding: namespace
            .port_forwarding
            .as_ref()
            .map(port_forwarding_entry),
        open_ports: namespace.open_ports.clone(),
        forwarded_ports: namespace.forwarded_ports.clone(),
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

fn server_status(namespace: &LockfileNamespaceStatus) -> anyhow::Result<Option<ServerStatus>> {
    let config_id = namespace.config_file.as_ref().and_then(|path| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
    });
    let id = config_id.or_else(|| namespace.server.clone());
    let Some(id) = id else {
        return Ok(None);
    };

    let parts = server_metadata::id_parts(&id);
    let (country_code, country) = server_metadata::country_from_id(&id);
    let mut aliases = BTreeSet::new();
    aliases.insert(id.clone());
    if let Some(requested) = &namespace.server {
        aliases.insert(requested.to_ascii_lowercase());
    }
    for part in parts {
        aliases.insert(part);
    }
    if let Some(code) = &country_code {
        aliases.insert(code.clone());
    }
    if let Some(country) = &country {
        aliases.insert(country.to_ascii_lowercase());
    }

    Ok(Some(ServerStatus {
        id,
        aliases: aliases.into_iter().collect(),
        country_code,
        country,
        hostname: namespace
            .config_file
            .as_deref()
            .and_then(|path| server_metadata::config_hostname(path, &namespace.protocol).ok())
            .flatten(),
        config_file: namespace
            .config_file
            .as_ref()
            .map(|path| path.display().to_string()),
    }))
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
    let daemon_state = if status.daemon.available {
        "available"
    } else {
        "unavailable"
    };
    println!(
        "daemon\t{}\tpid={}\tsocket={}\tversion={}\tcompatible={}",
        daemon_state,
        status
            .daemon
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        status.daemon.socket,
        status.daemon.version,
        status.daemon.compatible,
    );
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

fn format_timestamp(timestamp: u64) -> String {
    i64::try_from(timestamp)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| timestamp.to_string())
}
