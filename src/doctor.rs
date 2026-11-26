use crate::args::{CheckCommand, DoctorCommand};
use crate::check::ConnectivityStatus;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use vopono_core::config::providers::{VpnProvider, diagnostics as catalogue};
use vopono_core::config::vpn::Protocol;
use vopono_core::diagnostics::topology::{HostNetwork, NamespaceNetwork};
use vopono_core::diagnostics::{
    Diagnostic, DiagnosticCode as Code, DiagnosticState as State, endpoint_diagnostics,
    resolve_bounded, validate_config,
};

mod output;

#[derive(Serialize)]
struct Report {
    version: u8,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    namespaces: Vec<NamespaceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_network: Option<HostNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon: Option<DaemonInfo>,
}

#[derive(Serialize)]
struct DaemonInfo {
    cli_version: &'static str,
    /// Unknown when the daemon did not report its version.
    versions_match: Option<bool>,
    #[serde(flatten)]
    status: crate::daemon::DaemonStatus,
}

impl DaemonInfo {
    fn new(status: crate::daemon::DaemonStatus) -> Self {
        Self {
            cli_version: env!("CARGO_PKG_VERSION"),
            versions_match: status
                .version
                .as_deref()
                .map(|version| version == env!("CARGO_PKG_VERSION")),
            status,
        }
    }

    fn diagnostics(&self) -> Vec<Diagnostic> {
        let status = &self.status;
        let availability = if status.available {
            Diagnostic::new(
                Code::DaemonAvailability,
                State::Pass,
                &format!(
                    "Daemon socket reachable at {}{}",
                    status.socket,
                    status
                        .pid
                        .map(|pid| format!(" (PID {pid})"))
                        .unwrap_or_default()
                ),
                None,
            )
        } else {
            Diagnostic::new(
                Code::DaemonAvailability,
                State::Warning,
                &format!(
                    "No daemon reachable at {}; privileged checks may be skipped",
                    status.socket
                ),
                Some(
                    "Start the root daemon with sudo vopono daemon, or sudo systemctl start vopono if installed as a service; inspect vopono daemon status --json",
                ),
            )
        };
        let version = if !status.available {
            Diagnostic::new(
                Code::DaemonVersion,
                State::Skipped,
                &format!(
                    "CLI version {}; daemon version comparison unavailable",
                    self.cli_version
                ),
                None,
            )
        } else if let Some(version) = &status.version {
            let (state, message, action) = if self.versions_match == Some(true) {
                (
                    State::Pass,
                    format!(
                        "CLI and daemon both report version {}; equal versions do not guarantee identical builds or features",
                        self.cli_version
                    ),
                    None,
                )
            } else {
                (
                    if status.compatible {
                        State::Warning
                    } else {
                        State::Fail
                    },
                    format!(
                        "CLI version {}; daemon version {version}; {}",
                        self.cli_version,
                        if status.compatible {
                            "same major version, but features may differ"
                        } else {
                            "versions are incompatible or the daemon version is unrecognized"
                        }
                    ),
                    Some(
                        "Install matching CLI and daemon versions, then restart the daemon; for a systemd service use sudo systemctl restart vopono. Updating the executable alone does not update a running daemon",
                    ),
                )
            };
            Diagnostic::new(Code::DaemonVersion, state, &message, action)
        } else {
            Diagnostic::new(
                Code::DaemonVersion,
                State::Warning,
                &format!(
                    "CLI version {}; daemon socket is reachable but its version handshake did not succeed",
                    self.cli_version
                ),
                Some(
                    "Inspect vopono daemon status --json and daemon logs; update/restart an old or unresponsive daemon before relying on privileged checks",
                ),
            )
        };
        vec![availability, version]
    }
}

impl Report {
    fn failed(&self) -> bool {
        self.diagnostics
            .iter()
            .chain(self.namespaces.iter().flat_map(|ns| &ns.diagnostics))
            .any(|d| d.state == State::Fail)
            || self
                .host_network
                .iter()
                .flat_map(|n| &n.diagnostics)
                .any(|d| d.state == State::Fail)
            || self
                .namespaces
                .iter()
                .filter_map(|ns| ns.network.as_ref())
                .flat_map(|n| &n.diagnostics)
                .any(|d| d.state == State::Fail)
    }
}

pub fn run(command: DoctorCommand) -> anyhow::Result<i32> {
    let json = command.json;
    let plain = command.plain;
    let color = command.color;
    let offline = command.offline;
    let skip_ipv6 = command.skip_ipv6;
    let timeout = Duration::from_millis(command.timeout_ms);
    let mut report = if command.provider.is_none() && command.custom.is_none() {
        namespace_report(&command)
    } else {
        configuration_report(command)
    };
    let daemon = report
        .daemon
        .get_or_insert_with(|| DaemonInfo::new(crate::daemon::status()));
    let daemon_usable = daemon.status.available && daemon.status.compatible;
    report.diagnostics.splice(0..0, daemon.diagnostics());
    if !offline {
        report
            .diagnostics
            .push(vopono_core::diagnostics::host::host_dns(resolve_bounded(
                crate::check::DEFAULT_DNS_HOST,
                timeout,
            )));
    }
    report
        .diagnostics
        .extend(host_environment(skip_ipv6, daemon_usable));
    report.host_network = Some(vopono_core::diagnostics::topology::host_network(skip_ipv6));
    let failed = report.failed();
    if json {
        crate::api::print_json(&report)?;
    } else {
        print!("{}", output::render(&report, plain, color));
    }
    Ok(i32::from(failed))
}

fn host_environment(skip_ipv6: bool, daemon_available: bool) -> Vec<Diagnostic> {
    if !nix::unistd::getuid().is_root() && daemon_available {
        // New requests are appended to the wire enum. Older daemons may reject
        // this inspection; keep existing namespace checks working and fall
        // back to whatever read-only evidence the user can access locally.
        let remote = (|| -> anyhow::Result<Vec<Diagnostic>> {
            let mut conn =
                crate::daemon_client::connect(crate::daemon_client::Compatibility::Warn)?;
            crate::daemon::set_socket_timeouts_for(&conn, 5)?;
            let request = crate::daemon::DaemonRequest::HostDiagnostics { skip_ipv6 };
            crate::daemon::write_framed(&mut conn, &wincode::serialize(&request)?)?;
            let bytes = crate::daemon::read_framed(&mut conn, crate::daemon::MAX_FRAME_LEN)?;
            match wincode::deserialize::<crate::daemon::DaemonResponse>(&bytes)? {
                crate::daemon::DaemonResponse::Json(body) => Ok(serde_json::from_slice(&body)?),
                _ => anyhow::bail!("Host inspection unavailable through the daemon"),
            }
        })();
        if let Ok(diagnostics) = remote {
            return diagnostics;
        }
    }
    vopono_core::diagnostics::host::inspect(skip_ipv6)
}

fn namespace_environment(
    id: &str,
    command: &DoctorCommand,
    daemon_available: bool,
) -> Option<NamespaceNetwork> {
    let inspection = (|| -> anyhow::Result<NamespaceNetwork> {
        if nix::unistd::getuid().is_root() {
            let uid = vopono_core::util::resolve_config_owner()?
                .0
                .unwrap_or(nix::unistd::getuid());
            let snapshot = crate::namespace_ownership::diagnostic_snapshot(id, uid)?;
            return vopono_core::diagnostics::topology::namespace_network(
                &snapshot,
                command.offline,
                command.skip_ipv6,
                command.timeout_ms,
            );
        }
        anyhow::ensure!(daemon_available, "Daemon unavailable");
        let mut conn = crate::daemon_client::connect(crate::daemon_client::Compatibility::Warn)?;
        crate::daemon::set_socket_timeouts_for(&conn, 7)?;
        let request = crate::daemon::DaemonRequest::NamespaceDiagnostics {
            id: id.into(),
            offline: command.offline,
            skip_ipv6: command.skip_ipv6,
            timeout_ms: command.timeout_ms,
        };
        crate::daemon::write_framed(&mut conn, &wincode::serialize(&request)?)?;
        let bytes = crate::daemon::read_framed(&mut conn, crate::daemon::MAX_FRAME_LEN)?;
        match wincode::deserialize::<crate::daemon::DaemonResponse>(&bytes)? {
            crate::daemon::DaemonResponse::Json(body) => Ok(serde_json::from_slice(&body)?),
            _ => anyhow::bail!("Namespace topology inspection unavailable"),
        }
    })();
    match inspection {
        Ok(network) => Some(network),
        Err(_) => vopono_core::diagnostics::topology::namespace_resolver(id).ok().map(|mut network| {
            network.diagnostics.push(Diagnostic::new(Code::ProbeUnavailable, State::Skipped,
                "Detailed interfaces, NetworkManager and local-link probes require a readable root-owned namespace snapshot and an updated daemon",
                Some("Run the rebuilt daemon to enable namespace topology inspection; DNS file details remain available without it")));
            network
        }),
    }
}

fn configuration_report(command: DoctorCommand) -> Report {
    let timeout = Duration::from_millis(command.timeout_ms);
    let provider = command.provider.map(|p| p.to_variant());
    let protocol = command.protocol.map(|p| p.to_variant()).unwrap_or_else(|| {
        if let Some(path) = &command.custom {
            if std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() <= 4 * 1024 * 1024) {
                vopono_core::util::get_config_file_protocol(path).unwrap_or(Protocol::Wireguard)
            } else {
                Protocol::Wireguard
            }
        } else {
            provider
                .as_ref()
                .map(|p| {
                    if matches!(p, VpnProvider::Custom | VpnProvider::None) {
                        Protocol::None
                    } else {
                        p.get_dyn_provider().default_protocol()
                    }
                })
                .unwrap_or(Protocol::Wireguard)
        }
    });
    let mut report = Report {
        version: crate::api::SCHEMA_VERSION,
        diagnostics: Vec::new(),
        namespaces: Vec::new(),
        host_network: None,
        daemon: None,
    };
    let mut unsupported_protocol: Option<(State, String, Option<&str>)> = None;
    let path = if let Some(path) = command.custom {
        Some(path)
    } else if let Some(p) = &provider {
        enum Lookup {
            Dir(std::path::PathBuf),
            UnsupportedProviderProtocol(String),
            UnsupportedDiagnosticProtocol,
        }
        let lookup = match protocol {
            Protocol::Wireguard => match p.get_dyn_wireguard_provider() {
                Ok(wg) => wg
                    .wireguard_dir()
                    .map(Lookup::Dir)
                    .unwrap_or_else(|e| Lookup::UnsupportedProviderProtocol(e.to_string())),
                Err(e) => Lookup::UnsupportedProviderProtocol(e.to_string()),
            },
            Protocol::OpenVpn => match p.get_dyn_openvpn_provider() {
                Ok(ovpn) => ovpn
                    .openvpn_dir()
                    .map(Lookup::Dir)
                    .unwrap_or_else(|e| Lookup::UnsupportedProviderProtocol(e.to_string())),
                Err(e) => Lookup::UnsupportedProviderProtocol(e.to_string()),
            },
            _ => Lookup::UnsupportedDiagnosticProtocol,
        };
        match lookup {
            Lookup::Dir(dir) => {
                let mut files = vopono_core::util::get_configs_from_alias(
                    &dir,
                    command.server.as_deref().unwrap_or(""),
                );
                files.sort();
                if files.len() > 1 {
                    report.diagnostics.push(Diagnostic::new(Code::ProviderConfig, State::Warning,
                        "Selector matches multiple configurations; checking the first in filename order", Some("Use --server with a unique server selector")));
                }
                files.into_iter().next()
            }
            Lookup::UnsupportedProviderProtocol(message) => {
                unsupported_protocol = Some((
                    State::Fail,
                    format!(
                        "Provider {} does not support protocol {}: {message}",
                        p.id(),
                        protocol.id()
                    ),
                    Some(
                        "Select a protocol supported by this provider or pass --custom /path/to/config",
                    ),
                ));
                None
            }
            Lookup::UnsupportedDiagnosticProtocol => {
                unsupported_protocol = Some((
                    State::Skipped,
                    format!(
                        "Local configuration preflight does not support protocol {}",
                        protocol.id()
                    ),
                    Some("Run vopono doctor without --provider to inspect running namespaces"),
                ));
                None
            }
        }
    } else {
        None
    };
    let mut endpoints = Vec::new();
    let mut public_key = None;
    if let Some(path) = path {
        match validate_config(&path, &protocol) {
            Ok(found) => {
                if protocol == Protocol::Wireguard && command.catalogue {
                    public_key = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|s| {
                            s.parse::<vopono_core::network::wireguard_config::WireguardConfig>()
                                .ok()
                        })
                        .map(|c| c.peer.public_key);
                }
                endpoints = found;
                report.diagnostics.push(Diagnostic::new(Code::ProviderConfig, State::Pass,
                    "Local configuration structure, required keys and referenced files validated; usability is not yet verified", None));
            }
            Err(diagnostic) => {
                let template = (provider == Some(VpnProvider::PrivateInternetAccess)
                    && protocol == Protocol::Wireguard)
                    .then(|| vopono_core::diagnostics::validate_pia_template(&path).ok())
                    .flatten();
                if let Some(found) = template {
                    endpoints = found;
                    report.diagnostics.push(Diagnostic::new(Code::ProviderConfig, State::Warning,
                        "PIA bootstrap template is structurally valid; the configured IP:1337 is its TCP registration API. The server key, tunnel endpoint/address and DNS are supplied by addKey at connection time and remain unverified",
                        Some("Connect using this PIA provider/server, then run vopono doctor --namespace ID; doctor does not authenticate or register keys")));
                } else {
                    report.diagnostics.push(diagnostic);
                    // Key/reference errors need not hide an independently
                    // parseable endpoint's host-DNS bootstrap problem.
                    endpoints = vopono_core::diagnostics::config_endpoints(&path, &protocol)
                        .unwrap_or_default();
                }
            }
        }
        if let Some(provider) = &provider {
            let synced = crate::providers::configuration_last_synced(provider, &protocol, &path);
            report.diagnostics.push(Diagnostic::new(Code::ConfigFreshness, if synced.is_some() { State::Pass } else { State::Warning },
                &synced.map(|time| format!("Unmodified configuration last synced at {time}; current usability is not established"))
                    .unwrap_or_else(|| "No matching per-configuration sync fingerprint; synchronization provenance is unknown".into()), None));
        }
        // Age is evidence about age only, never proof of server retirement.
        if let Ok(meta) = std::fs::metadata(&path)
            && let Ok(modified) = meta.modified()
            && let Ok(age) = modified.elapsed()
        {
            let days = age.as_secs() / 86400;
            report.diagnostics.push(Diagnostic::new(
                Code::ConfigFreshness,
                if days >= 30 {
                    State::Warning
                } else {
                    State::Pass
                },
                &format!(
                    "Configuration file age: {days} days; age alone does not establish staleness",
                ),
                (days >= 30).then_some(
                    "Use --catalogue for a current public endpoint comparison where supported",
                ),
            ));
        }
    } else if let Some((state, message, action)) = unsupported_protocol {
        report.diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            state,
            &message,
            action,
        ));
    } else if let Some(provider) = &provider {
        if !provider.supports_sync() {
            report.diagnostics.push(Diagnostic::new(
                Code::ProviderConfig,
                State::Skipped,
                "This provider/protocol does not use synchronized local configuration files",
                Some("Pass --custom /path/to/config for custom profiles, or run vopono doctor without --provider to check running namespaces"),
            ));
        } else {
            report.diagnostics.push(Diagnostic::new(
                Code::ProviderConfig,
                State::Fail,
                "No stored configuration matches the requested provider, protocol and server",
                Some("Run vopono sync PROVIDER --protocol PROTOCOL as your user"),
            ));
        }
    } else {
        report.diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            State::Skipped,
            "Select --provider and --server, or --custom, to diagnose a VPN configuration",
            None,
        ));
    }
    if !command.offline {
        report.diagnostics.push(host_connectivity(timeout, false));
        for endpoint in &endpoints {
            report
                .diagnostics
                .extend(endpoint_diagnostics(endpoint, timeout));
        }
    }
    if command.catalogue {
        let p = provider.as_ref().expect("clap requires provider");
        if protocol != Protocol::Wireguard {
            report.diagnostics.push(Diagnostic::new(
                Code::ProviderCatalogue,
                State::Skipped,
                "Public catalogue comparison currently covers WireGuard only",
                None,
            ));
        } else {
            match catalogue::public_catalogue(p, timeout) {
                Ok(Some(servers)) => {
                    report.diagnostics.push(Diagnostic::new(Code::ProviderCatalogue, State::Pass,
                        &format!("Public catalogue schema validated: {} active endpoint records", servers.len()), None));
                    for endpoint in &endpoints {
                        if let Ok(ips) = resolve_bounded(&endpoint.host, timeout) {
                            report.diagnostics.push(catalogue::compare_endpoint(&servers, &ips, endpoint.host.parse::<IpAddr>().is_ok(), public_key.as_deref()));
                        }
                    }
                }
                Ok(None) => report.diagnostics.push(Diagnostic::new(Code::ProviderCatalogue, State::Skipped,
                    "No credential-free public catalogue adapter for this provider", None)),
                Err(_) => report.diagnostics.push(Diagnostic::new(Code::ProviderCatalogue, State::Warning,
                    "Public catalogue could not be fetched or parsed; configuration freshness is unknown",
                    Some("Retry later; report a persistent provider schema failure"))),
            }
        }
    }
    report.diagnostics.push(Diagnostic::new(
        Code::TunnelHandshake,
        State::Skipped,
        "Configuration preflight does not verify a live handshake, namespace DNS or isolation",
        Some(
            "Run vopono doctor to discover running namespaces and check their connectivity and DNS",
        ),
    ));
    report
}

#[derive(Serialize)]
struct NamespaceReport {
    id: String,
    provider: String,
    protocol: String,
    /// Cached monitor evidence, independent of this invocation's fresh probes.
    health: Option<crate::health::Health>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connectivity: Option<ConnectivityStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<NamespaceNetwork>,
}

fn namespace_report(command: &DoctorCommand) -> Report {
    let mut report = diagnose_namespaces(command, crate::list::status_snapshot(), |check| {
        let dns_host = check
            .dns_host
            .as_deref()
            .unwrap_or(crate::check::DEFAULT_DNS_HOST);
        if nix::unistd::getuid().is_root() {
            Ok(crate::check::probe_namespace(
                &check.id,
                crate::check::DEFAULT_V4_HOST,
                crate::check::DEFAULT_V6_HOST,
                check.port,
                check.timeout_ms,
                dns_host,
                false,
                check.skip_ipv6,
                false,
            ))
        } else {
            // Unlike an explicit `check`, automatic discovery must not elevate
            // privileges or clean up session state when the daemon is absent.
            crate::forward_check_to_daemon(
                check,
                crate::check::DEFAULT_V4_HOST,
                crate::check::DEFAULT_V6_HOST,
                dns_host,
                crate::daemon_client::Compatibility::Warn,
            )
        }
    });
    let daemon_usable = report
        .daemon
        .as_ref()
        .is_some_and(|d| d.status.available && d.status.compatible);
    for ns in &mut report.namespaces {
        ns.network = namespace_environment(&ns.id, command, daemon_usable);
    }
    if !command.offline {
        report.diagnostics.insert(
            0,
            host_connectivity(Duration::from_millis(command.timeout_ms), command.skip_ipv6),
        );
    }
    report
}

fn host_connectivity(timeout: Duration, skip_ipv6: bool) -> Diagnostic {
    let mut tested = Vec::new();
    let reachable = ["1.1.1.1", "2606:4700:4700::1111"].into_iter().any(|host| {
        if skip_ipv6 && host.contains(':') {
            return false;
        }
        let ip = host.parse::<IpAddr>().unwrap();
        let interface = vopono_core::diagnostics::topology::route_interface(ip)
            .unwrap_or_else(|| "unknown interface".into());
        match TcpStream::connect_timeout(&SocketAddr::new(ip, 443), timeout) {
            Ok(socket) => {
                tested.push(format!(
                    "{host}:443 via {interface}, source {}: succeeded",
                    socket
                        .local_addr()
                        .map(|s| s.ip().to_string())
                        .unwrap_or_else(|_| "unknown".into())
                ));
                true
            }
            Err(_) => {
                tested.push(format!("{host}:443 via {interface}: failed"));
                false
            }
        }
    });
    Diagnostic::new(
        Code::HostConnectivity,
        if reachable {
            State::Pass
        } else {
            State::Warning
        },
        &format!(
            "Host TCP probe(s): {}{}",
            tested.join("; "),
            if reachable {
                ""
            } else {
                "; probe targets may be blocked"
            }
        ),
        (!reachable)
            .then_some("Check host networking and firewall rules before diagnosing the VPN"),
    )
}

fn diagnose_namespaces(
    command: &DoctorCommand,
    snapshot: anyhow::Result<crate::list::StatusDocument>,
    mut probe: impl FnMut(&CheckCommand) -> Result<ConnectivityStatus, crate::CheckForwardError>,
) -> Report {
    let mut report = Report {
        version: crate::api::SCHEMA_VERSION,
        diagnostics: Vec::new(),
        namespaces: Vec::new(),
        host_network: None,
        daemon: None,
    };
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(_) => {
            report.diagnostics.push(Diagnostic::new(
                Code::ProbeUnavailable,
                State::Fail,
                "Could not discover running namespaces",
                Some("Run vopono status --json to inspect namespace discovery errors"),
            ));
            return report;
        }
    };
    report.daemon = Some(DaemonInfo::new(snapshot.daemon));
    if !snapshot.errors.is_empty() {
        report.diagnostics.push(Diagnostic::new(
            Code::ProbeUnavailable,
            State::Warning,
            "Some namespace records could not be read; discovery may be incomplete",
            Some("Run vopono status --json to inspect namespace discovery errors"),
        ));
    }
    for ns in snapshot.namespaces {
        if command.namespace.as_ref().is_some_and(|id| id != &ns.id) {
            continue;
        }
        let mut ns_report = NamespaceReport {
            id: ns.id,
            provider: ns.provider,
            protocol: ns.protocol,
            health: ns.health,
            diagnostics: Vec::new(),
            connectivity: None,
            network: None,
        };
        let retry = format!("Run vopono check {} --json", ns_report.id);
        if command.offline {
            ns_report.diagnostics.push(Diagnostic::new(
                Code::ProbeUnavailable,
                State::Skipped,
                "Running namespace discovered; --offline disables connectivity and DNS probes",
                Some(&retry),
            ));
        } else {
            let check = CheckCommand {
                id: ns_report.id.clone(),
                port: crate::check::DEFAULT_CHECK_PORT,
                timeout_ms: command.timeout_ms,
                v4_host: None,
                v6_host: None,
                skip_ipv4: false,
                skip_ipv6: command.skip_ipv6,
                dns_host: command.dns_host.clone(),
                skip_dns: false,
                json: true,
            };
            match probe(&check) {
                Ok(status) => {
                    ns_report.diagnostics = connectivity_diagnostics(&status, check.skip_ipv6);
                    ns_report.connectivity = Some(status);
                }
                Err(crate::CheckForwardError::Retry(_)) => {
                    ns_report.diagnostics.push(Diagnostic::new(
                        Code::ProbeUnavailable,
                        State::Skipped,
                        "Live probe unavailable through the daemon; doctor does not prompt for sudo",
                        Some(&format!("{retry} (uses the daemon or falls back to sudo)")),
                    ));
                }
                Err(crate::CheckForwardError::Reported(_)) => {
                    ns_report.diagnostics.push(Diagnostic::new(
                        Code::ProbeUnavailable,
                        State::Fail,
                        "The daemon rejected or could not complete this namespace probe",
                        Some(&format!("{retry} to see the daemon error")),
                    ));
                }
            }
        }
        report.namespaces.push(ns_report);
    }
    if report.namespaces.is_empty() {
        let (state, message, action) = if let Some(id) = &command.namespace {
            (
                State::Fail,
                format!("Namespace {id} was not found among your running namespaces"),
                "Run vopono status to find a running namespace ID",
            )
        } else {
            (
                State::Skipped,
                "No running namespaces were found for your user".into(),
                "To inspect a stored configuration, run vopono doctor --provider PROVIDER --server SERVER or vopono doctor --custom /path/to/vpn.conf",
            )
        };
        report.diagnostics.push(Diagnostic::new(
            Code::ProbeUnavailable,
            state,
            &message,
            Some(action),
        ));
    }
    report
}

pub(crate) fn connectivity_diagnostics(
    status: &ConnectivityStatus,
    skip_ipv6: bool,
) -> Vec<Diagnostic> {
    connectivity_diagnostics_for_families(status, false, skip_ipv6)
}

pub(crate) fn connectivity_diagnostics_for_families(
    status: &ConnectivityStatus,
    skip_ipv4: bool,
    skip_ipv6: bool,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let retry = format!("Run vopono check {} --json", status.id);
    for (label, family, skipped) in [
        ("IPv4", &status.ipv4, skip_ipv4),
        ("IPv6", &status.ipv6, skip_ipv6),
    ] {
        if skipped {
            continue;
        }
        if let Some(family) = family {
            let (state, message, action) = if let Some(ms) = family.latency_ms {
                (
                    State::Pass,
                    format!("{label} TCP to {} succeeded ({ms} ms)", family.target),
                    None,
                )
            } else {
                (
                    State::Fail,
                    format!(
                        "{label} TCP to {} failed: {}",
                        family.target,
                        family.error.as_deref().unwrap_or("unknown error")
                    ),
                    Some(if label == "IPv6" && status.connected {
                        format!(
                            "{retry}; if IPv6 is intentionally disabled, use vopono doctor --namespace {} --skip-ipv6",
                            status.id
                        )
                    } else {
                        format!(
                            "{retry}; check tunnel state, routes and firewall rules, or use check --v4-host/--v6-host to try another TCP target"
                        )
                    }),
                )
            };
            diagnostics.push(Diagnostic::new(
                family.code.unwrap_or(Code::TunnelConnectivity),
                state,
                &message,
                action.as_deref(),
            ));
        } else {
            diagnostics.push(Diagnostic::new(
                Code::ProbeUnavailable,
                State::Fail,
                &format!("The namespace probe returned no {label} result"),
                Some(&retry),
            ));
        }
    }
    if let Some(dns) = &status.dns {
        let passed = !dns.resolved_ips.is_empty();
        let message = if passed {
            format!(
                "Namespace DNS resolved {} to {}",
                dns.host,
                dns.resolved_ips.join(", ")
            )
        } else {
            format!(
                "Namespace DNS resolution of {} failed: {}{}",
                dns.host,
                dns.error.as_deref().unwrap_or("no addresses returned"),
                if status.connected {
                    "; TCP connectivity is available"
                } else {
                    ""
                }
            )
        };
        let action = if status.connected {
            format!(
                "Inspect /etc/netns/{}/resolv.conf and the configured DNS server's reachability; use vopono check {} --dns-host example.com --json to test another hostname",
                status.id, status.id
            )
        } else {
            format!("{retry}; resolve the TCP connectivity failure, then retry DNS")
        };
        diagnostics.push(Diagnostic::new(
            dns.code.unwrap_or(Code::NamespaceDns),
            if passed { State::Pass } else { State::Fail },
            &message,
            (!passed).then_some(action.as_str()),
        ));
    } else {
        diagnostics.push(Diagnostic::new(
            Code::ProbeUnavailable,
            State::Fail,
            "The namespace probe returned no DNS result",
            Some(&retry),
        ));
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{App, Command};
    use crate::list::{NamespaceEntry, StatusDocument};
    use clap::Parser;

    fn daemon_info(available: bool, version: Option<&str>, compatible: bool) -> DaemonInfo {
        DaemonInfo::new(crate::daemon::DaemonStatus {
            available,
            pid: available.then_some(42),
            socket: crate::SOCKET_PATH.into(),
            version: version.map(str::to_owned),
            compatible,
        })
    }

    #[test]
    fn missing_daemon_warns_and_skips_version_comparison_without_failing_preflight() {
        let info = daemon_info(false, None, false);
        let diagnostics = info.diagnostics();
        assert_eq!(diagnostics[0].state, State::Warning);
        assert!(
            diagnostics[0]
                .action
                .as_deref()
                .unwrap()
                .contains("sudo vopono daemon")
        );
        assert_eq!(diagnostics[1].state, State::Skipped);
        assert_eq!(info.versions_match, None);
        assert!(diagnostics.iter().all(|d| d.state != State::Fail));
    }

    #[test]
    fn reachable_daemon_without_a_version_handshake_is_unknown_rather_than_matched() {
        let info = daemon_info(true, None, false);
        let diagnostics = info.diagnostics();
        assert_eq!(diagnostics[0].state, State::Pass);
        assert_eq!(diagnostics[1].state, State::Warning);
        assert!(diagnostics[1].message.contains("handshake did not succeed"));
        assert!(serde_json::to_value(info).unwrap()["versions_match"].is_null());
    }

    #[test]
    fn matching_versions_include_both_versions_and_do_not_claim_build_identity() {
        let info = daemon_info(true, Some(env!("CARGO_PKG_VERSION")), true);
        let diagnostics = info.diagnostics();
        assert!(diagnostics.iter().all(|d| d.state == State::Pass));
        assert!(
            diagnostics[1]
                .message
                .contains("do not guarantee identical builds")
        );
        let json = serde_json::to_value(info).unwrap();
        assert_eq!(json["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(json["versions_match"], true);
        assert_eq!(json["compatible"], true);
        assert_eq!(json["pid"], 42);
        assert_eq!(json["socket"], crate::SOCKET_PATH);
    }

    #[test]
    fn same_major_version_difference_warns_and_explains_that_a_running_process_needs_restart() {
        let major = env!("CARGO_PKG_VERSION").split('.').next().unwrap();
        let info = daemon_info(true, Some(&format!("{major}.999.999")), true);
        let diagnostic = &info.diagnostics()[1];
        assert_eq!(diagnostic.state, State::Warning);
        assert_eq!(info.versions_match, Some(false));
        assert!(diagnostic.message.contains("features may differ"));
        assert!(
            diagnostic
                .action
                .as_deref()
                .unwrap()
                .contains("Updating the executable alone")
        );
    }

    #[test]
    fn incompatible_or_unrecognized_daemon_versions_fail_the_report() {
        for version in ["999.0.0", "unrecognized"] {
            let info = daemon_info(true, Some(version), false);
            let report = Report {
                version: crate::api::SCHEMA_VERSION,
                diagnostics: info.diagnostics(),
                namespaces: Vec::new(),
                host_network: None,
                daemon: Some(info),
            };
            assert_eq!(report.diagnostics[1].state, State::Fail);
            assert!(report.failed());
        }
    }

    fn command(options: &[&str]) -> DoctorCommand {
        let app = App::try_parse_from(
            ["vopono", "doctor"]
                .into_iter()
                .chain(options.iter().copied()),
        )
        .unwrap();
        let Some(Command::Doctor(command)) = app.cmd else {
            unreachable!()
        };
        command
    }

    fn snapshot(ids: &[&str]) -> anyhow::Result<StatusDocument> {
        Ok(StatusDocument {
            version: crate::api::SCHEMA_VERSION,
            daemon: crate::daemon::DaemonStatus {
                available: false,
                pid: None,
                socket: crate::SOCKET_PATH.into(),
                version: None,
                compatible: false,
            },
            namespaces: ids
                .iter()
                .map(|id| NamespaceEntry {
                    id: (*id).into(),
                    provider: "airvpn".into(),
                    protocol: "wireguard".into(),
                    server: None,
                    created_at: None,
                    uptime_seconds: 0,
                    applications: Vec::new(),
                    port_forwarding: None,
                    open_ports: Vec::new(),
                    host_forwarded_ports: Vec::new(),
                    health: None,
                    stopping: false,
                })
                .collect(),
            errors: Vec::new(),
        })
    }

    fn connected(check: &CheckCommand) -> ConnectivityStatus {
        serde_json::from_value(serde_json::json!({
            "id":check.id, "connected":true,
            "ipv4":{"target":"1.1.1.1:443", "latency_ms":5},
            "ipv6":if check.skip_ipv6 { serde_json::Value::Null } else {
                serde_json::json!({"target":"[2606:4700:4700::1111]:443", "latency_ms":6})
            },
            "dns":{"host":check.dns_host.as_deref().unwrap_or(crate::check::DEFAULT_DNS_HOST),
                "resolved_ips":["1.1.1.1"], "latency_ms":7}
        }))
        .unwrap()
    }

    #[test]
    fn bare_doctor_probes_every_discovered_namespace_and_preserves_results() {
        let mut probed = Vec::new();
        let report = diagnose_namespaces(&command(&[]), snapshot(&["vo_a", "vo_b"]), |check| {
            probed.push(check.id.clone());
            Ok(connected(check))
        });
        assert_eq!(probed, ["vo_a", "vo_b"]);
        assert!(!report.failed());
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["version"], 1);
        assert!(json["diagnostics"].is_array());
        assert_eq!(
            json["namespaces"][1]["connectivity"]["dns"]["resolved_ips"][0],
            "1.1.1.1"
        );
        assert_eq!(
            json["namespaces"][0]["diagnostics"][2]["code"],
            "namespace_dns"
        );
    }

    #[test]
    fn namespace_selector_and_probe_options_are_respected() {
        let report = diagnose_namespaces(
            &command(&[
                "--namespace",
                "vo_b",
                "--dns-host",
                "example.com",
                "--skip-ipv6",
                "--timeout-ms",
                "123",
            ]),
            snapshot(&["vo_a", "vo_b"]),
            |check| {
                assert_eq!(check.id, "vo_b");
                assert_eq!(check.dns_host.as_deref(), Some("example.com"));
                assert!(check.skip_ipv6);
                assert_eq!(check.timeout_ms, 123);
                Ok(connected(check))
            },
        );
        assert_eq!(report.namespaces.len(), 1);
        assert_eq!(report.namespaces[0].diagnostics.len(), 2);
        assert!(!report.failed());
    }

    #[test]
    fn offline_discovers_namespaces_without_running_probes() {
        let report = diagnose_namespaces(&command(&["--offline"]), snapshot(&["vo_a"]), |_| {
            panic!("offline must not probe")
        });
        assert!(!report.failed());
        assert_eq!(report.namespaces[0].diagnostics[0].state, State::Skipped);
        assert!(
            report.namespaces[0].diagnostics[0]
                .action
                .as_deref()
                .unwrap()
                .contains("vopono check vo_a --json")
        );
        assert!(
            serde_json::to_value(report).unwrap()["namespaces"][0]
                .get("connectivity")
                .is_none()
        );
    }

    #[test]
    fn absent_or_rejecting_daemon_does_not_prevent_checking_other_namespaces() {
        let report = diagnose_namespaces(
            &command(&[]),
            snapshot(&["vo_a", "vo_b", "vo_c"]),
            |check| match check.id.as_str() {
                "vo_a" => Err(crate::CheckForwardError::Retry(anyhow::anyhow!(
                    "unavailable"
                ))),
                "vo_b" => Err(crate::CheckForwardError::Reported(anyhow::anyhow!(
                    "rejected"
                ))),
                _ => Ok(connected(check)),
            },
        );
        assert_eq!(report.namespaces[0].diagnostics[0].state, State::Skipped);
        assert_eq!(report.namespaces[1].diagnostics[0].state, State::Fail);
        assert!(
            report.namespaces[2]
                .connectivity
                .as_ref()
                .unwrap()
                .connected
        );
        assert!(report.failed());
    }

    #[test]
    fn dns_failure_is_actionable_even_when_tcp_connects() {
        let report = diagnose_namespaces(&command(&[]), snapshot(&["vo_a"]), |check| {
            let mut status = connected(check);
            let dns = status.dns.as_mut().unwrap();
            dns.resolved_ips.clear();
            dns.error = Some("DNS resolution timed out".into());
            dns.latency_ms = None;
            dns.code = Some(Code::NamespaceDns);
            Ok(status)
        });
        assert!(
            report.namespaces[0]
                .connectivity
                .as_ref()
                .unwrap()
                .connected
        );
        let diagnostics = &report.namespaces[0].diagnostics;
        assert_eq!(diagnostics[0].state, State::Pass);
        assert_eq!(diagnostics[2].state, State::Fail);
        assert!(
            diagnostics[2]
                .message
                .contains("TCP connectivity is available")
        );
        assert!(
            diagnostics[2]
                .action
                .as_deref()
                .unwrap()
                .contains("/etc/netns/vo_a/resolv.conf")
        );
        assert!(report.failed());
    }

    #[test]
    fn partial_transport_failure_is_visible_and_fails_the_report() {
        let report = diagnose_namespaces(&command(&[]), snapshot(&["vo_a"]), |check| {
            let mut status = connected(check);
            let ipv6 = status.ipv6.as_mut().unwrap();
            ipv6.latency_ms = None;
            ipv6.error = Some("Network unreachable".into());
            Ok(status)
        });
        assert!(report.failed());
        assert_eq!(report.namespaces[0].diagnostics[2].state, State::Pass);
        assert!(
            report.namespaces[0].diagnostics[1]
                .action
                .as_deref()
                .unwrap()
                .contains("--namespace vo_a --skip-ipv6")
        );
    }

    #[test]
    fn missing_probe_results_are_failures_rather_than_passes() {
        let report = diagnose_namespaces(&command(&[]), snapshot(&["vo_a"]), |check| {
            let mut status = connected(check);
            status.ipv6 = None;
            status.dns = None;
            Ok(status)
        });
        assert!(report.failed());
        assert_eq!(
            report.namespaces[0].diagnostics[1].code,
            Code::ProbeUnavailable
        );
        assert_eq!(
            report.namespaces[0].diagnostics[2].code,
            Code::ProbeUnavailable
        );
    }

    #[test]
    fn missing_namespaces_and_discovery_errors_have_next_steps() {
        let report = diagnose_namespaces(&command(&[]), snapshot(&[]), |_| panic!("no namespaces"));
        assert!(!report.failed());
        assert!(
            report.diagnostics[0]
                .action
                .as_deref()
                .unwrap()
                .contains("--provider")
        );

        let report = diagnose_namespaces(
            &command(&["--namespace", "vo_missing"]),
            snapshot(&["vo_a"]),
            |_| panic!("wrong namespace"),
        );
        assert!(report.failed());
        assert!(
            report.diagnostics[0]
                .action
                .as_deref()
                .unwrap()
                .contains("vopono status")
        );

        let report = diagnose_namespaces(&command(&[]), Err(anyhow::anyhow!("unreadable")), |_| {
            panic!("discovery failed")
        });
        assert!(report.failed());
        assert_eq!(report.diagnostics[0].code, Code::ProbeUnavailable);

        let mut partial = snapshot(&["vo_a"]).unwrap();
        partial.errors.push("unreadable record".into());
        let report = diagnose_namespaces(&command(&[]), Ok(partial), |check| Ok(connected(check)));
        assert_eq!(report.diagnostics[0].state, State::Warning);
        assert!(report.namespaces[0].connectivity.is_some());
    }
}
