use crate::args::DoctorCommand;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use vopono_core::config::providers::{VpnProvider, diagnostics as catalogue};
use vopono_core::config::vpn::Protocol;
use vopono_core::diagnostics::{
    Diagnostic, DiagnosticCode as Code, DiagnosticState as State, endpoint_diagnostics,
    resolve_bounded, validate_config,
};

#[derive(Serialize)]
struct Report {
    version: u8,
    diagnostics: Vec<Diagnostic>,
}

pub fn run(command: DoctorCommand) -> anyhow::Result<i32> {
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
    };
    let path = if let Some(path) = command.custom {
        Some(path)
    } else if let Some(p) = &provider {
        let directory = match protocol {
            Protocol::Wireguard => p
                .get_dyn_wireguard_provider()
                .and_then(|p| p.wireguard_dir()),
            Protocol::OpenVpn => p.get_dyn_openvpn_provider().and_then(|p| p.openvpn_dir()),
            _ => Err(anyhow::anyhow!("Unsupported local diagnostic protocol")),
        };
        match directory {
            Ok(dir) => {
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
            Err(_) => None,
        }
    } else {
        None
    };
    let mut endpoints = Vec::new();
    let mut public_key = None;
    if let Some(path) = path {
        match validate_config(&path, &protocol) {
            Ok(found) => {
                if protocol == Protocol::Wireguard {
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
            Err(diagnostic) => report.diagnostics.push(diagnostic),
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
            report.diagnostics.push(Diagnostic::new(
                Code::ConfigFreshness,
                State::Warning,
                &format!(
                    "Configuration file age: {} days; age alone does not establish staleness",
                    age.as_secs() / 86400
                ),
                Some("Use --catalogue for a current public endpoint comparison where supported"),
            ));
        }
    } else if provider.is_some() {
        report.diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            State::Fail,
            "No stored configuration matches the requested provider, protocol and server",
            Some("Run vopono sync PROVIDER --protocol PROTOCOL as your user"),
        ));
    } else {
        report.diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            State::Skipped,
            "Select --provider and --server, or --custom, to diagnose a VPN configuration",
            None,
        ));
    }
    if !command.offline {
        let reachable = ["1.1.1.1", "2606:4700:4700::1111"].into_iter().any(|host| {
            TcpStream::connect_timeout(
                &SocketAddr::new(host.parse::<IpAddr>().unwrap(), 443),
                timeout,
            )
            .is_ok()
        });
        report.diagnostics.push(Diagnostic::new(
            Code::HostConnectivity,
            if reachable {
                State::Pass
            } else {
                State::Warning
            },
            if reachable {
                "Host TCP connectivity is available"
            } else {
                "Host TCP connectivity probes failed; the probe targets may be blocked"
            },
            None,
        ));
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
    report.diagnostics.push(Diagnostic::new(Code::TunnelHandshake, State::Skipped,
        "No live tunnel was created; authentication, WireGuard handshake, namespace DNS and isolation are not verified",
        Some("For an existing namespace, run vopono check ID --json")));
    let failed = report.diagnostics.iter().any(|d| d.state == State::Fail);
    if command.json {
        crate::api::print_json(&report)?;
    } else {
        for d in &report.diagnostics {
            println!("{:?}\t{:?}\t{}", d.code, d.state, d.message);
            if let Some(action) = &d.action {
                println!("  Suggested action: {action}");
            }
        }
    }
    Ok(i32::from(failed))
}
