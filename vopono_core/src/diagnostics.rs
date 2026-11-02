//! Read-only diagnostics. Reports contain fixed explanations, never raw config or provider replies.
use crate::config::vpn::Protocol;
use crate::network::wireguard_config::WireguardConfig;
use crate::util::wireguard::generate_public_key;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Safe setup failures: values are enums or fixed local explanations, never
/// configuration contents, filesystem error strings or provider replies.
#[derive(Debug)]
pub enum SetupError {
    Configuration(&'static str),
    ProviderNotConfigured {
        provider: crate::config::providers::VpnProvider,
        protocol: Protocol,
    },
    ProtocolNotSupported {
        provider: crate::config::providers::VpnProvider,
        protocol: Protocol,
    },
    DependencyMissing(&'static str),
}
impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(message) => f.write_str(message),
            Self::ProviderNotConfigured { provider, protocol } => write!(
                f,
                "Missing configuration for {provider} {protocol}. Run vopono sync {} --protocol {} as your user",
                provider.id(),
                protocol.id()
            ),
            Self::ProtocolNotSupported { provider, protocol } => {
                write!(f, "{provider} does not support {protocol}")
            }
            Self::DependencyMissing(binary) => {
                write!(f, "{binary} is not installed or is not on PATH")
            }
        }
    }
}
impl std::error::Error for SetupError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    ProviderConfig,
    ProviderCatalogue,
    ConfigFreshness,
    HostConnectivity,
    EndpointDns,
    EndpointTransport,
    NamespaceRouting,
    TunnelAuthentication,
    TunnelTls,
    TunnelHandshake,
    NamespaceDns,
    TunnelConnectivity,
    ProbeUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticState {
    Pass,
    Fail,
    Warning,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub state: DiagnosticState,
    pub message: String,
    pub action: Option<String>,
}
impl Diagnostic {
    pub fn new(
        code: DiagnosticCode,
        state: DiagnosticState,
        message: &str,
        action: Option<&str>,
    ) -> Self {
        Self {
            code,
            state,
            message: message.into(),
            action: action.map(str::to_owned),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)?;
        if let Some(action) = &self.action {
            write!(f, ". {action}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Diagnostic {}

pub fn config_fingerprint(path: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes)))
}

/// Do not claim NXDOMAIN or key revocation from an ambiguous system resolver/UDP failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFailure {
    Timeout,
    ResolutionFailed,
    NoAddresses,
}
impl std::fmt::Display for DnsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Timeout => "DNS resolution timed out",
            Self::ResolutionFailed => "System resolver failed (DNS response code unavailable)",
            Self::NoAddresses => "DNS returned no addresses",
        })
    }
}
impl std::error::Error for DnsFailure {}

pub fn resolve_bounded(host: &str, timeout: Duration) -> Result<Vec<IpAddr>, DnsFailure> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    // getaddrinfo has no portable per-call timeout. Bound the caller's wait;
    // the isolated resolver thread can finish later without blocking diagnosis.
    let host = host.to_owned();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (host.as_str(), 0)
            .to_socket_addrs()
            .map(|addrs| {
                let mut ips: Vec<_> = addrs.map(|addr| addr.ip()).collect();
                ips.sort();
                ips.dedup();
                ips
            })
            .map_err(|_| DnsFailure::ResolutionFailed)
            .and_then(|ips| {
                if ips.is_empty() {
                    Err(DnsFailure::NoAddresses)
                } else {
                    Ok(ips)
                }
            });
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout).unwrap_or(Err(DnsFailure::Timeout))
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tcp: bool,
}

/// Parse without echoing errors: parser errors may include private keys or inline credentials.
pub fn validate_config(path: &Path, protocol: &Protocol) -> Result<Vec<Endpoint>, Diagnostic> {
    let fail = || {
        Diagnostic::new(
            DiagnosticCode::ProviderConfig,
            DiagnosticState::Fail,
            "Configuration is unreadable, malformed, or contains unsupported settings",
            Some(
                "Check configuration syntax, required keys, endpoint, addresses and referenced files",
            ),
        )
    };
    // Bound user-controlled input before reading; symlinks are fine here: doctor runs as the user.
    if std::fs::metadata(path).map_or(true, |m| !m.is_file() || m.len() > 4 * 1024 * 1024) {
        return Err(fail());
    }
    let content = String::from_utf8(
        crate::util::owner_write::read_file_as_config_owner(path).map_err(|_| fail())?,
    )
    .map_err(|_| fail())?;
    match protocol {
        Protocol::Wireguard => {
            let config: WireguardConfig = content.parse().map_err(|_| fail())?;
            if generate_public_key(&config.interface.private_key).is_err()
                || generate_public_key(&config.peer.public_key).is_err()
                || config.interface.address.is_empty()
                || config.peer.allowed_ips.is_empty()
                || config.peer.endpoint.port() == 0
                || !valid_host(&config.peer.endpoint.ip_or_hostname())
                || config
                    .peer
                    .keepalive
                    .as_ref()
                    .is_some_and(|s| s.parse::<u16>().is_err())
                || config
                    .interface
                    .mtu
                    .as_ref()
                    .is_some_and(|s| s.parse::<u16>().is_err())
            {
                return Err(fail());
            }
            // These are not represented by the current execution model; never claim validation.
            if content
                .lines()
                .any(|l| l.trim().starts_with("PresharedKey"))
            {
                return Err(fail());
            }
            Ok(vec![Endpoint {
                host: config.peer.endpoint.ip_or_hostname(),
                port: config.peer.endpoint.port(),
                tcp: false,
            }])
        }
        Protocol::OpenVpn => {
            crate::network::openvpn_config::validate(&content, path).map_err(|_| fail())?;
            crate::network::openvpn_config::endpoints(&content).map_err(|_| fail())
        }
        _ => Err(Diagnostic::new(
            DiagnosticCode::ProviderConfig,
            DiagnosticState::Skipped,
            "Local validation currently supports WireGuard and OpenVPN",
            None,
        )),
    }
}

pub(crate) fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && (host.parse::<IpAddr>().is_ok()
            || host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')))
}

pub fn endpoint_diagnostics(endpoint: &Endpoint, timeout: Duration) -> Vec<Diagnostic> {
    let mut report = Vec::new();
    let ips = match resolve_bounded(&endpoint.host, timeout) {
        Ok(ips) => {
            report.push(Diagnostic::new(
                DiagnosticCode::EndpointDns,
                DiagnosticState::Pass,
                "Endpoint resolved",
                None,
            ));
            ips
        }
        Err(error) => {
            report.push(Diagnostic::new(DiagnosticCode::EndpointDns, DiagnosticState::Fail, &error.to_string(), Some("Check host DNS and the configured server; use the public catalogue to check for retired servers")));
            return report;
        }
    };
    // A route lookup sends no packet and validates the actual destination rather than a default alone.
    let reachable = ips
        .iter()
        .any(|ip| crate::network::route::lookup(*ip).is_ok());
    report.push(Diagnostic::new(
        DiagnosticCode::NamespaceRouting,
        if reachable {
            DiagnosticState::Pass
        } else {
            DiagnosticState::Fail
        },
        if reachable {
            "Host has a route to the endpoint"
        } else {
            "No usable host route to the endpoint could be established"
        },
        (!reachable).then_some("Restore host networking or check endpoint address families"),
    ));
    report.push(if endpoint.tcp {
        // One total transport deadline across all returned addresses.
        let deadline = std::time::Instant::now() + timeout;
        let reachable = ips.iter().any(|ip| {
            deadline
                .checked_duration_since(std::time::Instant::now())
                .is_some_and(|left| {
                    TcpStream::connect_timeout(&SocketAddr::new(*ip, endpoint.port), left).is_ok()
                })
        });
        Diagnostic::new(
            DiagnosticCode::EndpointTransport,
            if reachable {
                DiagnosticState::Pass
            } else {
                DiagnosticState::Fail
            },
            if reachable {
                "Endpoint TCP connection succeeded"
            } else {
                "Endpoint TCP connection failed; cause is not established"
            },
            (!reachable).then_some("Check endpoint, port, host firewall and provider availability"),
        )
    } else {
        Diagnostic::new(
            DiagnosticCode::EndpointTransport,
            DiagnosticState::Skipped,
            "UDP reachability requires a VPN handshake; sending a datagram proves nothing",
            None,
        )
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_addresses_need_no_dns() {
        assert_eq!(
            resolve_bounded("::1", Duration::ZERO).unwrap(),
            vec!["::1".parse::<IpAddr>().unwrap()]
        );
    }
    #[test]
    fn openvpn_defaults_inline_data_and_remote_protocol() {
        let endpoints = crate::network::openvpn_config::endpoints("proto tcp-client\nport 443\nremote localhost\nremote ::1 1194 udp6\n<key>\nPRIVATE SECRET\n</key>").unwrap();
        assert!(endpoints[0].tcp);
        assert_eq!(endpoints[0].port, 443);
        assert!(!endpoints[1].tcp);
        assert!(
            crate::network::openvpn_config::endpoints("remote localhost\n<key>\nsecret").is_err()
        );
        assert!(
            crate::network::openvpn_config::endpoints("remote localhost\nconfig other.ovpn")
                .is_err()
        );
    }
    #[test]
    fn openvpn_quoted_remotes_defaults_and_connection_scopes() {
        let endpoints = crate::network::openvpn_config::endpoints("--remote 'default.test'\n<connection>\nremote 'tcp.test'\nproto tcp-client\nrport 443\n</connection>\n<connection>\nremote udp.test 53 udp\n</connection>\n").unwrap();
        assert_eq!(endpoints.len(), 3);
        assert_eq!(endpoints[0].host, "default.test");
        assert_eq!(endpoints[0].port, 1194);
        assert!(!endpoints[0].tcp);
        assert_eq!(endpoints[1].port, 443);
        assert!(endpoints[1].tcp);
        assert_eq!(endpoints[2].port, 53);
        assert!(!endpoints[2].tcp);
    }
    #[test]
    fn reports_never_echo_secret_parser_input() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "[Interface]\nPrivateKey = SUPERSECRET\ninvalid",
        )
        .unwrap();
        let report = validate_config(file.path(), &Protocol::Wireguard).unwrap_err();
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("SUPERSECRET")
        );
    }
}
