//! Read-only diagnostics. Reports contain fixed explanations, never raw config or provider replies.
use crate::config::vpn::Protocol;
use crate::network::wireguard_config::WireguardConfig;
use crate::util::wireguard::generate_public_key;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

pub mod host;
pub mod runtime;
pub mod topology;

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
    HostDns,
    HostForwarding,
    HostFirewall,
    AppArmor,
    DnsConfiguration,
    NetworkInterface,
    HostLink,
    TailscaleDns,
    NetworkManager,
    DaemonAvailability,
    DaemonVersion,
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

// NSS modules can remain blocked after the caller's deadline. Repeated monitor
// lookups must never accumulate an unbounded number of resolver threads.
static DNS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_DNS_IN_FLIGHT: usize = 16;

struct ResolverPermit<'a>(&'a AtomicUsize);
impl<'a> ResolverPermit<'a> {
    fn acquire(counter: &'a AtomicUsize, limit: usize) -> Option<Self> {
        let mut count = counter.load(Ordering::Acquire);
        loop {
            if count >= limit {
                return None;
            }
            match counter.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(counter)),
                Err(current) => count = current,
            }
        }
    }
}
impl Drop for ResolverPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

pub fn resolve_bounded(host: &str, timeout: Duration) -> Result<Vec<IpAddr>, DnsFailure> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    // getaddrinfo has no portable per-call timeout. Bound the caller's wait;
    // the isolated resolver thread can finish later without blocking diagnosis.
    let permit = ResolverPermit::acquire(&DNS_IN_FLIGHT, MAX_DNS_IN_FLIGHT)
        .ok_or(DnsFailure::ResolutionFailed)?;
    let host = host.to_owned();
    let (tx, rx) = mpsc::sync_channel(1);
    let _worker = std::thread::Builder::new()
        .name("vopono-dns".into())
        .spawn(move || {
            let _permit = permit;
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
        })
        .map_err(|_| DnsFailure::ResolutionFailed)?;
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
    validate_config_for_launch(path, protocol, None)
}

/// Validate the same credentials that OpenVPN will use at launch.
pub fn validate_config_for_launch(
    path: &Path,
    protocol: &Protocol,
    openvpn_auth: Option<&Path>,
) -> Result<Vec<Endpoint>, Diagnostic> {
    validate_config_inner(path, protocol, false, openvpn_auth)
}

/// PIA's generated bootstrap profile intentionally has no server public key.
/// Only use this alternative for an explicitly selected PIA provider.
pub fn validate_pia_template(path: &Path) -> Result<Vec<Endpoint>, Diagnostic> {
    validate_config_inner(path, &Protocol::Wireguard, true, None)
}

fn validate_config_inner(
    path: &Path,
    protocol: &Protocol,
    pia_template: bool,
    openvpn_auth: Option<&Path>,
) -> Result<Vec<Endpoint>, Diagnostic> {
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
            let template = pia_template
                && config.peer.public_key.is_empty()
                && config.peer.endpoint.is_ip()
                && config.peer.endpoint.port() == 1337
                && config.interface.address.len() == 1
                && config.interface.address[0].to_string() == "127.0.0.1/32";
            if generate_public_key(&config.interface.private_key).is_err()
                || !template && generate_public_key(&config.peer.public_key).is_err()
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
            // The runtime preserves preshared keys in the raw wg setconf
            // input even though WireguardConfig does not model this field.
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=')
                    && key.trim() == "PresharedKey"
                {
                    use base64::Engine as _;
                    if base64::engine::general_purpose::STANDARD
                        .decode(value.split('#').next().unwrap_or_default().trim())
                        .map_or(true, |key| key.len() != 32)
                    {
                        return Err(fail());
                    }
                }
            }
            Ok(vec![Endpoint {
                host: config.peer.endpoint.ip_or_hostname(),
                port: config.peer.endpoint.port(),
                // Before addKey, PIA's port 1337 target is the HTTPS
                // registration API, not the eventual WireGuard UDP endpoint.
                tcp: template,
            }])
        }
        Protocol::OpenVpn => crate::network::openvpn_config::validate(&content, path, openvpn_auth)
            .and_then(|()| crate::network::openvpn_config::endpoints(&content))
            .map_err(|error| {
                Diagnostic::new(
                    DiagnosticCode::ProviderConfig,
                    DiagnosticState::Fail,
                    &format!("{}: {error:#}", path.display()),
                    None,
                )
            }),
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

/// Extract declared targets even if key/reference validation fails. This does
/// not establish that the profile is usable and never resolves a hostname.
pub fn config_endpoints(path: &Path, protocol: &Protocol) -> Result<Vec<Endpoint>, Diagnostic> {
    let fail = || {
        Diagnostic::new(
            DiagnosticCode::ProviderConfig,
            DiagnosticState::Fail,
            "Could not extract supported VPN endpoints from the configuration",
            None,
        )
    };
    if std::fs::metadata(path).map_or(true, |m| !m.is_file() || m.len() > 4 * 1024 * 1024) {
        return Err(fail());
    }
    let content = String::from_utf8(
        crate::util::owner_write::read_file_as_config_owner(path).map_err(|_| fail())?,
    )
    .map_err(|_| fail())?;
    let endpoints = match protocol {
        Protocol::Wireguard => {
            let config: WireguardConfig = content.parse().map_err(|_| fail())?;
            vec![Endpoint {
                host: config.peer.endpoint.ip_or_hostname(),
                port: config.peer.endpoint.port(),
                tcp: false,
            }]
        }
        Protocol::OpenVpn => {
            crate::network::openvpn_config::endpoints(&content).map_err(|_| fail())?
        }
        _ => return Err(fail()),
    };
    if endpoints
        .iter()
        .any(|endpoint| endpoint.port == 0 || !valid_host(&endpoint.host))
    {
        return Err(fail());
    }
    Ok(endpoints)
}

pub fn endpoint_diagnostics(endpoint: &Endpoint, timeout: Duration) -> Vec<Diagnostic> {
    endpoint_diagnostics_with_resolution(
        endpoint,
        timeout,
        resolve_bounded(&endpoint.host, timeout),
    )
}

fn endpoint_diagnostics_with_resolution(
    endpoint: &Endpoint,
    timeout: Duration,
    resolution: Result<Vec<IpAddr>, DnsFailure>,
) -> Vec<Diagnostic> {
    let mut report = Vec::new();
    let target = endpoint_label(endpoint);
    let ips = match resolution {
        Ok(ips) => {
            let literal = endpoint.host.parse::<IpAddr>().is_ok();
            let addresses = ips
                .iter()
                .take(16)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            report.push(Diagnostic::new(
                DiagnosticCode::EndpointDns,
                if literal { DiagnosticState::Skipped } else { DiagnosticState::Pass },
                &if literal {
                    format!("VPN endpoint {target} is a literal IP address; host DNS is not required for this endpoint")
                } else {
                    format!("Host resolver resolved VPN endpoint {target} before tunnel setup to {addresses}{}", if ips.len() > 16 { " (additional addresses omitted from display)" } else { "" })
                },
                None,
            ));
            ips
        }
        Err(error) => {
            report.push(Diagnostic::new(DiagnosticCode::EndpointDns, DiagnosticState::Fail,
                &format!("Host cannot resolve VPN endpoint {target} before tunnel setup: {error}. Tunnel DNS cannot bootstrap this initial lookup; private/tunnel-only DNS, a retired name or host DNS failure are possible, not established causes"),
                Some("Check this exact endpoint name using host DNS. Prefer a provider-generated IP-address profile or a publicly resolvable endpoint from its current catalogue; preserve VPN certificate/public-key verification. Changing namespace DNS does not fix a pre-tunnel lookup. Doctor does not change host DNS or rewrite the config")));
            return report;
        }
    };
    // A route lookup sends no packet and validates the actual destination rather than a default alone.
    let route = ips
        .iter()
        .find_map(|ip| topology::route_interface(*ip).map(|interface| (*ip, interface)));
    report.push(Diagnostic::new(
        DiagnosticCode::NamespaceRouting,
        if route.is_some() {
            DiagnosticState::Pass
        } else {
            DiagnosticState::Fail
        },
        &match &route {
            Some((ip, interface)) => format!("Host route to VPN endpoint candidate {} uses {interface}; a route does not establish that the VPN server is reachable", SocketAddr::new(*ip, endpoint.port)),
            None => format!("No usable host route/interface to VPN endpoint {target} could be established"),
        },
        route.is_none().then_some("Inspect host routes, policy routing and endpoint address families; repair the host route before connecting"),
    ));
    report.push(if endpoint.tcp {
        // One total transport deadline across all returned addresses.
        let deadline = std::time::Instant::now() + timeout;
        let connected = ips.iter().find_map(|ip| {
            deadline
                .checked_duration_since(std::time::Instant::now())
                .and_then(|left| {
                    let address = SocketAddr::new(*ip, endpoint.port);
                    TcpStream::connect_timeout(&address, left).ok().map(|_| address)
                })
        });
        Diagnostic::new(
            DiagnosticCode::EndpointTransport,
            if connected.is_some() {
                DiagnosticState::Pass
            } else {
                DiagnosticState::Fail
            },
            &match connected {
                Some(address) => format!("Host TCP connection to configured VPN endpoint {address} succeeded; VPN authentication and TLS/server identity remain unverified"),
                None => format!("No host TCP connection to VPN endpoint {target} succeeded within the probe budget; cause is not established"),
            },
            connected.is_none().then_some("Check endpoint, port, host firewall and provider availability; multiple addresses share one probe budget. An ordinary VPN connection is needed to verify authentication"),
        )
    } else {
        Diagnostic::new(
            DiagnosticCode::EndpointTransport,
            DiagnosticState::Skipped,
            &format!("VPN UDP endpoint {target}: peer reachability and key authorization remain unverified; DNS and route checks are prerequisites, not a VPN connection test"),
            Some("UDP endpoints can silently ignore unauthenticated traffic and ICMP; use an ordinary VPN connection and inspect WireGuard handshake/OpenVPN connection status, then check namespace connectivity with vopono doctor or vopono check"),
        )
    });
    report
}

fn endpoint_label(endpoint: &Endpoint) -> String {
    match endpoint.host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, endpoint.port).to_string(),
        Err(_) => format!("{}:{}", endpoint.host, endpoint.port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_admission_is_bounded_until_the_worker_releases_its_permit() {
        let counter = AtomicUsize::new(0);
        let first = ResolverPermit::acquire(&counter, 2).unwrap();
        let second = ResolverPermit::acquire(&counter, 2).unwrap();
        assert!(ResolverPermit::acquire(&counter, 2).is_none());
        drop(first);
        let replacement = ResolverPermit::acquire(&counter, 2).unwrap();
        assert_eq!(counter.load(Ordering::Acquire), 2);
        drop((second, replacement));
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn endpoint_bootstrap_failure_is_separate_from_general_host_dns() {
        let endpoint = Endpoint {
            host: "vpn.provider-only.example".into(),
            port: 51820,
            tcp: false,
        };
        assert_eq!(
            host::host_dns(Ok(vec!["1.1.1.1".parse().unwrap()])).state,
            DiagnosticState::Pass
        );
        for error in [
            DnsFailure::Timeout,
            DnsFailure::ResolutionFailed,
            DnsFailure::NoAddresses,
        ] {
            let report = endpoint_diagnostics_with_resolution(
                &endpoint,
                Duration::from_millis(50),
                Err(error),
            );
            assert_eq!(report.len(), 1);
            assert_eq!(report[0].code, DiagnosticCode::EndpointDns);
            assert_eq!(report[0].state, DiagnosticState::Fail);
            assert!(
                report[0]
                    .message
                    .contains("vpn.provider-only.example:51820")
            );
            assert!(report[0].message.contains(&error.to_string()));
            assert!(report[0].message.contains("Tunnel DNS cannot bootstrap"));
            assert!(
                report[0]
                    .action
                    .as_deref()
                    .unwrap()
                    .contains("provider-generated IP-address profile")
            );
        }
    }

    #[test]
    fn literal_udp_endpoint_needs_no_dns_and_sends_no_probe_packet() {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port: socket.local_addr().unwrap().port(),
            tcp: false,
        };
        let report = endpoint_diagnostics(&endpoint, Duration::from_millis(50));
        assert_eq!(report[0].state, DiagnosticState::Skipped);
        assert!(report[0].message.contains("literal IP"));
        assert_eq!(report[1].state, DiagnosticState::Pass);
        assert!(report[1].message.contains("lo"));
        assert_eq!(report[2].state, DiagnosticState::Skipped);
        assert!(report[2].message.contains("remain unverified"));
        assert!(report[2].action.as_deref().unwrap().contains("handshake"));
        assert!(socket.recv(&mut [0u8; 1]).is_err());
    }

    #[test]
    fn tcp_preflight_reports_the_configured_port_and_actual_successful_address_without_authentication()
     {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = Endpoint {
            host: "vpn.example".into(),
            port: address.port(),
            tcp: true,
        };
        let ips = vec!["127.0.0.2".parse().unwrap(), address.ip()];
        let report =
            endpoint_diagnostics_with_resolution(&endpoint, Duration::from_millis(100), Ok(ips));
        assert_eq!(report[0].state, DiagnosticState::Pass);
        assert!(report[0].message.contains("Host resolver"));
        assert_eq!(report[2].state, DiagnosticState::Pass);
        assert!(report[2].message.contains(&address.to_string()));
        assert!(
            report[2]
                .message
                .contains("TLS/server identity remain unverified")
        );
        // Reserve a non-listening TCP port instead of releasing a listener's
        // port for a concurrent test/process to reuse before the failed probe.
        use nix::sys::socket::{
            AddressFamily, SockFlag, SockType, SockaddrIn, bind, getsockname, socket,
        };
        use std::os::fd::AsRawFd;
        let reserved = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        bind(reserved.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, 0)).unwrap();
        let reserved_address: SockaddrIn = getsockname(reserved.as_raw_fd()).unwrap();
        let endpoint = Endpoint {
            port: reserved_address.port(),
            ..endpoint
        };
        let report = endpoint_diagnostics_with_resolution(
            &endpoint,
            Duration::from_millis(50),
            Ok(vec![address.ip()]),
        );
        assert_eq!(report[2].state, DiagnosticState::Fail);
    }

    #[test]
    fn ipv6_endpoint_labels_preserve_address_and_port_unambiguously() {
        let endpoint = Endpoint {
            host: "::1".into(),
            port: 51820,
            tcp: false,
        };
        assert_eq!(endpoint_label(&endpoint), "[::1]:51820");
    }

    #[test]
    fn bad_keys_do_not_hide_a_parseable_endpoint_and_extraction_does_not_resolve_it() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "[Interface]\nPrivateKey = SECRET_INVALID_KEY\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = INVALID_PUBLIC_KEY\nEndpoint = vpn.provider-only.example:51820\nAllowedIPs = 0.0.0.0/0\n").unwrap();
        assert!(validate_config(file.path(), &Protocol::Wireguard).is_err());
        let endpoints = config_endpoints(file.path(), &Protocol::Wireguard).unwrap();
        assert_eq!(endpoints[0].host, "vpn.provider-only.example");
        assert_eq!(endpoints[0].port, 51820);
        let report = endpoint_diagnostics_with_resolution(
            &endpoints[0],
            Duration::from_millis(50),
            Err(DnsFailure::ResolutionFailed),
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("SECRET_INVALID_KEY")
        );

        std::fs::write(file.path(), "client\ndev tun\nproto tcp-client\nremote vpn.provider-only.example 443\nauth-user-pass missing-credential-file\n").unwrap();
        assert!(validate_config(file.path(), &Protocol::OpenVpn).is_err());
        let endpoints = config_endpoints(file.path(), &Protocol::OpenVpn).unwrap();
        assert!(endpoints[0].tcp);
        assert_eq!(endpoints[0].port, 443);
    }
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

    #[test]
    fn validates_runtime_supported_preshared_keys_without_disclosing_them() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let profile = format!(
            "[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {key}\nPresharedKey = {{psk}}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        std::fs::write(file.path(), profile.replace("{psk}", key)).unwrap();
        assert!(validate_config(file.path(), &Protocol::Wireguard).is_ok());
        for invalid in ["SECRET_INVALID_PSK", "AAAA"] {
            std::fs::write(file.path(), profile.replace("{psk}", invalid)).unwrap();
            let report = validate_config(file.path(), &Protocol::Wireguard).unwrap_err();
            assert!(!serde_json::to_string(&report).unwrap().contains(invalid));
        }
    }

    #[test]
    fn pia_bootstrap_template_is_only_accepted_explicitly_and_still_validates_keys() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let profile = format!(
            "[Interface]\nPrivateKey = {key}\nAddress = 127.0.0.1/32\nDNS = 127.0.0.1\n[Peer]\nPublicKey =\nEndpoint = 192.0.2.1:1337\nAllowedIPs = 0.0.0.0/0\n"
        );
        std::fs::write(file.path(), &profile).unwrap();
        assert!(validate_config(file.path(), &Protocol::Wireguard).is_err());
        let endpoints = validate_pia_template(file.path()).unwrap();
        assert_eq!(endpoints[0].host, "192.0.2.1");
        assert_eq!(endpoints[0].port, 1337);
        assert!(endpoints[0].tcp);
        for invalid in [
            profile.replace(key, "BAD_SECRET"),
            profile.replace(":1337", ":0"),
            profile.replace("192.0.2.1", "private-only.test"),
        ] {
            std::fs::write(file.path(), invalid).unwrap();
            assert!(validate_pia_template(file.path()).is_err());
        }
    }
}
