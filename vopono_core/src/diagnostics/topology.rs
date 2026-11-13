//! Resolver, interface and local-link evidence, without changing networking.
use super::host::{command_result, read_command, system_tool};
use super::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State};
use crate::network::netns::NamespaceSnapshot;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn route_interface(destination: IpAddr) -> Option<String> {
    let route = crate::network::route::lookup(destination).ok()?;
    let mut name = [0; libc::IF_NAMESIZE];
    if unsafe { libc::if_indextoname(route.interface_index, name.as_mut_ptr()) }.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_str()
            .ok()?
            .to_owned(),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolverInfo {
    pub source: String,
    pub nameservers: Vec<String>,
    pub inherited_from_host: bool,
    pub nsswitch_source: String,
    pub hosts_lookup: Vec<String>,
    /// systemd-resolved's configured upstreams; not proof of which answered a lookup.
    pub upstreams: Vec<ResolverUpstream>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolverUpstream {
    pub scope: String,
    pub nameservers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteInfo {
    pub family: String,
    pub destination: String,
    pub interface: String,
    pub gateway: Option<String>,
    pub source: Option<String>,
    pub table: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostNetwork {
    pub dns: ResolverInfo,
    pub default_routes: Vec<RouteInfo>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamespaceNetwork {
    pub dns: ResolverInfo,
    pub host_veth: Option<String>,
    pub namespace_veth: Option<String>,
    pub recorded_veth_addresses: Option<crate::network::netns::VethPairIPs>,
    pub configured_host_uplink: Option<String>,
    pub tunnel_interfaces: Vec<String>,
    pub routes: Vec<RouteInfo>,
    pub link_probes: Vec<LinkProbe>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkProbe {
    pub direction: String,
    pub recorded_source: IpAddr,
    pub target: IpAddr,
    pub interface: String,
    pub state: State,
}

fn resolver(source: &str, content: Option<&str>, inherited: bool) -> ResolverInfo {
    let mut nameservers = Vec::new();
    for line in content.unwrap_or_default().lines() {
        let mut words = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_whitespace();
        if words.next() == Some("nameserver")
            && let Some(server) = words.next()
            && server
                .split('%')
                .next()
                .unwrap_or(server)
                .parse::<IpAddr>()
                .is_ok()
            && !nameservers.iter().any(|existing| existing == server)
        {
            nameservers.push(server.to_owned());
        }
    }
    ResolverInfo {
        source: source.into(),
        nameservers,
        inherited_from_host: inherited,
        nsswitch_source: String::new(),
        hosts_lookup: Vec::new(),
        upstreams: Vec::new(),
    }
}

fn resolver_evidence(dns: &ResolverInfo, namespace: bool) -> Vec<Diagnostic> {
    let mut diagnostics = vec![Diagnostic::new(Code::DnsConfiguration,
        if dns.nameservers.is_empty() { State::Warning } else { State::Pass },
        &format!("{} configured nameservers ({}{}): {}", if namespace { "Namespace" } else { "Host" }, dns.source,
            if dns.inherited_from_host { "; inherited host resolver" } else { "" },
            if dns.nameservers.is_empty() { "none found or file unreadable".into() } else { dns.nameservers.join(", ") }),
        dns.nameservers.is_empty().then_some("Inspect resolver configuration and /etc/nsswitch.conf; NSS services may supply DNS without resolv.conf nameservers"))];
    let magic = dns
        .nameservers
        .iter()
        .chain(dns.upstreams.iter().flat_map(|s| &s.nameservers))
        .any(|s| magic_dns(s));
    if !dns.hosts_lookup.is_empty() {
        diagnostics.push(Diagnostic::new(
            Code::DnsConfiguration,
            State::Pass,
            &format!(
                "{} NSS hosts lookup: {} ({})",
                if namespace { "Namespace" } else { "Host" },
                dns.hosts_lookup.join(" "),
                dns.nsswitch_source
            ),
            None,
        ));
    }
    if namespace && dns.hosts_lookup.iter().any(|s| s == "resolve") {
        diagnostics.push(Diagnostic::new(Code::DnsConfiguration, State::Warning,
            "Namespace NSS includes nss-resolve; its Unix socket can reach the host's systemd-resolved and bypass namespace resolv.conf, including MagicDNS when configured on the host",
            Some("Check the namespace-specific /etc/netns/ID/nsswitch.conf overlay. vopono normally sets hosts: files dns so namespace lookups use its VPN nameservers. See https://www.freedesktop.org/software/systemd/man/latest/nss-resolve.html")));
    }
    if magic {
        diagnostics.push(Diagnostic::new(Code::TailscaleDns, if namespace { State::Warning } else { State::Pass },
            if namespace { "Namespace DNS uses Tailscale's device-local MagicDNS resolver; it may be unreachable from this network namespace or routed into the VPN" }
            else { "Host DNS uses Tailscale MagicDNS; namespace resolver settings are checked independently" },
            namespace.then_some("Use DNS reachable through the namespace's VPN. Host MagicDNS and tailnet services are not automatically available inside a VPN namespace; do not copy the host resolver or open a kill-switch bypass. See https://tailscale.com/docs/reference/quad100")));
    }
    if namespace
        && dns
            .nameservers
            .iter()
            .any(|s| s.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
    {
        diagnostics.push(Diagnostic::new(Code::DnsConfiguration, State::Warning,
            "Namespace DNS references a loopback stub; loopback refers to the namespace itself, not the host resolver",
            Some("Verify a resolver is running inside the namespace, or configure a reachable VPN DNS server; host 127.0.0.53/127.0.0.1 stubs cannot be reached using namespace loopback")));
    }
    diagnostics
}

fn server_address(server: &str) -> Option<IpAddr> {
    server.split('#').next()?.split('%').next()?.parse().ok()
}

fn magic_dns(server: &str) -> bool {
    server_address(server).is_some_and(|ip| {
        ip == "100.100.100.100".parse::<IpAddr>().unwrap()
            || ip == "fd7a:115c:a1e0::53".parse::<IpAddr>().unwrap()
    })
}

fn upstreams(text: &str) -> Vec<ResolverUpstream> {
    text.lines()
        .filter_map(|line| {
            let (scope, servers) = line.split_once(": ")?;
            let nameservers: Vec<_> = servers
                .split_whitespace()
                .filter(|s| server_address(s).is_some())
                .map(str::to_owned)
                .collect();
            (!nameservers.is_empty()).then(|| ResolverUpstream {
                scope: scope.trim().into(),
                nameservers,
            })
        })
        .collect()
}

fn hosts_lookup(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split('#').next()?.split_once(':'))
        .find(|(key, _)| key.trim() == "hosts")
        .map(|(_, modules)| modules.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn nsswitch(dns: &mut ResolverInfo, source: &str) {
    dns.nsswitch_source = source.into();
    dns.hosts_lookup = hosts_lookup(&std::fs::read_to_string(source).unwrap_or_default());
}

fn routes(text: &str, family: &str) -> Option<Vec<RouteInfo>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    Some(
        value
            .as_array()?
            .iter()
            .filter_map(|row| {
                Some(RouteInfo {
                    family: match family {
                        "-4" => "IPv4",
                        "-6" => "IPv6",
                        other => other,
                    }
                    .into(),
                    destination: row
                        .get("dst")
                        .and_then(|s| s.as_str())
                        .unwrap_or("default")
                        .into(),
                    interface: row.get("dev")?.as_str()?.into(),
                    gateway: row
                        .get("gateway")
                        .and_then(|s| s.as_str())
                        .map(str::to_owned),
                    source: row
                        .get("prefsrc")
                        .and_then(|s| s.as_str())
                        .map(str::to_owned),
                    table: row.get("table").map(|s| {
                        s.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| s.to_string())
                    }),
                })
            })
            .collect(),
    )
}

pub fn host_network(skip_ipv6: bool) -> HostNetwork {
    host_network_until(skip_ipv6, Instant::now() + Duration::from_secs(3))
}

pub(super) fn host_network_until(skip_ipv6: bool, deadline: Instant) -> HostNetwork {
    let mut dns = resolver(
        "/etc/resolv.conf",
        std::fs::read_to_string("/etc/resolv.conf").ok().as_deref(),
        false,
    );
    nsswitch(&mut dns, "/etc/nsswitch.conf");
    if let Some(text) = read_command("resolvectl", &["dns"], deadline) {
        dns.upstreams = upstreams(&text);
    }
    let mut diagnostics = resolver_evidence(&dns, false);
    if dns.upstreams.is_empty()
        && dns
            .nameservers
            .iter()
            .any(|s| s.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
    {
        diagnostics.push(Diagnostic::new(Code::DnsConfiguration, State::Skipped, "Host DNS uses a local stub; its upstream nameservers could not be read from systemd-resolved", Some("Inspect resolvectl dns/status or the configuration of the local DNS service; the stub address is not the upstream DNS server")));
    }
    for upstream in &dns.upstreams {
        diagnostics.push(Diagnostic::new(
            Code::DnsConfiguration,
            State::Pass,
            &format!(
                "Host upstream DNS {}: {} (systemd-resolved configuration)",
                upstream.scope,
                upstream.nameservers.join(", ")
            ),
            None,
        ));
    }
    let mut defaults = Vec::new();
    for family in ["-4", "-6"] {
        if skip_ipv6 && family == "-6" {
            continue;
        }
        if let Some(found) =
            read_command("ip", &["-j", family, "route", "show", "default"], deadline)
                .and_then(|s| routes(&s, family))
        {
            for route in &found {
                diagnostics.push(route_evidence(
                    route,
                    "Host main-table default (configured, not a connectivity test)",
                ));
            }
            defaults.extend(found);
        }
    }
    if defaults.is_empty() {
        diagnostics.push(Diagnostic::new(Code::NetworkInterface, State::Skipped, "No host main-table default route found; policy routing or unavailable route inspection may apply", Some("Inspect ip rule, ip -4 route show table all and ip -6 route show table all")));
    }
    HostNetwork {
        dns,
        default_routes: defaults,
        diagnostics,
    }
}

fn route_evidence(route: &RouteInfo, context: &str) -> Diagnostic {
    Diagnostic::new(
        Code::NetworkInterface,
        State::Pass,
        &format!(
            "{context}: {} {} via {}{}{} (table {})",
            route.family,
            route.destination,
            route.interface,
            route
                .gateway
                .as_ref()
                .map(|g| format!(" gateway {g}"))
                .unwrap_or_default(),
            route
                .source
                .as_ref()
                .map(|s| format!(" source {s}"))
                .unwrap_or_default(),
            route.table.as_deref().unwrap_or("main")
        ),
        None,
    )
}

/// Available to unprivileged clients even when the daemon predates topology inspection.
pub fn namespace_resolver(name: &str) -> anyhow::Result<NamespaceNetwork> {
    crate::network::netns::validate_netns_name(name)?;
    let path = format!("/etc/netns/{name}/resolv.conf");
    let exists = Path::new(&path).try_exists()?;
    let source = if exists {
        path.as_str()
    } else {
        "/etc/resolv.conf"
    };
    let mut dns = resolver(
        source,
        std::fs::read_to_string(source).ok().as_deref(),
        !exists,
    );
    let ns_nss = format!("/etc/netns/{name}/nsswitch.conf");
    nsswitch(
        &mut dns,
        if Path::new(&ns_nss).exists() {
            &ns_nss
        } else {
            "/etc/nsswitch.conf"
        },
    );
    let diagnostics = resolver_evidence(&dns, true);
    Ok(NamespaceNetwork {
        dns,
        host_veth: None,
        namespace_veth: None,
        recorded_veth_addresses: None,
        configured_host_uplink: None,
        tunnel_interfaces: Vec::new(),
        routes: Vec::new(),
        link_probes: Vec::new(),
        diagnostics,
    })
}

pub fn namespace_network(
    state: &NamespaceSnapshot,
    offline: bool,
    skip_ipv6: bool,
    timeout_ms: u64,
) -> anyhow::Result<NamespaceNetwork> {
    namespace_network_until(
        state,
        offline,
        skip_ipv6,
        timeout_ms,
        Instant::now() + Duration::from_secs(5),
    )
}

pub(super) fn namespace_network_until(
    state: &NamespaceSnapshot,
    offline: bool,
    skip_ipv6: bool,
    timeout_ms: u64,
    deadline: Instant,
) -> anyhow::Result<NamespaceNetwork> {
    let mut report = namespace_resolver(&state.name)?;
    report.recorded_veth_addresses = state.veth_pair_ips.clone();
    report.configured_host_uplink = state
        .host_masquerade
        .as_ref()
        .map(|m| m.interface_name().to_owned());
    if let Some(interface) = &report.configured_host_uplink {
        report.diagnostics.push(Diagnostic::new(Code::NetworkInterface, State::Pass, &format!("Namespace's recorded host uplink: {interface}; compare with current host defaults and probe routes"), None));
    }
    if let Some(wg) = &state.wireguard {
        report.tunnel_interfaces.push(wg.if_name.clone());
    }
    if let Some(text) = read_command(
        "ip",
        &["-j", "-d", "-n", state.name.as_str(), "link", "show"],
        deadline,
    ) && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(interfaces) = value.as_array()
    {
        for interface in interfaces {
            if matches!(
                interface
                    .pointer("/linkinfo/info_kind")
                    .and_then(|s| s.as_str()),
                Some("wireguard" | "tun" | "tap")
            ) && let Some(name) = interface.get("ifname").and_then(|s| s.as_str())
                && !report.tunnel_interfaces.iter().any(|s| s == name)
            {
                report.tunnel_interfaces.push(name.to_owned());
            }
        }
    }
    if !report.tunnel_interfaces.is_empty() {
        report.diagnostics.push(Diagnostic::new(
            Code::NetworkInterface,
            State::Pass,
            &format!(
                "Namespace tunnel interface(s): {}",
                report.tunnel_interfaces.join(", ")
            ),
            None,
        ));
    }
    if let Some(pair) = &state.veth_pair {
        report.host_veth = Some(pair.dest.clone());
        report.namespace_veth = Some(pair.source.clone());
        for (label, args) in [
            (
                "Host veth",
                vec!["-j", "address", "show", "dev", pair.dest.as_str()],
            ),
            (
                "Namespace veth",
                vec![
                    "-j",
                    "-n",
                    state.name.as_str(),
                    "address",
                    "show",
                    "dev",
                    pair.source.as_str(),
                ],
            ),
        ] {
            let name = if label == "Host veth" {
                &pair.dest
            } else {
                &pair.source
            };
            let text = read_command("ip", &args, deadline);
            report
                .diagnostics
                .push(link_state(label, name, text.as_deref()));
        }
        let nm = read_command(
            "nmcli",
            &[
                "--colors",
                "no",
                "--get-values",
                "GENERAL.NM-MANAGED,GENERAL.STATE",
                "device",
                "show",
                &pair.dest,
            ],
            deadline,
        );
        report
            .diagnostics
            .push(network_manager(&pair.dest, nm.as_deref()));
    }
    for family in ["-4", "-6"] {
        if skip_ipv6 && family == "-6" {
            continue;
        }
        // Default/policy routes and destination lookup are local kernel reads, including offline mode.
        for query in [
            vec!["show", "table", "all", "default"],
            vec![
                "get",
                if family == "-4" {
                    "1.1.1.1"
                } else {
                    "2606:4700:4700::1111"
                },
            ],
        ] {
            let mut args = vec!["-j", "-n", state.name.as_str(), family, "route"];
            args.extend(query.iter().copied());
            if let Some(found) =
                read_command("ip", &args, deadline).and_then(|s| routes(&s, family))
            {
                for route in &found {
                    report.diagnostics.push(route_evidence(
                        route,
                        if query[0] == "get" {
                            "Namespace route to TCP probe target"
                        } else {
                            "Namespace default route"
                        },
                    ));
                }
                report.routes.extend(found);
            }
        }
    }
    if let Some(pair) = &state.veth_pair {
        if !offline && let Some(ips) = &state.veth_pair_ips {
            for ips in ips
                .ipv4
                .iter()
                .chain(ips.ipv6.iter().filter(|_| !skip_ipv6))
            {
                for (direction, source, target, interface, inside) in [
                    (
                        "host -> namespace",
                        ips.host_ip,
                        ips.namespace_ip,
                        pair.dest.as_str(),
                        false,
                    ),
                    (
                        "namespace -> host",
                        ips.namespace_ip,
                        ips.host_ip,
                        pair.source.as_str(),
                        true,
                    ),
                ] {
                    let mut args = Vec::new();
                    if inside {
                        args.extend(["netns", "exec", &state.name]);
                    }
                    // Numeric peer targets come exclusively from root-owned state, never from client input.
                    let timeout = format!("{:.3}", timeout_ms.clamp(1, 500) as f64 / 1000.0);
                    let target_text = target.to_string();
                    let mut ping = vec![
                        if target.is_ipv4() { "-4" } else { "-6" },
                        "-n",
                        "-c",
                        "1",
                        "-W",
                        &timeout,
                        "-I",
                        interface,
                        target_text.as_str(),
                    ];
                    let result = if inside {
                        if let Some(executable) = system_tool("ping") {
                            args.push(executable.to_str().unwrap_or("/usr/bin/ping"));
                            args.append(&mut ping);
                            command_result("ip", &args, deadline)
                        } else {
                            None
                        }
                    } else {
                        command_result("ping", &ping, deadline)
                    };
                    let state = match &result {
                        Some((true, _)) => State::Pass,
                        Some((false, _)) => State::Warning,
                        None => State::Skipped,
                    };
                    report.diagnostics.push(Diagnostic::new(Code::HostLink, state,
                        &format!("{direction}: ICMP to {target} over {interface} (recorded local IP {source}) {}", match state { State::Pass => "succeeded", State::Skipped => "probe unavailable or inspection budget exhausted", _ => "did not succeed" }),
                        (state != State::Pass).then_some("ICMP can be intentionally blocked by the kill switch or host firewall; failure alone does not prove a broken veth. Compare link state, addresses and route results. --allow-host-access permits host services; doctor never changes that policy")));
                    report.link_probes.push(LinkProbe {
                        direction: direction.into(),
                        recorded_source: source,
                        target,
                        interface: interface.into(),
                        state,
                    });
                }
            }
        } else if offline {
            report.diagnostics.push(Diagnostic::new(
                Code::HostLink,
                State::Skipped,
                "--offline disables both directions of the veth ICMP probes",
                None,
            ));
        } else {
            report.diagnostics.push(Diagnostic::new(Code::HostLink, State::Skipped, "No root-owned veth addresses are available for peer probes; no targets were guessed", None));
        }
    } else {
        report.diagnostics.push(Diagnostic::new(
            Code::HostLink,
            State::Skipped,
            "No vopono veth metadata is recorded for this namespace",
            None,
        ));
    }
    Ok(report)
}

fn link_state(label: &str, name: &str, text: Option<&str>) -> Diagnostic {
    let value = text.and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    let row = value
        .as_ref()
        .and_then(|v| v.as_array())
        .and_then(|v| v.first());
    let up = row
        .and_then(|v| v.get("flags"))
        .and_then(|v| v.as_array())
        .map(|flags| flags.iter().any(|s| s == "UP"));
    let carrier = row
        .and_then(|v| v.get("operstate"))
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");
    let addresses: Vec<_> = row
        .and_then(|v| v.get("addr_info"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| {
            Some(format!(
                "{}/{}",
                v.get("local")?.as_str()?,
                v.get("prefixlen")?.as_u64()?
            ))
        })
        .collect();
    let state = match up {
        Some(true) if !matches!(carrier, "DOWN" | "LOWERLAYERDOWN" | "NOTPRESENT") => State::Pass,
        Some(_) => State::Warning,
        None => State::Skipped,
    };
    Diagnostic::new(Code::NetworkInterface, state,
        &format!("{label} {name}: administrative state {}, operational state {carrier}, addresses {}", match up { Some(true) => "UP", Some(false) => "DOWN", None => "unavailable" }, if addresses.is_empty() { "none found".into() } else { addresses.join(", ") }),
        (state != State::Pass).then_some("Inspect ip -d link and ip -n NAMESPACE -d link; check the peer, addresses and NetworkManager ownership"))
}

fn network_manager(interface: &str, text: Option<&str>) -> Diagnostic {
    let lines: Vec<_> = text.unwrap_or_default().lines().collect();
    let (state, message) = match lines.first().copied() {
        Some("yes") => (
            State::Warning,
            format!(
                "NetworkManager manages vopono host veth {interface} ({}); it may reconfigure this link",
                lines.get(1).copied().unwrap_or("state unknown")
            ),
        ),
        Some("no") => (
            State::Pass,
            format!("NetworkManager leaves vopono host veth {interface} unmanaged"),
        ),
        _ => (
            State::Skipped,
            format!(
                "NetworkManager management state of {interface} unavailable (service/tool absent or query failed)"
            ),
        ),
    };
    Diagnostic::new(Code::NetworkManager, state, &message, (state == State::Warning).then_some("Inspect nmcli device show and /etc/NetworkManager/conf.d/unmanaged.conf; vopono's veth should remain unmanaged. No device configuration is changed by doctor"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_lists_numeric_nameservers_without_comments_or_duplicates() {
        let dns = resolver(
            "/etc/resolv.conf",
            Some(
                "# generated\nnameserver 100.100.100.100 # local\nnameserver fd7a:115c:a1e0::53\nnameserver 100.100.100.100\nsearch PRIVATE.ts.net\nnameserver invalid\nnameserver fe80::1%eth0\n",
            ),
            false,
        );
        assert_eq!(
            dns.nameservers,
            ["100.100.100.100", "fd7a:115c:a1e0::53", "fe80::1%eth0"]
        );
        assert!(!serde_json::to_string(&dns).unwrap().contains("PRIVATE"));
        assert!(resolver("missing", None, false).nameservers.is_empty());
    }

    #[test]
    fn systemd_resolved_upstreams_keep_their_interface_scope() {
        let upstream = upstreams(
            "Global: 1.1.1.1\nLink 2 (eth0): 192.0.2.53 2001:db8::53\nLink 3 (tailscale0): 100.100.100.100\n",
        );
        assert_eq!(upstream.len(), 3);
        assert_eq!(upstream[1].scope, "Link 2 (eth0)");
        assert_eq!(upstream[1].nameservers, ["192.0.2.53", "2001:db8::53"]);
        assert_eq!(
            upstreams("Global: 1.1.1.1#cloudflare-dns.com")[0].nameservers,
            ["1.1.1.1#cloudflare-dns.com"]
        );
        assert!(magic_dns("FD7A:115C:A1E0::53"));
    }

    #[test]
    fn tailscale_is_informational_on_host_but_a_namespace_resolver_warning() {
        for server in ["100.100.100.100", "fd7a:115c:a1e0::53"] {
            let dns = resolver(
                "/etc/resolv.conf",
                Some(&format!("nameserver {server}")),
                true,
            );
            assert!(
                resolver_evidence(&dns, false)
                    .iter()
                    .any(|d| d.code == Code::TailscaleDns && d.state == State::Pass)
            );
            assert!(
                resolver_evidence(&dns, true)
                    .iter()
                    .any(|d| d.code == Code::TailscaleDns && d.state == State::Warning)
            );
        }
        let dns = resolver(
            "/etc/netns/vo_test/resolv.conf",
            Some("nameserver 10.8.0.1"),
            false,
        );
        assert!(
            resolver_evidence(&dns, true)
                .iter()
                .all(|d| d.code != Code::TailscaleDns)
        );
    }

    #[test]
    fn namespace_loopback_stub_is_not_confused_with_the_host_stub() {
        let dns = resolver("/etc/resolv.conf", Some("nameserver 127.0.0.53"), true);
        assert!(
            resolver_evidence(&dns, true)
                .iter()
                .any(|d| d.message.contains("loopback refers to the namespace")
                    && d.state == State::Warning)
        );
        assert!(
            resolver_evidence(&dns, false)
                .iter()
                .all(|d| d.state == State::Pass)
        );
    }

    #[test]
    fn nss_resolve_can_override_namespace_nameservers_while_files_dns_cannot() {
        let mut dns = resolver(
            "/etc/netns/vo_test/resolv.conf",
            Some("nameserver 10.8.0.1"),
            false,
        );
        dns.hosts_lookup = hosts_lookup(
            "passwd: files systemd\n# hosts: ignore\nhosts: resolve [!UNAVAIL=return] files dns # comment\n",
        );
        assert_eq!(
            dns.hosts_lookup,
            ["resolve", "[!UNAVAIL=return]", "files", "dns"]
        );
        assert!(
            resolver_evidence(&dns, true)
                .iter()
                .any(|d| d.code == Code::DnsConfiguration && d.message.contains("Unix socket"))
        );
        dns.hosts_lookup = hosts_lookup("hosts: files dns");
        assert!(
            resolver_evidence(&dns, true)
                .iter()
                .all(|d| !d.message.contains("Unix socket"))
        );
    }

    #[test]
    fn route_details_distinguish_host_default_from_policy_tunnel_routes() {
        let host = routes(
            r#"[{"dst":"default","dev":"eth0","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}]"#,
            "-4",
        )
        .unwrap();
        assert_eq!(host[0].interface, "eth0");
        assert_eq!(host[0].source.as_deref(), Some("192.0.2.2"));
        let namespace = routes(r#"[{"dst":"default","dev":"wg0","table":51820},{"dst":"1.1.1.1","dev":"wg0","prefsrc":"10.8.0.2"}]"#, "-4").unwrap();
        assert_eq!(namespace[0].table.as_deref(), Some("51820"));
        assert_eq!(namespace[1].destination, "1.1.1.1");
        assert!(routes("not json", "-4").is_none());
        assert_eq!(
            route_interface("127.0.0.1".parse().unwrap()).as_deref(),
            Some("lo")
        );
    }

    #[test]
    fn device_management_is_checked_for_the_veth_without_reconfiguring_it() {
        assert_eq!(
            network_manager("vo_test_d", Some("yes\n100 (connected externally)\n")).state,
            State::Warning
        );
        assert_eq!(
            network_manager("vo_test_d", Some("no\n10 (unmanaged)\n")).state,
            State::Pass
        );
        assert_eq!(network_manager("vo_test_d", None).state, State::Skipped);
    }

    #[test]
    fn veth_state_reports_addresses_and_detects_a_down_peer() {
        let up = r#"[{"flags":["UP","LOWER_UP"],"operstate":"UP","addr_info":[{"local":"10.200.1.1","prefixlen":24}]}]"#;
        let diagnostic = link_state("Host veth", "vo_test_d", Some(up));
        assert_eq!(diagnostic.state, State::Pass);
        assert!(diagnostic.message.contains("10.200.1.1/24"));
        assert_eq!(
            link_state(
                "Host veth",
                "vo_test_d",
                Some(&up.replace("\"operstate\":\"UP\"", "\"operstate\":\"DOWN\""))
            )
            .state,
            State::Warning
        );
        assert_eq!(
            link_state("Host veth", "vo_test_d", None).state,
            State::Skipped
        );
    }
}
