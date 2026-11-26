//! Periodic read-only monitor evidence shared with doctor. Expensive scans have
//! one shared deadline; health never authorizes changes to host DNS or policy.
use super::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State, host, topology};
use crate::network::netns::NamespaceSnapshot;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Decide which address families are configured when monitoring starts. Do not
/// drop an expected family merely because it later becomes unreachable.
pub fn skip_ipv6(state: &NamespaceSnapshot) -> bool {
    if state
        .veth_pair_ips
        .as_ref()
        .is_none_or(|ips| ips.ipv6.is_none())
    {
        return true;
    }
    skip_tunnel_family(state, true)
}

pub fn skip_ipv4(state: &NamespaceSnapshot) -> bool {
    skip_tunnel_family(state, false)
}

fn skip_tunnel_family(state: &NamespaceSnapshot, ipv6: bool) -> bool {
    if let Some(wg) = &state.wireguard {
        return !wg.interface_addresses.iter().any(|ip| ip.is_ipv6() == ipv6);
    }
    if state.openvpn.is_some() {
        let text = host::read_command(
            "ip",
            &[
                "-j",
                if ipv6 { "-6" } else { "-4" },
                "-n",
                &state.name,
                "address",
                "show",
            ],
            Instant::now() + Duration::from_millis(750),
        );
        if let Some(value) = text.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            && let Some(interfaces) = value.as_array()
        {
            return !interfaces.iter().any(|interface| {
                let name = interface
                    .get("ifname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                name != "lo"
                    && state.veth_pair.as_ref().is_none_or(|v| name != v.source)
                    && interface
                        .get("addr_info")
                        .and_then(|v| v.as_array())
                        .is_some_and(|addresses| {
                            addresses
                                .iter()
                                .any(|v| v.get("scope").and_then(|v| v.as_str()) == Some("global"))
                        })
            });
        }
    }
    false
}

pub fn collect(
    state: Option<&NamespaceSnapshot>,
    skip_ipv6: bool,
    budget: Duration,
) -> Vec<Diagnostic> {
    let deadline = Instant::now() + budget;
    let mut diagnostics = Vec::new();
    if let Some(left) = deadline.checked_duration_since(Instant::now()) {
        diagnostics.push(host::host_dns(super::resolve_bounded(
            "one.one.one.one",
            left.min(Duration::from_millis(500)),
        )));
    }
    if let Some(state) = state {
        if let Some(hostname) = state
            .wireguard
            .as_ref()
            .and_then(|wg| wg.recovery.as_ref().map(|p| p.host.as_str()))
            .or_else(|| {
                state
                    .openvpn
                    .as_ref()
                    .and_then(|vpn| vpn.recovery_host.as_deref())
            })
            && hostname.parse::<std::net::IpAddr>().is_err()
            && let Some(left) = deadline.checked_duration_since(Instant::now())
        {
            match super::resolve_bounded(hostname, left.min(Duration::from_millis(500))) {
                Ok(_) => diagnostics.push(Diagnostic::new(Code::EndpointDns, State::Pass, &format!("Host can resolve the frozen VPN endpoint {hostname}; reachability and authentication require the live tunnel probes"), None)),
                Err(_) => diagnostics.push(Diagnostic::new(Code::EndpointDns, State::Warning, "Host cannot resolve the frozen VPN endpoint; an existing IP-based tunnel can still work, but reconnection may fail", Some("Inspect host DNS or regenerate a provider IP-address profile; namespace DNS does not bootstrap the VPN endpoint"))),
            }
        }
        match topology::namespace_network_until(state, false, skip_ipv6, 250, deadline) {
            Ok(network) => diagnostics.extend(network.diagnostics),
            Err(_) => diagnostics.push(Diagnostic::new(
                Code::ProbeUnavailable,
                State::Skipped,
                "Namespace topology evidence unavailable",
                Some("Run vopono doctor for a fresh report"),
            )),
        }
    }
    diagnostics.extend(host::inspect_until(skip_ipv6, deadline));
    diagnostics.extend(topology::host_network_until(skip_ipv6, deadline).diagnostics);
    bounded(diagnostics)
}

/// Telemetry has a 64 KiB reader limit. Retain actionable evidence first and
/// cap both fields and serialized size so a large ruleset/NSS file cannot hide it.
pub fn bounded(mut diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    diagnostics.sort_by_key(|d| match d.state {
        State::Fail => 0,
        State::Warning => 1,
        State::Skipped => 2,
        State::Pass => 3,
    });
    let mut omitted = diagnostics.len() > 48;
    diagnostics.truncate(48);
    for diagnostic in &mut diagnostics {
        truncate(&mut diagnostic.message, 768);
        if let Some(action) = &mut diagnostic.action {
            truncate(action, 384);
        }
    }
    while serde_json::to_vec(&diagnostics).is_ok_and(|s| s.len() > 48 * 1024) {
        diagnostics.pop();
        omitted = true;
    }
    if omitted {
        diagnostics.push(Diagnostic::new(
            Code::ProbeUnavailable,
            State::Warning,
            "Additional monitoring evidence was omitted to bound telemetry size",
            Some("Run vopono doctor for a full report"),
        ));
    }
    diagnostics
}

fn truncate(text: &mut String, limit: usize) {
    if text.len() > limit {
        let mut end = limit.saturating_sub(3);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
}

pub fn handshake_age(name: &str, executable: &str, interface: &str) -> Option<u64> {
    crate::network::netns::validate_netns_name(name).ok()?;
    let executable = host::system_tool(executable)?;
    let output = host::read_command(
        "ip",
        &[
            "netns",
            "exec",
            name,
            executable.to_str()?,
            "show",
            interface,
            "latest-handshakes",
        ],
        Instant::now() + Duration::from_millis(750),
    )?;
    let last = output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .max()?;
    Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs()
            .saturating_sub(last),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_tunnel_addresses_determine_required_families() {
        let ns =
            crate::network::netns::NetworkNamespace::attach_unmanaged("monitor_family_test".into())
                .unwrap();
        let mut state = ns.snapshot().unwrap();
        for (addresses, skip4, skip6) in [
            (vec!["10.66.0.2"], false, true),
            (vec!["fd66::2"], true, false),
            (vec!["10.66.0.2", "fd66::2"], false, false),
        ] {
            state.wireguard = Some(
                serde_json::from_value(serde_json::json!({
                    "executable_wg":"wg", "ip_link_type":"wireguard", "ns_name":state.name,
                    "config_file":"/unused", "firewall":"NfTables", "if_name":"wg0",
                    "interface_addresses":addresses,
                }))
                .unwrap(),
            );
            assert_eq!(skip_tunnel_family(&state, false), skip4);
            assert_eq!(skip_tunnel_family(&state, true), skip6);
        }
    }

    #[test]
    fn telemetry_is_bounded_and_preserves_actionable_states_first() {
        let diagnostics = (0..200)
            .map(|n| {
                Diagnostic::new(
                    Code::HostFirewall,
                    if n == 199 { State::Fail } else { State::Pass },
                    &"\"é\n".repeat(2000),
                    Some(&"x".repeat(2000)),
                )
            })
            .collect();
        let result = bounded(diagnostics);
        assert_eq!(result[0].state, State::Fail);
        assert!(serde_json::to_vec(&result).unwrap().len() < 49 * 1024);
        assert!(result.iter().any(|d| d.code == Code::ProbeUnavailable));
    }
}
