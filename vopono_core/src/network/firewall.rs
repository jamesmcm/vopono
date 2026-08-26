use super::netns::NetworkNamespace;
use anyhow::{Context, anyhow, bail};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use strum_macros::{Display, EnumIter};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Display, EnumIter)]
pub enum Firewall {
    IpTables,
    NfTables,
}

/// Fail-closed egress policy for protocols whose clients do not implement a
/// killswitch themselves (Warp, OpenConnect, OpenFortiVpn).
///
/// Once the VPN client is running and its tunnel interface is up, all
/// input/output in the namespace is dropped except loopback, the tunnel
/// interface, return traffic and the resolved VPN server endpoints (the
/// client needs those to keep its session alive). Without this policy the
/// namespace keeps a working default route through the host veth/NAT path,
/// so any tunnel failure silently bypasses the VPN.
///
/// `rules` is separated from execution so the generated commands stay unit
/// testable.
pub fn tunnel_only_killswitch_rules(
    ns_name: &str,
    firewall: Firewall,
    tunnel_iface: Option<&str>,
    endpoints: &[IpAddr],
    disable_ipv6: bool,
) -> Vec<Vec<String>> {
    let mut rules: Vec<Vec<String>> = Vec::new();
    match firewall {
        Firewall::IpTables => {
            for ipcmd in ["iptables", "ip6tables"] {
                let is_v6 = ipcmd == "ip6tables";
                if is_v6 && disable_ipv6 {
                    continue;
                }
                for chain in ["INPUT", "FORWARD", "OUTPUT"] {
                    rules.push(vec![ipcmd.into(), "-P".into(), chain.into(), "DROP".into()]);
                }
                rules.push(vec![
                    ipcmd.into(),
                    "-A".into(),
                    "INPUT".into(),
                    "-m".into(),
                    "conntrack".into(),
                    "--ctstate".into(),
                    "RELATED,ESTABLISHED".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ]);
                rules.push(vec![
                    ipcmd.into(),
                    "-A".into(),
                    "INPUT".into(),
                    "-i".into(),
                    "lo".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ]);
                if let Some(iface) = tunnel_iface {
                    rules.push(vec![
                        ipcmd.into(),
                        "-A".into(),
                        "INPUT".into(),
                        "-i".into(),
                        iface.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ]);
                }
                rules.push(vec![
                    ipcmd.into(),
                    "-A".into(),
                    "OUTPUT".into(),
                    "-o".into(),
                    "lo".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ]);
                for endpoint in endpoints {
                    if endpoint.is_ipv6() != is_v6 {
                        continue;
                    }
                    rules.push(vec![
                        ipcmd.into(),
                        "-A".into(),
                        "OUTPUT".into(),
                        "-d".into(),
                        endpoint.to_string(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ]);
                }
                rules.push(vec![
                    ipcmd.into(),
                    "-A".into(),
                    "OUTPUT".into(),
                    "-m".into(),
                    "conntrack".into(),
                    "--ctstate".into(),
                    "RELATED,ESTABLISHED".into(),
                    "-j".into(),
                    "ACCEPT".into(),
                ]);
                if let Some(iface) = tunnel_iface {
                    rules.push(vec![
                        ipcmd.into(),
                        "-A".into(),
                        "OUTPUT".into(),
                        "-o".into(),
                        iface.into(),
                        "-j".into(),
                        "ACCEPT".into(),
                    ]);
                }
                let reject_with = if is_v6 {
                    "icmp6-no-route"
                } else {
                    "icmp-net-unreachable"
                };
                rules.push(vec![
                    ipcmd.into(),
                    "-A".into(),
                    "OUTPUT".into(),
                    "-j".into(),
                    "REJECT".into(),
                    "--reject-with".into(),
                    reject_with.into(),
                ]);
            }
        }
        Firewall::NfTables => {
            // The base table (setup_nftables_firewall) already allows
            // established/related input and loopback on both directions.
            if let Some(iface) = tunnel_iface {
                rules.push(vec![
                    "nft".into(),
                    "add".into(),
                    "rule".into(),
                    "inet".into(),
                    ns_name.into(),
                    "input".into(),
                    "iifname".into(),
                    format!("\"{iface}\""),
                    "accept".into(),
                ]);
                rules.push(vec![
                    "nft".into(),
                    "add".into(),
                    "rule".into(),
                    "inet".into(),
                    ns_name.into(),
                    "output".into(),
                    "oifname".into(),
                    format!("\"{iface}\""),
                    "accept".into(),
                ]);
            }
            for endpoint in endpoints {
                if disable_ipv6 && endpoint.is_ipv6() {
                    continue;
                }
                let family = if endpoint.is_ipv4() { "ip" } else { "ip6" };
                rules.push(vec![
                    "nft".into(),
                    "add".into(),
                    "rule".into(),
                    "inet".into(),
                    ns_name.into(),
                    "output".into(),
                    family.into(),
                    "daddr".into(),
                    endpoint.to_string(),
                    "counter".into(),
                    "accept".into(),
                ]);
            }
            rules.push(vec![
                "nft".into(),
                "add".into(),
                "rule".into(),
                "inet".into(),
                ns_name.into(),
                "input".into(),
                "counter".into(),
                "drop".into(),
            ]);
            rules.push(vec![
                "nft".into(),
                "add".into(),
                "rule".into(),
                "inet".into(),
                ns_name.into(),
                "forward".into(),
                "counter".into(),
                "drop".into(),
            ]);
            rules.push(vec![
                "nft".into(),
                "add".into(),
                "rule".into(),
                "inet".into(),
                ns_name.into(),
                "output".into(),
                "counter".into(),
                "reject".into(),
                "with".into(),
                "icmpx".into(),
                "type".into(),
                "admin-prohibited".into(),
            ]);
        }
    }
    rules
}

/// Apply [`tunnel_only_killswitch_rules`] inside the namespace.
pub fn apply_tunnel_only_killswitch(
    netns: &NetworkNamespace,
    tunnel_iface: Option<&str>,
    endpoints: &[IpAddr],
    firewall: Firewall,
    disable_ipv6: bool,
) -> anyhow::Result<()> {
    info!(
        "Applying tunnel-only killswitch in {} (interface: {}, endpoints: {}, IPv6 disabled: {})",
        netns.name,
        tunnel_iface.unwrap_or("<not yet available>"),
        endpoints.len(),
        disable_ipv6
    );
    for rule in
        tunnel_only_killswitch_rules(&netns.name, firewall, tunnel_iface, endpoints, disable_ipv6)
    {
        debug!("killswitch: {}", rule.join(" "));
        let argv: Vec<&str> = rule.iter().map(String::as_str).collect();
        NetworkNamespace::exec(&netns.name, &argv)
            .with_context(|| format!("Failed to apply killswitch rule: {}", rule.join(" ")))?;
    }
    if disable_ipv6 {
        crate::network::firewall::disable_ipv6(netns, firewall)?;
    }
    Ok(())
}

/// Resolve the host from a user-supplied VPN server string (which may include
/// a scheme, userinfo, port or URL path) and apply the fail-closed
/// tunnel-only killswitch for it.
///
/// Waits briefly for the tunnel interface so its accept rules can be scoped;
/// on timeout an endpoint-only policy is applied anyway (fail closed).
pub fn apply_tunnel_only_killswitch_for_server(
    netns: &NetworkNamespace,
    firewall: Firewall,
    disable_ipv6: bool,
    server: &str,
    tunnel_interface_prefixes: &[&str],
) -> anyhow::Result<()> {
    let Some(host) = host_from_server_arg(server) else {
        bail!("Could not derive a VPN server host from '{server}' for the killswitch");
    };
    let endpoints = crate::util::hostname_to_ip(&host)
        .map_err(|e| anyhow!("Cannot resolve VPN server {host} for killswitch: {e}"))?;
    if endpoints.is_empty() {
        bail!("VPN server {host} resolved to no addresses for killswitch");
    }
    let tunnel_iface = wait_for_tunnel_interface(&netns.name, tunnel_interface_prefixes, 20)?;
    apply_tunnel_only_killswitch(
        netns,
        tunnel_iface.as_deref(),
        &endpoints,
        firewall,
        disable_ipv6,
    )
}

/// Extract a resolvable host from a user-supplied server argument which may
/// include a scheme, userinfo, port or URL path.
fn host_from_server_arg(server: &str) -> Option<String> {
    let mut rest = server.trim();
    if let Some((_, remainder)) = rest.split_once("://") {
        rest = remainder;
    }
    rest = rest.split('/').next()?;
    if let Some((_, remainder)) = rest.rsplit_once('@') {
        rest = remainder;
    }
    if rest.starts_with('[') {
        // Bracketed IPv6 literal, optionally followed by :port
        let end = rest.find(']')?;
        let host = rest.get(1..end)?;
        return (!host.is_empty()).then(|| host.to_string());
    }
    match rest.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() {
                return None;
            }
            match port.parse::<u16>() {
                // host:port
                Ok(_) if !host.contains(':') => (!host.is_empty()).then(|| host.to_string()),
                // Unbracketed IPv6 literal whose last segment looks like a
                // port (e.g. `2001:db8::1`) - keep the whole address.
                Ok(_) => (!rest.is_empty()).then(|| rest.to_string()),
                // Unbracketed IPv6 literal with a non-numeric tail.
                Err(_) => (!rest.is_empty()).then(|| rest.to_string()),
            }
        }
        None => (!rest.is_empty()).then(|| rest.to_string()),
    }
}

/// Parse `ip -o link` output, returning the first interface that is neither
/// loopback nor a vopono-created veth (names prefixed `vo_`).
pub fn parse_tunnel_interface_from_ip_link(
    output: &str,
    expected_prefixes: &[&str],
) -> Option<String> {
    for line in output.lines() {
        let mut parts = line.split(':');
        let _index = parts.next()?;
        let name = parts.next()?.trim().split('@').next()?;
        if name == "lo" || name.starts_with("vo_") {
            continue;
        }
        if expected_prefixes
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Poll the namespace until a non-veth interface appears (the tunnel device),
/// giving VPN clients time to register and connect.
///
/// Returns `Ok(None)` on timeout so callers can still apply a stricter
/// endpoint-only policy instead of failing open.
pub fn wait_for_tunnel_interface(
    netns_name: &str,
    expected_prefixes: &[&str],
    timeout_secs: u64,
) -> anyhow::Result<Option<String>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        let output = NetworkNamespace::exec_with_output(netns_name, &["ip", "-o", "link"])?;
        if output.status.success()
            && let Some(iface) = parse_tunnel_interface_from_ip_link(
                &String::from_utf8_lossy(&output.stdout),
                expected_prefixes,
            )
        {
            info!("Detected tunnel interface {iface} in {netns_name}");
            return Ok(Some(iface));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    warn!(
        "Timed out waiting for a tunnel interface in {netns_name}; applying endpoint-only killswitch"
    );
    Ok(None)
}

pub fn disable_ipv6(netns: &NetworkNamespace, firewall: Firewall) -> anyhow::Result<()> {
    match firewall {
        Firewall::IpTables => {
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "INPUT", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "INPUT", "-j", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "FORWARD", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "FORWARD", "-j", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "OUTPUT", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "OUTPUT", "-j", "DROP"])?;
        }
        Firewall::NfTables => {
            NetworkNamespace::exec(&netns.name, &["nft", "add", "table", "ip6", &netns.name])?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_input",
                    "{ type filter hook input priority -1 ; policy drop; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_output",
                    "{ type filter hook output priority -1 ; policy drop; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_forward",
                    "{ type filter hook forward priority -1 ; policy drop; }",
                ],
            )?;
        }
    }
    Ok(())
}

/// Tag return traffic entering the namespace through the host veth with the
/// Wireguard fwmark. These packets are the only tunnel-related traffic that
/// arrives outside the tunnel device; without the tag their reverse-path
/// lookup follows the fwmark policy routing table back to the tunnel device
/// instead of the ingress interface, so hosts enforcing strict reverse-path
/// filtering (rp_filter=1) silently drop them. Requires
/// net.ipv4.conf.*.src_valid_mark=1 (set during Wireguard setup) for the
/// kernel to honour the mark during source validation. Rules live inside the
/// namespace and are discarded with it.
pub fn tag_return_traffic(
    netns: &NetworkNamespace,
    ingress_iface: &str,
    fwmark: &str,
    firewall: Firewall,
) -> anyhow::Result<()> {
    debug!(
        "Tagging return traffic on {ingress_iface} with fwmark {fwmark} in netns {}",
        netns.name
    );
    match firewall {
        Firewall::IpTables => NetworkNamespace::exec(
            &netns.name,
            &[
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-i",
                ingress_iface,
                "-j",
                "MARK",
                "--set-xmark",
                fwmark,
            ],
        )?,
        Firewall::NfTables => {
            NetworkNamespace::exec(&netns.name, &["nft", "add", "table", "ip", &netns.name])?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    &netns.name,
                    "prerouting_mark",
                    "{ type filter hook prerouting priority -150 ; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    &netns.name,
                    "prerouting_mark",
                    &format!("iifname \"{ingress_iface}\" meta mark set {fwmark}"),
                ],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn iptables_tunnel_rules_fail_closed() {
        let endpoints = vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V6("2001:db8::53".parse::<Ipv6Addr>().unwrap()),
        ];
        let rules = tunnel_only_killswitch_rules(
            "vo_t",
            Firewall::IpTables,
            Some("tun0"),
            &endpoints,
            false,
        );
        let joined: Vec<String> = rules.iter().map(|r| r.join(" ")).collect();
        for policy in [
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT DROP",
        ] {
            assert!(joined.iter().any(|r| *r == policy), "missing {policy}");
        }
        assert!(
            joined
                .iter()
                .any(|r| r == "iptables -A OUTPUT -d 198.51.100.7 -j ACCEPT")
        );
        assert!(
            joined
                .iter()
                .any(|r| r == "ip6tables -A OUTPUT -d 2001:db8::53 -j ACCEPT")
        );
        assert!(
            joined
                .iter()
                .any(|r| r == "iptables -A OUTPUT -o tun0 -j ACCEPT")
        );
        assert!(
            joined
                .iter()
                .any(|r| r.starts_with("iptables -A OUTPUT -j REJECT")),
            "final output rule must reject"
        );
    }

    #[test]
    fn iptables_rules_skip_ipv6_when_disabled() {
        let endpoints = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))];
        let rules =
            tunnel_only_killswitch_rules("vo_t", Firewall::IpTables, None, &endpoints, true);
        assert!(rules.iter().all(|r| r[0] != "ip6tables"));
    }

    #[test]
    fn nftables_tunnel_rules_drop_after_accepts() {
        let endpoints = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))];
        let rules = tunnel_only_killswitch_rules(
            "vo_t",
            Firewall::NfTables,
            Some("ppp0"),
            &endpoints,
            false,
        );
        let joined: Vec<String> = rules.iter().map(|r| r.join(" ")).collect();
        assert!(
            joined
                .iter()
                .any(|r| r == "nft add rule inet vo_t input iifname \"ppp0\" accept")
        );
        assert!(
            joined
                .iter()
                .any(|r| r == "nft add rule inet vo_t output ip daddr 198.51.100.7 counter accept")
        );
        let last_input = joined
            .iter()
            .rev()
            .find(|r| r.contains(" inet vo_t input "))
            .unwrap();
        assert!(
            last_input.ends_with(" counter drop"),
            "input must end in drop: {last_input}"
        );
        let last_output = joined
            .iter()
            .rev()
            .find(|r| r.contains(" inet vo_t output "))
            .unwrap();
        assert!(
            last_output.ends_with("admin-prohibited"),
            "output must end in reject: {last_output}"
        );
        assert!(
            joined
                .iter()
                .any(|r| r == "nft add rule inet vo_t forward counter drop")
        );
    }

    #[test]
    fn parses_tunnel_interface_from_ip_link_output() {
        let sample = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: vo_x_s@vo_x_d: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...\n5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 ...";
        assert_eq!(
            parse_tunnel_interface_from_ip_link(sample, &["tun"]),
            Some("tun0".to_string())
        );
        assert_eq!(parse_tunnel_interface_from_ip_link(sample, &["ppp"]), None);
        assert_eq!(parse_tunnel_interface_from_ip_link("", &["tun"]), None);
    }

    #[test]
    fn extracts_host_from_server_arguments() {
        use super::host_from_server_arg;
        assert_eq!(
            host_from_server_arg("vpn.example.com").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            host_from_server_arg("https://vpn.example.com:443/some/path").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            host_from_server_arg("user@vpn.example.com").as_deref(),
            Some("vpn.example.com")
        );
        assert_eq!(
            host_from_server_arg("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            host_from_server_arg("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(host_from_server_arg(""), None);
        assert_eq!(host_from_server_arg("vpn.example.com:"), None);
        assert_eq!(
            host_from_server_arg("vpn.example.com:notaport").as_deref(),
            Some("vpn.example.com:notaport")
        );
    }
}
