//! Repair a tunnel's underlay without removing its namespace or kill switch.
use super::netns::{NamespaceSnapshot, NetworkNamespace};
use super::network_interface::NetworkInterface;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub host: String,
    pub port: u16,
    pub public_key: String,
    pub address: IpAddr,
    pub disable_ipv6: bool,
    #[serde(default)]
    pub persistent_keepalive: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<ipnet::IpNet>,
}

fn select_recovery_destination(
    candidates: &[IpAddr],
    current: Option<IpAddr>,
    ipv6_disabled: bool,
    mut is_routable: impl FnMut(IpAddr) -> bool,
) -> Option<IpAddr> {
    let routable: Vec<IpAddr> = candidates
        .iter()
        .copied()
        .filter(|ip| !ip.is_ipv6() || !ipv6_disabled)
        .filter(|ip| is_routable(*ip))
        .collect();
    if let Some(current) = current
        && routable.contains(&current)
    {
        return Some(current);
    }
    routable
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| routable.first().copied())
}

fn peer_needs_bypass_route(address: IpAddr, allowed_ips: &[ipnet::IpNet]) -> bool {
    if address.is_loopback() {
        return false;
    }
    if allowed_ips.is_empty() {
        return true;
    }
    allowed_ips.iter().any(|net| net.contains(&address))
}

fn destination(state: &NamespaceSnapshot) -> anyhow::Result<IpAddr> {
    if let Some(address) = state.openvpn.as_ref().and_then(|vpn| vpn.recovery_address) {
        return Ok(address);
    }
    let current = state
        .wireguard
        .as_ref()
        .and_then(|wg| wg.recovery.as_ref().map(|p| p.address));
    let host = state
        .wireguard
        .as_ref()
        .and_then(|wg| wg.recovery.as_ref().map(|p| p.host.as_str()))
        .or_else(|| {
            state
                .openvpn
                .as_ref()
                .and_then(|vpn| vpn.recovery_host.as_deref())
        })
        .context("Protocol has no frozen endpoint recovery metadata")?;
    let ipv6_disabled = state
        .wireguard
        .as_ref()
        .and_then(|wg| wg.recovery.as_ref())
        .is_some_and(|p| p.disable_ipv6)
        || state
            .veth_pair_ips
            .as_ref()
            .is_some_and(|ips| ips.ipv6.is_none());
    let resolved = crate::diagnostics::resolve_bounded(host, Duration::from_secs(1))?;
    select_recovery_destination(&resolved, current, ipv6_disabled, |ip| {
        super::route::lookup(ip).is_ok()
    })
    .context("No host route to a VPN endpoint")
}

pub fn signature(state: &NamespaceSnapshot) -> Option<(IpAddr, Vec<u8>)> {
    let ip = destination(state).ok()?;
    Some((ip, super::route::lookup(ip).ok()?.signature))
}

fn checked(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = NetworkNamespace::exec_with_output(name, args)
        .with_context(|| format!("Could not run {} during network repair", args[0]))?;
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(512)
            .collect();
        anyhow::bail!(
            "{} failed during network repair in {name} ({}): {stderr}",
            args[0],
            output.status
        );
    }
    Ok(())
}

fn interface(index: u32) -> anyhow::Result<String> {
    let mut name = [0i8; libc::IF_NAMESIZE];
    ensure!(
        !unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null(),
        "Host route interface disappeared"
    );
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()?
        .to_owned())
}

pub fn repair(state: &mut NamespaceSnapshot) -> anyhow::Result<()> {
    ensure!(
        state.trojan.is_none(),
        "Automatic proxy-tunnel recovery is unsupported"
    );
    let address = destination(state)?;
    let host_interface =
        NetworkInterface::new(interface(super::route::lookup(address)?.interface_index)?)?;
    let veth = state.veth_pair.as_ref().context("Missing namespace veth")?;
    if let Some(masquerade) = &mut state.host_masquerade {
        masquerade.recover_interface(host_interface.clone())?;
    }
    if let Some(exception) = &mut state.firewall_exception {
        exception.recover_interface(host_interface, &veth.dest)?;
    }
    if let Some(wg) = &mut state.wireguard {
        let peer = wg
            .recovery
            .as_mut()
            .context("Missing frozen WireGuard endpoint")?;
        let endpoint = SocketAddr::new(address, peer.port);
        // A new destination already uses a different conntrack tuple. For an
        // unchanged destination, discard the old mapping after an underlay change.
        if address == peer.address {
            let output = NetworkNamespace::exec_with_output(
                &state.name,
                &[&wg.executable_wg, "show", &wg.if_name, "listen-port"],
            )?;
            ensure!(
                output.status.success(),
                "Could not inspect WireGuard UDP socket"
            );
            let port = std::str::from_utf8(&output.stdout)?.trim().parse::<u16>()?;
            let source = if peer.address.is_ipv4() {
                state
                    .veth_pair_ips
                    .as_ref()
                    .and_then(|ips| ips.ipv4.as_ref())
            } else {
                state
                    .veth_pair_ips
                    .as_ref()
                    .and_then(|ips| ips.ipv6.as_ref())
            }
            .context("Missing tunnel underlay source")?;
            if let Err(error) = super::conntrack::delete_udp(
                SocketAddr::new(source.namespace_ip, port),
                SocketAddr::new(peer.address, peer.port),
            ) {
                // Some kernels do not expose conntrack deletion. A new local UDP
                // port makes a fresh mapping without touching firewall policy.
                checked(&state.name, &[&wg.executable_wg, "set", &wg.if_name, "listen-port", "0"])
                    .with_context(|| format!("Could not renew the WireGuard UDP socket after conntrack deletion failed: {error:#}"))?;
                log::info!(
                    "Renewed the WireGuard UDP socket in {} after conntrack deletion failed: {error:#}",
                    state.name
                );
            }
        }
        if address != peer.address {
            if peer_needs_bypass_route(address, &peer.allowed_ips) {
                let family = if address.is_ipv4() { "-4" } else { "-6" };
                let gateway = if address.is_ipv4() {
                    state
                        .veth_pair_ips
                        .as_ref()
                        .and_then(|ips| ips.ipv4.as_ref())
                } else {
                    state
                        .veth_pair_ips
                        .as_ref()
                        .and_then(|ips| ips.ipv6.as_ref())
                }
                .context("Endpoint address family has no veth route")?;
                checked(
                    &state.name,
                    &[
                        "ip",
                        family,
                        "route",
                        "replace",
                        &address.to_string(),
                        "via",
                        &gateway.host_ip.to_string(),
                        "dev",
                        &veth.source,
                    ],
                )?;
            }
            match state.firewall {
                super::firewall::Firewall::NfTables => {
                    endpoint_rule(&state.name, address, peer.port)?;
                }
                super::firewall::Firewall::IpTables => {
                    iptables_endpoint_rules(
                        &state.name,
                        peer.address,
                        address,
                        peer.port,
                        peer.disable_ipv6,
                    )?;
                }
            }
            // Remove the previous endpoint bypass route once the new route and
            // firewall rules are active so DNS rotation does not accumulate routes.
            if peer_needs_bypass_route(peer.address, &peer.allowed_ips) {
                let old_family = if peer.address.is_ipv4() { "-4" } else { "-6" };
                let _ = NetworkNamespace::exec_with_output(
                    &state.name,
                    &[
                        "ip",
                        old_family,
                        "route",
                        "del",
                        &peer.address.to_string(),
                        "dev",
                        &veth.source,
                    ],
                );
            }
        }
        // Reinstall even an unchanged destination: WireGuard must discard the
        // cached source address/route after the host underlay has changed.
        checked(
            &state.name,
            &[
                &wg.executable_wg,
                "set",
                &wg.if_name,
                "peer",
                &peer.public_key,
                "endpoint",
                &endpoint.to_string(),
            ],
        )?;
        let keepalive = peer.persistent_keepalive.as_deref().unwrap_or("25");
        checked(
            &state.name,
            &[
                &wg.executable_wg,
                "set",
                &wg.if_name,
                "peer",
                &peer.public_key,
                "persistent-keepalive",
                keepalive,
            ],
        )?;
        peer.address = address;
    } else if let Some(openvpn) = &state.openvpn {
        // Clear any stale host UDP conntrack entry for the OpenVPN remote before
        // restarting the child, matching WireGuard recovery on underlay changes.
        if openvpn.recovery_udp
            && let (Some(address), Some(port)) = (openvpn.recovery_address, openvpn.recovery_port)
            && let Some(veth_ips) = &state.veth_pair_ips
        {
            let ns_ip = if address.is_ipv4() {
                veth_ips.ipv4.as_ref().map(|pair| pair.namespace_ip)
            } else {
                veth_ips.ipv6.as_ref().map(|pair| pair.namespace_ip)
            };
            if let Some(ns_ip) = ns_ip {
                let remote = SocketAddr::new(address, port);
                if let Ok(output) =
                    NetworkNamespace::exec_with_output(&state.name, &["ss", "-Hanup"])
                    && output.status.success()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for local_port in parse_openvpn_udp_local_ports(&stdout, remote) {
                        let _ = super::conntrack::delete_udp(
                            SocketAddr::new(ns_ip, local_port),
                            remote,
                        );
                    }
                }
            }
        }
        // OpenVPN restarts from the frozen configuration. Automatic endpoint
        // DNS rotation currently only updates WireGuard kill-switch rules;
        // OpenVPN profiles that rotate to a new IP may require an explicit
        // reconnect after the old endpoint is retired.
        openvpn.request_restart()?;
    } else {
        anyhow::bail!("Protocol does not support automatic recovery");
    }
    Ok(())
}

fn iptables_endpoint_rule_args(ip: IpAddr, port: u16, insert: bool) -> (String, Vec<String>) {
    let command = if ip.is_ipv4() {
        "iptables"
    } else {
        "ip6tables"
    };
    let mut args = vec![
        if insert { "-I" } else { "-D" }.to_string(),
        "OUTPUT".to_string(),
    ];
    if insert {
        // Insert ahead of the kill-switch's final REJECT rule.
        args.push("1".to_string());
    }
    args.extend(
        [
            "-p",
            "udp",
            "-m",
            "udp",
            "-d",
            &ip.to_string(),
            "--dport",
            &port.to_string(),
            "-m",
            "mark",
            "--mark",
            super::wireguard::WIREGUARD_FWMARK,
            "-j",
            "ACCEPT",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    (command.to_string(), args)
}

fn iptables_endpoint_rules(
    name: &str,
    old: IpAddr,
    new: IpAddr,
    port: u16,
    disable_ipv6: bool,
) -> anyhow::Result<()> {
    if old == new {
        return Ok(());
    }
    // Add the new exception before removing the old one so a failure cannot
    // leave the tunnel with no endpoint permission. Insert ahead of the final
    // kill-switch REJECT/DROP rules.
    if !(disable_ipv6 && new.is_ipv6()) {
        let (command, args) = iptables_endpoint_rule_args(new, port, true);
        let mut argv = vec![command.as_str()];
        argv.extend(args.iter().map(String::as_str));
        checked(name, &argv)?;
        checked(
            name,
            &[
                command.as_str(),
                "-I",
                "INPUT",
                "1",
                "-p",
                "udp",
                "-m",
                "udp",
                "-s",
                &new.to_string(),
                "--sport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
        )?;
    }
    if !(disable_ipv6 && old.is_ipv6()) {
        let (command, args) = iptables_endpoint_rule_args(old, port, false);
        let mut argv = vec![command.as_str()];
        argv.extend(args.iter().map(String::as_str));
        // The old rule may already be absent after a concurrent repair.
        let _ = NetworkNamespace::exec_with_output(name, &argv);
        let _ = NetworkNamespace::exec_with_output(
            name,
            &[
                command.as_str(),
                "-D",
                "INPUT",
                "-p",
                "udp",
                "-m",
                "udp",
                "-s",
                &old.to_string(),
                "--sport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
        );
    }
    Ok(())
}

fn endpoint_rule(name: &str, ip: IpAddr, port: u16) -> anyhow::Result<()> {
    // Insert narrow exceptions ahead of the existing reject rule; the tunnel
    // policy itself remains continuously installed. Remove prior repair rules
    // in the same nft transaction to bound DNS-rotation state.
    use std::io::Write;
    let family = if ip.is_ipv4() { "ip" } else { "ip6" };
    let output =
        NetworkNamespace::exec_with_output(name, &["nft", "-j", "list", "table", "inet", name])?;
    ensure!(
        output.status.success(),
        "Could not inspect endpoint firewall"
    );
    let table: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let mut batch = String::new();
    for item in table["nftables"]
        .as_array()
        .context("Invalid nftables result")?
    {
        if let Some(rule) = item.get("rule")
            && rule["comment"] == "vopono-recovery-endpoint"
        {
            let chain = rule["chain"].as_str().context("Missing chain")?;
            ensure!(
                ["input", "output"].contains(&chain),
                "Invalid endpoint rule chain"
            );
            batch.push_str(&format!(
                "delete rule inet {name} {chain} handle {}\n",
                rule["handle"].as_u64().context("Missing rule handle")?
            ));
        }
    }
    let mark = super::wireguard::WIREGUARD_FWMARK;
    batch.push_str(&format!("insert rule inet {name} output meta mark {mark} {family} daddr {ip} udp dport {port} accept comment \"vopono-recovery-endpoint\"\ninsert rule inet {name} input {family} saddr {ip} udp sport {port} accept comment \"vopono-recovery-endpoint\"\n"));
    let mut file = tempfile::NamedTempFile::new_in("/run")?;
    file.write_all(batch.as_bytes())?;
    checked(
        name,
        &[
            "nft",
            "-f",
            file.path()
                .to_str()
                .context("Invalid firewall runtime path")?,
        ],
    )
}

/// Extract local UDP ports from `ss -Hanup` output that either connect directly
/// to `remote` or are unconnected OpenVPN sockets (`UNCONN` with peer `*:*`).
fn parse_openvpn_udp_local_ports(stdout: &str, remote: SocketAddr) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // `ss -Hanup` columns: State, Recv-Q, Send-Q, Local, Peer, [Process...]
        let (Some(state), Some(local), Some(peer)) = (fields.first(), fields.get(3), fields.get(4))
        else {
            continue;
        };
        let connected_match = peer.parse::<SocketAddr>().ok() == Some(remote);
        let unconnected_openvpn = *state == "UNCONN"
            && (*peer == "*:*" || *peer == "0.0.0.0:*" || *peer == "[::]:*" || *peer == ":::*")
            && fields[5..]
                .iter()
                .any(|field| field.contains("\"openvpn\""));
        if (connected_match || unconnected_openvpn)
            && let Some(local_port) = local
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
            && !ports.contains(&local_port)
        {
            ports.push(local_port);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::{
        iptables_endpoint_rule_args, parse_openvpn_udp_local_ports, peer_needs_bypass_route,
        select_recovery_destination,
    };
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn recovery_prefers_current_address_then_ipv4_over_ipv6() {
        let v4_a: IpAddr = "198.51.100.1".parse().unwrap();
        let v4_b: IpAddr = "198.51.100.2".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();

        // RFC 6724 order puts IPv6 first; keep current IPv4 when still routable.
        assert_eq!(
            select_recovery_destination(&[v6, v4_b, v4_a], Some(v4_a), false, |_| true),
            Some(v4_a)
        );
        // When current is gone, still prefer IPv4 over IPv6.
        assert_eq!(
            select_recovery_destination(&[v6, v4_b], Some(v4_a), false, |_| true),
            Some(v4_b)
        );
        // Fall back to IPv6 when no IPv4 is routable and IPv6 is enabled.
        assert_eq!(
            select_recovery_destination(&[v6], Some(v4_a), false, |_| true),
            Some(v6)
        );
        assert_eq!(
            select_recovery_destination(&[v6], Some(v4_a), true, |_| true),
            None
        );
    }

    #[test]
    fn bypass_route_skips_loopback_and_unmatched_split_tunnel() {
        let split: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(!peer_needs_bypass_route("127.0.0.1".parse().unwrap(), &[]));
        assert!(!peer_needs_bypass_route(
            "198.51.100.7".parse().unwrap(),
            &split
        ));
        assert!(peer_needs_bypass_route("10.1.2.3".parse().unwrap(), &split));
        assert!(peer_needs_bypass_route(
            "198.51.100.7".parse().unwrap(),
            &[]
        ));
    }

    #[test]
    fn parses_connected_and_unconnected_openvpn_udp_ports() {
        let remote: SocketAddr = "198.51.100.7:1194".parse().unwrap();
        let sample = "\
UNCONN 0 0 0.0.0.0:45123 0.0.0.0:* users:((\"openvpn\",pid=123,fd=5))\n\
ESTAB  0 0 10.200.1.2:45124 198.51.100.7:1194 users:((\"openvpn\",pid=124,fd=6))\n\
UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"other\",pid=125,fd=7))\n";
        assert_eq!(
            parse_openvpn_udp_local_ports(sample, remote),
            vec![45123, 45124]
        );
    }

    #[test]
    fn iptables_endpoint_rules_insert_before_reject_and_delete_by_family() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        let (command, args) = iptables_endpoint_rule_args(v4, 51820, true);
        assert_eq!(command, "iptables");
        assert_eq!(&args[..3], ["-I", "OUTPUT", "1"]);
        assert!(args.windows(2).any(|pair| pair == ["-d", "192.0.2.10"]));
        assert!(args.windows(2).any(|pair| pair == ["--dport", "51820"]));
        assert!(args.windows(2).any(|pair| pair == ["--mark", "51820"]));

        let (command, args) = iptables_endpoint_rule_args(v6, 51820, false);
        assert_eq!(command, "ip6tables");
        assert_eq!(&args[..2], ["-D", "OUTPUT"]);
        assert!(args.windows(2).any(|pair| pair == ["-d", "2001:db8::10"]));
    }
}
