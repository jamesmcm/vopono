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
}

fn destination(state: &NamespaceSnapshot) -> anyhow::Result<IpAddr> {
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
    crate::diagnostics::resolve_bounded(host, Duration::from_secs(1))?
        .into_iter()
        .filter(|ip| {
            !ip.is_ipv6()
                || state
                    .wireguard
                    .as_ref()
                    .and_then(|wg| wg.recovery.as_ref())
                    .is_none_or(|p| !p.disable_ipv6)
        })
        .find(|ip| super::route::lookup(*ip).is_ok())
        .context("No host route to a VPN endpoint")
}

pub fn signature(state: &NamespaceSnapshot) -> Option<(IpAddr, Vec<u8>)> {
    let ip = destination(state).ok()?;
    Some((ip, super::route::lookup(ip).ok()?.signature))
}

fn checked(name: &str, args: &[&str]) -> anyhow::Result<()> {
    ensure!(
        NetworkNamespace::exec_with_output(name, args)?
            .status
            .success(),
        "Network repair command failed"
    );
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
    let changed_underlay = if let Some(masquerade) = &mut state.host_masquerade {
        masquerade.recover_interface(host_interface.clone())?
    } else {
        false
    };
    if changed_underlay && let Some(exception) = &mut state.firewall_exception {
        exception.recover_interface(host_interface, &veth.dest)?;
    }
    if let Some(wg) = &mut state.wireguard {
        let peer = wg
            .recovery
            .as_mut()
            .context("Missing frozen WireGuard endpoint")?;
        let endpoint = SocketAddr::new(address, peer.port);
        // Recovery may follow a gateway/preferred-source change on the same
        // interface. Invalidate exactly this tunnel's old NAT tuple on every
        // repair; interface-name comparisons cannot detect those changes.
        {
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
            super::conntrack::delete_udp(
                SocketAddr::new(source.namespace_ip, port),
                SocketAddr::new(peer.address, peer.port),
            )?;
        }
        if address != peer.address {
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
            peer.address = address;
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
        checked(
            &state.name,
            &[
                &wg.executable_wg,
                "set",
                &wg.if_name,
                "peer",
                &peer.public_key,
                "persistent-keepalive",
                "25",
            ],
        )?;
    } else if let Some(openvpn) = &state.openvpn {
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
    // kill-switch REJECT rule.
    if !(disable_ipv6 && new.is_ipv6()) {
        let (command, args) = iptables_endpoint_rule_args(new, port, true);
        let mut argv = vec![command.as_str()];
        argv.extend(args.iter().map(String::as_str));
        checked(name, &argv)?;
    }
    if !(disable_ipv6 && old.is_ipv6()) {
        let (command, args) = iptables_endpoint_rule_args(old, port, false);
        let mut argv = vec![command.as_str()];
        argv.extend(args.iter().map(String::as_str));
        // The old rule may already be absent after a concurrent repair.
        let _ = NetworkNamespace::exec_with_output(name, &argv);
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
    batch.push_str(&format!("insert rule inet {name} output {family} daddr {ip} udp dport {port} accept comment \"vopono-recovery-endpoint\"\ninsert rule inet {name} input {family} saddr {ip} udp sport {port} accept comment \"vopono-recovery-endpoint\"\n"));
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

#[cfg(test)]
mod tests {
    use super::iptables_endpoint_rule_args;
    use std::net::IpAddr;

    #[test]
    fn iptables_endpoint_rules_insert_before_reject_and_delete_by_family() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        let (command, args) = iptables_endpoint_rule_args(v4, 51820, true);
        assert_eq!(command, "iptables");
        assert_eq!(&args[..3], ["-I", "OUTPUT", "1"]);
        assert!(args.windows(2).any(|pair| pair == ["-d", "192.0.2.10"]));
        assert!(args.windows(2).any(|pair| pair == ["--dport", "51820"]));

        let (command, args) = iptables_endpoint_rule_args(v6, 51820, false);
        assert_eq!(command, "ip6tables");
        assert_eq!(&args[..2], ["-D", "OUTPUT"]);
        assert!(args.windows(2).any(|pair| pair == ["-d", "2001:db8::10"]));
    }
}
