use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;

pub fn open_ports(
    netns: &NetworkNamespace,
    ports: &[u16],
    firewall: Firewall,
) -> anyhow::Result<()> {
    // IPv6 is configured on the veth pair only when it is enabled for this
    // namespace.  Use that as the source of truth so callers do not have to
    // thread the CLI flag through every protocol implementation.
    let ipv6_enabled = netns
        .veth_pair_ips
        .as_ref()
        .and_then(|ips| ips.ipv6.as_ref())
        .is_some();

    for port in ports {
        let port_str = &port.to_string();
        match firewall {
            Firewall::IpTables => {
                let iptables_cmds: &[&str] = if ipv6_enabled {
                    &["iptables", "ip6tables"]
                } else {
                    &["iptables"]
                };
                for iptables_cmd in iptables_cmds {
                    for protocol in ["tcp", "udp"] {
                        NetworkNamespace::exec(
                            &netns.name,
                            &[
                                iptables_cmd,
                                "-I",
                                "INPUT",
                                "-p",
                                protocol,
                                "--dport",
                                port_str,
                                "-j",
                                "ACCEPT",
                            ],
                        )?;
                        let ips = netns.veth_pair_ips.as_ref().and_then(|ips| {
                            if *iptables_cmd == "iptables" {
                                ips.ipv4.as_ref()
                            } else {
                                ips.ipv6.as_ref()
                            }
                        });
                        if let (Some(veth), Some(ips)) = (&netns.veth_pair, ips) {
                            // Only host-relay replies need an exception outside
                            // the VPN. A source port alone lets applications bind
                            // that port and originate arbitrary plaintext traffic.
                            NetworkNamespace::exec(
                                &netns.name,
                                &[
                                    iptables_cmd,
                                    "-I",
                                    "OUTPUT",
                                    "-o",
                                    &veth.source,
                                    "-s",
                                    &ips.namespace_ip.to_string(),
                                    "-p",
                                    protocol,
                                    "--sport",
                                    port_str,
                                    "-m",
                                    "conntrack",
                                    "--ctstate",
                                    "ESTABLISHED,RELATED",
                                    "--ctdir",
                                    "REPLY",
                                    "-j",
                                    "ACCEPT",
                                ],
                            )?;
                        }
                    }
                }
            }
            Firewall::NfTables => {
                for protocol in ["tcp", "udp"] {
                    let family = if ipv6_enabled {
                        Vec::new()
                    } else {
                        vec!["ip", "protocol", protocol]
                    };

                    let mut input = vec!["nft", "insert", "rule", "inet", &netns.name, "input"];
                    input.extend(family.iter().copied());
                    input.extend([protocol, "dport", port_str, "counter", "accept"]);
                    NetworkNamespace::exec(&netns.name, &input)?;

                    if let (Some(veth), Some(ips)) = (&netns.veth_pair, &netns.veth_pair_ips) {
                        for (family, ips) in [("ip", ips.ipv4.as_ref()), ("ip6", ips.ipv6.as_ref())]
                        {
                            if let Some(ips) = ips {
                                NetworkNamespace::exec(
                                    &netns.name,
                                    &[
                                        "nft",
                                        "insert",
                                        "rule",
                                        "inet",
                                        &netns.name,
                                        "output",
                                        "oifname",
                                        &veth.source,
                                        family,
                                        "saddr",
                                        &ips.namespace_ip.to_string(),
                                        protocol,
                                        "sport",
                                        port_str,
                                        "ct",
                                        "direction",
                                        "reply",
                                        "ct",
                                        "state",
                                        "established,related",
                                        "counter",
                                        "accept",
                                    ],
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
