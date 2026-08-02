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
                        NetworkNamespace::exec(
                            &netns.name,
                            &[
                                iptables_cmd,
                                "-I",
                                "OUTPUT",
                                "-p",
                                protocol,
                                "--sport",
                                port_str,
                                "-j",
                                "ACCEPT",
                            ],
                        )?;
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

                    let mut output = vec!["nft", "insert", "rule", "inet", &netns.name, "output"];
                    output.extend(family.iter().copied());
                    output.extend([protocol, "sport", port_str, "counter", "accept"]);
                    NetworkNamespace::exec(&netns.name, &output)?;
                }
            }
        }
    }
    Ok(())
}
