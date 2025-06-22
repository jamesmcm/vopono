use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;

// TODO: Should we accept disable_ipv6 here and not try ip6tables if disabled
pub fn open_ports(
    netns: &NetworkNamespace,
    ports: &[u16],
    firewall: Firewall,
) -> anyhow::Result<()> {
    // TODO: Allow UDP port opening?
    for port in ports {
        let port_str = &port.to_string();
        match firewall {
            Firewall::IpTables => {
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "iptables", "-I", "INPUT", "-p", "tcp", "--dport", port_str, "-j", "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", port_str, "-j",
                        "ACCEPT",
                    ],
                )?;

                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "ip6tables",
                        "-I",
                        "INPUT",
                        "-p",
                        "tcp",
                        "--dport",
                        port_str,
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "ip6tables",
                        "-I",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "--sport",
                        port_str,
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            Firewall::NfTables => {
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "nft",
                        "insert",
                        "rule",
                        "inet",
                        &netns.name,
                        "input",
                        "tcp",
                        "dport",
                        port_str,
                        "counter",
                        "accept",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "nft",
                        "insert",
                        "rule",
                        "inet",
                        &netns.name,
                        "output",
                        "tcp",
                        "sport",
                        port_str,
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }
    }
    Ok(())
}
