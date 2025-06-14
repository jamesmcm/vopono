use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;

pub fn open_ports(
    netns: &NetworkNamespace,
    ports: &[u16],
    firewall: Firewall,
) -> anyhow::Result<()> {
    // TODO: Allow UDP port forwarding?
    // IPv6 forwarding?
    for port in ports {
        match firewall {
            Firewall::IpTables => {
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "iptables",
                        "-I",
                        "INPUT",
                        "-p",
                        "tcp",
                        "--dport",
                        &port.to_string(),
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "iptables",
                        "-I",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "--sport",
                        &port.to_string(),
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
                        &port.to_string(),
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
                        &port.to_string(),
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }
    }
    Ok(())
}
