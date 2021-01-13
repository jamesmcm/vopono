use crate::firewall::Firewall;
use crate::netns::NetworkNamespace;

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
                netns.exec(&[
                    "iptables",
                    "-I",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ])?;
                netns.exec(&[
                    "iptables",
                    "-I",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--sport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ])?;
            }
            Firewall::NfTables => {
                netns.exec(&["nft", "add", "table", "inet", &netns.name])?;
                netns.exec(&[
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    &netns.name,
                    "input",
                    "{ type filter hook input priority 100 ; }",
                ])?;
                netns.exec(&[
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
                ])?;
                netns.exec(&[
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    &netns.name,
                    "output",
                    "{ type filter hook output priority 100 ; }",
                ])?;
                netns.exec(&[
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
                ])?;
            }
        }
    }
    Ok(())
}
