use std::net::IpAddr;
use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;

pub fn open_hosts(
    netns: &NetworkNamespace,
    hosts: Vec<IpAddr>,
    firewall: Firewall,
) -> anyhow::Result<()> {
    for host in hosts {
        match firewall {
            Firewall::IpTables => {
                netns.exec(&[
                    "iptables",
                    "-I",
                    "OUTPUT",
                    "1",
                    "-d",
                    &host.to_string(),
                    "-j",
                    "ACCEPT",
                ])?;
            }
            Firewall::NfTables => {
                netns.exec(&[
                    "nft",
                    "insert",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "ip",
                    "daddr",
                    &host.to_string(),
                    "counter",
                    "accept",
                ])?;
            }
        }
    }
    Ok(())
}
