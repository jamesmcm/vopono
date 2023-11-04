use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;
use std::net::IpAddr;

pub fn open_hosts(
    netns: &NetworkNamespace,
    hosts: Vec<IpAddr>,
    firewall: Firewall,
) -> anyhow::Result<()> {
    for host in hosts {
        match firewall {
            Firewall::IpTables => {
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "iptables",
                        "-I",
                        "OUTPUT",
                        "1",
                        "-d",
                        &host.to_string(),
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
                        "output",
                        "ip",
                        "daddr",
                        &host.to_string(),
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }
    }
    Ok(())
}
