use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;
use std::net::IpAddr;

pub fn open_hosts(netns_name: &str, hosts: &[IpAddr], firewall: Firewall) -> anyhow::Result<()> {
    for host in hosts {
        match firewall {
            Firewall::IpTables => {
                NetworkNamespace::exec(
                    netns_name,
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
                    netns_name,
                    &[
                        "nft",
                        "insert",
                        "rule",
                        "inet",
                        netns_name,
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
