use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;
use std::net::IpAddr;

pub fn open_hosts(netns_name: &str, hosts: &[IpAddr], firewall: Firewall) -> anyhow::Result<()> {
    for host in hosts {
        let host_str = &host.to_string();
        match firewall {
            Firewall::IpTables => {
                // Select the correct command based on IP version
                let iptables_cmd = if host.is_ipv4() {
                    "iptables"
                } else {
                    "ip6tables"
                };

                NetworkNamespace::exec(
                    netns_name,
                    &[
                        iptables_cmd,
                        "-I",
                        "OUTPUT",
                        "1",
                        "-d",
                        host_str,
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            Firewall::NfTables => {
                let addr_family_keyword = if host.is_ipv4() { "ip" } else { "ip6" };

                NetworkNamespace::exec(
                    netns_name,
                    &[
                        "nft",
                        "insert",
                        "rule",
                        "inet",
                        netns_name,
                        "output",
                        addr_family_keyword, // Use 'ip' or 'ip6'
                        "daddr",
                        host_str,
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }
    }
    Ok(())
}
