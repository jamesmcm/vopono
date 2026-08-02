use crate::network::firewall::Firewall;
use crate::network::netns::NetworkNamespace;
use std::net::IpAddr;

pub(crate) fn nft_interface_name(interface: &str) -> String {
    if let Some(prefix) = interface.strip_suffix('+') {
        format!("\"{prefix}*\"")
    } else {
        interface.to_owned()
    }
}

pub fn open_hosts(netns_name: &str, hosts: &[IpAddr], firewall: Firewall) -> anyhow::Result<()> {
    open_hosts_on_interface(netns_name, hosts, firewall, None)
}

pub fn open_hosts_on_interface(
    netns_name: &str,
    hosts: &[IpAddr],
    firewall: Firewall,
    egress_interface: Option<&str>,
) -> anyhow::Result<()> {
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

                let mut command = vec![iptables_cmd, "-I", "OUTPUT", "1", "-d", host_str];
                if let Some(interface) = egress_interface {
                    command.extend(["-o", interface]);
                }
                command.extend(["-j", "ACCEPT"]);
                NetworkNamespace::exec(netns_name, &command)?;
            }
            Firewall::NfTables => {
                let addr_family_keyword = if host.is_ipv4() { "ip" } else { "ip6" };
                let nft_interface = egress_interface.map(nft_interface_name);

                let mut command = vec!["nft", "insert", "rule", "inet", netns_name, "output"];
                if let Some(interface) = nft_interface.as_deref() {
                    command.extend(["oifname", interface]);
                }
                command.extend([
                    addr_family_keyword, // Use 'ip' or 'ip6'
                    "daddr",
                    host_str,
                    "counter",
                    "accept",
                ]);
                NetworkNamespace::exec(netns_name, &command)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_iptables_wildcard_to_nft_interface_pattern() {
        assert_eq!(nft_interface_name("tun+"), "\"tun*\"");
        assert_eq!(nft_interface_name("wg0"), "wg0");
    }
}
