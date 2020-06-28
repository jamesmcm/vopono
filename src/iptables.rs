use super::network_interface::NetworkInterface;
use super::util::sudo_command;
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct IpTables {
    ip_mask: String,
    interface: NetworkInterface,
}

impl IpTables {
    pub fn add_masquerade_rule(
        ip_mask: String,
        interface: NetworkInterface,
    ) -> anyhow::Result<Self> {
        sudo_command(&[
            "iptables",
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &ip_mask,
            "-o",
            &interface.name,
            "-j",
            "MASQUERADE",
        ])
        .with_context(|| {
            format!(
                "Failed to add iptables masquerade rule, ip_mask: {}, interface: {}",
                &ip_mask, &interface.name
            )
        })?;
        Ok(IpTables { ip_mask, interface })
    }
}

impl Drop for IpTables {
    fn drop(&mut self) {
        sudo_command(&[
            "iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &self.ip_mask,
            "-o",
            &self.interface.name,
            "-j",
            "MASQUERADE",
        ])
        .expect(&format!(
            "Failed to delete iptables masquerade rule, ip_mask: {}, interface: {}",
            &self.ip_mask, &self.interface.name
        ));
    }
}

// Killswitch
//:INPUT DROP [0:0]
// :FORWARD DROP [0:0]
// :OUTPUT DROP [0:10]
// -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
// -A INPUT -i lo -j ACCEPT
// -A INPUT -i tun+ -j ACCEPT
// -A OUTPUT -o lo -j ACCEPT
// -A OUTPUT -d 209.222.18.222/32 -j ACCEPT
// -A OUTPUT -d 209.222.18.218/32 -j ACCEPT
// -A OUTPUT -p udp -m udp --dport 1197 -j ACCEPT
// -A OUTPUT -o tun+ -j ACCEPT
// -A OUTPUT -j REJECT --reject-with icmp-net-unreachable
// COMMIT
