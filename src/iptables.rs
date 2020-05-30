use super::network_interface::NetworkInterface;
use super::util::sudo_command;
use anyhow::Context;

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
            &interface.wildcard(),
            "-j",
            "MASQUERADE",
        ])
        .with_context(|| {
            format!(
                "Failed to add iptables masquerade rule, ip_mask: {}, interface: {}",
                &ip_mask,
                interface.wildcard()
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
            &self.interface.wildcard(),
            "-j",
            "MASQUERADE",
        ])
        .expect(&format!(
            "Failed to delete iptables masquerade rule, ip_mask: {}, interface: {}",
            &self.ip_mask,
            &self.interface.wildcard()
        ));
    }
}
