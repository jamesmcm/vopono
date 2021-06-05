use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use super::util::sudo_command;
use anyhow::Context;
use log::debug;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostMasquerade {
    ip_mask: String,
    interface: NetworkInterface,
    firewall: Firewall,
}

impl HostMasquerade {
    /// Add masquerade rule to route traffic from network namespace to active network interface
    pub fn add_masquerade_rule(
        ip_mask: String,
        interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        match firewall {
            Firewall::IpTables => {
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
            }
            Firewall::NfTables => {
                sudo_command(&["nft", "add", "table", "inet", "vopono_nat"])
                    .context("Failed to create nft table vopono_nat")?;

                sudo_command(&["nft", "add chain inet vopono_nat postrouting { type nat hook postrouting priority 100 ; }"])
                    .context("Failed to create nft postrouting chain in vopono_nat")?;

                sudo_command(&[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "vopono_nat",
                    "postrouting",
                    "oifname",
                    &interface.name,
                    "ip",
                    "saddr",
                    &ip_mask,
                    "counter",
                    "masquerade",
                ])
                .with_context(|| {
                    format!(
                        "Failed to add nftables masquerade rule, ip_mask: {}, interface: {}",
                        &ip_mask, &interface.name
                    )
                })?;
            }
        }
        Ok(HostMasquerade {
            ip_mask,
            interface,
            firewall,
        })
    }
}

impl Drop for HostMasquerade {
    fn drop(&mut self) {
        // Only drop these settings if there are no other active namespaces
        let namespaces = crate::list::get_lock_namespaces();
        debug!("Remaining namespaces: {:?}", namespaces);
        if namespaces.is_ok() {
            if namespaces.unwrap().is_empty() {
                match self.firewall {
                    Firewall::IpTables => {
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
                        .unwrap_or_else(|_| {
                            panic!(
                        "Failed to delete iptables masquerade rule, ip_mask: {}, interface: {}",
                        &self.ip_mask, &self.interface.name
                    )
                        });
                    }
                    Firewall::NfTables => {
                        sudo_command(&["nft", "delete", "table", "inet", "vopono_nat"])
                            .unwrap_or_else(|_| {
                                panic!(
                            "Failed to delete nftables masquerade rule, ip_mask: {}, interface: {}",
                            &self.ip_mask, &self.interface.name
                        )
                            });
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallException {
    host_interface: NetworkInterface,
    ns_interface: NetworkInterface,
    firewall: Firewall,
}

impl FirewallException {
    /// Add firewall exception for network namespace to host and vice versa (in case of ufw
    /// running)
    pub fn add_firewall_exception(
        ns_interface: NetworkInterface,
        host_interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        match firewall {
            Firewall::IpTables => {
                sudo_command(&[
                    "iptables",
                    "-I",
                    "FORWARD",
                    "-i",
                    &host_interface.name,
                    "-o",
                    &ns_interface.name,
                    "-j",
                    "ACCEPT",
                ])
                .with_context(|| {
                    format!(
                        "Failed to add iptables host input exception, host interface: {}, namespace interface: {}",
                        &host_interface.name, &ns_interface.name
                    )
                })?;
                sudo_command(&[
                    "iptables",
                    "-I",
                    "FORWARD",
                    "-o",
                    &host_interface.name,
                    "-i",
                    &ns_interface.name,
                    "-j",
                    "ACCEPT",
                ])
                .with_context(|| {
                    format!(
                        "Failed to add iptables host output exception, host interface: {}, namespace interface: {}",
                        &host_interface.name, &ns_interface.name
                    )
                })?;
            }
            Firewall::NfTables => {
                sudo_command(&["nft", "add", "table", "inet", "vopono_bridge"])
                    .context("Failed to create nft table vopono_bridge")?;

                sudo_command(&[
                    "nft",
                    "add chain inet vopono_bridge forward { type filter hook forward priority -10 ; }",
                ])
                .context("Failed to create nft forward chain in vopono_bridge")?;

                sudo_command(&[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "vopono_bridge",
                    "forward",
                    "iifname",
                    &host_interface.name,
                    "oifname",
                    &ns_interface.name,
                    "counter",
                    "accept",
                ])
                .with_context(|| {
                    format!(
                        "Failed to add nftables bridge input accept rule, host_interface: {}, namespace interface: {}",
                        &host_interface.name, &ns_interface.name
                    )
                })?;

                sudo_command(&[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "vopono_bridge",
                    "forward",
                    "oifname",
                    &host_interface.name,
                    "iifname",
                    &ns_interface.name,
                    "counter",
                    "accept",
                ])
                .with_context(|| {
                    format!(
                        "Failed to add nftables bridge output accept rule, host_interface: {}, namespace interface: {}",
                        &host_interface.name, &ns_interface.name
                    )
                })?;
            }
        }
        Ok(FirewallException {
            host_interface,
            ns_interface,
            firewall,
        })
    }
}

impl Drop for FirewallException {
    fn drop(&mut self) {
        // Only drop these settings if there are no other active namespaces
        let namespaces = crate::list::get_lock_namespaces();
        debug!("Remaining namespaces: {:?}", namespaces);
        if namespaces.is_ok() {
            if namespaces.unwrap().is_empty() {
                match self.firewall {
                    Firewall::IpTables => {
                        sudo_command(&[
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-o",
                    &self.host_interface.name,
                    "-i",
                    &self.ns_interface.name,
                    "-j",
                    "ACCEPT",
                ])
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to delete iptables host output rule, host interface: {}, namespace interface: {}",
                        &self.host_interface.name, &self.ns_interface.name
                    )
                });

                        sudo_command(&[
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-i",
                    &self.host_interface.name,
                    "-o",
                    &self.ns_interface.name,
                    "-j",
                    "ACCEPT",
                ])
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to delete iptables host input rule, host interface: {}, namespace interface: {}",
                        &self.host_interface.name, &self.ns_interface.name
                    )
                });
                    }
                    Firewall::NfTables => {
                        sudo_command(&["nft", "delete", "table", "inet", "vopono_bridge"]).unwrap_or_else(
                    |_| {
                        panic!(
                            "Failed to delete nftables namespace bridge firewall rule, host interface: {}, namespace interface: {}",
                            &self.host_interface.name, &self.ns_interface.name
                        )
                    },
                );
                    }
                }
            }
        }
    }
}
