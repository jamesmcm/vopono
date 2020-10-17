use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use super::util::sudo_command;
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct HostMasquerade {
    ip_mask: String,
    interface: NetworkInterface,
    firewall: Firewall,
}

impl HostMasquerade {
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
                sudo_command(&["nft", "delete", "table", "inet", "vopono_nat"]).unwrap_or_else(
                    |_| {
                        panic!(
                            "Failed to delete nftables masquerade rule, ip_mask: {}, interface: {}",
                            &self.ip_mask, &self.interface.name
                        )
                    },
                );
            }
        }
    }
}
