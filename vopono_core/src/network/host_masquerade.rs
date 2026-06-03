use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use crate::util::sudo_command;
use anyhow::Context;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug)]
pub struct HostMasquerade {
    ipv4_mask: Option<String>,
    ipv6_mask: Option<String>,
    interface: NetworkInterface,
    firewall: Firewall,
}

impl HostMasquerade {
    /// Add masquerade rule to route traffic from network namespace to active network interface
    pub fn add_masquerade_rule(
        ipv4_mask: Option<String>,
        ipv6_mask: Option<String>,
        interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        match firewall {
            Firewall::IpTables => {
                if let Some(ref mask) = ipv4_mask {
                    // Insert before provider-managed chains such as piavpn.POSTROUTING.
                    // If those chains run first they can consume or block namespace
                    // traffic before vopono's MASQUERADE rule is reached.
                    sudo_command(&[
                        "iptables",
                        "-t",
                        "nat",
                        "-I",
                        "POSTROUTING",
                        "-s",
                        mask,
                        "-o",
                        &interface.name,
                        "-j",
                        "MASQUERADE",
                    ])
                    .with_context(|| {
                        format!(
                            "Failed to add iptables masquerade rule, mask: {}, interface: {}",
                            mask, interface.name
                        )
                    })?;
                } else {
                    log::error!("IPv4 mask was None for masquerade rule!");
                }

                // Will be None if IPv6 disabled
                if let Some(ref mask) = ipv6_mask {
                    sudo_command(&[
                        "ip6tables",
                        "-t",
                        "nat",
                        "-I",
                        "POSTROUTING",
                        "-s",
                        mask,
                        "-o",
                        &interface.name,
                        "-j",
                        "MASQUERADE",
                    ])
                    .with_context(|| {
                        format!(
                            "Failed to add ip6tables masquerade rule, mask: {}, interface: {}",
                            mask, interface.name
                        )
                    })?;
                }
            }
            Firewall::NfTables => {
                sudo_command(&["nft", "add", "table", "inet", "vopono_nat"])
                    .context("Failed to create nft table vopono_nat")?;
                sudo_command(&[
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    "vopono_nat",
                    "postrouting",
                    "{ type nat hook postrouting priority 100 ; }",
                ])
                .context("Failed to create nft postrouting chain in vopono_nat")?;

                if let Some(ref mask) = ipv4_mask {
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
                        mask,
                        "counter",
                        "masquerade",
                    ])
                    .with_context(|| {
                        format!(
                            "Failed to add nftables IPv4 masquerade rule, mask: {}, interface: {}",
                            mask, interface.name
                        )
                    })?;
                }
                if let Some(ref mask) = ipv6_mask {
                    sudo_command(&[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        "vopono_nat",
                        "postrouting",
                        "oifname",
                        &interface.name,
                        "ip6",
                        "saddr",
                        mask,
                        "counter",
                        "masquerade",
                    ])
                    .with_context(|| {
                        format!(
                            "Failed to add nftables IPv6 masquerade rule, mask: {}, interface: {}",
                            mask, interface.name
                        )
                    })?;
                }
            }
        }
        Ok(HostMasquerade {
            ipv4_mask,
            ipv6_mask,
            interface,
            firewall,
        })
    }
}

impl Drop for HostMasquerade {
    fn drop(&mut self) {
        let namespaces = crate::util::get_lock_namespaces();
        debug!("Remaining namespaces: {namespaces:?}");
        if namespaces.is_ok() && namespaces.unwrap().is_empty() {
            match self.firewall {
                Firewall::IpTables => {
                    if let Some(ref mask) = self.ipv4_mask {
                        sudo_command(&[
                            "iptables",
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-s",
                            mask,
                            "-o",
                            &self.interface.name,
                            "-j",
                            "MASQUERADE",
                        ])
                        .unwrap_or_else(|e| log::warn!("Failed to delete iptables rule: {e}"));
                    }
                    if let Some(ref mask) = self.ipv6_mask {
                        sudo_command(&[
                            "ip6tables",
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-s",
                            mask,
                            "-o",
                            &self.interface.name,
                            "-j",
                            "MASQUERADE",
                        ])
                        .unwrap_or_else(|e| log::warn!("Failed to delete ip6tables rule: {e}"));
                    }
                }
                Firewall::NfTables => {
                    // The entire table is deleted, removing all rules within it.
                    sudo_command(&["nft", "delete", "table", "inet", "vopono_nat"]).unwrap_or_else(
                        |e| log::warn!("Failed to delete nftables table vopono_nat: {e}"),
                    );
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FirewallException {
    host_interface: NetworkInterface,
    ns_interface: NetworkInterface,
    firewall: Firewall,
    disable_ipv6: bool,
    #[serde(default)]
    docker_user_ipv4: bool,
    #[serde(default)]
    docker_user_ipv6: bool,
    #[serde(default)]
    ufw_forward_ipv4: bool,
    #[serde(default)]
    ufw_forward_ipv6: bool,
}

impl FirewallException {
    /// Add firewall exception for network namespace to host and vice versa (in case of ufw
    /// running)
    pub fn add_firewall_exception(
        ns_interface: NetworkInterface,
        host_interface: NetworkInterface,
        firewall: Firewall,
        disable_ipv6: bool,
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
                        host_interface.name, ns_interface.name
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
                        host_interface.name, ns_interface.name
                    )
                })?;
                if !disable_ipv6 {
                    sudo_command(&[
                        "ip6tables",
                        "-I",
                        "FORWARD",
                        "-i",
                        &host_interface.name,
                        "-o",
                        &ns_interface.name,
                        "-j",
                        "ACCEPT",
                    ])?;
                    sudo_command(&[
                        "ip6tables",
                        "-I",
                        "FORWARD",
                        "-o",
                        &host_interface.name,
                        "-i",
                        &ns_interface.name,
                        "-j",
                        "ACCEPT",
                    ])?;
                }

                let ufw_forward_ipv4 =
                    add_ufw_forward_exception("iptables", &host_interface, &ns_interface)?;
                let ufw_forward_ipv6 = if disable_ipv6 {
                    false
                } else {
                    add_ufw_forward_exception("ip6tables", &host_interface, &ns_interface)?
                };

                Ok(FirewallException {
                    host_interface,
                    ns_interface,
                    firewall,
                    disable_ipv6,
                    docker_user_ipv4: false,
                    docker_user_ipv6: false,
                    ufw_forward_ipv4,
                    ufw_forward_ipv6,
                })
            }
            Firewall::NfTables => {
                sudo_command(&["nft", "add", "table", "inet", "vopono_bridge"])
                    .context("Failed to create nft table vopono_bridge")?;

                sudo_command(&[
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    "vopono_bridge",
                    "forward",
                    "{ type filter hook forward priority filter - 10 ; }",
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
                        host_interface.name, ns_interface.name
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
                        host_interface.name, ns_interface.name
                    )
                })?;

                // If Docker is using the iptables frontend with the nf_tables backend
                // (iptables-nft), its FORWARD base chain can still have policy drop.
                // An accept in vopono_bridge is not final across later nft base chains,
                // so add the same exceptions to Docker's pre-forwarding user chain.
                let docker_user_ipv4 =
                    add_docker_user_exception("iptables", &host_interface, &ns_interface)?;
                let docker_user_ipv6 = if disable_ipv6 {
                    false
                } else {
                    add_docker_user_exception("ip6tables", &host_interface, &ns_interface)?
                };
                // UFW keeps primary chains hooked into FORWARD when disabled
                // with MANAGE_BUILTINS=no. When iptables is backed by
                // nf_tables, those chains can still run after vopono's nft
                // base chain, so add early UFW exceptions too.
                let ufw_forward_ipv4 =
                    add_ufw_forward_exception("iptables", &host_interface, &ns_interface)?;
                let ufw_forward_ipv6 = if disable_ipv6 {
                    false
                } else {
                    add_ufw_forward_exception("ip6tables", &host_interface, &ns_interface)?
                };

                Ok(FirewallException {
                    host_interface,
                    ns_interface,
                    firewall,
                    disable_ipv6,
                    docker_user_ipv4,
                    docker_user_ipv6,
                    ufw_forward_ipv4,
                    ufw_forward_ipv6,
                })
            }
        }
    }
}

impl Drop for FirewallException {
    fn drop(&mut self) {
        // DOCKER-USER rules are scoped to this namespace's veth interface pair.
        // Remove them with this instance even if other vopono namespaces are
        // still running; each namespace owns different interface-specific rules.
        if let Firewall::NfTables = self.firewall {
            if self.docker_user_ipv4 {
                delete_docker_user_exception("iptables", &self.host_interface, &self.ns_interface);
            }
            if self.docker_user_ipv6 {
                delete_docker_user_exception("ip6tables", &self.host_interface, &self.ns_interface);
            }
        }
        if self.ufw_forward_ipv4 {
            delete_forward_chain_exception(
                "iptables",
                "ufw-before-forward",
                &self.host_interface,
                &self.ns_interface,
            );
        }
        if self.ufw_forward_ipv6 {
            delete_forward_chain_exception(
                "ip6tables",
                "ufw6-before-forward",
                &self.host_interface,
                &self.ns_interface,
            );
        }

        // Only drop these settings if there are no other active namespaces
        let namespaces = crate::util::get_lock_namespaces();
        debug!("Remaining namespaces: {namespaces:?}");
        if namespaces.is_ok() && namespaces.unwrap().is_empty() {
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
                    log::error!(
                        "Failed to delete iptables host output rule, host interface: {}, namespace interface: {}",
                        self.host_interface.name, self.ns_interface.name
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
                    log::error!(
                        "Failed to delete iptables host input rule, host interface: {}, namespace interface: {}",
                        self.host_interface.name, self.ns_interface.name
                    )
                });

                    if !self.disable_ipv6 {
                        sudo_command(&[
                        "ip6tables",
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
                    log::error!(
                        "Failed to delete ip6tables host output rule, host interface: {}, namespace interface: {}",
                        self.host_interface.name, self.ns_interface.name
                    )
                });

                        sudo_command(&[
                        "ip6tables",
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
                    log::error!(
                        "Failed to delete ip6tables host input rule, host interface: {}, namespace interface: {}",
                        self.host_interface.name, self.ns_interface.name
                    )
                });
                    }
                }
                Firewall::NfTables => {
                    sudo_command(&["nft", "delete", "table", "inet", "vopono_bridge"]).unwrap_or_else(
                    |_| {
                        log::error!(
                            "Failed to delete nftables namespace bridge firewall rule, host interface: {}, namespace interface: {}",
                            self.host_interface.name, self.ns_interface.name
                        )
                    },
                );
                }
            }
        }
    }
}

fn docker_user_chain_active(iptables_cmd: &str) -> bool {
    forward_chain_active(iptables_cmd, "DOCKER-USER")
}

fn ufw_forward_chain(iptables_cmd: &str) -> &str {
    if iptables_cmd == "ip6tables" {
        "ufw6-before-forward"
    } else {
        "ufw-before-forward"
    }
}

fn ufw_forward_chain_active(iptables_cmd: &str) -> bool {
    forward_chain_active(iptables_cmd, ufw_forward_chain(iptables_cmd))
}

fn forward_chain_active(iptables_cmd: &str, chain: &str) -> bool {
    let chain_status = Command::new(iptables_cmd)
        .args(["-S", chain])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(chain_status, Ok(status) if status.success()) {
        return false;
    }

    let forward = Command::new(iptables_cmd)
        .args(["-S", "FORWARD"])
        .stderr(Stdio::null())
        .output();
    match forward {
        Ok(output) if output.status.success() => {
            let jump = format!("-A FORWARD -j {chain}");
            String::from_utf8_lossy(&output.stdout).contains(&jump)
        }
        _ => false,
    }
}

fn add_docker_user_exception(
    iptables_cmd: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) -> anyhow::Result<bool> {
    if !docker_user_chain_active(iptables_cmd) {
        return Ok(false);
    }

    sudo_command(&[
        iptables_cmd,
        "-I",
        "DOCKER-USER",
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .with_context(|| {
        format!(
            "Failed to add {iptables_cmd} DOCKER-USER input exception, host interface: {}, namespace interface: {}",
            host_interface.name, ns_interface.name
        )
    })?;
    sudo_command(&[
        iptables_cmd,
        "-I",
        "DOCKER-USER",
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .with_context(|| {
        format!(
            "Failed to add {iptables_cmd} DOCKER-USER output exception, host interface: {}, namespace interface: {}",
            host_interface.name, ns_interface.name
        )
    })?;

    Ok(true)
}

fn delete_docker_user_exception(
    iptables_cmd: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) {
    sudo_command(&[
        iptables_cmd,
        "-D",
        "DOCKER-USER",
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} DOCKER-USER output rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });

    sudo_command(&[
        iptables_cmd,
        "-D",
        "DOCKER-USER",
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} DOCKER-USER input rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });
}

fn add_ufw_forward_exception(
    iptables_cmd: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) -> anyhow::Result<bool> {
    let chain = ufw_forward_chain(iptables_cmd);
    if !ufw_forward_chain_active(iptables_cmd) {
        return Ok(false);
    }

    add_forward_chain_exception(iptables_cmd, chain, host_interface, ns_interface)
}

fn add_forward_chain_exception(
    iptables_cmd: &str,
    chain: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) -> anyhow::Result<bool> {
    sudo_command(&[
        iptables_cmd,
        "-I",
        chain,
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .with_context(|| {
        format!(
            "Failed to add {iptables_cmd} {chain} input exception, host interface: {}, namespace interface: {}",
            host_interface.name, ns_interface.name
        )
    })?;
    sudo_command(&[
        iptables_cmd,
        "-I",
        chain,
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .with_context(|| {
        format!(
            "Failed to add {iptables_cmd} {chain} output exception, host interface: {}, namespace interface: {}",
            host_interface.name, ns_interface.name
        )
    })?;

    Ok(true)
}

fn delete_forward_chain_exception(
    iptables_cmd: &str,
    chain: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) {
    sudo_command(&[
        iptables_cmd,
        "-D",
        chain,
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} {chain} output rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });

    sudo_command(&[
        iptables_cmd,
        "-D",
        chain,
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} {chain} input rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });
}
