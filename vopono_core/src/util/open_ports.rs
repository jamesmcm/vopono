use crate::network::firewall::Firewall;
use crate::network::netns::{NetworkNamespace, VethPairIPs};

pub fn open_ports(
    netns: &NetworkNamespace,
    ports: &[u16],
    firewall: Firewall,
) -> anyhow::Result<()> {
    // IPv6 is configured on the veth pair only when it is enabled for this
    // namespace.  Use that as the source of truth so callers do not have to
    // thread the CLI flag through every protocol implementation.
    let ipv6_enabled = netns
        .veth_pair_ips
        .as_ref()
        .and_then(|ips| ips.ipv6.as_ref())
        .is_some();

    for &port in ports {
        open_port_in_namespace(
            &netns.name,
            firewall,
            ipv6_enabled,
            netns.veth_pair.as_ref().map(|v| v.source.as_str()),
            netns.veth_pair_ips.as_ref(),
            port,
        )?;
    }

    Ok(())
}

pub fn open_port_in_namespace(
    netns_name: &str,
    firewall: Firewall,
    ipv6_enabled: bool,
    veth_source: Option<&str>,
    veth_ips: Option<&VethPairIPs>,
    port: u16,
) -> anyhow::Result<()> {
    let port_str = &port.to_string();
    match firewall {
        Firewall::IpTables => {
            let iptables_cmds: &[&str] = if ipv6_enabled {
                &["iptables", "ip6tables"]
            } else {
                &["iptables"]
            };
            for iptables_cmd in iptables_cmds {
                for protocol in ["tcp", "udp"] {
                    NetworkNamespace::exec(
                        netns_name,
                        &[
                            iptables_cmd,
                            "-I",
                            "INPUT",
                            "-p",
                            protocol,
                            "--dport",
                            port_str,
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                    let ips = veth_ips.and_then(|ips| {
                        if *iptables_cmd == "iptables" {
                            ips.ipv4.as_ref()
                        } else {
                            ips.ipv6.as_ref()
                        }
                    });
                    if let (Some(veth_source), Some(ips)) = (veth_source, ips) {
                        // Only host-relay replies need an exception outside
                        // the VPN. A source port alone lets applications bind
                        // that port and originate arbitrary plaintext traffic.
                        NetworkNamespace::exec(
                            netns_name,
                            &[
                                iptables_cmd,
                                "-I",
                                "OUTPUT",
                                "-o",
                                veth_source,
                                "-s",
                                &ips.namespace_ip.to_string(),
                                "-p",
                                protocol,
                                "--sport",
                                port_str,
                                "-m",
                                "conntrack",
                                "--ctstate",
                                "ESTABLISHED,RELATED",
                                "--ctdir",
                                "REPLY",
                                "-j",
                                "ACCEPT",
                            ],
                        )?;
                    }
                }
            }
        }
        Firewall::NfTables => {
            for protocol in ["tcp", "udp"] {
                let family = if ipv6_enabled {
                    Vec::new()
                } else {
                    vec!["ip", "protocol", protocol]
                };

                let mut input = vec!["nft", "insert", "rule", "inet", netns_name, "input"];
                input.extend(family.iter().copied());
                input.extend([protocol, "dport", port_str, "counter", "accept"]);
                NetworkNamespace::exec(netns_name, &input)?;

                if let (Some(veth_source), Some(ips)) = (veth_source, veth_ips) {
                    let families = [
                        ("ip", ips.ipv4.as_ref()),
                        ("ip6", ipv6_enabled.then_some(ips.ipv6.as_ref()).flatten()),
                    ];
                    for (family, ips) in families {
                        if let Some(ips) = ips {
                            NetworkNamespace::exec(
                                netns_name,
                                &[
                                    "nft",
                                    "insert",
                                    "rule",
                                    "inet",
                                    netns_name,
                                    "output",
                                    "oifname",
                                    veth_source,
                                    family,
                                    "saddr",
                                    &ips.namespace_ip.to_string(),
                                    protocol,
                                    "sport",
                                    port_str,
                                    "ct",
                                    "direction",
                                    "reply",
                                    "ct",
                                    "state",
                                    "established,related",
                                    "counter",
                                    "accept",
                                ],
                            )?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Remove port-opening rules for an expired provider-assigned forwarded port.
pub fn close_port_in_namespace(
    netns_name: &str,
    firewall: Firewall,
    ipv6_enabled: bool,
    port: u16,
) {
    let port_str = port.to_string();
    match firewall {
        Firewall::IpTables => {
            let iptables_cmds: &[&str] = if ipv6_enabled {
                &["iptables", "ip6tables"]
            } else {
                &["iptables"]
            };
            for iptables_cmd in iptables_cmds {
                for protocol in ["tcp", "udp"] {
                    let _ = NetworkNamespace::exec(
                        netns_name,
                        &[
                            iptables_cmd,
                            "-D",
                            "INPUT",
                            "-p",
                            protocol,
                            "--dport",
                            &port_str,
                            "-j",
                            "ACCEPT",
                        ],
                    );
                }
                // Also remove any OUTPUT veth-reply rule installed for the initial port.
                if let Ok(output) =
                    NetworkNamespace::exec_with_output(netns_name, &[iptables_cmd, "-S", "OUTPUT"])
                    && output.status.success()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if let Some(rest) = line.strip_prefix("-A OUTPUT ")
                            && rest.contains(&format!("--sport {port_str} "))
                            && rest.contains("--ctdir REPLY")
                            && let Ok(tokens) = shell_words::split(rest)
                        {
                            let mut args = vec![iptables_cmd, "-D", "OUTPUT"];
                            args.extend(tokens.iter().map(String::as_str));
                            let _ = NetworkNamespace::exec(netns_name, &args);
                        }
                    }
                }
            }
        }
        Firewall::NfTables => {
            for (chain, field) in [("input", "dport"), ("output", "sport")] {
                let Ok(output) = NetworkNamespace::exec_with_output(
                    netns_name,
                    &["nft", "-j", "list", "chain", "inet", netns_name, chain],
                ) else {
                    continue;
                };
                if !output.status.success() {
                    continue;
                }
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
                    continue;
                };
                let Some(items) = value["nftables"].as_array() else {
                    continue;
                };
                for item in items {
                    let Some(rule) = item.get("rule") else {
                        continue;
                    };
                    let Some(handle) = rule["handle"].as_u64() else {
                        continue;
                    };
                    let Some(exprs) = rule["expr"].as_array() else {
                        continue;
                    };
                    let matches_port = exprs.iter().any(|expr| {
                        expr.get("match")
                            .map(|m| {
                                let is_field =
                                    m.pointer("/left/payload/field").and_then(|f| f.as_str())
                                        == Some(field);
                                let is_port = m.get("right").and_then(|r| r.as_u64())
                                    == Some(u64::from(port));
                                is_field && is_port
                            })
                            .unwrap_or(false)
                    });
                    let matches_reply = chain == "input"
                        || exprs.iter().any(|expr| {
                            expr.get("match").is_some_and(|m| {
                                m.pointer("/left/ct/key").and_then(|k| k.as_str())
                                    == Some("direction")
                                    && m.get("right").and_then(|r| r.as_str()) == Some("reply")
                            })
                        });
                    let is_accept = exprs.iter().any(|expr| expr.get("accept").is_some());
                    if matches_port && matches_reply && is_accept {
                        let handle_str = handle.to_string();
                        let _ = NetworkNamespace::exec(
                            netns_name,
                            &[
                                "nft",
                                "delete",
                                "rule",
                                "inet",
                                netns_name,
                                chain,
                                "handle",
                                &handle_str,
                            ],
                        );
                    }
                }
            }
        }
    }
}
