use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use super::trojan::trojan_config::TrojanConfig;
use crate::network::wireguard_config::WireguardConfig;
use crate::util::sudo_command;
use anyhow::{Context, anyhow};
use ipnet::IpNet;
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use tempfile::NamedTempFile;

const DEFAULT_PERSISTENT_KEEPALIVE_SECS: &str = "25";
const WIREGUARD_FWMARK: &str = "51820";

#[derive(Serialize, Deserialize, Debug)]
pub struct Wireguard {
    pub executable_wg: String,
    pub ip_link_type: String,
    pub ns_name: String,
    pub config_file: PathBuf,
    pub firewall: Firewall,
    pub if_name: String,
    pub interface_addresses: Vec<IpAddr>,
}

impl Wireguard {
    pub fn config_from_file(config_file: &Path) -> anyhow::Result<WireguardConfig> {
        let config_string = std::fs::read_to_string(config_file)
            .context(format!("Reading Wireguard config file: {:?}", config_file))?;

        WireguardConfig::from_str(&config_string)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        namespace: &mut NetworkNamespace,
        config_file: PathBuf,
        executable_wg: Option<&str>,
        ip_link_type: Option<&str>,
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
        dns: Option<&Vec<IpAddr>>,
        hosts_entries: Option<&Vec<String>>,
        allow_host_access: bool,
        trojan_config: Option<TrojanConfig>,
    ) -> anyhow::Result<Self> {
        let executable_wg = executable_wg.unwrap_or("wg").to_string();
        let ip_link_type = ip_link_type.unwrap_or("wireguard").to_string();

        if let Err(x) = which::which(&executable_wg) {
            error!("{executable_wg} binary not found. Is wireguard-tools installed and on PATH?");
            return Err(anyhow!(
                "{executable_wg} binary not found. Is wireguard-tools installed and on PATH?: {:?}",
                x
            ));
        }

        let mut config_string = std::fs::read_to_string(&config_file)
            .context(format!("Reading Wireguard config file: {:?}", config_file))?;

        // Replace Endpoint with Trojan server for Wireguard forwarding
        if let Some(tc) = trojan_config.as_ref() {
            let re = Regex::new(r"Endpoint\s*=\s*(?:\[([^\]]+)\]|([^:\s]+)):(\d+)")?;
            let new_endpoint = tc.get_local_socketaddr()?;
            config_string = re
                .replace_all(&config_string, format!("Endpoint = {new_endpoint}"))
                .to_string();
        }

        let config = WireguardConfig::from_str(&config_string)
            .with_context(|| format!("Parsing Wireguard config file: {}", config_file.display()))?;
        if config.interface.address.is_empty() {
            return Err(anyhow!(
                "Wireguard config has an empty Address field: {}",
                config_file.display()
            ));
        }
        if config.peer.public_key.trim().is_empty() {
            return Err(anyhow!(
                "Wireguard config has an empty PublicKey field: {}. For PIA Wireguard configs, rerun `vopono sync --protocol wireguard privateinternetaccess` and check that PIA authentication succeeds.",
                config_file.display()
            ));
        }
        if config.peer.allowed_ips.is_empty() {
            return Err(anyhow!(
                "Wireguard config has an empty AllowedIPs field: {}. Use `AllowedIPs = 0.0.0.0/0` for IPv4-only routing or `AllowedIPs = 0.0.0.0/0, ::/0` for dual-stack routing.",
                config_file.display()
            ));
        }

        let has_ipv4_default = has_default_allowed_ip(&config.peer.allowed_ips, true);
        let has_ipv6_default = has_default_allowed_ip(&config.peer.allowed_ips, false);
        let has_ipv6_address = config
            .interface
            .address
            .iter()
            .any(|address| matches!(address, IpNet::V6(_)));
        if has_ipv6_default && !has_ipv6_address {
            warn!(
                "Wireguard config routes IPv6 but has no IPv6 interface address; IPv6 traffic will be blocked by the killswitch"
            );
        }

        // Resolve the peer with the host resolver before configuring WireGuard. A provider's
        // tunnel DNS is not reachable until WireGuard is connected, so passing a hostname to
        // `wg setconf` would create a DNS bootstrap dependency inside the namespace.
        let endpoint_addresses = config
            .peer
            .endpoint
            .resolve_ips()
            .context("Failed to resolve Wireguard peer endpoint")?;
        let peer_endpoint_ip =
            select_endpoint_ip(&endpoint_addresses, disable_ipv6).with_context(|| {
                format!(
                    "No usable Wireguard endpoint found for {}{}",
                    config.peer.endpoint,
                    if disable_ipv6 {
                        " while IPv6 is disabled"
                    } else {
                        ""
                    }
                )
            })?;
        debug!(
            "Resolved Wireguard peer endpoint {} to {} (candidates: {:?})",
            config.peer.endpoint, peer_endpoint_ip, endpoint_addresses
        );
        let peer_endpoint =
            SocketAddr::new(peer_endpoint_ip, config.peer.endpoint.port()).to_string();
        let endpoint_line = Regex::new(r"(?m)^Endpoint\s*=.*$")?;
        config_string = endpoint_line
            .replace_all(&config_string, format!("Endpoint = {peer_endpoint}"))
            .to_string();

        // Valid keys for wireguard config (see wg(8):CONFIGURATION FILE FORMAT).
        // wg setconf does not accept wg-quick-only keys such as Address, DNS or MTU.
        let allow_keys = [
            "PrivateKey",
            "ListenPort",
            "FwMark",
            "PublicKey",
            "PresharedKey",
            "AllowedIPs",
            "Endpoint",
            "PersistentKeepalive",
            // AmneziaWG extended parameters
            "Jc",
            "Jmin",
            "Jmax",
            "S1",
            "S2",
            "H1",
            "H2",
            "H3",
            "H4",
        ];
        let mut wg_temp_file =
            NamedTempFile::new().context("Creating temporary Wireguard config")?;
        write!(
            wg_temp_file,
            "{}",
            config_string
                .split('\n')
                .filter(|x| x
                    .split_once('=')
                    .map(|(key, _)| allow_keys.contains(&key.trim()))
                    // If line doesn't include an =, don't filter it out
                    .unwrap_or(true))
                .collect::<Vec<&str>>()
                .join("\n")
        )?;
        if firewall == Firewall::NfTables {
            let peer_port = config.peer.endpoint.port().to_string();
            let peer_ip_str = peer_endpoint_ip.to_string();
            let ip_family = if peer_endpoint_ip.is_ipv4() {
                "ip"
            } else {
                "ip6"
            };

            debug!("Opening firewall for Wireguard peer (out): {peer_ip_str} dport {peer_port}");
            // Allow the initial OUTGOING connection packet.
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &namespace.name,
                    "output",
                    ip_family,
                    "daddr",
                    &peer_ip_str,
                    "udp",
                    "dport",
                    &peer_port,
                    "counter",
                    "accept",
                ],
            )?;

            debug!("Opening firewall for Wireguard peer (in): {peer_ip_str} sport {peer_port}");
            // Allow the server's INCOMING reply packet.
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &namespace.name,
                    "input",
                    ip_family,
                    "saddr",
                    &peer_ip_str,
                    "udp",
                    "sport",
                    &peer_port,
                    "counter",
                    "accept",
                ],
            )?;
        }

        // TODO: Use bs58 here?
        let if_name = namespace.name
            [((namespace.name.len() as i32) - 13).max(0) as usize..namespace.name.len()]
            .to_string();
        assert!(if_name.len() <= 15, "ifname must be <= 15 chars: {if_name}");

        NetworkNamespace::exec(
            &namespace.name,
            &["ip", "link", "add", &if_name, "type", &ip_link_type],
        )?;

        let wg_temp_path = wg_temp_file.path().to_string_lossy();
        NetworkNamespace::exec(
            &namespace.name,
            &[&executable_wg, "setconf", &if_name, &wg_temp_path],
        )
        .context(format!(
            "Failed to run {executable_wg} setconf - is wireguard-tools installed?"
        ))?;

        if config.peer.keepalive.is_none() {
            info!(
                "No PersistentKeepalive set in Wireguard config, setting {} seconds to improve recovery after network drops",
                DEFAULT_PERSISTENT_KEEPALIVE_SECS
            );
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    &executable_wg,
                    "set",
                    &if_name,
                    "peer",
                    &config.peer.public_key,
                    "persistent-keepalive",
                    DEFAULT_PERSISTENT_KEEPALIVE_SECS,
                ],
            )
            .context("Failed to set default Wireguard PersistentKeepalive")?;
        }

        let mut interface_addresses: Vec<IpAddr> = Vec::new();
        // Extract addresses
        for address in config.interface.address.iter() {
            match address {
                IpNet::V6(address) => {
                    interface_addresses.push(IpAddr::V6(address.addr()));
                    NetworkNamespace::exec(
                        &namespace.name,
                        &[
                            "ip",
                            "-6",
                            "address",
                            "add",
                            &address.to_string(),
                            "dev",
                            &if_name,
                        ],
                    )?;
                }
                IpNet::V4(address) => {
                    interface_addresses.push(IpAddr::V4(address.addr()));
                    NetworkNamespace::exec(
                        &namespace.name,
                        &[
                            "ip",
                            "-4",
                            "address",
                            "add",
                            &address.to_string(),
                            "dev",
                            &if_name,
                        ],
                    )?;
                }
            }
        }

        let mtu: u32 = config
            .interface
            .mtu
            .and_then(|m| {
                let v = m.parse().ok();
                if v.is_none() {
                    warn!("Invalid MTU value in Wireguard config: {m} - will use default 1420");
                } else if v.is_some() {
                    debug!("Using MTU set in Wireguard config: {m}");
                }
                v
            })
            .unwrap_or_else(|| {
                warn!("No MTU set in Wireguard config, using default: 1420");
                1420
            });

        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip",
                "link",
                "set",
                "mtu",
                &mtu.to_string(),
                "up",
                "dev",
                &if_name,
            ],
        )?;

        let dns: Vec<IpAddr> = dns
            .cloned()
            .or_else(|| config.interface.dns.clone())
            .unwrap_or_else(|| {
                warn!("Found no DNS settings in Wireguard config, using 8.8.8.8");
                vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
            });
        // TODO: DNS suffixes?
        let dns_egress_interface =
            (use_killswitch && (has_ipv4_default || has_ipv6_default)).then_some(if_name.as_str());
        namespace.dns_config_with_interface(
            &dns,
            &[],
            hosts_entries,
            allow_host_access,
            dns_egress_interface,
        )?;
        let fwmark = WIREGUARD_FWMARK;
        NetworkNamespace::exec(
            &namespace.name,
            &[&executable_wg, "set", &if_name, "fwmark", fwmark],
        )?;

        add_endpoint_bypass_route(namespace, peer_endpoint_ip, &config.peer.allowed_ips)?;
        add_routes(
            namespace,
            &if_name,
            fwmark,
            &config.peer.allowed_ips,
            true,
            has_ipv4_default,
        )?;
        if has_ipv4_default {
            // This sysctl belongs to the namespace containing the fwmark policy rules. Setting
            // it only in the host namespace does not configure Wireguard's routing namespace.
            NetworkNamespace::exec(
                &namespace.name,
                &["sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1"],
            )?;
        }

        // Tag veth-ingress return traffic with the tunnel fwmark so its
        // reverse path stays symmetric even under strict rp_filter.
        crate::network::firewall::tag_return_traffic(
            namespace,
            &namespace
                .veth_pair
                .as_ref()
                .context("Veth pair not set while tagging return traffic")?
                .source,
            fwmark,
            firewall,
        )?;

        if disable_ipv6 {
            crate::network::firewall::disable_ipv6(namespace, firewall)?;
        } else {
            add_routes(
                namespace,
                &if_name,
                fwmark,
                &config.peer.allowed_ips,
                false,
                has_ipv6_default,
            )?;
        }

        match firewall {
            Firewall::NfTables => {
                // nft
                let nftable = namespace.name.clone();
                let pf = "inet";
                let mut nftcmd: Vec<String> = Vec::with_capacity(16);
                nftcmd.push(format!("add table {} {}", pf, nftable));
                nftcmd.push(format!(
                    "add chain {} {} preraw {{ type filter hook prerouting priority -300; }}",
                    pf, nftable
                ));
                nftcmd.push(format!(
                    "add chain {} {} premangle {{ type filter hook prerouting priority -150; }}",
                    pf, nftable
                ));
                nftcmd.push(format!(
                    "add chain {} {} postmangle {{ type filter hook postrouting priority -150; }}",
                    pf, nftable
                ));

                for address in config.interface.address.iter() {
                    match address {
                        IpNet::V6(address) => {
                            nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, nftable, if_name, "ip6", address
            ));
                        }

                        IpNet::V4(address) => {
                            nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, nftable, if_name, "ip", address
            ));
                        }
                    }
                }

                nftcmd.push(format!(
                    "add rule {} {} postmangle meta l4proto udp mark {} ct mark set mark",
                    pf, nftable, fwmark
                ));
                nftcmd.push(format!(
                    "add rule {} {} premangle meta l4proto udp meta mark set ct mark",
                    pf, nftable
                ));

                let mut nft_temp_file =
                    NamedTempFile::new().context("Creating temporary nftables rules file")?;
                write!(nft_temp_file, "{}", nftcmd.join("\n"))?;
                let nft_temp_path = nft_temp_file.path().to_string_lossy();
                NetworkNamespace::exec(&namespace.name, &["nft", "-f", &nft_temp_path])?;
            }
            Firewall::IpTables => {
                for address in config.interface.address.iter() {
                    match address {
                        IpNet::V6(address) => {
                            NetworkNamespace::exec(
                                &namespace.name,
                                &[
                                    "ip6tables",
                                    "-t",
                                    "raw",
                                    "-A",
                                    "PREROUTING",
                                    "!",
                                    "-i",
                                    &if_name,
                                    "-d",
                                    &address.to_string(),
                                    "-m",
                                    "addrtype",
                                    "!",
                                    "--src-type",
                                    "LOCAL",
                                    "-j",
                                    "DROP",
                                ],
                            )?;
                        }

                        IpNet::V4(address) => {
                            NetworkNamespace::exec(
                                &namespace.name,
                                &[
                                    "iptables",
                                    "-t",
                                    "raw",
                                    "-A",
                                    "PREROUTING",
                                    "!",
                                    "-i",
                                    &if_name,
                                    "-d",
                                    &address.to_string(),
                                    "-m",
                                    "addrtype",
                                    "!",
                                    "--src-type",
                                    "LOCAL",
                                    "-j",
                                    "DROP",
                                ],
                            )?;
                        }
                    }
                }

                let ipcmds = if disable_ipv6 {
                    vec!["iptables"]
                } else {
                    vec!["iptables", "ip6tables"]
                };

                for ipcmd in ipcmds {
                    NetworkNamespace::exec(
                        &namespace.name,
                        &[
                            ipcmd,
                            "-t",
                            "mangle",
                            "-A",
                            "POSTROUTING",
                            "-p",
                            "udp",
                            "-j",
                            "MARK",
                            "--set-mark",
                            fwmark,
                        ],
                    )?;
                    NetworkNamespace::exec(
                        &namespace.name,
                        &[
                            ipcmd,
                            "-t",
                            "mangle",
                            "-A",
                            "PREROUTING",
                            "-p",
                            "udp",
                            "-j",
                            "CONNMARK",
                            "--save-mark",
                        ],
                    )?;
                }
            }
        };

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            crate::util::open_ports(namespace, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            crate::util::open_ports(namespace, forwards.as_slice(), firewall)?;
        }

        if use_killswitch && (has_ipv4_default || has_ipv6_default) {
            killswitch(&if_name, fwmark, namespace, firewall, disable_ipv6)?;
        } else if use_killswitch {
            warn!(
                "Wireguard config is split-tunnel (AllowedIPs has no default route); not enabling the full-tunnel killswitch"
            );
        }

        Ok(Self {
            executable_wg,
            ip_link_type,
            config_file,
            ns_name: namespace.name.clone(),
            firewall,
            if_name,
            interface_addresses,
        })
    }
}

fn has_default_allowed_ip(allowed_ips: &[IpNet], ipv4: bool) -> bool {
    allowed_ips
        .iter()
        .any(|network| network.prefix_len() == 0 && network.addr().is_ipv4() == ipv4)
}

fn select_endpoint_ip(addresses: &[IpAddr], disable_ipv6: bool) -> anyhow::Result<IpAddr> {
    let ipv4 = addresses.iter().copied().find(IpAddr::is_ipv4);

    if let Some(ipv4) = ipv4 {
        // The outer Wireguard transport can carry IPv6 traffic, so prefer IPv4 whenever it is
        // available. This avoids making a dual-stack endpoint depend on host IPv6 forwarding
        // and also supports IPv4-only Wireguard servers whose hostnames have an AAAA record.
        return Ok(ipv4);
    }

    if disable_ipv6 {
        return Err(anyhow!("Only IPv6 Wireguard endpoints were resolved"));
    }

    addresses
        .first()
        .copied()
        .ok_or_else(|| anyhow!("No Wireguard endpoint addresses were resolved"))
}

/// The endpoint is the only remote whose traffic enters/leaves the namespace
/// via the veth instead of the tunnel, so its route must stay symmetric:
/// without a specific route in the main table, an unmarked return packet from
/// the endpoint reverse-routes through the fwmark policy table to the tunnel
/// device and hosts with strict reverse-path filtering (rp_filter=1) silently
/// drop it. A /32 (or /128) via the veth gateway keeps both directions on the
/// veth regardless of rp_filter mode.
fn endpoint_needs_bypass_route(endpoint: IpAddr, allowed_ips: &[IpNet]) -> bool {
    allowed_ips
        .iter()
        .any(|network| network.contains(&endpoint))
}

fn add_endpoint_bypass_route(
    namespace: &NetworkNamespace,
    endpoint: IpAddr,
    allowed_ips: &[IpNet],
) -> anyhow::Result<()> {
    if !endpoint_needs_bypass_route(endpoint, allowed_ips) {
        return Ok(());
    }

    let veth_pair = namespace
        .veth_pair
        .as_ref()
        .context("Veth pair not set while adding Wireguard endpoint route")?;
    let veth_ips = namespace
        .veth_pair_ips
        .as_ref()
        .context("Veth IPs not set while adding Wireguard endpoint route")?;
    let (family, prefix, gateway) = if endpoint.is_ipv4() {
        (
            "-4",
            32,
            veth_ips
                .ipv4
                .as_ref()
                .context("IPv4 veth route missing")?
                .host_ip,
        )
    } else {
        (
            "-6",
            128,
            veth_ips
                .ipv6
                .as_ref()
                .context("IPv6 veth route missing")?
                .host_ip,
        )
    };

    info!(
        "Wireguard endpoint {endpoint} is inside AllowedIPs; preserving its route outside the tunnel"
    );
    NetworkNamespace::exec(
        &namespace.name,
        &[
            "ip",
            family,
            "route",
            "add",
            &format!("{endpoint}/{prefix}"),
            "via",
            &gateway.to_string(),
            "dev",
            &veth_pair.source,
        ],
    )
}

fn add_routes(
    namespace: &NetworkNamespace,
    if_name: &str,
    fwmark: &str,
    allowed_ips: &[IpNet],
    ipv4: bool,
    has_default: bool,
) -> anyhow::Result<()> {
    let family = if ipv4 { "-4" } else { "-6" };

    if has_default {
        let default_route = if ipv4 { "0.0.0.0/0" } else { "::/0" };
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip",
                family,
                "route",
                "add",
                default_route,
                "dev",
                if_name,
                "table",
                fwmark,
            ],
        )?;
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip", family, "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
            ],
        )?;
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip",
                family,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        )?;
    } else {
        for network in allowed_ips
            .iter()
            .filter(|network| network.addr().is_ipv4() == ipv4)
        {
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "ip",
                    family,
                    "route",
                    "add",
                    &network.to_string(),
                    "dev",
                    if_name,
                ],
            )?;
        }
    }

    Ok(())
}

pub fn killswitch(
    ifname: &str,
    fwmark: &str,
    netns: &NetworkNamespace,
    firewall: Firewall,
    disable_ipv6: bool,
) -> anyhow::Result<()> {
    debug!("Setting Wireguard killswitch....");
    match firewall {
        Firewall::IpTables => {
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "!",
                    "-o",
                    ifname,
                    "-m",
                    "mark",
                    "!",
                    "--mark",
                    fwmark,
                    "-m",
                    "addrtype",
                    "!",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    "REJECT",
                ],
            )
            .context("Executing iptables killswitch")?;

            if !disable_ipv6 {
                let veth_ifname = netns
                    .veth_pair
                    .as_ref()
                    .context("Veth pair not set while configuring IPv6 killswitch")?
                    .source
                    .as_str();

                // ICMPv6 sent through Wireguard is encrypted by the interface and is safe to
                // allow. On the veth, only neighbour discovery is needed to reach the host
                // gateway. In particular, do not accept all ICMPv6 here: that would let tools
                // such as ping6 bypass the full-tunnel killswitch.
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "ip6tables",
                        "-A",
                        "OUTPUT",
                        "-o",
                        ifname,
                        "-p",
                        "icmpv6",
                        "-j",
                        "ACCEPT",
                    ],
                )
                .context("Allowing ICMPv6 through Wireguard")?;

                for icmpv6_type in ["135", "136"] {
                    NetworkNamespace::exec(
                        &netns.name,
                        &[
                            "ip6tables",
                            "-A",
                            "OUTPUT",
                            "-o",
                            veth_ifname,
                            "-p",
                            "icmpv6",
                            "-m",
                            "icmp6",
                            "--icmpv6-type",
                            icmpv6_type,
                            "-j",
                            "ACCEPT",
                        ],
                    )
                    .with_context(|| {
                        format!(
                            "Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname}"
                        )
                    })?;
                }

                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "ip6tables",
                        "-A",
                        "OUTPUT",
                        "!",
                        "-o",
                        ifname,
                        "-m",
                        "mark",
                        "!",
                        "--mark",
                        fwmark,
                        "-m",
                        "addrtype",
                        "!",
                        "--dst-type",
                        "LOCAL",
                        "-j",
                        "REJECT",
                    ],
                )?;
            }
        }
        Firewall::NfTables => {
            if !disable_ipv6 {
                let veth_ifname = netns
                    .veth_pair
                    .as_ref()
                    .context("Veth pair not set while configuring IPv6 killswitch")?
                    .source
                    .as_str();

                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        &netns.name,
                        "output",
                        "oifname",
                        ifname,
                        "meta",
                        "l4proto",
                        "icmpv6",
                        "accept",
                    ],
                )
                .context("Allowing ICMPv6 through Wireguard in nftables")?;

                for icmpv6_type in ["nd-neighbor-solicit", "nd-neighbor-advert"] {
                    NetworkNamespace::exec(
                        &netns.name,
                        &[
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            &netns.name,
                            "output",
                            "oifname",
                            veth_ifname,
                            "icmpv6",
                            "type",
                            icmpv6_type,
                            "accept",
                        ],
                    )
                    .with_context(|| {
                        format!(
                            "Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname} in nftables"
                        )
                    })?;
                }
            }

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "oifname",
                    "!=",
                    ifname,
                    "mark",
                    "!=",
                    fwmark,
                    "fib",
                    "daddr",
                    "type",
                    "!=",
                    "local",
                    "counter",
                    "reject",
                ],
            )?;
        }
    }
    Ok(())
}

impl Drop for Wireguard {
    fn drop(&mut self) {
        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "ip",
            "link",
            "del",
            &self.if_name,
        ]) {
            Ok(_) => {}
            Err(e) => warn!(
                "Failed to delete ip link {}, {}: {:?}",
                self.ns_name, self.if_name, e
            ),
        };

        if let Firewall::NfTables = self.firewall {
            match sudo_command(&[
                "ip",
                "netns",
                "exec",
                &self.ns_name,
                "nft",
                "delete",
                "table",
                "inet",
                &self.ns_name,
            ]) {
                Ok(_) => {}
                Err(e) => warn!("Failed to delete nft table: {}: {:?}", self.ns_name, e),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks(values: &[&str]) -> Vec<IpNet> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn detects_default_routes_per_address_family() {
        let allowed_ips = networks(&["0.0.0.0/0", "fd00::/8"]);

        assert!(has_default_allowed_ip(&allowed_ips, true));
        assert!(!has_default_allowed_ip(&allowed_ips, false));

        let allowed_ips = networks(&["10.0.0.0/8", "::/0"]);

        assert!(!has_default_allowed_ip(&allowed_ips, true));
        assert!(has_default_allowed_ip(&allowed_ips, false));
    }

    #[test]
    fn split_tunnel_networks_have_no_default_route() {
        let allowed_ips = networks(&["10.0.0.0/8", "192.168.1.0/24", "fd00::/8"]);

        assert!(!has_default_allowed_ip(&allowed_ips, true));
        assert!(!has_default_allowed_ip(&allowed_ips, false));
    }

    #[test]
    fn endpoint_inside_allowed_ips_needs_bypass_route() {
        let allowed_ips = networks(&["192.168.1.0/24"]);

        assert!(endpoint_needs_bypass_route(
            "192.168.1.10".parse().unwrap(),
            &allowed_ips
        ));
        assert!(!endpoint_needs_bypass_route(
            "203.0.113.10".parse().unwrap(),
            &allowed_ips
        ));

        let default_allowed_ips = networks(&["0.0.0.0/0", "::/0"]);
        assert!(endpoint_needs_bypass_route(
            "203.0.113.10".parse().unwrap(),
            &default_allowed_ips
        ));
        assert!(endpoint_needs_bypass_route(
            "2001:db8::10".parse().unwrap(),
            &default_allowed_ips
        ));
    }

    #[test]
    fn selects_ipv4_for_dual_stack_endpoint() {
        let addresses = vec![
            "2001:db8::10".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
        ];

        assert_eq!(
            select_endpoint_ip(&addresses, false).unwrap(),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn uses_ipv6_when_it_is_the_only_endpoint_family() {
        let addresses = vec!["2001:db8::10".parse().unwrap()];

        assert_eq!(
            select_endpoint_ip(&addresses, false).unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_endpoint_is_rejected_when_ipv6_is_disabled() {
        let addresses = vec!["2001:db8::10".parse().unwrap()];

        assert!(select_endpoint_ip(&addresses, true).is_err());
    }
}
