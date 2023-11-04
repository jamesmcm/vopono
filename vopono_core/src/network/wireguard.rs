use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use crate::util::sudo_command;
use anyhow::{anyhow, Context};
use ipnet::IpNet;
use log::{debug, error, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
pub struct Wireguard {
    ns_name: String,
    config_file: PathBuf,
    firewall: Firewall,
    if_name: String,
}

impl Wireguard {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        namespace: &mut NetworkNamespace,
        config_file: PathBuf,
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
        dns: Option<&Vec<IpAddr>>,
        hosts_entries: Option<&Vec<String>>,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("wg") {
            error!("wg binary not found. Is wireguard-tools installed and on PATH?");
            return Err(anyhow!(
                "wg binary not found. Is wireguard-tools installed and on PATH?: {:?}",
                x
            ));
        }

        let config_string = std::fs::read_to_string(&config_file)
            .context(format!("Reading Wireguard config file: {:?}", &config_file))?;
        // Create temp conf file
        {
            // TODO: Maybe properly parse ini format

            // Valid keys for wireguard config (see wg(8):CONFIGURATION FILE FORMAT)
            let allow_keys = [
                "PrivateKey",
                "ListenPort",
                "FwMark",
                "PublicKey",
                "PresharedKey",
                "AllowedIPs",
                "Endpoint",
                "PersistentKeepalive",
            ];

            let mut f = std::fs::File::create("/tmp/vopono_nft.conf")
                .context("Creating file: /tmp/vopono_nft.conf")?;
            write!(
                f,
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
        }
        // TODO: Avoid hacky regex for valid toml
        let re = Regex::new(
            r"(?m)^[[:blank:]]*(?P<key>[^\s=#]+)[[:blank:]]*=[[:blank:]]*(?P<value>[^\r\n#]+?)[[:blank:]]*(?:#[^\r\n]*)?\r?$",
        )?;
        let mut config_string = re
            .replace_all(&config_string, "$key = \"$value\"")
            .to_string();
        config_string.push('\n');
        let config: WireguardConfig = toml::from_str(&config_string)
            .map_err(anyhow::Error::from)
            .with_context(|| {
                format!(
                    "Failed while converting Wireguard config to TOML. Result may be malformed:\n\n{config_string}"
                )
            })?;
        debug!("TOML config: {:?}", config);
        // TODO: Use bs58 here?
        let if_name = namespace.name
            [((namespace.name.len() as i32) - 13).max(0) as usize..namespace.name.len()]
            .to_string();
        assert!(if_name.len() <= 15, "ifname must be <= 15 chars: {if_name}");

        NetworkNamespace::exec(
            &namespace.name,
            &["ip", "link", "add", &if_name, "type", "wireguard"],
        )?;

        NetworkNamespace::exec(
            &namespace.name,
            &["wg", "setconf", &if_name, "/tmp/vopono_nft.conf"],
        )
        .context("Failed to run wg setconf - is wireguard-tools installed?")?;
        std::fs::remove_file("/tmp/vopono_nft.conf")
            .context("Deleting file: /tmp/vopono_nft.conf")
            .ok();
        // Extract addresses
        for address in config.interface.address.iter() {
            match address {
                IpNet::V6(address) => {
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

        // TODO: Handle custom MTU
        NetworkNamespace::exec(
            &namespace.name,
            &["ip", "link", "set", "mtu", "1420", "up", "dev", &if_name],
        )?;

        let dns: Vec<IpAddr> = dns
            .cloned()
            .or_else(|| config.interface.dns.clone())
            .unwrap_or_else(|| {
                warn!("Found no DNS settings in Wireguard config, using 8.8.8.8");
                vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
            });
        // TODO: DNS suffixes?
        namespace.dns_config(&dns, &[], hosts_entries)?;
        let fwmark = "51820";
        NetworkNamespace::exec(&namespace.name, &["wg", "set", &if_name, "fwmark", fwmark])?;

        // IPv4 routes
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip",
                "-4",
                "route",
                "add",
                "0.0.0.0/0",
                "dev",
                &if_name,
                "table",
                fwmark,
            ],
        )?;
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
            ],
        )?;
        NetworkNamespace::exec(
            &namespace.name,
            &[
                "ip",
                "-4",
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        )?;
        sudo_command(&["sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1"])?;
        // IPv6
        if disable_ipv6 {
            crate::network::firewall::disable_ipv6(namespace, firewall)?;
        } else {
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "ip", "-6", "route", "add", "::/0", "dev", &if_name, "table", fwmark,
                ],
            )?;
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "ip", "-6", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
                ],
            )?;
            NetworkNamespace::exec(
                &namespace.name,
                &[
                    "ip",
                    "-6",
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?;
        }

        match firewall {
            Firewall::NfTables => {
                // nft
                let nftable = namespace.name.clone();
                let pf = "inet";
                let mut nftcmd: Vec<String> = Vec::with_capacity(16);
                nftcmd.push(format!("add table {} {}", pf, &nftable));
                nftcmd.push(format!(
                    "add chain {} {} preraw {{ type filter hook prerouting priority -300; }}",
                    pf, &nftable
                ));
                nftcmd.push(format!(
                    "add chain {} {} premangle {{ type filter hook prerouting priority -150; }}",
                    pf, &nftable
                ));
                nftcmd.push(format!(
                    "add chain {} {} postmangle {{ type filter hook prerouting priority -150; }}",
                    pf, &nftable
                ));

                for address in config.interface.address.iter() {
                    match address {
                        IpNet::V6(address) => {
                            nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &if_name, "ip6", address
            ));
                        }

                        IpNet::V4(address) => {
                            nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &if_name, "ip", address
            ));
                        }
                    }
                }

                nftcmd.push(format!(
                    "add rule {} {} postmangle meta l4proto udp mark {} ct mark set mark",
                    pf, &nftable, fwmark
                ));
                nftcmd.push(format!(
                    "add rule {} {} premangle meta l4proto udp meta mark set ct mark",
                    pf, &nftable
                ));

                let nftcmd = nftcmd.join("\n");
                {
                    let mut f = std::fs::File::create("/tmp/vopono_nft.sh")
                        .context("Creating file: /tmp/vopono_nft.sh")?;
                    write!(f, "{nftcmd}")?;
                }

                NetworkNamespace::exec(&namespace.name, &["nft", "-f", "/tmp/vopono_nft.sh"])?;
                std::fs::remove_file("/tmp/vopono_nft.sh")
                    .context("Deleting file: /tmp/vopono_nft.sh")
                    .ok();
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

        if use_killswitch {
            killswitch(&if_name, fwmark, namespace, firewall)?;
        }
        Ok(Self {
            config_file,
            ns_name: namespace.name.clone(),
            firewall,
            if_name,
        })
    }
}

pub fn killswitch(
    ifname: &str,
    fwmark: &str,
    netns: &NetworkNamespace,
    firewall: Firewall,
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
            .context("Executing ip6tables")?;

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
        Firewall::NfTables => {
            NetworkNamespace::exec(&netns.name, &["nft", "add", "table", "inet", &netns.name])
                .context("Executing nft")?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    &netns.name,
                    "output",
                    "{ type filter hook output priority -500 ; policy accept; }",
                ],
            )?;
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
                &self.ns_name, &self.if_name, e
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

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Address", deserialize_with = "de_vec_ipnet")]
    pub address: Vec<IpNet>,
    #[serde(rename = "DNS", deserialize_with = "de_vec_ipaddr")]
    pub dns: Option<Vec<IpAddr>>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "AllowedIPs", deserialize_with = "de_vec_ipnet")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(rename = "Endpoint", deserialize_with = "de_socketaddr")]
    pub endpoint: SocketAddr,
    #[serde(rename = "PersistentKeepalive")]
    pub keepalive: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    pub interface: WireguardInterface,
    #[serde(rename = "Peer")]
    pub peer: WireguardPeer,
}

impl TryInto<String> for WireguardConfig {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<String, Self::Error> {
        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        let mut toml = toml::to_string(&self)?;
        toml.retain(|c| c != '"');
        let toml = toml.replace(", ", ",");
        Ok(re.replace_all(&toml, "= $value").to_string())
    }
}

impl FromStr for WireguardConfig {
    type Err = anyhow::Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        // TODO: Avoid hacky regex for valid toml
        let re = Regex::new(
            r"(?m)^[[:blank:]]*(?P<key>[^\s=#]+)[[:blank:]]*=[[:blank:]]*(?P<value>[^\r\n#]+?)[[:blank:]]*(?:#[^\r\n]*)?\r?$",
        )?;
        let mut config_string = re
            .replace_all(config_string, "$key = \"$value\"")
            .to_string();
        config_string.push('\n');
        toml::from_str(&config_string)
            .map_err(anyhow::Error::from)
            .with_context(|| {
                format!(
                    "Failed while converting Wireguard config to TOML. Result may be malformed:\n\n{config_string}"
                )
            })
    }
}

pub fn de_vec_ipnet<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // serde::de::value::StringDeserializer::deserialize_string(deserializer)?;
    let raw = String::deserialize(deserializer)?;
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpNet>())
        .collect::<Result<Vec<IpNet>, ipnet::AddrParseError>>()
    {
        Ok(x) => Ok(x),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpNet deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_vec_ipaddr<'de, D>(deserializer: D) -> Result<Option<Vec<IpAddr>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = match String::deserialize(deserializer) {
        Ok(s) => s,
        Err(e) => {
            debug!("Missing optional DNS field in Wireguard config - serde");
            debug!("serde: {:?}", e);
            return Ok(None);
        }
    };
    debug!("Deserializing: {} to Vec<IpAddr>", raw);
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpAddr>())
        .collect::<Result<Vec<IpAddr>, _>>()
    {
        Ok(x) => Ok(Some(x)),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_socketaddr<'de, D>(deserializer: D) -> Result<std::net::SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.trim().to_socket_addrs() {
        Ok(mut x) => Ok(x.next().unwrap()),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}
