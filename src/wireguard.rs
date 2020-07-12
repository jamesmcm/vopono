use super::netns::NetworkNamespace;
use super::util::{config_dir, sudo_command};
use super::vpn::VpnProvider;
use anyhow::anyhow;
use ipnet::IpNet;
use log::{debug, info, warn};
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use walkdir::WalkDir;
#[derive(Serialize, Deserialize)]
pub struct Wireguard {
    ns_name: String,
    config_file: PathBuf,
}

// TODO: Add killswitch support:
//
// PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
// PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

impl Wireguard {
    pub fn run(namespace: &mut NetworkNamespace, config_file: PathBuf) -> anyhow::Result<Self> {
        let config_string = std::fs::read_to_string(&config_file)?;
        // Create temp conf file
        {
            let skip_keys = vec![
                "Address",
                "DNS",
                "MTU",
                "Table",
                "PreUp",
                "PreDown",
                "PostUp",
                "PostDown",
                "SaveConfig",
            ];

            let mut f = std::fs::File::create("/tmp/vopono_nft.conf")?;
            write!(
                f,
                "{}",
                config_string
                    .split('\n')
                    .filter(|x| !skip_keys.contains(&x.split_whitespace().next().unwrap_or("")))
                    .collect::<Vec<&str>>()
                    .join("\n")
            )?;
        }
        // TODO: Avoid hacky regex for valid toml
        let re = Regex::new(r"(?P<key>[^\s]+) = (?P<value>[^\s]+)")?;
        let mut config_string = re
            .replace_all(&config_string, "$key = \"$value\"")
            .to_string();
        config_string.push('\n');
        let config: WireguardConfig = toml::from_str(&config_string)?;
        debug!("TOML config: {:?}", config);
        let if_name = format!("{}", &namespace.name[7..namespace.name.len().min(20)]);
        assert!(
            if_name.len() <= 15,
            "ifname must be <= 15 chars: {}",
            if_name
        );

        namespace.exec(&["ip", "link", "add", &if_name, "type", "wireguard"])?;

        namespace.exec(&["wg", "setconf", &if_name, "/tmp/vopono_nft.conf"])?;
        std::fs::remove_file("/tmp/vopono_nft.conf")?;
        // Extract addresses
        for address in config.interface.address.iter() {
            match address {
                IpNet::V6(address) => {
                    namespace.exec(&[
                        "ip",
                        "-6",
                        "address",
                        "add",
                        &address.to_string(),
                        "dev",
                        &if_name,
                    ])?;
                }
                IpNet::V4(address) => {
                    namespace.exec(&[
                        "ip",
                        "-4",
                        "address",
                        "add",
                        &address.to_string(),
                        "dev",
                        &if_name,
                    ])?;
                }
            }
        }

        // TODO: Handle custom MTU
        namespace.exec(&["ip", "link", "set", "mtu", "1420", "up", "dev", &if_name])?;

        namespace.dns_config(&[config.interface.dns])?;
        let fwmark = "51820";
        namespace.exec(&["wg", "set", &if_name, "fwmark", fwmark])?;

        // TODO: Handle case where ipv6 is disabled
        // IPv6
        namespace.exec(&[
            "ip", "-6", "route", "add", "::/0", "dev", &if_name, "table", fwmark,
        ])?;
        namespace.exec(&[
            "ip", "-6", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
        ])?;
        namespace.exec(&[
            "ip",
            "-6",
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ])?;

        // nft ipv6
        let nftable = namespace.name.clone();
        let pf = "ip6";
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

        // IPv4 handled below - TODO: DRY
        for address in config.interface.address.iter() {
            if let IpNet::V6(address) = address {
                nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &if_name, pf, address
            ));
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
            let mut f = std::fs::File::create("/tmp/vopono_nft.sh")?;
            write!(f, "{}", nftcmd)?;
        }

        namespace.exec(&["nft", "-f", "/tmp/vopono_nft.sh"])?;
        std::fs::remove_file("/tmp/vopono_nft.sh")?;

        // IPv4
        namespace.exec(&[
            "ip",
            "-4",
            "route",
            "add",
            "0.0.0.0/0",
            "dev",
            &if_name,
            "table",
            fwmark,
        ])?;
        namespace.exec(&[
            "ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
        ])?;
        namespace.exec(&[
            "ip",
            "-4",
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ])?;
        sudo_command(&["sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1"])?;

        //nft ipv4  -TODO: DRY
        let nftable = namespace.name.clone();
        let pf = "ip";
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
            if let IpNet::V4(address) = address {
                nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &if_name, pf, address
            ));
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
            let mut f = std::fs::File::create("/tmp/vopono_nft.sh")?;
            write!(f, "{}", nftcmd)?;
        }

        namespace.exec(&["nft", "-f", "/tmp/vopono_nft.sh"])?;
        std::fs::remove_file("/tmp/vopono_nft.sh")?;
        Ok(Self {
            config_file,
            ns_name: namespace.name.clone(),
        })
    }
}

impl Drop for Wireguard {
    fn drop(&mut self) {
        // TODO: Handle case of only ipv4
        let if_name = format!("{}", &self.ns_name[7..self.ns_name.len().min(20)]);
        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "ip",
            "link",
            "del",
            &if_name,
        ]) {
            Ok(_) => {}
            Err(e) => warn!("Failed to delete ip link {}: {:?}", &self.ns_name, e),
        };

        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "nft",
            "delete",
            "table",
            "ip",
            &self.ns_name,
        ]) {
            Ok(_) => {}
            Err(e) => warn!("Failed to delete nft ipv4 table: {}: {:?}", self.ns_name, e),
        };

        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "nft",
            "delete",
            "table",
            "ip6",
            &self.ns_name,
        ]) {
            Ok(_) => {}
            Err(e) => warn!("Failed to delete nft ipv6 table: {}: {:?}", self.ns_name, e),
        };
    }
}

pub fn get_config_from_alias(provider: &VpnProvider, alias: &str) -> anyhow::Result<PathBuf> {
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/wireguard", provider.alias()));

    // TODO: Make this more resilient (i.e. missing - etc.)
    let paths = WalkDir::new(&list_path)
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
        .filter(|x| {
            x.path().is_file()
                && x.path().extension().is_some()
                && x.path().extension().expect("No file extension") == "conf"
        })
        .map(|x| {
            (
                x.clone(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split('-')
                    .next()
                    .expect("No - in filename")
                    .to_string(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split('-')
                    .nth(1)
                    .expect("No - in filename")
                    .to_string(),
            )
        })
        .filter(|x| x.2.starts_with(alias) || (x.1 != "mullvad" && x.1.starts_with(alias)))
        .map(|x| PathBuf::from(x.0.path()))
        .collect::<Vec<PathBuf>>();

    if paths.is_empty() {
        Err(anyhow!(
            "Could not find Wireguard config file for alias {}",
            &alias
        ))
    } else {
        let config = paths
            .choose(&mut rand::thread_rng())
            .expect("Could not find Wireguard config");

        info!("Chosen Wireguard config: {}", config.display());
        Ok(config.clone())
    }
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Address", deserialize_with = "de_vec_ipnet")]
    pub address: Vec<IpNet>,
    #[serde(rename = "DNS")]
    pub dns: IpAddr,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "AllowedIPs", deserialize_with = "de_vec_ipnet")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(rename = "Endpoint")]
    pub endpoint: SocketAddr,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    pub interface: WireguardInterface,
    #[serde(rename = "Peer")]
    pub peer: WireguardPeer,
}

fn de_vec_ipnet<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // serde::de::value::StringDeserializer::deserialize_string(deserializer)?;
    let raw = String::deserialize(deserializer)?;
    let strings = raw.split(',');
    match strings
        .map(|x| x.parse::<IpNet>())
        .collect::<Result<Vec<IpNet>, ipnet::AddrParseError>>()
    {
        Ok(x) => Ok(x),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpNet deserialisation error: {:?}",
            x
        ))),
    }
}
