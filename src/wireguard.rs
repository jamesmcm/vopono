use super::netns::NetworkNamespace;
use super::util::sudo_command;
use anyhow::{anyhow, Context};
use ipnet::IpNet;
use log::{debug, error, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Wireguard {
    ns_name: String,
    config_file: PathBuf,
}

impl Wireguard {
    pub fn run(
        namespace: &mut NetworkNamespace,
        config_file: PathBuf,
        use_killswitch: bool,
        forward_ports: Option<&Vec<u16>>,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("wg") {
            error!("wg binary not found. Is wireguard-tools installed and on PATH?");
            return Err(anyhow!(
                "wg binary not found. Is wireguard-tools installed and on PATH?: {:?}",
                x
            ));
        }

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
        let if_name = namespace.name[7..namespace.name.len().min(20)].to_string();
        assert!(
            if_name.len() <= 15,
            "ifname must be <= 15 chars: {}",
            if_name
        );

        namespace.exec(&["ip", "link", "add", &if_name, "type", "wireguard"])?;

        namespace
            .exec(&["wg", "setconf", &if_name, "/tmp/vopono_nft.conf"])
            .context("Failed to run wg setconf - is wireguard-tools installed?")?;
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

        namespace.dns_config(&config.interface.dns)?;
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

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            super::util::open_ports(&namespace, forwards.as_slice())?;
        }

        if use_killswitch {
            killswitch(&if_name, fwmark, namespace)?;
        }
        Ok(Self {
            config_file,
            ns_name: namespace.name.clone(),
        })
    }
}

pub fn killswitch(ifname: &str, fwmark: &str, netns: &NetworkNamespace) -> anyhow::Result<()> {
    debug!("Setting Wireguard killswitch....");
    netns.exec(&[
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
    ])?;

    netns.exec(&[
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
    ])?;
    Ok(())
}

impl Drop for Wireguard {
    fn drop(&mut self) {
        // TODO: Handle case of only ipv4
        let if_name = &self.ns_name[7..self.ns_name.len().min(20)];
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

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Address", deserialize_with = "de_vec_ipnet")]
    pub address: Vec<IpNet>,
    #[serde(rename = "DNS", deserialize_with = "de_vec_ipaddr")]
    pub dns: Vec<IpAddr>,
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

pub fn de_vec_ipaddr<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    debug!("Deserializing: {} to Vec<IpAddr>", raw);
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpAddr>())
        .collect::<Result<Vec<IpAddr>, _>>()
    {
        Ok(x) => Ok(x),
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
