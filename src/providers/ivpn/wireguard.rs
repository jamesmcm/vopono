use super::ConfigurationChoice;
use super::WireguardProvider;
use super::IVPN;
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey};
use crate::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use dialoguer::Input;
use ipnet::{IpNet, Ipv4Net};
use log::info;
use regex::Regex;
use serde::Deserialize;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(EnumIter, PartialEq)]
enum WgKeyChoice {
    NewKey,
    ExistingKey,
}

impl Display for WgKeyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NewKey => "Generate new Wireguard keypair",
            Self::ExistingKey => "Enter existing Wireguard keypair (keys page: https://www.ivpn.net/clientarea/vpn/273887/wireguard/keys )",
        };
        write!(f, "{}", s)
    }
}
impl Default for WgKeyChoice {
    fn default() -> Self {
        Self::NewKey
    }
}

impl ConfigurationChoice for WgKeyChoice {
    fn prompt() -> String {
        "Do you want to generate a new Wireguard keypair or use an existing one?".to_string()
    }

    fn variants() -> Vec<Self> {
        WgKeyChoice::iter().collect()
    }
    fn description(&self) -> Option<String> {
        None
    }
}

// TODO: Hardcoded IPs - can we scrape this anywhere?
// The IP address of the standard DNS server is 172.16.0.1.
// The AntiTracker DNS address is 10.0.254.2.
// The AntiTracker's Hardcore Mode DNS address is 10.0.254.3.
#[derive(EnumIter, PartialEq)]
enum DNSChoice {
    Standard,
    AntiTracker,
    AntiTrackerHardcore,
}

impl Display for DNSChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Standard => "Standard DNS",
            Self::AntiTracker => "AntiTracker DNS (block some advertising and tracking domains)",
            Self::AntiTrackerHardcore => {
                "AntiTracker Hardcore Mode DNS (block above plus social media trackers)"
            }
        };
        write!(f, "{}", s)
    }
}
impl Default for DNSChoice {
    fn default() -> Self {
        Self::Standard
    }
}

impl ConfigurationChoice for DNSChoice {
    fn prompt() -> String {
        "Choose DNS server configuration".to_string()
    }

    fn variants() -> Vec<Self> {
        DNSChoice::iter().collect()
    }
    fn description(&self) -> Option<String> {
        None
    }
}

impl DNSChoice {
    fn to_ipv4(&self) -> Ipv4Addr {
        match self {
            Self::Standard => Ipv4Addr::new(172, 16, 0, 1),
            Self::AntiTracker => Ipv4Addr::new(10, 0, 254, 2),
            Self::AntiTrackerHardcore => Ipv4Addr::new(10, 0, 254, 3),
        }
    }
}

impl WireguardProvider for IVPN {
    fn create_wireguard_config(&self) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let relays_str = include_str!("./ivpn_wg_hosts.csv");
        let mut reader = csv::Reader::from_reader(relays_str.as_bytes());
        let mut relays = Vec::new();
        for record in reader.deserialize() {
            let relay: WireguardRelay = record?;
            relays.push(relay);
        }

        let wg_key_choice = WgKeyChoice::choose_one()?;
        let keypair: WgKey = if wg_key_choice == WgKeyChoice::ExistingKey {
            prompt_for_wg_key()?
        } else {
            let keypair = generate_keypair()?;
            info!("Generated Wireguard keypair (save this): {:?}", &keypair);
            info!("Please upload public key {} to https://www.ivpn.net/clientarea/vpn/273887/wireguard/keys", &keypair.public);
            keypair
        };

        let ip_address = Input::<String>::new()
            .with_prompt(format!("Enter the IP address linked to this public key ({})\nSee https://www.ivpn.net/clientarea/vpn/273887/wireguard/keys ", &keypair.public))
            .validate_with(move |ipstr: &str| -> Result<(), String> {
                let ip_parse = Ipv4Addr::from_str(ipstr.trim());
                if let Err(err) = ip_parse {
                    return Err(format!("Input: {} is not valid IPv4 address: {}", ipstr.trim(), err));
                };
                if let Ok(ip) = ip_parse {
                    if ip.octets()[0] != 172 {
                        return Err(format!("IP address: {} did not start with expected octet 172", ipstr.trim()));
                    }
                }
                Ok(())
            }).interact()?;

        let ip_address = Ipv4Addr::from_str(ip_address.trim())?;
        let ipnet = IpNet::from(Ipv4Net::new(ip_address, 32)?);
        let dns_choice = DNSChoice::choose_one()?;
        let dns = dns_choice.to_ipv4();
        let interface = WireguardInterface {
            private_key: keypair.private,
            address: vec![ipnet],
            dns: vec![IpAddr::from(dns)],
        };

        let port = request_port()?;

        // IPv6 not supported for Wireguard on iVPN
        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?];

        let code_map = crate::util::country_map::code_to_country_map();
        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for relay in relays.iter() {
            let wireguard_peer = WireguardPeer {
                public_key: relay.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: SocketAddr::new(relay.ip, port),
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };

            let mut strsplit = relay.country.split('-');
            let country_code = strsplit.next().unwrap();
            let city = strsplit.next().unwrap();
            let country_name = code_map
                .get(country_code)
                .unwrap_or_else(|| panic!("Could not find code in map: {}", country_code));

            let path =
                wireguard_dir.join(format!("{}-{}-{}.conf", country_name, country_code, city));

            let mut toml = toml::to_string(&wireguard_conf)?;
            toml.retain(|c| c != '"');
            let toml = toml.replace(", ", ",");
            let toml = re.replace_all(&toml, "= $value").to_string();
            // Create file, write TOML
            {
                let mut f = std::fs::File::create(path)?;
                write!(f, "{}", toml)?;
            }
        }

        info!(
            "iVPN Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}

fn prompt_for_wg_key() -> anyhow::Result<WgKey> {
    let public_key = Input::<String>::new()
        .with_prompt("Enter Wireguard public key")
        .validate_with(move |public_key: &str| -> Result<(), &str> {
            let public_key = public_key.trim();
            if public_key.len() != 44 {
                return Err("Expected private key length of 44 characters");
            }
            Ok(())
        })
        .interact()?;

    let closure_pubkey = public_key.clone();
    let private_key = Input::<String>::new()
        .with_prompt(format!("Private key for {}", &public_key))
        .validate_with(move |private_key: &str| -> Result<(), &str> {
            let private_key = private_key.trim();

            if private_key.len() != 44 {
                return Err("Expected private key length of 44 characters");
            }

            match generate_public_key(private_key) {
                Ok(pubkey) => {
                    if pubkey != closure_pubkey {
                        return Err("Private key does not match public key");
                    }
                    Ok(())
                }
                Err(_) => Err("Failed to generate public key"),
            }
        })
        .interact()?;

    Ok(WgKey {
        public: public_key,
        private: private_key,
    })
}

#[derive(Deserialize, Debug)]
struct WireguardRelay {
    country: String,
    hostname: String,
    ip: IpAddr,
    pubkey: String,
}

fn request_port() -> anyhow::Result<u16> {
    // https://www.ivpn.net/setup/gnu-linux-wireguard.html
    let port = Input::<u16>::new()
        .with_prompt("Enter port number:")
        .validate_with(|x: &str| -> Result<(), &str> {
            let p = x.parse::<u16>();
            match p {
                Ok(n) => {
                    if [2049,2050,53,30587,41893,48574,58237].contains(&n)                    {
                        Ok(())
                    } else {
                        Err("Port must be one of: 2049,2050,53,30587,41893,48574,58237 (see https://www.ivpn.net/setup/gnu-linux-wireguard.html for ports reference)")
                    }
                }
                Err(_) => Err("Invalid number"),
            }
        })
        .default(41893)
        .interact()?;
    Ok(port)
}
