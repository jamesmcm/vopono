use super::Mullvad;
use super::WireguardProvider;
use crate::config::providers::{ConfigurationChoice, Input, InputNumericu16, UiClient};
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_public_key, WgKey, WgPeer};
use anyhow::Context;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

impl WireguardProvider for Mullvad {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = Client::new();
        let relays: Vec<WireguardRelay> = client
            .get("https://api.mullvad.net/www/relays/wireguard/")
            .send()?
            .json().with_context(|| "Failed to parse Mullvad relays response - try again after a few minutes or report an issue if it is persistent")?;

        let (keypair, ipv4_net, ipv6_net) = prompt_for_wg_key(uiclient)?;

        debug!("Chosen keypair: {:?}", keypair);

        // TODO: Hardcoded IP - can we scrape this anywhere?
        let dns = std::net::Ipv4Addr::new(193, 138, 218, 74);
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![ipv4_net, ipv6_net],
            dns: Some(vec![IpAddr::from(dns)]),
        };

        let port = request_port(uiclient)?;

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];

        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for relay in relays.iter().filter(|x| x.active) {
            let wireguard_peer = WireguardPeer {
                public_key: relay.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: SocketAddr::new(IpAddr::from(relay.ipv4_addr_in), port),
                keepalive: None,
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };

            let host = if relay.hostname.chars().filter(|c| *c == '-').count() > 1 {
                // New naming convention -  at-vie-wg-001
                let substrings: Vec<&str> = relay.hostname.split('-').collect();

                substrings[0].to_owned() + substrings[1] + substrings[3]
            } else {
                // Old naming convention - au10-wireguard
                relay
                    .hostname
                    .split('-')
                    .next()
                    .unwrap_or_else(|| panic!("Failed to split hostname: {}", relay.hostname))
                    .to_owned()
            };

            let country = relay.country_name.to_lowercase().replace(' ', "_");
            let path = wireguard_dir.join(format!("{country}-{host}.conf"));

            let mut toml = toml::to_string(&wireguard_conf)?;
            toml.retain(|c| c != '"');
            let toml = toml.replace(", ", ",");
            let toml = re.replace_all(&toml, "= $value").to_string();
            // Create file, write TOML
            {
                let mut f = std::fs::File::create(path)?;
                write!(f, "{toml}")?;
            }
        }

        info!(
            "Mullvad Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct WireguardRelay {
    hostname: String,
    country_code: String,
    country_name: String,
    city_code: String,
    city_name: String,
    active: bool,
    owned: bool,
    provider: String,
    ipv4_addr_in: std::net::Ipv4Addr,
    ipv6_addr_in: std::net::Ipv6Addr,
    pubkey: String,
    multihop_port: u16,
}

struct Devices {
    devices: Vec<WgPeer>,
}

impl ConfigurationChoice for Devices {
    fn prompt(&self) -> String {
        "The following Wireguard keys exist on your account, which would you like to use (you will need the private key)".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.devices.iter().map(|x| x.to_string()).collect();
        v.push("Generate a new keypair".to_string());
        v
    }

    fn all_descriptions(&self) -> Option<Vec<String>> {
        None
    }
    fn description(&self) -> Option<String> {
        None
    }
}

fn prompt_for_wg_key(uiclient: &dyn UiClient) -> anyhow::Result<(WgKey, IpNet, IpNet)> {
    // TODO: We could also generate new private key first - generate_keypair()
    let private_key = uiclient.get_input(Input {
        prompt: "Enter your Wireguard Private key and upload the Public Key as a Mullvad device"
            .to_owned(),
        validator: Some(Box::new(
            move |private_key: &String| -> Result<(), String> {
                let private_key = private_key.trim();

                if private_key.len() != 44 {
                    Err("Expected private key length of 44 characters".to_string())
                } else {
                    Ok(())
                }
            },
        )),
    })?;

    let ipv4_address = IpNet::from_str(&uiclient.get_input(Input {
        prompt: "Enter the IPv4 address range Mullvad returned after adding the device".to_owned(),
        validator: Some(Box::new(move |_ip: &String| -> Result<(), String> {
            // TODO: Ipv4 range validator
            Ok(())
        })),
    })?)?;

    let ipv6_address = IpNet::from_str(&uiclient.get_input(Input {
        prompt: "Enter the IPv6 address range Mullvad returned after adding the device".to_owned(),
        validator: Some(Box::new(move |_ip: &String| -> Result<(), String> {
            // TODO: Ipv4 range validator
            Ok(())
        })),
    })?)?;

    Ok((
        WgKey {
            public: generate_public_key(&private_key).expect("Failed to generate public key"),
            private: private_key,
        },
        ipv4_address,
        ipv6_address,
    ))
}

fn request_port(uiclient: &dyn UiClient) -> anyhow::Result<u16> {
    let port = uiclient.get_input_numeric_u16(InputNumericu16 {
        prompt: "Enter port number".to_string(),
        validator: Some(Box::new(|n: &u16| -> Result<(), String> {
            if *n == 53
                || (*n >= 4000 && *n <= 33433)
                || (*n >= 33565 && *n <= 51820)
                || (*n >= 52000 && *n <= 60000)
            {
                Ok(())
            } else {
                Err("
        Port must be 53, or in range 4000-33433, 33565-51820, 52000-60000"
                    .to_string())
            }
        })),
        default: Some(51820),
    })?;
    Ok(port)
}
