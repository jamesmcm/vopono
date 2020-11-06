use super::ConfigurationChoice;
use super::WireguardProvider;
use super::IVPN;
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey};
use crate::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use anyhow::{anyhow, Context};
use dialoguer::Input;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

enum WgKeyChoice {
    NewKey,
    ExistingKey,
}

impl Display for WgKeyChoice {}
impl ConfigurationChoice for WgKeyChoice {}

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

        // WgKeyChoice
        let keypair: WgKey = prompt_for_wg_key(user_info, &client, &auth.auth_token)?;

        // TODO: Hardcoded IP - can we scrape this anywhere?
        // The IP address of the standard DNS server is 172.16.0.1.
        // The AntiTracker DNS address is 10.0.254.2.
        // The AntiTracker's Hardcore Mode DNS address is 10.0.254.3.
        let dns = std::net::Ipv4Addr::new(172, 16, 0, 1);
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![
                IpNet::from(wg_peer.ipv4_address),
                IpNet::from(wg_peer.ipv6_address),
            ],
            dns: vec![IpAddr::from(dns)],
        };

        let port = request_port()?;

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];

        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for relay in relays.iter().filter(|x| x.active) {
            let wireguard_peer = WireguardPeer {
                public_key: relay.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: SocketAddr::new(IpAddr::from(relay.ipv4_addr_in), port),
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };

            let host = relay
                .hostname
                .split('-')
                .next()
                .unwrap_or_else(|| panic!("Failed to split hostname: {}", relay.hostname));

            let country = relay.country_name.to_lowercase().replace(' ', "_");
            let path = wireguard_dir.join(format!("{}-{}.conf", country, host));

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
            "Mullvad Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct WireguardRelay {
    country_string: String,
    hostname: String,
    ip: IpAddr,
    pubkey: String,
}

fn request_port() -> anyhow::Result<u16> {
    // UDP 2049
    // UDP 2050
    // UDP 53
    // UDP 30587
    // UDP 41893
    // UDP 48574
    // UDP 58237
    let port = Input::<u16>::new()
        .with_prompt("Enter port number:")
        .validate_with(|x: &str| -> Result<(), &str> {
            let p = x.parse::<u16>();
            match p {
                Ok(n) => {
                    if n == 53
                        || (n >= 4000 && n <= 33433)
                        || (n >= 33565 && n <= 51820)
                        || (n >= 52000 && n <= 60000)
                    {
                        Ok(())
                    } else {
                        Err("
        Port must be 53, or in range 4000-33433, 33565-51820, 52000-60000")
                    }
                }
                Err(_) => Err("Invalid number"),
            }
        })
        .default(51820)
        .interact()?;
    Ok(port)
}
