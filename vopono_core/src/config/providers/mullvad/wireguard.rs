use super::Mullvad;
use super::{AuthToken, UserInfo, UserResponse, WireguardProvider};
use crate::config::providers::{BoolChoice, ConfigurationChoice, Input, InputNumericu16, UiClient};
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey, WgPeer};
use anyhow::{anyhow, Context};
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

impl Mullvad {
    fn upload_wg_key(client: &Client, auth_token: &str, keypair: &WgKey) -> anyhow::Result<()> {
        let mut map = HashMap::new();
        map.insert("pubkey", keypair.public.clone());
        client
            .post("https://api.mullvad.net/www/wg-pubkeys/add/")
            .header(AUTHORIZATION, format!("Token {auth_token}"))
            .json(&map)
            .send()?
            .error_for_status()
            .context("Failed to upload keypair to Mullvad")?;
        info!(
            "Public key submitted to Mullvad. Private key will be saved in generated config files."
        );
        Ok(())
    }
}

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

        let username = self.request_mullvad_username(uiclient)?;
        let auth: AuthToken = client
            .get(&format!("https://api.mullvad.net/www/accounts/{username}/"))
            .send()?
            .json()?;

        let user_info: UserResponse = client
            .get("https://api.mullvad.net/www/me/")
            .header(AUTHORIZATION, format!("Token {}", auth.auth_token))
            .send()?
            .json()?;

        let user_info = user_info.account;
        debug!("Received user info: {:?}", user_info);

        let keypair: WgKey = prompt_for_wg_key(user_info, &client, &auth.auth_token, uiclient)?;

        debug!("Chosen keypair: {:?}", keypair);
        // Get user info again in case we uploaded new key
        let user_info: UserResponse = client
            .get("https://api.mullvad.net/www/me/")
            .header(AUTHORIZATION, format!("Token {}", auth.auth_token))
            .send()?
            .json()?;

        let user_info = user_info.account;
        let wg_peer = user_info
            .wg_peers
            .iter()
            .find(|x| x.key.public == keypair.public)
            .ok_or_else(|| anyhow!("Did not find key: {} in Mullvad account", keypair.public))?;

        // TODO: Hardcoded IP - can we scrape this anywhere?
        let dns = std::net::Ipv4Addr::new(193, 138, 218, 74);
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![
                IpNet::from(wg_peer.ipv4_address),
                IpNet::from(wg_peer.ipv6_address),
            ],
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

            let host = relay
                .hostname
                .split('-')
                .next()
                .unwrap_or_else(|| panic!("Failed to split hostname: {}", relay.hostname));

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
    socks_name: String,
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

fn prompt_for_wg_key(
    user_info: UserInfo,
    client: &Client,
    auth_token: &str,
    uiclient: &dyn UiClient,
) -> anyhow::Result<WgKey> {
    if !user_info.wg_peers.is_empty() {
        let existing = Devices { devices: user_info.wg_peers.clone()};

        let selection = uiclient.get_configuration_choice(&existing)?;

        if selection >= user_info.wg_peers.len() {
            if user_info.wg_peers.len() >= user_info.max_wg_peers as usize
                || !user_info.can_add_wg_peers
            {
                return Err(anyhow!("Cannot add more Wireguard keypairs to this account. Try to delete existing keypairs."));
            }
            let keypair = generate_keypair()?;
            Mullvad::upload_wg_key(client, auth_token, &keypair)?;
            Ok(keypair)
        } else {
            let pubkey_clone =  user_info.wg_peers[selection].key.public.clone();
            let private_key = uiclient.get_input(Input{
                    prompt: format!("Private key for {}",
                    &user_info.wg_peers[selection].key.public
                ),
        validator: Some(Box::new(move |private_key: &String| -> Result<(), String> {

            let private_key = private_key.trim();

            if private_key.len() != 44 {
                return Err("Expected private key length of 44 characters".to_string()
                );
            }

            match generate_public_key(private_key) {
                Ok(public_key) => {
            if public_key != pubkey_clone {
                return Err("Private key does not match public key".to_string());
            }
            Ok(())
                }
                Err(_) => Err("Failed to generate public key".to_string())
        }}))})?;


            Ok(WgKey {
                public: user_info.wg_peers[selection].key.public.clone(),
                private: private_key,
            })
        }
    } else if uiclient.get_bool_choice(BoolChoice{
            prompt:
                "No Wireguard keys currently exist on your Mullvad account, would you like to generate a new keypair?".to_string(),
            default: true,
    })?
             {
                let keypair = generate_keypair()?;
                Mullvad::upload_wg_key(client, auth_token, &keypair)?;
                Ok(keypair)
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to Mullvad or let vopono generate one"))
    }
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
