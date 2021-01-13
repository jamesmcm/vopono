use super::Mullvad;
use super::{AuthToken, UserInfo, UserResponse, WireguardProvider};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey};
use crate::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use anyhow::{anyhow, Context};
use dialoguer::Input;
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
            .header(AUTHORIZATION, format!("Token {}", auth_token))
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
    fn create_wireguard_config(&self) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = Client::new();
        let relays: Vec<WireguardRelay> = client
            .get("https://api.mullvad.net/www/relays/wireguard/")
            .send()?
            .json()?;

        let username = self.request_mullvad_username()?;
        let auth: AuthToken = client
            .get(&format!(
                "https://api.mullvad.net/www/accounts/{}/",
                username
            ))
            .send()?
            .json()?;

        let user_info: UserResponse = client
            .get("https://api.mullvad.net/www/me/")
            .header(AUTHORIZATION, format!("Token {}", auth.auth_token))
            .send()?
            .json()?;

        let user_info = user_info.account;
        debug!("Received user info: {:?}", user_info);

        let keypair: WgKey = prompt_for_wg_key(user_info, &client, &auth.auth_token)?;

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

fn prompt_for_wg_key(
    user_info: UserInfo,
    client: &Client,
    auth_token: &str,
) -> anyhow::Result<WgKey> {
    if !user_info.wg_peers.is_empty() {
        let selection = dialoguer::Select::new()
            .with_prompt(
                "The following Wireguard keys exist on your account, which would you like to use (you will need the private key)",
            )
            .items(&user_info.wg_peers)
            .item("Generate a new key pair")
            .default(0)
            .interact()?;

        if selection >= user_info.wg_peers.len() {
            if user_info.wg_peers.len() >= user_info.max_wg_peers as usize
                || !user_info.can_add_wg_peers
            {
                return Err(anyhow!("Cannot add more Wireguard keypairs to this account. Try to delete existing keypairs."));
            }
            let keypair = generate_keypair()?;
            Mullvad::upload_wg_key(&client, auth_token, &keypair)?;
            Ok(keypair)
        } else {
            let private_key = Input::<String>::new()
                .with_prompt(format!(
                    "Private key for {}",
                    &user_info.wg_peers[selection].key.public
                ))
        .validate_with(|private_key: &String| -> Result<(), &str> {

            let private_key = private_key.trim();

            if private_key.len() != 44 {
                return Err("Expected private key length of 44 characters"
                );
            }

            match generate_public_key(private_key) {
                Ok(public_key) => {
            if public_key != user_info.wg_peers[selection].key.public {
                return Err("Private key does not match public key");
            }
            Ok(())
                }
                Err(_) => Err("Failed to generate public key")
        }})
                .interact()?;


            Ok(WgKey {
                public: user_info.wg_peers[selection].key.public.clone(),
                private: private_key,
            })
        }
    } else if dialoguer::Confirm::new()
            .with_prompt(
                "No Wireguard keys currently exist on your Mullvad account, would you like to generate a new keypair?"
            )
            .default(true)
            .interact()? {
                let keypair = generate_keypair()?;
                Mullvad::upload_wg_key(client, auth_token, &keypair)?;
                Ok(keypair)
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to Mullvad or let vopono generate one"))
    }
}

fn request_port() -> anyhow::Result<u16> {
    let port = Input::<u16>::new()
        .with_prompt("Enter port number:")
        .validate_with(|n: &u16| -> Result<(), &str> {
            if *n == 53
                || (*n >= 4000 && *n <= 33433)
                || (*n >= 33565 && *n <= 51820)
                || (*n >= 52000 && *n <= 60000)
            {
                Ok(())
            } else {
                Err("
        Port must be 53, or in range 4000-33433, 33565-51820, 52000-60000")
            }
        })
        .default(51820)
        .interact()?;
    Ok(port)
}
