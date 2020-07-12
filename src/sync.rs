use super::args::SynchCommand;
use super::util::config_dir;
use super::vpn::{Protocol, VpnProvider};
use super::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use anyhow::{anyhow, Context};
use dialoguer::Input;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::str::FromStr;

#[derive(Deserialize, Debug)]
struct AuthToken {
    auth_token: String,
}

#[derive(Deserialize, Debug)]
struct WgKey {
    public: String,
    private: String,
}

#[derive(Deserialize, Debug)]
struct WgPeer {
    key: WgKey,
    ipv4_address: ipnet::Ipv4Net,
    ipv6_address: ipnet::Ipv6Net,
    ports: Vec<u16>,
    can_add_ports: bool,
}

impl Display for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.key.public)
    }
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    max_ports: u8,
    active: bool,
    max_wg_peers: u8,
    can_add_wg_peers: bool,
    wg_peers: Vec<WgPeer>,
}

// TODO: use Json::Value to remove this?
#[derive(Deserialize, Debug)]
struct UserResponse {
    account: UserInfo,
}

#[derive(Deserialize, Debug)]
struct Relay {
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

pub fn synch(command: SynchCommand) -> anyhow::Result<()> {
    match (command.vpn_provider, command.protocol) {
        (VpnProvider::Mullvad, Some(Protocol::Wireguard)) => mullvad_wireguard(),
        _ => Err(anyhow!("Unimplemented!")),
    }
}

pub fn mullvad_wireguard() -> anyhow::Result<()> {
    // TODO: DRY
    let client = Client::new();
    let relays: Vec<Relay> = client
        .get("https://api.mullvad.net/www/relays/wireguard/")
        .send()?
        .json()?;

    // debug!("First relay: {:?}", relays.iter().next());

    let mut username = Input::<String>::new()
        .with_prompt("Mullvad account number")
        .interact()?;
    username.retain(|c| !c.is_whitespace() && c.is_digit(10));
    if username.len() != 16 {
        return Err(anyhow!(
            "Mullvad account number should be 16 digits!, parsed: {}",
            username
        ));
    }

    let auth: AuthToken = client
        .get(&format!(
            "https://api.mullvad.net/www/accounts/{}/",
            username
        ))
        .send()?
        .json()?;

    debug!("Received auth token: {:?}", auth);

    let user_info: UserResponse = client
        .get("https://api.mullvad.net/www/me/")
        .header(AUTHORIZATION, format!("Token {}", auth.auth_token))
        .send()?
        .json()?;

    let user_info = user_info.account;
    debug!("Received user info: {:?}", user_info);

    let keypair: WgKey = if !user_info.wg_peers.is_empty() {
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
            generate_keypair(&client, &auth.auth_token)?
        } else {
            let private_key = Input::<String>::new()
                .with_prompt(format!(
                    "Private key for {}",
                    user_info.wg_peers[selection].key.public
                ))
                .interact()?;

            let private_key = private_key.trim();

            if private_key.len() != 44 {
                return Err(anyhow!(
                    "Expected private key length of 44 characters, received {}",
                    private_key.len()
                ));
            }

            let public_key = generate_public_key(private_key)?;
            if public_key != user_info.wg_peers[selection].key.public {
                // TODO: Allow user to try again?
                return Err(anyhow!("Private key does not match public key",));
            }

            WgKey {
                public: user_info.wg_peers[selection].key.public.clone(),
                private: private_key.to_string(),
            }
        }
    } else {
        if dialoguer::Confirm::new()
            .with_prompt(
                "No Wireguard keys currently exist on your Mullvad account, would you like to generate a new keypair?"
            )
            .default(true)
            .interact()? {
                generate_keypair(&client, &auth.auth_token)?
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to Mullvad or let vopono generate one"))?
    }
    };

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
        .filter(|x| x.key.public == keypair.public)
        .next()
        .ok_or(anyhow!(
            "Did not find key: {} in Mullvad account",
            keypair.public
        ))?;

    // TODO: Hardcoded IP - can we scrape this anywhere?
    let dns = std::net::Ipv4Addr::new(193, 138, 218, 74);
    let interface = WireguardInterface {
        private_key: keypair.private.clone(),
        address: vec![
            IpNet::from(wg_peer.ipv4_address),
            IpNet::from(wg_peer.ipv6_address),
        ],
        dns: IpAddr::from(dns),
    };
    let port = 51820; // TODO: Allow port specification
    let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];
    let mut config_path = config_dir()?;
    config_path.push("vopono/mv/wireguard");
    std::fs::create_dir_all(&config_path)?;
    // Delete all files in directory
    config_path
        .read_dir()?
        .flatten()
        .map(|x| std::fs::remove_file(x.path()))
        .collect::<Result<Vec<()>, std::io::Error>>()?;
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
            .split("-")
            .next()
            .expect(&format!("Failed to split hostname: {}", relay.hostname));

        let country = relay.country_name.to_lowercase().replace(' ', "_");
        let mut path = config_path.clone();
        path.push(format!("{}-{}.conf", country, host));

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
    Ok(())
}

fn generate_keypair(client: &Client, auth_token: &str) -> anyhow::Result<WgKey> {
    // Generate new keypair
    let output = Command::new("wg").arg("genkey").output()?.stdout;
    let private_key = std::str::from_utf8(&output)?.trim().to_string();

    let public_key = generate_public_key(&private_key)?;
    let keypair = WgKey {
        public: public_key,
        private: private_key,
    };
    debug!("Generated keypair: {:?}", keypair);
    // Submit public key to Mullvad
    let mut map = HashMap::new();
    map.insert("pubkey", keypair.public.clone());
    client
        .post("https://api.mullvad.net/www/wg-pubkeys/add/")
        .header(AUTHORIZATION, format!("Token {}", auth_token))
        .json(&map)
        .send()?
        .error_for_status()
        .context("Failed to upload keypair to Mullvad")?;
    info!("Generated keypair submitted to Mullvad. Private key will be saved in generated config files.");
    Ok(keypair)
}

fn generate_public_key(private_key: &str) -> anyhow::Result<String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    {
        write!(child.stdin.as_mut().unwrap(), "{}", &private_key)?;
    }

    let output = child.wait_with_output()?.stdout;
    Ok(std::str::from_utf8(&output)?.trim().to_string())
}

// TODO:
// Mullvad OpenVPN:
// curl https://api.mullvad.net/www/relays/openvpn/
// Filter for active
// User pass is token from me request above (same as account ID), m is pass
//
// PIA: Parse https://www.privateinternetaccess.com/pages/network/
//
// TigerVPN: Parse https://www.tigervpn.com/dashboard/geeks but behind Captcha :(
