use super::args::SynchCommand;
use super::util::config_dir;
use super::util::set_config_permissions;
use super::vpn::OpenVpnProtocol;
use super::vpn::VpnServer;
use super::vpn::{Protocol, VpnProvider};
use super::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use anyhow::{anyhow, bail, Context};
use dialoguer::{Input, MultiSelect};
use ipnet::IpNet;
use log::{debug, error, info};
use rand::seq::SliceRandom;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::include_str;
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

#[derive(Deserialize, Debug)]
struct OpenVpnRelay {
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
}

pub fn sync_menu() -> anyhow::Result<()> {
    let variants = VpnProvider::variants()
        .iter()
        .filter(|x| **x != "Custom")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();

    let selection = MultiSelect::new()
        .with_prompt("Which VPN providers do you wish to synchronise? Press Space to select and Enter to continue")
        .items(variants.as_slice())
        .interact()?;

    if selection.is_empty() {
        bail!("Must choose at least one VPN provider to sync");
    }

    // TODO: Allow for overriding default port here
    for provider in selection
        .into_iter()
        .map(|x| VpnProvider::from_str(&variants[x]))
        .flatten()
    {
        synch(SynchCommand {
            vpn_provider: Some(provider),
            protocol: None,
            port: None,
        })?;
    }

    Ok(())
}

pub fn synch(command: SynchCommand) -> anyhow::Result<()> {
    match (command.vpn_provider, command.protocol) {
        (None, _) => sync_menu(),
        (Some(VpnProvider::Mullvad), Some(Protocol::Wireguard)) => mullvad_wireguard(command.port),
        (Some(VpnProvider::Mullvad), Some(Protocol::OpenVpn)) => mullvad_openvpn(command.port),
        (Some(VpnProvider::Mullvad), None) => {
            mullvad_openvpn(command.port)?;
            mullvad_wireguard(command.port)
        }
        (Some(VpnProvider::PrivateInternetAccess), Some(Protocol::OpenVpn)) => {
            pia_openvpn(command.port)
        }
        (Some(VpnProvider::PrivateInternetAccess), None) => pia_openvpn(command.port),
        (Some(VpnProvider::PrivateInternetAccess), Some(Protocol::Wireguard)) => Err(anyhow!(
            "Wireguard is not supported for PrivateInternetAccess"
        )),
        (Some(VpnProvider::TigerVpn), Some(Protocol::OpenVpn)) => tig_openvpn(command.port),
        (Some(VpnProvider::TigerVpn), None) => tig_openvpn(command.port),
        (Some(VpnProvider::TigerVpn), Some(Protocol::Wireguard)) => {
            Err(anyhow!("Wireguard is not supported for TigerVPN"))
        }
        _ => Err(anyhow!("Unimplemented!")),
    }?;
    set_config_permissions()?;
    Ok(())
}

pub fn mullvad_openvpn(port: Option<u16>) -> anyhow::Result<()> {
    let mullvad_alias = VpnProvider::Mullvad.alias();

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", mullvad_alias));
    std::fs::create_dir_all(list_path)?;

    let client = Client::new();
    let relays: Vec<OpenVpnRelay> = client
        .get("https://api.mullvad.net/www/relays/openvpn/")
        .send()?
        .json()?;

    let default_ports = vec![1300, 1301, 1302, 1194, 1195, 1196, 1197];
    let protocol = if port.is_some() {
        if default_ports.contains(port.as_ref().unwrap()) || port == Some(53) {
            Ok(OpenVpnProtocol::UDP)
        } else if port == Some(80) || port == Some(443) {
            Ok(OpenVpnProtocol::TCP)
        } else {
            error!("Mullvad OpenVPN port must be one of [1300, 1301, 1302, 1194, 1195, 1196, 1197, 53] for UDP or [80, 443] for TCP");
            Err(anyhow!("Mullvad OpenVPN port must be one of [1300, 1301, 1302, 1194, 1195, 1196, 1197, 53] for UDP or [80, 443] for TCP"))
        }
    } else {
        Ok(OpenVpnProtocol::UDP)
    }?;

    let mut output: Vec<VpnServer> = Vec::with_capacity(relays.len());
    for relay in relays.into_iter().filter(|x| x.active) {
        let mut alias = String::with_capacity(16);
        let mut alias_iter = relay
            .hostname
            .split('.')
            .next()
            .expect("No . in hostname")
            .split('-');
        alias.push_str(alias_iter.next().expect("No - in hostname"));
        alias.push_str(alias_iter.next().expect("No - in hostname"));
        alias.push_str(
            alias_iter
                .next()
                .expect("No . in hostname")
                .trim_start_matches('0'),
        );

        let port = port.unwrap_or_else(|| {
            *default_ports
                .choose(&mut rand::thread_rng())
                .expect("Could not choose default port")
        });
        output.push(VpnServer {
            name: relay.country_name.to_lowercase().replace(' ', "_"),
            alias,
            host: format!("{}.mullvad.net", relay.hostname),
            port: Some(port),
            protocol: Some(protocol.clone()),
        });
    }

    // Write serverlist
    // TODO: DRY
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/serverlist.csv", mullvad_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }

    {
        let file = File::create(&list_path).context("Could not create mullvad serverlist")?;
        let write_buf = std::io::BufWriter::new(file);
        let mut csv_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(write_buf);

        output
            .into_iter()
            .map(|x| csv_writer.serialize(x))
            .collect::<Result<(), csv::Error>>()?;
    }

    // Copy CA cert
    let ca = include_str!("static/mullvad_ca.crt");

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/mullvad_ca.crt", mullvad_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }

    {
        let file = File::create(&list_path).context("Could not create mullvad CA file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", ca)?;
    }

    // Check and write auth file
    // let mut list_path = config_dir()?;
    // list_path.push(format!("vopono/{}/openvpn/auth.txt", mullvad_alias));
    // if list_path.exists() {
    //     std::fs::remove_file(&list_path)?;
    // }
    // {
    //     // TODO: handle case when syncing both to avoid requesting username twice
    //     let username = request_mullvad_username()?;
    //     let file = File::create(&list_path).context("Could not create mullvad auth file")?;
    //     let mut write_buf = std::io::BufWriter::new(file);
    //     write!(write_buf, "{}\nm", username)?;
    // }

    // Write conf file
    let mullvad_conf = include_str!("static/mullvad_openvpn.conf");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/mullvad.conf", mullvad_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file = File::create(&list_path).context("Could not create mullvad conf file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", mullvad_conf)?;
    }

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", mullvad_alias));
    info!("Mullvad OpenVPN config written to {}", list_path.display());

    Ok(())
}

pub fn request_mullvad_username() -> anyhow::Result<String> {
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
    Ok(username)
}

pub fn mullvad_wireguard(port: Option<u16>) -> anyhow::Result<()> {
    // TODO: DRY
    let mullvad_alias = VpnProvider::Mullvad.alias();

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/wireguard", mullvad_alias));
    std::fs::create_dir_all(list_path)?;

    let client = Client::new();
    let relays: Vec<Relay> = client
        .get("https://api.mullvad.net/www/relays/wireguard/")
        .send()?
        .json()?;

    // debug!("First relay: {:?}", relays.iter().next());
    let username = request_mullvad_username()?;
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
    } else if dialoguer::Confirm::new()
            .with_prompt(
                "No Wireguard keys currently exist on your Mullvad account, would you like to generate a new keypair?"
            )
            .default(true)
            .interact()? {
                generate_keypair(&client, &auth.auth_token)?
        } else {
            return Err(anyhow!("Wireguard requires a keypair, either upload one to Mullvad or let vopono generate one"))
    }
    ;

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
        dns: IpAddr::from(dns),
    };

    let port = if let Some(x) = port {
        if x == 53
            || (x >= 4000 && x <= 33433)
            || (x >= 33565 && x <= 51820)
            || (x >= 52000 && x <= 60000)
        {
            Ok(x)
        } else {
            Err(anyhow!("Invalid port number for Mullvad Wireguard: {}. Port must be 53, 4000-33433, 33565-51820 or 52000-60000."))
        }
    } else {
        Ok(51820)
    }?;

    let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];
    let mut config_path = config_dir()?;
    config_path.push(format!("vopono/{}/wireguard", mullvad_alias));
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
            .split('-')
            .next()
            .unwrap_or_else(|| panic!("Failed to split hostname: {}", relay.hostname));

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

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/wireguard", mullvad_alias));
    info!(
        "Mullvad Wireguard config written to {}",
        list_path.display()
    );
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

pub fn pia_openvpn(port: Option<u16>) -> anyhow::Result<()> {
    let pia_alias = VpnProvider::PrivateInternetAccess.alias();

    // TODO: DRY
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", pia_alias));
    std::fs::create_dir_all(list_path)?;

    let client = Client::new();
    let relays: String = client
        .get("https://www.privateinternetaccess.com/pages/network/")
        .send()?
        .text()?;

    let protocol = if port.is_some() {
        if port == Some(1198) {
            Ok(OpenVpnProtocol::UDP)
        } else if port == Some(502) {
            Ok(OpenVpnProtocol::TCP)
        } else if port == Some(501) || port == Some(1197) {
            // TODO: Support changing cipher based on port + provider
            Err(anyhow!("PrivateInternetAccess ports 501 and 1197 require a stronger cipher, this is not currently supported unless you modify the generated configuration files manually"))
        } else if port == Some(8080) || port == Some(443) {
            // TODO: Support changing cipher based on port + provider
            Err(anyhow!("PrivateInternetAccess ports 8080 and 443 use a legacy cipher, this is not currently supported unless you modify the generated configuration files manually"))
        } else {
            Err(anyhow!(
                "PrivateInternetAccess OpenVPN ports must be either 1198 for UDP or 502 for TCP"
            ))
        }
    } else {
        Ok(OpenVpnProtocol::UDP)
    }?;

    // TODO: Don't parse HTML with regex
    let name_regex = Regex::new("class=\"subregionname\">(?P<name>[a-zA-Z\\s]+)</p>")?;
    let host_regex = Regex::new("class=\"hostname\">(?P<host>[a-zA-Z\\.\\-]+)</p>")?;

    let names: Vec<String> = name_regex
        .captures_iter(&relays)
        .map(|x| x["name"].to_string())
        .collect();
    let hosts: Vec<String> = host_regex
        .captures_iter(&relays)
        .map(|x| x["host"].to_string())
        .collect();

    let mut output: Vec<VpnServer> = Vec::with_capacity(names.len());
    for (host, name) in hosts.into_iter().zip(names) {
        let alias = host
            .split('.')
            .next()
            .expect("No . in hostname")
            .to_string();

        let port = port.unwrap_or(1198);

        output.push(VpnServer {
            name: if name.contains(':') {
                alias.clone()
            } else {
                name.to_lowercase().replace(' ', "_")
            },
            alias,
            host,
            port: Some(port),
            protocol: Some(protocol.clone()),
        });
    }

    // Write serverlist
    // TODO: DRY
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/serverlist.csv", pia_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }

    {
        let file = File::create(&list_path).context("Could not create PIA serverlist")?;
        let write_buf = std::io::BufWriter::new(file);
        let mut csv_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(write_buf);

        output
            .into_iter()
            .map(|x| csv_writer.serialize(x))
            .collect::<Result<(), csv::Error>>()?;
    }

    // Write configs
    let pia_conf = include_str!("static/pia_openvpn.conf");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/client.conf", pia_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file = File::create(&list_path).context("Could not create PIA OpenVPN conf file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", pia_conf)?;
    }

    let pia_conf = include_str!("static/pia_ca.rsa.2048.crt");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/ca.rsa.2048.crt", pia_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file = File::create(&list_path).context("Could not create PIA OpenVPN CA file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", pia_conf)?;
    }

    let pia_conf = include_str!("static/pia_crl.rsa.2048.pem");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/crl.rsa.2048.pem", pia_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file = File::create(&list_path).context("Could not create PIA OpenVPN PEM file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", pia_conf)?;
    }

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", pia_alias));
    info!(
        "PrivateInternetAccess OpenVPN config written to {}",
        list_path.display()
    );
    Ok(())
}

// TigerVPN: Parse https://www.tigervpn.com/dashboard/geeks but behind Captcha :(
// For now use static list
pub fn tig_openvpn(port: Option<u16>) -> anyhow::Result<()> {
    let tig_alias = VpnProvider::TigerVpn.alias();

    // TODO: DRY
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", tig_alias));
    std::fs::create_dir_all(list_path)?;

    let protocol = if port.is_some() {
        if port == Some(1194) {
            Ok(OpenVpnProtocol::UDP)
        } else if port == Some(443) {
            Ok(OpenVpnProtocol::TCP)
        } else {
            Err(anyhow!(
                "TigerVPN OpenVPN ports must be either 1194 for UDP or 443 for TCP"
            ))
        }
    } else {
        Ok(OpenVpnProtocol::UDP)
    }?;

    let tig_list = include_str!("static/tig_serverlist.csv");
    let mut output: Vec<VpnServer> = Vec::with_capacity(16);
    for line in tig_list.trim_end().split('\n') {
        let mut iter = line.split(',');
        let country = iter.next().expect("No country").to_string();
        let alias = iter.next().expect("No alias").to_string();
        let host = iter.next().expect("No host").to_string();

        let port = port.unwrap_or(1194);

        output.push(VpnServer {
            name: country,
            alias,
            host,
            port: Some(port),
            protocol: Some(protocol.clone()),
        });
    }

    // Write serverlist
    // TODO: DRY
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/serverlist.csv", tig_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }

    {
        let file = File::create(&list_path).context("Could not create TigerVPN serverlist")?;
        let write_buf = std::io::BufWriter::new(file);
        let mut csv_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(write_buf);

        output
            .into_iter()
            .map(|x| csv_writer.serialize(x))
            .collect::<Result<(), csv::Error>>()?;
    }

    // Write configs
    let tig_conf = include_str!("static/tig_ca.crt");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/ca.crt", tig_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file = File::create(&list_path).context("Could not create TigerVPN CA file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", tig_conf)?;
    }

    let tig_conf = include_str!("static/tig_openvpn.conf");
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn/config.ovpn", tig_alias));
    if list_path.exists() {
        std::fs::remove_file(&list_path)?;
    }
    {
        let file =
            File::create(&list_path).context("Could not create TigerVPN OpenVPN config file")?;
        let mut write_buf = std::io::BufWriter::new(file);
        write!(write_buf, "{}", tig_conf)?;
    }

    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/openvpn", tig_alias));
    info!("TigerVPN OpenVPN config written to {}", list_path.display());
    Ok(())
}
