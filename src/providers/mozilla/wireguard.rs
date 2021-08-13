use super::validate_hostname;
use super::MozillaVPN;
use super::{Error, User};
use super::{Login, WireguardProvider};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey};
use crate::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use anyhow::anyhow;
use dialoguer::Input;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

impl MozillaVPN {
    fn upload_new_device(
        &self,
        device: &NewDevice,
        client: &Client,
        login: &Login,
    ) -> anyhow::Result<()> {
        let response = client
            .post(&format!("{}/vpn/device", self.base_url()))
            .bearer_auth(&login.token)
            .json(&device)
            .send()
            .unwrap();
        if response.status().is_success() {
            info!("New device uploaded to MozillaVPN");
            Ok(())
        } else {
            Err(anyhow!(
                "Failed to upload new device: {:?}",
                response.json::<Error>().unwrap()
            ))
        }
    }

    fn prompt_for_wg_key(
        &self,
        client: &Client,
        login: &Login,
    ) -> anyhow::Result<(NewDevice, WgKey)> {
        let devices = &login.user.devices;
        if !devices.is_empty() {
        let selection = dialoguer::Select::new()
            .with_prompt(
                "The following devices exist on your account, which would you like to use (you will need the private key)",
            )
            .items(devices)
            .item("Create a new device (keypair)")
            .default(0)
            .interact()?;

        if selection >= devices.len() {
            let (device, keypair) = generate_device()?;
            self.upload_new_device(&device, client, login)?;
            Ok((device, keypair))
        } else {
            let private_key = Input::<String>::new()
                .with_prompt(format!(
                    "Private key for {}",
                    &devices[selection].pubkey
                ))
        .validate_with(|private_key: &String| -> Result<(), &str> {
            let private_key = private_key.trim();
            if private_key.len() != 44 {
                return Err("Expected private key length of 44 characters"
                );
            }

            match generate_public_key(private_key) {
                Ok(public_key) => {
            if public_key.as_str() != devices[selection].pubkey {
                return Err("Private key does not match public key");
            }
            Ok(())
                }
                Err(_) => Err("Failed to generate public key")
        }})
                .interact()?;
            // TODO: Fix clones here
            let device = devices[selection].clone();
            Ok((NewDevice { name: device.name.clone(), pubkey: device.pubkey.clone()},
            WgKey {public: device.pubkey, private: private_key  } ))
        }
    } else if dialoguer::Confirm::new()
            .with_prompt(
                "No devices currently exist on your Mozilla account, would you like to generate a new device?"
            )
            .default(true)
            .interact()? {
                let (device, keypair) = generate_device()?;
                self.upload_new_device(&device, client, login)?;
                Ok((device, keypair))
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to MozillaVPN or let vopono generate one"))
    }
    }
}

impl WireguardProvider for MozillaVPN {
    fn create_wireguard_config(&self) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = reqwest::blocking::Client::builder()
            // Some operations fail when no User-Agent is present
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36")
            .build()
            .expect("Failed to build reqwest client for MozillaVPN");

        let relays: Vec<WireguardRelay> = client
            .get("https://api.mullvad.net/www/relays/wireguard/")
            .send()?
            .json()?;

        let login = self.get_login(&client)?;
        debug!("Received user info: {:?}", &login);

        let (_device, keypair) = self.prompt_for_wg_key(&client, &login)?;

        debug!("Chosen keypair: {:?}", keypair);

        // Get user info again in case we uploaded new key
        let user_info: User = client
            .get(&format!("{}/vpn/account", self.base_url()))
            .bearer_auth(login.token)
            .send()?
            .json()?;

        let wg_peer = user_info
            .devices
            .iter()
            .find(|x| x.pubkey == keypair.public)
            .ok_or_else(|| anyhow!("Did not find key: {} in MozillaVPN account", keypair.public))?;

        // TODO: Hardcoded IP - can we scrape this anywhere?
        let dns = std::net::Ipv4Addr::new(10, 64, 0, 1);
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![
                IpNet::from(wg_peer.ipv4_address),
                IpNet::from(wg_peer.ipv6_address),
            ],
            dns: vec![IpAddr::from(dns)],
        };

        let port = request_port()?;

        // Note we tunnel both IPv4 and IPv6
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
            "MozillaVPN Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}

fn generate_device() -> anyhow::Result<(NewDevice, WgKey)> {
    let keypair = generate_keypair()?;
    let name = Input::<String>::new()
        .with_prompt("Please enter name for new device")
        .validate_with(|x: &String| {
            if validate_hostname(x) {
                Ok(())
            } else {
                Err(anyhow!(
                    "Device name must can only contain letters, numbers and dashes"
                ))
            }
        })
        .interact()?;

    Ok((
        NewDevice {
            name,
            pubkey: keypair.public.clone(),
        },
        keypair,
    ))
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

#[derive(Serialize, Debug)]
struct NewDevice {
    name: String,
    pubkey: String,
}
