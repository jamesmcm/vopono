use super::validate_hostname;
use super::Device;
use super::MozillaVPN;
use super::{Error, User};
use super::{Login, WireguardProvider};
use crate::config::providers::BoolChoice;
use crate::config::providers::ConfigurationChoice;
use crate::config::providers::Input;
use crate::config::providers::InputNumericu16;
use crate::config::providers::UiClient;
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, generate_public_key, WgKey};
use anyhow::anyhow;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client; // TODO: Can we use a smaller dependency?
use serde::{Deserialize, Serialize};
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

struct Devices {
    devices: Vec<Device>,
}

impl ConfigurationChoice for Devices {
    fn prompt(&self) -> String {
        "The following devices exist on your account, which would you like to use (you will need the private key)".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.devices.iter().map(|x| x.name.clone()).collect();
        v.push("Create a new device (keypair)".to_string());
        v
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        None
    }

    fn description(&self) -> Option<String> {
        None
    }
}

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
        uiclient: &dyn UiClient,
    ) -> anyhow::Result<(NewDevice, WgKey)> {
        let devices = &login.user.devices;
        if !devices.is_empty() {
        let selection = uiclient.get_configuration_choice(&Devices{devices: devices.clone()})?;

        if selection >= devices.len() {
            let (device, keypair) = generate_device(uiclient)?;
            self.upload_new_device(&device, client, login)?;
            Ok((device, keypair))
        } else {
            let pubkey_clone = devices[selection].pubkey.clone();
            let private_key = uiclient.get_input(Input {
               prompt:format!(
                    "Private key for {}",
                    &devices[selection].pubkey
                ),
        validator: Some(Box::new( move |private_key: &String| -> Result<(), String> {
            let private_key = private_key.trim();
            if private_key.len() != 44 {
                return Err("Expected private key length of 44 characters".to_string()
                );
            }

            match generate_public_key(private_key) {
                Ok(public_key) => {
            if public_key.as_str() != pubkey_clone {
                return Err("Private key does not match public key".to_string());
            }
            Ok(())
                }
                Err(_) => Err("Failed to generate public key".to_string())
        }}))})?;
            // TODO: Fix clones here
            let device = devices[selection].clone();
            Ok((NewDevice { name: device.name.clone(), pubkey: device.pubkey.clone()},
            WgKey {public: device.pubkey, private: private_key  } ))
        }
    } else if uiclient.get_bool_choice(BoolChoice {
                prompt: "No devices currently exist on your Mozilla account, would you like to generate a new device?".to_string(),
                default: true,
    })?
             {
                let (device, keypair) = generate_device(uiclient)?;
                self.upload_new_device(&device, client, login)?;
                Ok((device, keypair))
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to MozillaVPN or let vopono generate one"))
    }
    }
}

impl WireguardProvider for MozillaVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
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

        let (_device, keypair) = self.prompt_for_wg_key(&client, &login, uiclient)?;

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
            dns: Some(vec![IpAddr::from(dns)]),
        };

        let port = request_port(uiclient)?;

        // Note we tunnel both IPv4 and IPv6
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

fn generate_device(uiclient: &dyn UiClient) -> anyhow::Result<(NewDevice, WgKey)> {
    let keypair = generate_keypair()?;
    let name = uiclient.get_input(Input {
        prompt: "Please enter name for new device".to_string(),
        validator: Some(Box::new(|x: &String| {
            if validate_hostname(x) {
                Ok(())
            } else {
                Err("Device name must can only contain letters, numbers and dashes".to_string())
            }
        })),
    })?;

    Ok((
        NewDevice {
            name,
            pubkey: keypair.public.clone(),
        },
        keypair,
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

#[derive(Serialize, Debug)]
struct NewDevice {
    name: String,
    pubkey: String,
}
