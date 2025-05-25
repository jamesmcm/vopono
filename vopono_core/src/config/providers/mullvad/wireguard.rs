use super::Mullvad;
use super::WireguardProvider;
use crate::config::providers::BoolChoice;
use crate::config::providers::mullvad::AccessToken;
use crate::config::providers::mullvad::Device;
use crate::config::providers::mullvad::UserInfo;
use crate::config::providers::{ConfigurationChoice, Input, InputNumericu16, UiClient};
use crate::network::wireguard::WireguardEndpoint;
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::generate_keypair;
use crate::util::wireguard::{WgKey, generate_public_key};
use anyhow::{Context, anyhow};
use chrono::DateTime;
use chrono::Utc;
use ipnet::IpNet;
use log::warn;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PrivateDevice {
    public_key: String,
    private_key: String,
    ipv4_address: String,
    ipv6_address: String,
}

impl PrivateDevice {
    fn from_device(device: &Device, private_key: &str) -> Self {
        PrivateDevice {
            public_key: device.pubkey.clone(),
            private_key: private_key.to_owned(),
            ipv4_address: device.ipv4_address.clone(),
            ipv6_address: device.ipv6_address.clone(),
        }
    }
}

impl Mullvad {
    fn upload_wg_key(
        client: &Client,
        access_token: &str,
        keypair: &WgKey,
    ) -> anyhow::Result<Device> {
        let mut map = HashMap::new();
        map.insert("pubkey", keypair.public.clone());
        let device: Device = client
            .post("https://api.mullvad.net/accounts/v1/devices")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .json(&map)
            .send()
            .context("Failed to upload keypair to Mullvad")?
            .error_for_status()?
            .json()?;
        info!(
            "Public key {} submitted to Mullvad. Private key will be saved in generated config files.",
            &keypair.public
        );
        Ok(device)
    }

    fn prompt_for_wg_key(&self, uiclient: &dyn UiClient) -> anyhow::Result<(WgKey, IpNet, IpNet)> {
        // - Get or upload keypair from/to Mullvad
        //   - List existing keys
        //     - Create new keypair and upload (save keypair locally too)
        //     - Choose key and enter private key (validate that is valid for this public key)
        // - Enter previously uploaded keypair manually

        let use_automatic = uiclient.get_bool_choice(BoolChoice {
            prompt: "Handle Mullvad key upload automatically?".to_string(),
            default: true,
        })?;

        if use_automatic {
            let client = Client::new();
            let username = self.request_mullvad_username(uiclient)?;

            let mut map = HashMap::new();
            map.insert("account_number", username.clone());

            let auth: AccessToken = client
                .post("https://api.mullvad.net/auth/v1/token".to_owned())
                .json(&map)
                .send()?
                .json()?;

            let user_info: UserInfo = client
                .get("https://api.mullvad.net/accounts/v1/accounts/me")
                .header(AUTHORIZATION, format!("Bearer {}", &auth.access_token))
                .send()?
                .json()?;

            // Warn if account expired
            match DateTime::parse_from_rfc3339(&user_info.expiry) {
                Ok(datetime) => {
                    let datetime_utc = datetime.with_timezone(&Utc);
                    if datetime_utc <= Utc::now() {
                        warn!("Mullvad account expired on {}", &user_info.expiry);
                    }
                }
                Err(e) => warn!("Could not parse Mullvad account expiry date: {e}"),
            }

            debug!("Received user info: {user_info:?}");

            let existing_devices: Vec<Device> = client
                .get("https://api.mullvad.net/accounts/v1/devices")
                .header(AUTHORIZATION, format!("Bearer {}", &auth.access_token))
                .send()?
                .json()?;

            if !existing_devices.is_empty() {
        let existing = Devices { devices: existing_devices.clone()};

        let selection = uiclient.get_configuration_choice(&existing)?;

        if selection >= existing_devices.len() {
            if existing_devices.len() >= user_info.max_devices as usize
                || !user_info.can_add_devices
            {
                return Err(anyhow!("Cannot add more Wireguard keypairs to this account. Try to delete existing keypairs."));
            }
            let keypair = generate_keypair()?;
            let dev = Mullvad::upload_wg_key(&client, &auth.access_token, &keypair)?;

            // Save keypair
            let path = self.wireguard_dir()?.join("wireguard_device.json");
            {
                let mut f = std::fs::File::create(path.clone())?;
                write!(f, "{}", serde_json::to_string(&PrivateDevice::from_device(&dev, &keypair.private))?)?;
            }
            info!("Saved Wireguard keypair details to {}", &path.to_string_lossy());

            Ok((keypair, IpNet::from_str(&dev.ipv4_address).expect("Invalid IPv4 address"), IpNet::from_str(&dev.ipv6_address).expect("Invalid IPv6 address")))
        } else {
            let dev = existing_devices[selection].clone();
            let pubkey_clone = dev.pubkey.clone();

            let private_key = uiclient.get_input(Input{
                    prompt: format!("Private key for {}",
                    &existing.devices[selection].pubkey
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
            Ok(())}
                Err(_) => Err("Failed to generate public key".to_string())
 }}))})?;

            // Save keypair
            let path = self.wireguard_dir()?.join("wireguard_device.json");
            {
                let mut f = std::fs::File::create(path.clone())?;
                write!(f, "{}", serde_json::to_string(&PrivateDevice::from_device(&dev, &private_key))?)?;
            }
            info!("Saved Wireguard keypair details to {}", &path.to_string_lossy());


 Ok((WgKey {
                public: dev.pubkey.clone(),
                private: private_key,
            },
        IpNet::from_str(&dev.ipv4_address).expect("Invalid IPv4 address"), IpNet::from_str(&dev.ipv6_address).expect("Invalid IPv6 address"))
        )
        }
    } else if uiclient.get_bool_choice(BoolChoice{
            prompt:
                "No Wireguard keys currently exist on your Mullvad account, would you like to generate a new keypair?".to_string(),
            default: true,
    })?
             {
                let keypair = generate_keypair()?;
                let dev = Mullvad::upload_wg_key(&client, &auth.access_token, &keypair)?;

           // Save keypair
            let path = self.wireguard_dir()?.join("wireguard_device.json");
            {
                let mut f = std::fs::File::create(path.clone())?;
                write!(f, "{}", serde_json::to_string(&PrivateDevice::from_device(&dev, &keypair.private))?)?;
            }
            info!("Saved Wireguard keypair details to {}", &path.to_string_lossy());

                Ok((keypair, IpNet::from_str(&dev.ipv4_address).expect("Invalid IPv4 address"), IpNet::from_str(&dev.ipv6_address).expect("Invalid IPv6 address")))
        } else {
            Err(anyhow!("Wireguard requires a keypair, either upload one to Mullvad or let vopono generate one"))
    }
        } else {
            let manual_dev = get_manually_entered_keypair(uiclient)?;
            // Save keypair
            let path = self.wireguard_dir()?.join("wireguard_device.json");
            {
                let mut f = std::fs::File::create(path.clone())?;
                write!(
                    f,
                    "{}",
                    serde_json::to_string(&PrivateDevice {
                        public_key: manual_dev.0.public.clone(),
                        private_key: manual_dev.0.private.clone(),
                        ipv4_address: manual_dev.1.to_string(),
                        ipv6_address: manual_dev.2.to_string()
                    })?
                )?;
            }
            info!(
                "Saved Wireguard keypair details to {}",
                &path.to_string_lossy()
            );
            Ok(manual_dev)
        }
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

        let (keypair, ipv4_net, ipv6_net) = self.prompt_for_wg_key(uiclient)?;

        debug!("Chosen keypair: {keypair:?}");

        // TODO: Fix this with endpoint-specific DNS - unfortunately this is not simply the first address in the IpNet
        let dns = std::net::Ipv4Addr::new(8, 8, 8, 8);

        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![ipv4_net, ipv6_net],
            dns: Some(vec![IpAddr::from(dns)]),
            mtu: Some(1420.to_string()),
        };

        let port = request_port(uiclient)?;

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];

        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for relay in relays.iter().filter(|x| x.active) {
            let wireguard_peer = WireguardPeer {
                public_key: relay.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: WireguardEndpoint::IpWithPort(SocketAddr::new(
                    IpAddr::from(relay.ipv4_addr_in),
                    port,
                )),
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
    devices: Vec<Device>,
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
fn get_manually_entered_keypair(uiclient: &dyn UiClient) -> anyhow::Result<(WgKey, IpNet, IpNet)> {
    // Manual keypair entry
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
