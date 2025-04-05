use super::{AzireVPN, ExistingDeviceResponseData};
use super::{DeviceResponse, LocationsResponse, WireguardProvider};
use crate::config::providers::azirevpn::{
    ExistingDevicesResponse, LocationResponse, ReplaceKeyResponse, UserProfileResponse,
};
use crate::config::providers::{BoolChoice, UiClient};
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::country_map::code_to_country_map;
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{WgKey, generate_keypair, generate_public_key};
use anyhow::Context;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

impl AzireVPN {
    fn upload_wg_key(
        &self,
        keypair: &WgKey,
        token: &str,
        client: &Client,
    ) -> anyhow::Result<WireguardInterface> {
        let device_response: DeviceResponse = client
            .post("https://api.azirevpn.com/v2/ip/add")
            .form(&[("key", keypair.public.as_str()), ("token", token)])
            .send()?
            .json()?;

        debug!("device_response: {:?}", &device_response);

        let v4_net = IpNet::new(
            IpAddr::V4(Ipv4Addr::from_str(&device_response.ipv4.address)?),
            device_response.ipv4.netmask,
        )?;
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![v4_net],
            dns: Some(device_response.dns),
        };

        Ok(interface)
    }

    // Replaces all keys for the given device
    fn replace_wg_key(
        &self,
        device: &ExistingDeviceResponseData,
        keypair: &WgKey,
        token: &str,
        client: &Client,
    ) -> anyhow::Result<WireguardInterface> {
        let replace_key_response: ReplaceKeyResponse = client
            .put(format!(
                "https://api.azirevpn.com/v3/ips/{}/keys",
                device.id
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({ "key": keypair.public }))
            .send()?
            .json()
            .with_context(|| "Deserialisation of ReplaceKeyResponse failed")?;

        debug!("replace_key_response: {:?}", &replace_key_response);

        // Look up new device details
        // TODO: This fails with a 500 internal error - for now just use all devices list
        // debug!("Getting details for device ID: {}", id);
        // let existing_device_response: ExistingDeviceResponse = client
        //     .get(format!("https://api.azirevpn.com/v3/ips/{}", id))
        //     .bearer_auth(token)
        //     .send()?
        //     .json()
        //     .with_context(|| "Deserialisation of ExistingDeviceResponse failed")?;

        // debug!("existing_device_response: {:?}", &existing_device_response);

        let v4_net = IpNet::new(
            IpAddr::V4(Ipv4Addr::from_str(&device.ipv4_address)?),
            device.ipv4_netmask,
        )?;
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![v4_net],
            dns: Some(device.dns.clone()),
        };

        Ok(interface)
    }
}

impl WireguardProvider for AzireVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = Client::new();

        let country_map = code_to_country_map();
        // TODO: Allow user to specify existing device and provide private key

        // This creates an API token for the user if we do not have one cached
        let token = self.get_access_token(uiclient)?;
        // TODO: Check account is active and credentials okay
        let user_profile_response: UserProfileResponse = client
            .get("https://api.azirevpn.com/v3/users/me")
            .header("Authorization", format!("Bearer {}", token))
            .send()?
            .json().with_context(|| "Failed to parse AzireVPN user profile response - if this persists try deleting cached data at ~/.config/vopono/azire/ and/or manually deleting access tokens at https://manager.azirevpn.com/account/token")?;

        if !user_profile_response.data.is_active {
            log::error!(
                "AzireVPN reports that account is inactive - please check your account status"
            );
        }

        // Note with AzireVPN it is possible to replace keys but keep an existing device
        // This could be useful for separate long-term port forwarding set ups
        // So we also support replacing keys for existing devices

        // WireguardInterface is defined by device selection
        let interface: WireguardInterface = if user_profile_response.data.ips.allocated > 0 {
            // Existing Wireguard devices registered - ask to select and enter private key
            // Or replace existing keys with new keypair
            let existing_devices: ExistingDevicesResponse = client
                .get("https://api.azirevpn.com/v3/ips")
                .header("Authorization", format!("Bearer {}", token))
                .send()?
                .json()
                .with_context(|| "Failed to parse existing devices response")?;

            let selection = uiclient.get_configuration_choice(&existing_devices)?;

            if selection > existing_devices.data.len() {
                if user_profile_response.data.ips.allocated
                    >= user_profile_response.data.ips.available
                {
                    log::error!(
                        "Maximum number of devices registered - please delete an existing device at https://manager.azirevpn.com/wireguard before creating a new one"
                    );
                    return Err(anyhow::anyhow!("Maximum number of devices registered"));
                }
                // Create new device
                let keypair: WgKey = generate_keypair()?;
                debug!("Chosen keypair: {:?}", keypair);
                self.upload_wg_key(&keypair, &token, &client)?
            } else {
                let existing_device = &existing_devices.data[selection];
                let replace_keys = uiclient.get_bool_choice(BoolChoice {
                    prompt: "Would you like to replace the existing keys for this device?"
                        .to_string(),
                    default: false,
                })?;

                if replace_keys {
                    // Replace existing keys
                    let keypair: WgKey = generate_keypair()?;
                    debug!("Chosen keypair: {:?}", keypair);
                    self.replace_wg_key(existing_device, &keypair, &token, &client)?
                } else {
                    // Use existing device
                    // TODO: Refactor common code between this and Mullvad key management

                    let pubkey = if existing_device.keys.len() > 1 {
                        let key_selection = uiclient.get_configuration_choice(existing_device)?;
                        existing_device.keys[key_selection].key.clone()
                    } else {
                        existing_device.keys[0].key.clone()
                    };
                    let pubkey_clone = pubkey.clone();

                    // Check number of public keys - if more than 1 prompt for key to use
                    let private_key = uiclient.get_input(crate::config::providers::Input {
                        prompt: format!(
                            "Private key for {} - {}",
                            existing_device.device_name, pubkey
                        ),
                        validator: Some(Box::new(
                            move |private_key: &String| -> Result<(), String> {
                                let private_key = private_key.trim();

                                if private_key.len() != 44 {
                                    return Err(
                                        "Expected private key length of 44 characters".to_string()
                                    );
                                }

                                match generate_public_key(private_key) {
                                    Ok(public_key) => {
                                        if public_key != pubkey_clone {
                                            return Err(
                                                "Private key does not match public key".to_string()
                                            );
                                        }
                                        Ok(())
                                    }
                                    Err(_) => Err("Failed to generate public key".to_string()),
                                }
                            },
                        )),
                    })?;

                    let v4_net = IpNet::new(
                        IpAddr::V4(Ipv4Addr::from_str(&existing_device.ipv4_address)?),
                        existing_device.ipv4_netmask,
                    )?;
                    WireguardInterface {
                        private_key,
                        address: vec![v4_net],
                        dns: Some(existing_device.dns.clone()),
                    }
                }
            }
        } else {
            // No existing devices - create new device
            // Note max devices is limited to 10 registered, 5 concurrent connections
            // Start device and keypair generation
            let keypair: WgKey = generate_keypair()?;
            debug!("Chosen keypair: {:?}", keypair);
            self.upload_wg_key(&keypair, &token, &client)?
        };

        // Save keypair
        let details = WireguardDetails::from_interface(&interface);
        if let Ok(det) = details {
            let path = self.wireguard_dir()?.join("wireguard_device.json");
            {
                let mut f = std::fs::File::create(path.clone())?;
                write!(
                    f,
                    "{}",
                    serde_json::to_string(&det)
                        .expect("JSON serialisation of WireguardDetails failed")
                )?;
            }
            info!(
                "Saved Wireguard keypair details to {}",
                &path.to_string_lossy()
            );
        } else {
            log::error!("Failed to save Wireguard keypair details: {:?}", details);
        }

        // This gets locations data from token
        let location_resp: LocationsResponse = client.get(self.locations_url()).send()?.json()?;

        debug!("locations_response: {:?}", &location_resp);
        let locations: Vec<LocationResponse> = location_resp.locations;

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for location in locations {
            // TODO: Can we avoid DNS lookup here?
            let host_lookup = dns_lookup::lookup_host(&location.pool);
            if host_lookup.is_err() {
                log::error!("Could not resolve hostname: {}, skipping...", location.pool);
                continue;
            }
            let host_ip = host_lookup.unwrap().first().cloned().unwrap();
            log::debug!("Resolved hostname: {} to IP: {}", &location.pool, &host_ip);
            // TODO: avoid hacky regex for TOML -> wireguard config conversion
            let wireguard_peer = WireguardPeer {
                public_key: location.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: SocketAddr::new(host_ip, 51820),
                keepalive: None,
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };
            let location_name = location.name.as_str();

            let country = country_map
                .get(&location_name[0..2])
                .expect("Could not map country code");

            let path = wireguard_dir.join(format!("{country}-{location_name}.conf"));

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
            "AzireVPN Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}

// TODO: Can we add AzireVPN device name here?
#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireguardDetails {
    public_key: String,
    private_key: String,
    addresses: Vec<IpNet>,
}

impl WireguardDetails {
    fn from_interface(interface: &WireguardInterface) -> anyhow::Result<Self> {
        Ok(WireguardDetails {
            public_key: generate_public_key(interface.private_key.as_str())?,
            private_key: interface.private_key.clone(),
            addresses: interface.address.clone(),
        })
    }
}
