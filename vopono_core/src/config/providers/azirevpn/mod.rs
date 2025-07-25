mod wireguard;

use super::{ConfigurationChoice, Input, Password, Provider, UiClient, WireguardProvider};
use crate::config::vpn::Protocol;
use anyhow::Context;
use serde::Deserialize;
use serde_json::json;
use std::io::Write;
use std::{net::IpAddr, path::PathBuf};

// AzireVPN details: https://www.azirevpn.com/docs/servers
// servers: https://www.azirevpn.com/service/servers#openvpn
pub struct AzireVPN {}

impl AzireVPN {
    fn locations_url(&self) -> &str {
        "https://api.azirevpn.com/v3/locations"
    }
}
impl Provider for AzireVPN {
    fn alias(&self) -> String {
        "azire".to_string()
    }
    fn alias_2char(&self) -> String {
        "az".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct ReplaceKeyResponse {
    status: String,
    data: Vec<KeyResponse>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct KeyResponse {
    key: String, // public key
    created_at: i64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct ExistingDeviceResponse {
    status: String,
    data: ExistingDeviceResponseData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct ExistingDevicesResponse {
    status: String,
    data: Vec<ExistingDeviceResponseData>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct ExistingDeviceResponseData {
    id: String,
    ipv4_address: String,
    ipv4_netmask: u8,
    ipv6_address: String,
    ipv6_netmask: u8,
    dns: Vec<IpAddr>,
    device_name: Option<String>,
    keys: Vec<KeyResponse>,
}

impl ConfigurationChoice for ExistingDevicesResponse {
    fn prompt(&self) -> String {
        "The following Wireguard devices exist on your account, which would you like to use (you will need to enter the private key or replace the existing keys)".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.data.iter().map(|x| x.id.clone()).collect();
        v.push("Create a new device".to_string());
        v
    }

    fn all_descriptions(&self) -> Option<Vec<String>> {
        let mut v: Vec<String> = self
            .data
            .iter()
            .filter_map(|x| {
                // Filter out entries with null names
                x.device_name.as_ref().map(|name| format!("{}, {}", name, x.ipv4_address))
            })
            .collect();
        v.push("generate a new keypair".to_string());
        Some(v)
    }
    fn description(&self) -> Option<String> {
        None
    }
}

impl ConfigurationChoice for ExistingDeviceResponseData {
    fn prompt(&self) -> String {
        "The selected device has the following public keys assigned - select which one you wish to use (and enter the private key for)".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        self.keys.iter().map(|x| x.key.clone()).collect()
    }

    fn all_descriptions(&self) -> Option<Vec<String>> {
        None
    }
    fn description(&self) -> Option<String> {
        None
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct UserProfileResponse {
    status: String,
    data: UserProfileResponseData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct UserProfileResponseData {
    username: String,
    email: String,
    currency: String,
    is_email_verified: bool,
    is_active: bool,
    is_oldschool: bool,
    is_subscribed: bool,
    ips: UserIpsData,
    created_at: i64,
    expires_at: i64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct UserIpsData {
    allocated: u32,
    available: u32,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct AccessTokenResponse {
    status: String,
    data: AccessTokenResponseData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct AccessTokenResponseData {
    id: String,
    device_name: Option<String>,
    key: String,
    comment: Option<String>,
    created_at: i64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct DeviceResponse {
    status: String,
    ipv4: IpResponse,
    ipv6: IpResponse,
    dns: Vec<IpAddr>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct IpResponse {
    address: String,
    netmask: u8,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct LocationsResponse {
    status: String,
    locations: Vec<LocationResponse>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct LocationResponse {
    name: String,
    city: String,
    country: String,
    iso: String,
    pool: String,
    pubkey: String,
}

impl AzireVPN {
    fn request_userpass(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {
            prompt: "AzireVPN username".to_string(),
            validator: None,
        })?;
        let username = username.trim();
        let password = uiclient.get_password(Password {
            prompt: "AzireVPN password".to_string(),
            confirm: true,
        })?;
        let password = password.trim();
        Ok((username.to_string(), password.to_string()))
    }

    fn token_file_path(&self) -> PathBuf {
        self.provider_dir().unwrap().join("token.txt")
    }

    pub fn get_access_token(&self, uiclient: &dyn UiClient) -> anyhow::Result<String> {
        let token_file_path = self.token_file_path();
        if token_file_path.exists() {
            let token = std::fs::read_to_string(&token_file_path)?;
            log::debug!(
                "AzireVPN Auth Token read from {}",
                self.token_file_path().display()
            );
            return Ok(token);
        }
        let (username, password) = self.request_userpass(uiclient)?;
        let client = reqwest::blocking::Client::new();
        let auth_response: AccessTokenResponse = client
            .post("https://api.azirevpn.com/v3/tokens")
            .json(&json!(
                {
                    "username": username,
                    "password": password,
                    "comment": "vopono sync"
                }
            ))
            .send()?
            .json()
            .with_context(
                || "Authentication error: Ensure your AzireVPN credentials are correct",
            )?;

        let auth_response_data = if auth_response.status == "success" {
            Ok(auth_response.data)
        } else {
            Err(anyhow::anyhow!(
                "Authentication error, ensure your AzireVPN credentials are correct. Response: {}",
                auth_response.status
            ))
        }?;

        // log::debug!("auth_response: {:?}", &auth_response);
        let mut outfile = std::fs::File::create(self.token_file_path())?;
        write!(outfile, "{}", auth_response_data.key)?;
        log::debug!(
            "AzireVPN Auth Token written to {}",
            self.token_file_path().display()
        );

        Ok(auth_response_data.key)
    }

    pub fn read_access_token(&self) -> anyhow::Result<String> {
        let token_file_path = self.token_file_path();
        if token_file_path.exists() {
            let token = std::fs::read_to_string(&token_file_path)?;
            log::debug!(
                "AzireVPN Auth Token read from {}",
                self.token_file_path().display()
            );
            return Ok(token);
        }
        Err(anyhow::anyhow!(
            "AzireVPN Auth Token not found at {}",
            token_file_path.display()
        ))
    }
}
