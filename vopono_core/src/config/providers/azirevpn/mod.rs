mod openvpn;
mod wireguard;

use super::{Input, OpenVpnProvider, Password, Provider, UiClient, WireguardProvider};
use crate::config::vpn::Protocol;
use anyhow::Context;
use serde::Deserialize;
use std::io::Write;
use std::{net::IpAddr, path::PathBuf};

// AzireVPN details: https://www.azirevpn.com/docs/servers
// servers: https://www.azirevpn.com/service/servers#openvpn
pub struct AzireVPN {}

impl AzireVPN {
    fn locations_url(&self) -> &str {
        "https://api.azirevpn.com/v2/locations"
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
struct AccessTokenResponse {
    status: String,
    user: UserResponse,
    token: String,
    device_name: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
struct UserResponse {
    username: String,
    email: String,
    email_verified: bool,
    active: bool,
    expires_at: i64,
    subscription: bool,
    is_oldschool: bool,
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
struct ConnectResponse {
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
            .post("https://api.azirevpn.com/v2/auth/client")
            .form(&[
                ("username", &username),
                ("password", &password),
                ("comment", &"web generator".to_string()),
            ])
            .send()?
            .json()
            .with_context(|| {
                "Authentication error: Ensure your AzireVPN credentials are correct"
            })?;

        // log::debug!("auth_response: {:?}", &auth_response);
        let mut outfile = std::fs::File::create(self.token_file_path())?;
        write!(outfile, "{}", auth_response.token)?;
        log::debug!(
            "AzireVPN Auth Token written to {}",
            self.token_file_path().display()
        );

        Ok(auth_response.token)
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
