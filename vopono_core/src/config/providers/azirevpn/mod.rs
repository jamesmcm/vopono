mod openvpn;
mod wireguard;

use super::{Input, OpenVpnProvider, Password, Provider, UiClient, WireguardProvider};
use crate::config::vpn::Protocol;
use serde::Deserialize;
use std::net::IpAddr;

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
}
