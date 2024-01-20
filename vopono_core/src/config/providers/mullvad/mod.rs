mod openvpn;
mod wireguard;

use std::fmt::Display;

use super::{
    ConfigurationChoice, Input, OpenVpnProvider, Provider, ShadowsocksProvider, UiClient,
    WireguardProvider,
};
use crate::config::vpn::Protocol;
use anyhow::anyhow;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct AccessToken {
    access_token: String,
}

#[derive(Deserialize, Debug, Clone)]
struct UserInfo {
    expiry: String,
    max_devices: u8,
    can_add_devices: bool,
}

#[derive(Deserialize, Debug, Clone)]
struct Device {
    name: String,
    pubkey: String,
    created: String,
    ipv4_address: String,
    ipv6_address: String,
}

impl Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} (created: {})",
            self.name, self.pubkey, self.created
        )
    }
}

pub struct Mullvad {}

impl Provider for Mullvad {
    fn alias(&self) -> String {
        "mv".to_string()
    }

    fn alias_2char(&self) -> String {
        "mv".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

impl Mullvad {
    fn request_mullvad_username(&self, uiclient: &dyn UiClient) -> anyhow::Result<String> {
        let mut username = uiclient.get_input(Input {
            prompt: "Mullvad account number".to_string(),
            validator: Some(Box::new(|username: &String| -> Result<(), String> {
                let mut username = username.to_string();
                username.retain(|c| !c.is_whitespace() && c.is_ascii_digit());
                if username.len() != 16 {
                    return Err("Mullvad account number should be 16 digits!".to_string());
                }
                Ok(())
            })),
        })?;

        username.retain(|c| !c.is_whitespace() && c.is_ascii_digit());
        if username.len() != 16 {
            return Err(anyhow!(
                "Mullvad account number should be 16 digits!, parsed: {}",
                username
            ));
        }
        Ok(username)
    }
}

impl ShadowsocksProvider for Mullvad {
    // Hardcoded password from documentation
    // https://mullvad.net/en/help/shadowsocks-openvpn-linux/
    fn password(&self) -> String {
        "mullvad".to_string()
    }
    fn encrypt_method(&self) -> String {
        "aes-256-gcm".to_string()
    }
}
