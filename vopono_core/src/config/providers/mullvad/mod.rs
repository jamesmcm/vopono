mod openvpn;
mod wireguard;

use super::{
    ConfigurationChoice, Input, OpenVpnProvider, Provider, ShadowsocksProvider, UiClient,
    WireguardProvider,
};
use crate::config::vpn::Protocol;
use crate::util::wireguard::WgPeer;
use anyhow::anyhow;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct AuthToken {
    auth_token: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
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
