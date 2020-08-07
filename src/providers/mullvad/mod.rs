mod openvpn;
mod wireguard;

use super::{ConfigurationChoice, OpenVpnProvider, Provider, WireguardProvider};
use crate::util::wireguard::WgPeer;
use crate::vpn::Protocol;
use anyhow::anyhow;
use dialoguer::Input;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct AuthToken {
    auth_token: String,
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

pub struct Mullvad {}

impl Provider for Mullvad {
    fn alias(&self) -> String {
        "mv".to_string()
    }
    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

fn request_mullvad_username() -> anyhow::Result<String> {
    let mut username = Input::<String>::new()
        .with_prompt("Mullvad account number")
        .validate_with(|username: &str| -> Result<(), &str> {
            username
                .to_string()
                .retain(|c| !c.is_whitespace() && c.is_digit(10));
            if username.len() != 16 {
                return Err("Mullvad account number should be 16 digits!");
            }
            Ok(())
        })
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
