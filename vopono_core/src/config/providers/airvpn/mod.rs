mod openvpn;
mod wireguard;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::vpn::Protocol;

pub struct AirVPN {}

pub(super) fn validate_api_key(value: &str) -> Result<(), String> {
    let key = value.trim().as_bytes();
    if key.len() == 40
        && key
            .iter()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(character))
    {
        Ok(())
    } else {
        Err("AirVPN API keys must be 40 lower-case hexadecimal characters".to_string())
    }
}

impl Provider for AirVPN {
    fn alias(&self) -> String {
        "air".to_string()
    }

    fn alias_2char(&self) -> String {
        "ar".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
