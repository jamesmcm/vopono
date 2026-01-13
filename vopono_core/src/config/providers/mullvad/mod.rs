mod openvpn;
mod wireguard;

use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader};

use super::{
    ConfigurationChoice, Input, OpenVpnProvider, Provider, ShadowsocksProvider, UiClient,
    WireguardProvider,
};
use crate::config::vpn::Protocol;
use anyhow::anyhow;
use log::info;
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
    /// Try to read cached Mullvad account number from the OpenVPN auth file.
    /// Returns None if the file doesn't exist or doesn't contain a valid account number.
    fn read_cached_username(&self) -> Option<String> {
        let auth_path = self
            .provider_dir()
            .ok()?
            .join("openvpn/mullvad_userpass.txt");
        let file = File::open(auth_path).ok()?;
        let reader = BufReader::new(file);
        let first_line = reader.lines().next()?.ok()?;
        let mut username = first_line.trim().to_string();
        username.retain(|c| !c.is_whitespace() && c.is_ascii_digit());
        if username.len() == 16 {
            Some(username)
        } else {
            None
        }
    }

    fn request_mullvad_username(&self, uiclient: &dyn UiClient) -> anyhow::Result<String> {
        // First check if we have cached credentials from a previous sync
        if let Some(cached_username) = self.read_cached_username() {
            info!(
                "Using cached Mullvad account number: {}...{}",
                &cached_username[..4],
                &cached_username[12..]
            );
            return Ok(cached_username);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse and validate a Mullvad account number from a raw string.
    /// Returns the cleaned 16-digit account number if valid, None otherwise.
    fn parse_mullvad_username(raw: &str) -> Option<String> {
        let mut username = raw.trim().to_string();
        username.retain(|c| !c.is_whitespace() && c.is_ascii_digit());
        if username.len() == 16 {
            Some(username)
        } else {
            None
        }
    }

    /// Validate a Mullvad account number string.
    /// Returns Ok(()) if valid, Err with message if invalid.
    fn validate_mullvad_username(username: &str) -> Result<(), String> {
        let mut cleaned = username.to_string();
        cleaned.retain(|c| !c.is_whitespace() && c.is_ascii_digit());
        if cleaned.len() != 16 {
            return Err("Mullvad account number should be 16 digits!".to_string());
        }
        Ok(())
    }

    #[test]
    fn test_parse_mullvad_username_valid() {
        // Valid 16-digit account number
        assert_eq!(
            parse_mullvad_username("1234567890123456"),
            Some("1234567890123456".to_string())
        );
    }

    #[test]
    fn test_parse_mullvad_username_with_spaces() {
        // Account number with spaces (common copy-paste format)
        assert_eq!(
            parse_mullvad_username("1234 5678 9012 3456"),
            Some("1234567890123456".to_string())
        );
    }

    #[test]
    fn test_parse_mullvad_username_with_whitespace() {
        // With leading/trailing whitespace and newlines
        assert_eq!(
            parse_mullvad_username("  1234567890123456  \n"),
            Some("1234567890123456".to_string())
        );
    }

    #[test]
    fn test_parse_mullvad_username_too_short() {
        assert_eq!(parse_mullvad_username("12345678901234"), None);
    }

    #[test]
    fn test_parse_mullvad_username_too_long() {
        assert_eq!(parse_mullvad_username("12345678901234567890"), None);
    }

    #[test]
    fn test_parse_mullvad_username_with_letters() {
        // Letters should be stripped, resulting in too few digits
        assert_eq!(parse_mullvad_username("1234abcd56789012"), None);
    }

    #[test]
    fn test_parse_mullvad_username_empty() {
        assert_eq!(parse_mullvad_username(""), None);
    }

    #[test]
    fn test_validate_mullvad_username_valid() {
        assert!(validate_mullvad_username("1234567890123456").is_ok());
        assert!(validate_mullvad_username("1234 5678 9012 3456").is_ok());
    }

    #[test]
    fn test_validate_mullvad_username_invalid() {
        assert!(validate_mullvad_username("123456789012345").is_err());
        assert!(validate_mullvad_username("").is_err());
        assert!(validate_mullvad_username("abcdefghijklmnop").is_err());
    }

    #[test]
    fn test_provider_alias() {
        let mullvad = Mullvad {};
        assert_eq!(mullvad.alias(), "mv");
        assert_eq!(mullvad.alias_2char(), "mv");
    }

    #[test]
    fn test_default_protocol() {
        let mullvad = Mullvad {};
        assert_eq!(mullvad.default_protocol(), Protocol::Wireguard);
    }

    #[test]
    fn test_shadowsocks_provider() {
        let mullvad = Mullvad {};
        assert_eq!(mullvad.password(), "mullvad");
        assert_eq!(mullvad.encrypt_method(), "aes-256-gcm");
    }
}
