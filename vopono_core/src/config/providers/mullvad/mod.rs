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

/// Parse and validate a Mullvad account number from a raw string.
/// Strips whitespace and non-digit characters, then validates it's exactly 16 digits.
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

/// Validate a Mullvad account number string for use with Dialoguer input.
/// Returns Ok(()) if valid, Err with error message if invalid.
#[allow(clippy::ptr_arg)] // Dialoguer validator requires &String
fn validate_mullvad_username(username: &String) -> Result<(), String> {
    parse_mullvad_username(username)
        .map(|_| ())
        .ok_or_else(|| "Mullvad account number should be 16 digits!".to_string())
}

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
        parse_mullvad_username(&first_line)
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

        let username = uiclient.get_input(Input {
            prompt: "Mullvad account number".to_string(),
            validator: Some(Box::new(validate_mullvad_username)),
        })?;

        parse_mullvad_username(&username).ok_or_else(|| {
            anyhow!(
                "Mullvad account number should be 16 digits!, parsed: {}",
                username
            )
        })
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

    #[test]
    fn test_parse_mullvad_username_valid() {
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
        assert!(validate_mullvad_username(&"1234567890123456".to_string()).is_ok());
    }

    #[test]
    fn test_validate_mullvad_username_with_spaces() {
        // Account number with spaces should be accepted
        assert!(validate_mullvad_username(&"1234 5678 9012 3456".to_string()).is_ok());
    }

    #[test]
    fn test_validate_mullvad_username_too_short() {
        let result = validate_mullvad_username(&"123456789012345".to_string());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Mullvad account number should be 16 digits!"
        );
    }

    #[test]
    fn test_validate_mullvad_username_too_long() {
        let result = validate_mullvad_username(&"12345678901234567".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mullvad_username_empty() {
        let result = validate_mullvad_username(&"".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_mullvad_username_non_digits() {
        // Letters get stripped, resulting in too few digits
        let result = validate_mullvad_username(&"abcdefghijklmnop".to_string());
        assert!(result.is_err());
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
