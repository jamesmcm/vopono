mod openvpn;
mod wireguard;

use std::fs::File;
use std::io::{BufRead, BufReader};

use super::{
    ConfigurationChoice, Input, OpenVpnProvider, Password, Provider, UiClient, WireguardProvider,
};
use crate::config::vpn::Protocol;
use log::info;

pub struct PrivateInternetAccess {}

impl Provider for PrivateInternetAccess {
    fn alias(&self) -> String {
        "pia".to_string()
    }

    fn alias_2char(&self) -> String {
        "pi".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}

impl PrivateInternetAccess {
    /// Try to read cached PIA credentials from the OpenVPN auth file.
    /// Returns None if the file doesn't exist or doesn't contain valid credentials.
    fn read_cached_credentials(&self) -> Option<(String, String)> {
        let auth_path = self.provider_dir().ok()?.join("openvpn/auth.txt");
        let file = File::open(auth_path).ok()?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let username = lines.next()?.ok()?;
        let password = lines.next()?.ok()?;
        let username = username.trim().to_string();
        let password = password.trim().to_string();
        if !username.is_empty() && !password.is_empty() {
            Some((username, password))
        } else {
            None
        }
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        // First check if we have cached credentials from a previous sync
        if let Some((username, password)) = self.read_cached_credentials() {
            info!("Using cached PIA credentials for user: {}", &username);
            return Ok((username, password));
        }

        let username = uiclient.get_input(Input {
            prompt: "PrivateInternetAccess username".to_string(),
            validator: None,
        })?;
        let password = uiclient.get_password(Password {
            prompt: "Password".to_string(),
            confirm: true,
        })?;

        Ok((username, password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse credentials from raw lines (username on first line, password on second).
    /// Returns the cleaned credentials if valid, None otherwise.
    fn parse_credentials(first_line: &str, second_line: &str) -> Option<(String, String)> {
        let username = first_line.trim().to_string();
        let password = second_line.trim().to_string();
        if !username.is_empty() && !password.is_empty() {
            Some((username, password))
        } else {
            None
        }
    }

    #[test]
    fn test_parse_credentials_valid() {
        assert_eq!(
            parse_credentials("user123", "password456"),
            Some(("user123".to_string(), "password456".to_string()))
        );
    }

    #[test]
    fn test_parse_credentials_with_whitespace() {
        assert_eq!(
            parse_credentials("  user123  ", "  password456  "),
            Some(("user123".to_string(), "password456".to_string()))
        );
    }

    #[test]
    fn test_parse_credentials_with_newlines() {
        assert_eq!(
            parse_credentials("user123\n", "password456\n"),
            Some(("user123".to_string(), "password456".to_string()))
        );
    }

    #[test]
    fn test_parse_credentials_empty_username() {
        assert_eq!(parse_credentials("", "password456"), None);
        assert_eq!(parse_credentials("   ", "password456"), None);
    }

    #[test]
    fn test_parse_credentials_empty_password() {
        assert_eq!(parse_credentials("user123", ""), None);
        assert_eq!(parse_credentials("user123", "   "), None);
    }

    #[test]
    fn test_parse_credentials_both_empty() {
        assert_eq!(parse_credentials("", ""), None);
        assert_eq!(parse_credentials("   ", "   "), None);
    }

    #[test]
    fn test_provider_alias() {
        let pia = PrivateInternetAccess {};
        assert_eq!(pia.alias(), "pia");
        assert_eq!(pia.alias_2char(), "pi");
    }

    #[test]
    fn test_default_protocol() {
        let pia = PrivateInternetAccess {};
        assert_eq!(pia.default_protocol(), Protocol::OpenVpn);
    }
}
