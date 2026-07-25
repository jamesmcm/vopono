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
        if validate_pia_auth(&username, &password).is_ok() {
            Some((username, password))
        } else {
            None
        }
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        // First check if we have cached credentials from a previous sync
        if let Some((username, password)) = self.read_cached_credentials() {
            info!("Using cached PIA credentials for user: {}", username);
            return Ok((username, password));
        }

        let username = uiclient.get_input(Input {
            prompt: "PrivateInternetAccess username (p followed by 7 digits)".to_string(),
            validator: Some(Box::new(|username| {
                validate_pia_username(username).map_err(|error| error.to_string())
            })),
        })?;
        let password = uiclient.get_password(Password {
            prompt: "Password".to_string(),
            confirm: true,
        })?;

        Ok((username, password))
    }
}

fn validate_pia_username(username: &str) -> anyhow::Result<()> {
    if username.len() == 8
        && username.starts_with('p')
        && username[1..].bytes().all(|byte| byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "PIA username must be in the form p1234567; use the VPN service username, not an email address"
        ))
    }
}

fn validate_pia_auth(username: &str, password: &str) -> anyhow::Result<()> {
    validate_pia_username(username)?;
    if password.is_empty() {
        return Err(anyhow::anyhow!("PIA password must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_pia_service_credentials() {
        assert!(validate_pia_auth("p1234567", "password").is_ok());
        assert!(validate_pia_auth("p1234567", " password ").is_ok());
    }

    #[test]
    fn rejects_non_service_usernames_and_empty_passwords() {
        assert!(validate_pia_auth("user@example.com", "password").is_err());
        assert!(validate_pia_auth("P1234567", "password").is_err());
        assert!(validate_pia_auth("p123456", "password").is_err());
        assert!(validate_pia_auth("p1234567", "").is_err());
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

    #[test]
    fn openvpn_does_not_use_tunnel_dns_before_connecting() {
        let pia = PrivateInternetAccess {};
        assert_eq!(pia.provider_dns(), None);
    }
}
