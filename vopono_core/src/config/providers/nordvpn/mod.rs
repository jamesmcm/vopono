mod openvpn;
mod wireguard;

use super::{ConfigurationChoice, OpenVpnProvider, Password, Provider, UiClient};
use crate::config::vpn::Protocol;
use anyhow::{Context, anyhow};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::sync::OnceLock;

pub struct NordVPN {}

#[derive(Deserialize)]
pub(super) struct ServiceCredentials {
    pub username: String,
    pub password: String,
    pub nordlynx_private_key: Option<String>,
}

impl NordVPN {
    fn access_token(&self, uiclient: &dyn UiClient) -> anyhow::Result<String> {
        static ACCESS_TOKEN: OnceLock<String> = OnceLock::new();
        if let Some(token) = ACCESS_TOKEN.get() {
            return Ok(token.clone());
        }

        let token = match std::env::var("NORDVPN_ACCESS_TOKEN") {
            Ok(token) if !token.trim().is_empty() => token,
            _ => uiclient.get_password(Password {
                prompt: "NordVPN access token".to_string(),
                confirm: false,
            })?,
        };
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(anyhow!("NordVPN access token must not be empty"));
        }

        Ok(ACCESS_TOKEN.get_or_init(|| token).clone())
    }

    pub(super) fn service_credentials(
        &self,
        uiclient: &dyn UiClient,
    ) -> anyhow::Result<ServiceCredentials> {
        let token = self.access_token(uiclient)?;
        let credentials: ServiceCredentials = Client::new()
            .get("https://api.nordvpn.com/v1/users/services/credentials")
            .basic_auth("token", Some(token))
            .send()
            .context("Failed to request NordVPN service credentials")?
            .error_for_status()
            .context("NordVPN rejected the access token")?
            .json()
            .context("Failed to parse NordVPN service credentials")?;

        if credentials.username.is_empty() || credentials.password.is_empty() {
            return Err(anyhow!("NordVPN returned empty service credentials"));
        }

        Ok(credentials)
    }
}

impl Provider for NordVPN {
    fn alias(&self) -> String {
        "nordvpn".to_string()
    }

    fn alias_2char(&self) -> String {
        "nd".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
