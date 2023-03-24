mod openvpn;
mod wireguard;

use super::{
    ConfigurationChoice, Input, OpenVpnProvider, Password, Provider, UiClient, WireguardProvider,
};
use crate::config::vpn::Protocol;

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
    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
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
