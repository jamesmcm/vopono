mod openvpn;
mod wireguard;

use super::{ConfigurationChoice, OpenVpnProvider, Provider, WireguardProvider};
use crate::vpn::Protocol;
use crate::wireguard::{de_socketaddr, de_vec_ipaddr, de_vec_ipnet};
use dialoguer::{Input, Password};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;

// AzireVPN details: https://www.azirevpn.com/docs/servers

pub struct AzireVPN {}

impl AzireVPN {
    fn server_aliases(&self) -> &[&str] {
        &[
            "ca1", "dk1", "fr1", "de1", "it1", "es1", "nl1", "no1", "ro1", "se1", "se2", "ch1",
            "th1", "us1", "us2", "uk1",
        ]
    }
}
impl Provider for AzireVPN {
    fn alias(&self) -> String {
        "azire".to_string()
    }
    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

#[derive(Deserialize, Debug, Clone)]
struct ConnectResponse {
    status: String,
    data: WgResponse,
}

#[derive(Deserialize, Debug, Clone)]
struct WgResponse {
    #[serde(alias = "DNS", deserialize_with = "de_vec_ipaddr")]
    dns: Option<Vec<IpAddr>>,
    #[serde(alias = "Address", deserialize_with = "de_vec_ipnet")]
    address: Vec<IpNet>,
    #[serde(alias = "PublicKey")]
    public_key: String,
    #[serde(alias = "Endpoint", deserialize_with = "de_socketaddr")]
    endpoint: std::net::SocketAddr,
}

impl AzireVPN {
    fn request_userpass(&self) -> anyhow::Result<(String, String)> {
        let username = Input::<String>::new()
            .with_prompt("AzireVPN username")
            .interact()?;
        let username = username.trim();
        let password = Password::new()
            .with_prompt("AzireVPN password")
            .interact()?;
        let password = password.trim();
        Ok((username.to_string(), password.to_string()))
    }
}
