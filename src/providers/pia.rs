use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use reqwest::Url;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

pub struct PrivateInternetAccess {}

impl Provider for PrivateInternetAccess {
    fn alias(&self) -> String {
        "pia".to_string()
    }
}

impl OpenVpnProvider for PrivateInternetAccess {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(209, 222, 18, 222)),
            IpAddr::V4(Ipv4Addr::new(209, 222, 18, 218)),
        ])
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(EnumIter)]
enum ConfigType {
    DefaultConf,
    Ip,
    Strong,
    Tcp,
    StrongTcp,
}

impl ConfigType {
    fn url(&self) -> anyhow::Result<Url> {
        todo!()
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DefaultConf => "Default",
            Self::Ip => "IP",
            Self::Strong => "Strong",
            Self::Tcp => "TCP",
            Self::StrongTcp => "Strong TCP",
        };
        write!(f, "{}", s)
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::DefaultConf
    }
}

impl ConfigurationChoice for ConfigType {
    fn variants(&self) -> Vec<Self> {
        ConfigType::iter().collect()
    }
    fn description(&self) -> Option<String> {
        Some( match self {
            Self::DefaultConf => "These files connect over UDP port 1198 with AES-128-CBC+SHA1, using the server name to connect.",
            Self::Ip => "These files connect over UDP port 1198 with AES-128-CBC+SHA1, and connect via an IP address instead of the server name.",
            Self::Strong => "These files connect over UDP port 1197 with AES-256-CBC+SHA256, using the server name to connect.",
            Self::Tcp => "These files connect over TCP port 502 with AES-128-CBC+SHA1, using the server name to connect.",
            Self::StrongTcp => "These files connect over TCP port 501 with AES-256-CBC+SHA256, using the server name to connect."
        }.to_string())
    }
}
