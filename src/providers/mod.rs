use crate::util::vopono_dir;
use clap::arg_enum;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;

// Command-line arguments use VpnProvider enum
// We pattern match on that to build an instance of the actual provider struct
// That struct must implement traits below
// All functions that work with providers then use dynamic dispatch to receive them

// Methods below take full responsiblity for generating config files
// Should be output to ~/.config/vopono/{provider}/{protocol}/{country}-{host_alias}.{conf,ovpn}
// Methods should use dialoguer to request authentication, and reqwest for any HTTP requests
// Should prompt user for any user input - i.e. port + protocol choice

arg_enum! {
/// enum used to accept VPN Provider as an argument
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum VpnProvider {
    PrivateInternetAccess,
    Mullvad,
    TigerVpn,
    Custom,
}
}

/// The base trait for any VPN provider
pub trait Provider {
    fn alias(&self) -> String;

    fn provider_dir(&self) -> anyhow::Result<PathBuf> {
        let mut dir = vopono_dir()?;
        dir.push(self.alias());
        Ok(dir)
    }
}

/// This trait is implemented if the VPN provider has Wireguard support
pub trait WireguardProvider: Provider {
    /// This method must create the Wireguard wg-quick config files
    fn create_wireguard_config(&self) -> anyhow::Result<()>;

    fn wireguard_dir(&self) -> anyhow::Result<PathBuf> {
        let mut dir = self.provider_dir()?;
        dir.push("wireguard");
        Ok(dir)
    }
}

/// This trait is implemented if the VPN provider has OpenVPN support
pub trait OpenVpnProvider: Provider {
    /// This method must create the OpenVPN .ovpn config files
    fn create_openvpn_config(&self) -> anyhow::Result<()>;
    fn provider_dns(&self) -> Option<Ipv4Addr>;

    fn openvpn_dir(&self) -> anyhow::Result<PathBuf> {
        let mut dir = self.provider_dir()?;
        dir.push("openvpn");
        Ok(dir)
    }
}
