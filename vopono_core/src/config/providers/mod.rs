mod airvpn;
mod azirevpn;
mod hma;
mod ivpn;
mod mozilla;
mod mullvad;
mod nordvpn;
mod pia;
mod protonvpn;
mod ui;
mod warp;

use crate::config::vpn::Protocol;
use crate::util::vopono_dir;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{net::IpAddr, path::Path};
use strum_macros::{Display, EnumIter};
// TODO: Consider removing this re-export
pub use ui::*;

// Command-line arguments use VpnProvider enum
// We pattern match on that to build an instance of the actual provider struct
// That struct must implement traits below
// All functions that work with providers then use dynamic dispatch to receive them

// Methods below take full responsiblity for generating config files
// Should be output to ~/.config/vopono/{provider}/{protocol}/{country}-{host_alias}.{conf,ovpn}
// Should prompt user for any user input - i.e. port + protocol choice

/// enum used to accept VPN Provider as an argument
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Display, EnumIter)]
pub enum VpnProvider {
    PrivateInternetAccess,
    Mullvad,
    ProtonVPN,
    MozillaVPN,
    AzireVPN,
    AirVPN,
    IVPN,
    NordVPN,
    HMA,
    Warp,
    Custom,
}

// Do this since we can't downcast from Provider to other trait objects
impl VpnProvider {
    pub fn get_dyn_provider(&self) -> Box<dyn Provider> {
        match self {
            Self::PrivateInternetAccess => Box::new(pia::PrivateInternetAccess {}),
            Self::Mullvad => Box::new(mullvad::Mullvad {}),
            Self::ProtonVPN => Box::new(protonvpn::ProtonVPN {}),
            Self::MozillaVPN => Box::new(mozilla::MozillaVPN {}),
            Self::AzireVPN => Box::new(azirevpn::AzireVPN {}),
            Self::AirVPN => Box::new(airvpn::AirVPN {}),
            Self::IVPN => Box::new(ivpn::IVPN {}),
            Self::NordVPN => Box::new(nordvpn::NordVPN {}),
            Self::HMA => Box::new(hma::HMA {}),
            Self::Warp => Box::new(warp::Warp {}),
            Self::Custom => unimplemented!("Custom provider uses separate logic"),
        }
    }

    pub fn get_dyn_openvpn_provider(&self) -> anyhow::Result<Box<dyn OpenVpnProvider>> {
        match self {
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::ProtonVPN => Ok(Box::new(protonvpn::ProtonVPN {})),
            Self::AzireVPN => Ok(Box::new(azirevpn::AzireVPN {})),
            Self::AirVPN => Ok(Box::new(airvpn::AirVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::NordVPN => Ok(Box::new(nordvpn::NordVPN {})),
            Self::HMA => Ok(Box::new(hma::HMA {})),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            Self::MozillaVPN => Err(anyhow!("MozillaVPN only supports Wireguard!")),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
        }
    }

    pub fn get_dyn_wireguard_provider(&self) -> anyhow::Result<Box<dyn WireguardProvider>> {
        match self {
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::MozillaVPN => Ok(Box::new(mozilla::MozillaVPN {})),
            Self::AzireVPN => Ok(Box::new(azirevpn::AzireVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            _ => Err(anyhow!("Wireguard not implemented")),
        }
    }

    pub fn get_dyn_shadowsocks_provider(&self) -> anyhow::Result<Box<dyn ShadowsocksProvider>> {
        match self {
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::Custom => Err(anyhow!("Start Shadowsocks manually for custom provider")),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            _ => Err(anyhow!("Shadowsocks not supported")),
        }
    }
}

/// The base trait for any VPN provider
pub trait Provider {
    fn alias(&self) -> String;

    fn alias_2char(&self) -> String;

    fn default_protocol(&self) -> Protocol;

    fn provider_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(vopono_dir()?.join(self.alias()))
    }
}

/// This trait is implemented if the VPN provider has Wireguard support
pub trait WireguardProvider: Provider {
    /// This method must create the Wireguard wg-quick config files
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()>;

    fn wireguard_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(self.provider_dir()?.join("wireguard"))
    }

    fn wireguard_preup(&self, _config_file: &Path) -> anyhow::Result<()> {
        Ok(())
    }
}

/// This trait is implemented if the VPN provider has OpenVPN support
pub trait OpenVpnProvider: Provider {
    /// This method must create the OpenVPN .ovpn config files
    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()>;
    fn provider_dns(&self) -> Option<Vec<IpAddr>>;
    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)>;
    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>>;

    fn openvpn_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(self.provider_dir()?.join("openvpn"))
    }
}

/// This trait is implemented if the provider has a Shadowsocks server
pub trait ShadowsocksProvider: Provider {
    fn password(&self) -> String;
    fn encrypt_method(&self) -> String;
}
