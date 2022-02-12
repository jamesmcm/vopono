mod airvpn;
mod azirevpn;
mod hma;
mod ivpn;
mod mozilla;
mod mullvad;
mod nordvpn;
mod pia;
mod protonvpn;
mod tigervpn;

use crate::util::vopono_dir;
use crate::vpn::Protocol;
use anyhow::anyhow;
use clap::ArgEnum;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::IpAddr;
use std::path::PathBuf;
use std::string::ToString;

// Command-line arguments use VpnProvider enum
// We pattern match on that to build an instance of the actual provider struct
// That struct must implement traits below
// All functions that work with providers then use dynamic dispatch to receive them

// Methods below take full responsiblity for generating config files
// Should be output to ~/.config/vopono/{provider}/{protocol}/{country}-{host_alias}.{conf,ovpn}
// Methods should use dialoguer to request authentication, and reqwest for any HTTP requests
// Should prompt user for any user input - i.e. port + protocol choice

/// enum used to accept VPN Provider as an argument
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, ArgEnum)]
#[clap(rename_all = "verbatim")]
pub enum VpnProvider {
    PrivateInternetAccess,
    Mullvad,
    TigerVPN,
    ProtonVPN,
    MozillaVPN,
    AzireVPN,
    AirVPN,
    IVPN,
    NordVPN,
    HMA,
    Custom,
}

impl std::fmt::Display for VpnProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(self.to_possible_value().unwrap().get_name(), f)
    }
}

// Do this since we can't downcast from Provider to other trait objects
impl VpnProvider {
    pub fn get_dyn_provider(&self) -> Box<dyn Provider> {
        match self {
            Self::PrivateInternetAccess => Box::new(pia::PrivateInternetAccess {}),
            Self::Mullvad => Box::new(mullvad::Mullvad {}),
            Self::TigerVPN => Box::new(tigervpn::TigerVPN {}),
            Self::ProtonVPN => Box::new(protonvpn::ProtonVPN {}),
            Self::MozillaVPN => Box::new(mozilla::MozillaVPN {}),
            Self::AzireVPN => Box::new(azirevpn::AzireVPN {}),
            Self::AirVPN => Box::new(airvpn::AirVPN {}),
            Self::IVPN => Box::new(ivpn::IVPN {}),
            Self::NordVPN => Box::new(nordvpn::NordVPN {}),
            Self::HMA => Box::new(hma::HMA {}),
            Self::Custom => unimplemented!("Custom provider uses separate logic"),
        }
    }

    pub fn get_dyn_openvpn_provider(&self) -> anyhow::Result<Box<dyn OpenVpnProvider>> {
        match self {
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::TigerVPN => Ok(Box::new(tigervpn::TigerVPN {})),
            Self::ProtonVPN => Ok(Box::new(protonvpn::ProtonVPN {})),
            Self::AzireVPN => Ok(Box::new(azirevpn::AzireVPN {})),
            Self::AirVPN => Ok(Box::new(airvpn::AirVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::NordVPN => Ok(Box::new(nordvpn::NordVPN {})),
            Self::HMA => Ok(Box::new(hma::HMA {})),
            Self::MozillaVPN => Err(anyhow!("MozillaVPN only supports Wireguard!")),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
        }
    }

    pub fn get_dyn_wireguard_provider(&self) -> anyhow::Result<Box<dyn WireguardProvider>> {
        match self {
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::MozillaVPN => Ok(Box::new(mozilla::MozillaVPN {})),
            Self::AzireVPN => Ok(Box::new(azirevpn::AzireVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
            _ => Err(anyhow!("Wireguard not implemented")),
        }
    }

    pub fn get_dyn_shadowsocks_provider(&self) -> anyhow::Result<Box<dyn ShadowsocksProvider>> {
        match self {
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::Custom => Err(anyhow!("Start Shadowsocks manually for custom provider")),
            _ => Err(anyhow!("Shadowsocks not supported")),
        }
    }
}

/// The base trait for any VPN provider
pub trait Provider {
    fn alias(&self) -> String;

    fn default_protocol(&self) -> Protocol;

    fn provider_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(vopono_dir()?.join(self.alias()))
    }
}

/// This trait is implemented if the VPN provider has Wireguard support
pub trait WireguardProvider: Provider {
    /// This method must create the Wireguard wg-quick config files
    fn create_wireguard_config(&self) -> anyhow::Result<()>;

    fn wireguard_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(self.provider_dir()?.join("wireguard"))
    }
}

/// This trait is implemented if the VPN provider has OpenVPN support
pub trait OpenVpnProvider: Provider {
    /// This method must create the OpenVPN .ovpn config files
    fn create_openvpn_config(&self) -> anyhow::Result<()>;
    fn provider_dns(&self) -> Option<Vec<IpAddr>>;
    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)>;
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

/// Implement this trait for enums used as configuration choices e.g. when deciding which set of
/// config files to generate
/// The default option will be used if generated in non-interactive mode
pub trait ConfigurationChoice: Display + Sized + Default + PartialEq {
    /// Prompt string for the selector (automatically terminates in ':')
    fn prompt() -> String;

    /// Get all enum variants (this order will be used for other methods)
    fn variants() -> Vec<Self>;

    /// Descriptions are a user-friendly descriptions for each enum variant
    fn description(&self) -> Option<String>;

    /// Launches a dialoguer single select menu for the enum
    fn choose_one() -> anyhow::Result<Self> {
        let mut variants = Self::variants();
        let display_names = variants.iter().map(|x| x.to_string());
        let descriptions = variants.iter().map(|x| x.description());
        let index = dialoguer::Select::new()
            .with_prompt(Self::prompt())
            .items(
                display_names
                    .zip(descriptions)
                    .map(|x| {
                        if x.1.is_some() {
                            format!("{}: {}", x.0, x.1.unwrap())
                        } else {
                            x.0
                        }
                    })
                    .collect::<Vec<String>>()
                    .as_slice(),
            )
            .default(variants.iter().position(|x| *x == Self::default()).unwrap())
            .interact()?;
        Ok(variants.remove(index))
    }
}
