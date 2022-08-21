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

use crate::config::vpn::Protocol;
use crate::util::vopono_dir;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{net::IpAddr, path::Path};
use strum_macros::{Display, EnumIter};

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
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
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

/// Implement this trait for enums used as configuration choices e.g. when deciding which set of
/// config files to generate
/// The default option will be used if generated in non-interactive mode
pub trait ConfigurationChoice {
    /// Prompt string for the selector (automatically terminates in ':')
    fn prompt(&self) -> String;

    /// Descriptions are a user-friendly descriptions for each enum variant
    fn description(&self) -> Option<String>;

    /// Descriptions are a user-friendly descriptions for each enum variant
    fn all_descriptions(&self) -> Option<Vec<String>>;

    /// Get all enum variant names (this order will be used for other methods)
    fn all_names(&self) -> Vec<String>;
}
// TODO: FromStr, ToString

pub struct BoolChoice {
    pub prompt: String,
    pub default: bool,
}

#[allow(clippy::type_complexity)]
/// Only supports strings
pub struct Input {
    pub prompt: String,
    pub validator: Option<Box<dyn Fn(&String) -> core::result::Result<(), String>>>,
}

#[allow(clippy::type_complexity)]
/// Only supports u16 input - so UI Client can allow numbers only
pub struct InputNumericu16 {
    pub prompt: String,
    pub validator: Option<Box<dyn Fn(&u16) -> core::result::Result<(), String>>>,
    pub default: Option<u16>,
}

pub struct Password {
    pub prompt: String,
    pub confirm: bool,
}

/// Trait to be implemented by a struct wrapping the user-facing client code
/// e.g. separate implementations for CLI, TUI, GUI, etc.
/// For GUI and TUI may want to override `process_choices()` to get the responses in a batch
pub trait UiClient {
    /// Returns index of chosen element from ConfigurationChoice - this can then be used with concrete enum::variants() for concrete variant
    fn get_configuration_choice(
        &self,
        conf_choice: &dyn ConfigurationChoice,
    ) -> anyhow::Result<usize>;
    fn get_bool_choice(&self, bool_choice: BoolChoice) -> anyhow::Result<bool>;
    fn get_input(&self, input: Input) -> anyhow::Result<String>;
    fn get_input_numeric_u16(&self, input: InputNumericu16) -> anyhow::Result<u16>;
    fn get_password(&self, password: Password) -> anyhow::Result<String>;
}
