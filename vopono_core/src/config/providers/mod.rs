mod airvpn;
pub mod azirevpn;
mod ivpn;
mod mozilla;
mod mullvad;
mod nordvpn;
pub mod pia;
mod protonvpn;
mod ui;
mod warp;

use crate::config::vpn::Protocol;
use crate::util::vopono_dir;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::{Path, PathBuf},
};
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
    Warp,
    Custom,
    None, // Run no protocol inside netns
}

// Do this since we can't downcast from Provider to other trait objects
impl VpnProvider {
    // Keep these explicit: the machine-facing IDs are stable API values and
    // intentionally do not depend on Rust's enum or Display names.
    /// Stable, lower-case identifier used by machine-facing interfaces.
    pub fn id(&self) -> &'static str {
        match self {
            Self::PrivateInternetAccess => "privateinternetaccess",
            Self::Mullvad => "mullvad",
            Self::ProtonVPN => "protonvpn",
            Self::MozillaVPN => "mozillavpn",
            Self::AzireVPN => "azirevpn",
            Self::AirVPN => "airvpn",
            Self::IVPN => "ivpn",
            Self::NordVPN => "nordvpn",
            Self::Warp => "warp",
            Self::Custom => "custom",
            Self::None => "none",
        }
    }

    /// Human-readable provider name for frontend display.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::PrivateInternetAccess => "Private Internet Access",
            Self::Mullvad => "Mullvad",
            Self::ProtonVPN => "ProtonVPN",
            Self::MozillaVPN => "Mozilla VPN",
            Self::AzireVPN => "AzireVPN",
            Self::AirVPN => "AirVPN",
            Self::IVPN => "IVPN",
            Self::NordVPN => "NordVPN",
            Self::Warp => "Cloudflare WARP",
            Self::Custom => "Custom",
            Self::None => "None",
        }
    }

    /// Protocols for which this provider can generate/sync configurations.
    ///
    /// Single source of truth so the CLI, sync menu, and server listings cannot
    /// drift apart. Providers needing per-protocol setup beyond OpenVPN/Wireguard
    /// must extend this method together with their dyn getters.
    pub fn supported_sync_protocols(&self) -> Vec<Protocol> {
        let mut protocols = Vec::new();
        if self.get_dyn_openvpn_provider().is_ok() {
            protocols.push(Protocol::OpenVpn);
        }
        if self.get_dyn_wireguard_provider().is_ok() {
            protocols.push(Protocol::Wireguard);
        }
        if matches!(self, Self::Warp) {
            protocols.push(Protocol::Warp);
        }
        protocols
    }

    /// Whether `vopono sync` applies to this provider at all.
    pub fn supports_sync(&self) -> bool {
        !matches!(self, Self::Warp | Self::Custom | Self::None)
    }

    /// Whether the provider offers forwarded ports that users must configure
    /// on the provider side (vopono can open the tunnel port but cannot claim it).
    pub fn supports_port_forwarding(&self) -> bool {
        matches!(
            self,
            Self::PrivateInternetAccess | Self::ProtonVPN | Self::AzireVPN | Self::AirVPN
        )
    }

    /// Whether vopono can obtain/refresh the forwarded port automatically.
    pub fn has_automatic_port_forwarding(&self) -> bool {
        matches!(
            self,
            Self::PrivateInternetAccess | Self::ProtonVPN | Self::AzireVPN
        )
    }

    /// Whether port forwarding is available for this provider when using the
    /// given protocol. PIA and ProtonVPN forwarders are tunnel-agnostic;
    /// AzireVPN only implements its flow over Wireguard. AirVPN exposes
    /// manually configured forwarded ports regardless of protocol.
    pub fn port_forwarding_for(&self, protocol: Protocol) -> bool {
        if !self.supports_port_forwarding() {
            return false;
        }
        match self {
            Self::AzireVPN => matches!(protocol, Protocol::Wireguard),
            _ => true,
        }
    }

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
            Self::Warp => Box::new(warp::Warp {}),
            Self::Custom => unimplemented!("Custom provider uses separate logic"),
            Self::None => unimplemented!("None provider runs no protocol"),
        }
    }

    pub fn get_dyn_openvpn_provider(&self) -> anyhow::Result<Box<dyn OpenVpnProvider>> {
        match self {
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
            Self::Mullvad => Err(anyhow!(
                "Mullvad does not support OpenVPN as of January 2026"
            )),
            Self::ProtonVPN => Ok(Box::new(protonvpn::ProtonVPN {})),
            Self::AzireVPN => Err(anyhow!(
                "AzireVPN does not support OpenVPN as of March 2025"
            )),
            Self::AirVPN => Ok(Box::new(airvpn::AirVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::NordVPN => Ok(Box::new(nordvpn::NordVPN {})),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            Self::MozillaVPN => Err(anyhow!("MozillaVPN only supports Wireguard!")),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
            Self::None => unimplemented!("None provider runs no protocol"),
        }
    }

    pub fn get_dyn_wireguard_provider(&self) -> anyhow::Result<Box<dyn WireguardProvider>> {
        match self {
            Self::PrivateInternetAccess => Ok(Box::new(pia::PrivateInternetAccess {})),
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::MozillaVPN => Ok(Box::new(mozilla::MozillaVPN {})),
            Self::AzireVPN => Ok(Box::new(azirevpn::AzireVPN {})),
            Self::AirVPN => Ok(Box::new(airvpn::AirVPN {})),
            Self::IVPN => Ok(Box::new(ivpn::IVPN {})),
            Self::Custom => Err(anyhow!("Custom provider uses separate logic")),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            Self::None => unimplemented!("None provider runs no protocol"),
            _ => Err(anyhow!("Wireguard not implemented")),
        }
    }

    pub fn get_dyn_shadowsocks_provider(&self) -> anyhow::Result<Box<dyn ShadowsocksProvider>> {
        match self {
            Self::Mullvad => Ok(Box::new(mullvad::Mullvad {})),
            Self::Custom => Err(anyhow!("Start Shadowsocks manually for custom provider")),
            Self::Warp => Err(anyhow!("Cloudflare Warp supports only the Warp protocol")),
            Self::None => unimplemented!("None provider runs no protocol"),
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

    fn validate_auth(&self, user: &str, pass: &str) -> anyhow::Result<()> {
        if user.is_empty() {
            return Err(anyhow!("VPN username must not be empty"));
        }
        if pass.is_empty() {
            return Err(anyhow!("VPN password must not be empty"));
        }
        Ok(())
    }

    fn load_openvpn_auth(&self) -> anyhow::Result<(String, String)> {
        let auth_file = self.auth_file_path()?;
        if let Some(auth_file) = auth_file {
            let mut reader = BufReader::new(File::open(auth_file)?);
            let mut user = String::new();
            reader.read_line(&mut user)?;
            let mut pass = String::new();
            reader.read_line(&mut pass)?;
            let user = user.trim_end_matches(['\r', '\n']).to_string();
            let pass = pass.trim_end_matches(['\r', '\n']).to_string();
            self.validate_auth(&user, &pass)?;
            Ok((user, pass))
        } else {
            Err(anyhow!("Auth file required to load credentials!"))
        }
    }

    fn openvpn_dir(&self) -> anyhow::Result<PathBuf> {
        Ok(self.provider_dir()?.join("openvpn"))
    }
}

/// This trait is implemented if the provider has a Shadowsocks server
pub trait ShadowsocksProvider: Provider {
    fn password(&self) -> String;
    fn encrypt_method(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::VpnProvider;
    use crate::config::vpn::Protocol;

    #[test]
    fn sync_protocol_capabilities_match_dyn_providers() {
        let airvpn = VpnProvider::AirVPN.supported_sync_protocols();
        assert!(airvpn.contains(&Protocol::OpenVpn));
        assert!(airvpn.contains(&Protocol::Wireguard));

        // Mullvad dropped OpenVPN support; only Wireguard remains.
        assert_eq!(
            VpnProvider::Mullvad.supported_sync_protocols(),
            vec![Protocol::Wireguard]
        );

        // Warp reports only its own protocol and never participates in
        // config-file syncing.
        assert_eq!(
            VpnProvider::Warp.supported_sync_protocols(),
            vec![Protocol::Warp]
        );
        assert!(!VpnProvider::Warp.supports_sync());
        assert!(!VpnProvider::Custom.supports_sync());
    }

    #[test]
    fn port_forwarding_capabilities_are_explicit() {
        assert!(VpnProvider::AirVPN.supports_port_forwarding());
        assert!(!VpnProvider::AirVPN.has_automatic_port_forwarding());

        for automatic in [
            VpnProvider::PrivateInternetAccess,
            VpnProvider::ProtonVPN,
            VpnProvider::AzireVPN,
        ] {
            assert!(automatic.supports_port_forwarding());
            assert!(automatic.has_automatic_port_forwarding());
        }

        assert!(!VpnProvider::Mullvad.supports_port_forwarding());
    }
}
