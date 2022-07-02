mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::vpn::Protocol;

pub struct NordVPN {}

impl Provider for NordVPN {
    fn alias(&self) -> String {
        "nordvpn".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
