mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::vpn::Protocol;

pub struct IVPN {}

impl Provider for IVPN {
    fn alias(&self) -> String {
        "ivpn".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        // TODO: Change to Wireguard
        Protocol::OpenVpn
    }
}
