mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::vpn::Protocol;

pub struct AirVPN {}

impl Provider for AirVPN {
    fn alias(&self) -> String {
        "air".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
