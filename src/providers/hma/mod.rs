mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::vpn::Protocol;

pub struct HMA {}

impl Provider for HMA {
    fn alias(&self) -> String {
        "hma".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
