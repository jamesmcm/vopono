mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::vpn::Protocol;

pub struct ProtonVPN {}

impl Provider for ProtonVPN {
    fn alias(&self) -> String {
        "proton".to_string()
    }

    fn alias_2char(&self) -> String {
        "pr".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
