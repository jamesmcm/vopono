mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::vpn::Protocol;

#[allow(clippy::upper_case_acronyms)]
pub struct HMA {}

impl Provider for HMA {
    fn alias(&self) -> String {
        "hma".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}
