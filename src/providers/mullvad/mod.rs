mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};

pub struct Mullvad {}

impl Provider for Mullvad {
    fn alias(&self) -> String {
        "mv".to_string()
    }
}
