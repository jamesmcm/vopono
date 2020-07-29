mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};

pub struct PrivateInternetAccess {}

impl Provider for PrivateInternetAccess {
    fn alias(&self) -> String {
        "pia".to_string()
    }
}
