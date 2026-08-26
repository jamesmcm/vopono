mod openvpn;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::vpn::Protocol;
use std::net::{IpAddr, Ipv4Addr};

/// The NAT-PMP gateway ProtonVPN serves port-forwarding mappings from inside
/// the tunnel.
pub const PROTONVPN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));

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
