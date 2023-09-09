use super::Provider;
use crate::config::vpn::Protocol;

pub struct Warp {}

impl Provider for Warp {
    fn alias(&self) -> String {
        "warp".to_string()
    }

    fn alias_2char(&self) -> String {
        "wp".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::Warp
    }
}
