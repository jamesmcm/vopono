pub mod application_wrapper;
pub mod dns_config;
pub mod firewall;
pub mod host_masquerade;
pub mod natpmpc;
pub mod netns;
pub mod network_interface;
pub mod openconnect;
pub mod openfortivpn;
pub mod openvpn;
pub mod piapf;
pub mod shadowsocks;
pub mod sysctl;
pub mod veth_pair;
pub mod warp;
pub mod wireguard;

pub trait Forwarder {
    fn forwarded_port(&self) -> u16;
}
