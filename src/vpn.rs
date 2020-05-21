// use std::str::FromStr;
use clap::arg_enum;

arg_enum! {
    #[derive(Debug)]
pub enum VpnProvider {
    PrivateInternetAccess,
    Mullvad,
    NordVpn,
}
}

// impl FromStr for VpnProvider {
//     type Err = anyhow::Error;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s.lower() {
//             "pia" => Ok(Self::PrivateInternetAccess),
//             "mullvad" => Ok(Self::Mullvad),
//             "nordvpn" => Ok(Self::NordVpn),
//             _ => anyhow!("Unknown VPN provider: {}", s),
//         }
//     }
// }

pub enum Protocol {
    OpenVpn,
    Wireguard,
}

pub enum Firewall {
    IpTables,
    NfTables,
    Ufw,
}
