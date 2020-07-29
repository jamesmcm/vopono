use super::Mullvad;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::vpn::OpenVpnProtocol;
use log::{debug, warn};
use rand::seq::SliceRandom;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

impl Mullvad {
    fn get_default_openvpn_settings(&self) -> Vec<&'static str> {
        vec![
            "client",
            "dev tun",
            "resolv-retry infinite",
            "nobind",
            "persist-key",
            "persist-tun",
            "verb 3",
            "remote-cert-tls server",
            "ping 10",
            "ping-restart 60",
            "sndbuf 524288",
            "rcvbuf 524288",
            "cipher AES-256-CBC",
            "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
            "auth-user-pass mullvad_userpass.txt",
            "ca mullvad_ca.crt",
            "tun-ipv6",
            "script-security 2",
        ]
    }
}

impl OpenVpnProvider for Mullvad {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![IpAddr::V4(Ipv4Addr::new(193, 138, 218, 74))])
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(openvpn_dir)?;

        let client = Client::new();
        let relays: Vec<OpenVpnRelay> = client
            .get("https://api.mullvad.net/www/relays/openvpn/")
            .send()?
            .json()?;

        let mut config_choice = ConfigType::choose_one()?;
        let port = config_choice.generate_port();

        let use_ips = dialoguer::Confirm::new()
            .with_prompt(
                "Use IP addresses instead of hostnames? (may be resistant to DNS blocking, but need to be synced more frequently)"
            )
            .default(false)
            .interact()?;

        let use_bridges = dialoguer::Confirm::new()
            .with_prompt(
                "Connect via a bridge? (route over two separate servers, requires connecting on TCP port 443)"
            )
            .default(false)
            .interact()?;

        let mut settings = self.get_default_openvpn_settings();

        if use_bridges {
            if config_choice != ConfigType::Tcp443 {
                warn!("Overriding chosen protocol and port to TCP 443 due to use of bridge");
                config_choice = ConfigType::Tcp443;
            }
            settings.push("socks-proxy 127.0.0.1 1080");
        }

        match config_choice.get_protocol() {
            OpenVpnProtocol::UDP => {
                settings.push("proto udp");
                settings.push("fast-io");
            }
            OpenVpnProtocol::TCP => {
                settings.push("proto tcp");
            }
        }

        // Group relays by country
        // Generate config file per relay given options
        // Naming: country_name-hostalias.ovpn

        // if using bridges, add all bridges
        // route ${b.ipv4_addr_in} 255.255.255.255 net_gateway # ${b.hostname}
        //
        // if using IPs
        // remote ${r.ipv4_addr_in} ${port} # ${r.hostname}
        // else
        // remote ${r.hostname}.mullvad.net ${port}
        //
        // if relays.len() > 1
        // remote-random

        // Write config files
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    DefaultUdp,
    Udp53,
    Tcp80,
    Tcp443,
}

impl ConfigType {
    fn get_protocol(&self) -> OpenVpnProtocol {
        match self {
            Self::DefaultUdp => OpenVpnProtocol::UDP,
            Self::Udp53 => OpenVpnProtocol::UDP,
            Self::Tcp80 => OpenVpnProtocol::TCP,
            Self::Tcp443 => OpenVpnProtocol::TCP,
        }
    }

    fn generate_port(&self) -> u16 {
        match self {
            Self::DefaultUdp => *[1300, 1301, 1302, 1194, 1195, 1196, 1197]
                .choose(&mut rand::thread_rng())
                .expect("Could not choose default port"),
            Self::Udp53 => 53,
            Self::Tcp80 => 80,
            Self::Tcp443 => 443,
        }
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DefaultUdp => "Default (UDP)",
            Self::Udp53 => "UDP (Port 53)",
            Self::Tcp80 => "TCP (Port 80)",
            Self::Tcp443 => "TCP (Port 443)",
        };
        write!(f, "{}", s)
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::DefaultUdp
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt() -> String {
        "Please choose your OpenVPN connection protocol and port".to_string()
    }

    fn variants() -> Vec<Self> {
        ConfigType::iter().collect()
    }

    fn description(&self) -> Option<String> {
        None
    }
}

#[derive(Deserialize, Debug)]
struct OpenVpnRelay {
    hostname: String,
    country_code: String,
    country_name: String,
    city_code: String,
    city_name: String,
    active: bool,
    owned: bool,
    provider: String,
    ipv4_addr_in: std::net::Ipv4Addr,
    ipv6_addr_in: std::net::Ipv6Addr,
}
