use super::Mullvad;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::UiClient;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use anyhow::Context;
use log::warn;
use rand::seq::SliceRandom;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
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

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = self.request_mullvad_username(uiclient)?;
        Ok((username, "m".to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("mullvad_userpass.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;

        let client = Client::new();
        let relays: Vec<OpenVpnRelay> = client
            .get("https://api.mullvad.net/www/relays/openvpn/")
            .send()?
            .json()?;

        let mut config_choice = ConfigType::index_to_variant(
            uiclient.get_configuration_choice(&ConfigType::default())?,
        );
        let port = config_choice.generate_port();

        let use_ips = Confirm::new()
            .with_prompt(
                "Use IP addresses instead of hostnames? (may be resistant to DNS blocking, but need to be synced more frequently)"
            )
            .default(false)
            .interact()?;

        let use_bridges = Confirm::new()
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
        let mut file_set: HashMap<String, Vec<String>> = HashMap::with_capacity(128);
        for relay in relays.into_iter().filter(|x| x.active) {
            let file_name = format!(
                "{}-{}.ovpn",
                relay.country_name.to_lowercase().replace(' ', "_"),
                relay.country_code
            );

            let remote_string = if use_ips {
                format!(
                    "remote {} {} # {}",
                    relay.ipv4_addr_in, port, relay.hostname
                )
            } else {
                format!("remote {}.mullvad.net {}", relay.hostname, port)
            };

            file_set
                .entry(file_name)
                .or_insert_with(Vec::new)
                .push(remote_string);
        }

        let bridge_vec = if use_bridges {
            let bridges: Vec<OpenVpnRelay> = client
                .get("https://api.mullvad.net/www/relays/bridge/")
                .send()?
                .json()?;
            bridges
                .into_iter()
                .filter(|x| x.active)
                .map(|x| {
                    format!(
                        "route {} 255.255.255.255 net_gateway # {}",
                        x.ipv4_addr_in, x.hostname
                    )
                })
                .collect::<Vec<String>>()
        } else {
            Vec::new()
        };

        for (file_name, mut remote_vec) in file_set.into_iter() {
            let mut file = File::create(&openvpn_dir.join(file_name))?;
            writeln!(file, "{}", settings.join("\n"))?;

            remote_vec.shuffle(&mut rand::thread_rng());
            writeln!(
                file,
                "{}",
                remote_vec[0..remote_vec.len().min(64)].join("\n")
            )?;
            if remote_vec.len() > 1 {
                writeln!(file, "remote-random")?;
            }

            if !bridge_vec.is_empty() {
                writeln!(file, "{}", bridge_vec.join("\n"))?;
            }
        }

        // Write CA cert
        let ca = include_str!("mullvad_ca.crt");
        {
            let file = File::create(openvpn_dir.join("mullvad_ca.crt"))
                .context("Could not create mullvad CA file")?;
            let mut write_buf = std::io::BufWriter::new(file);
            write!(write_buf, "{}", ca)?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{}\n{}", user, pass)?;
        }
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
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
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
    fn prompt(&self) -> String {
        "Please choose your OpenVPN connection protocol and port".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{}", x)).collect()
    }

    fn description(&self) -> Option<String> {
        None
    }
}

// Note we ignore ipv6 addr here
#[allow(dead_code)]
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
}
