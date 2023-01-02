use super::NordVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::{Input, Password, UiClient};
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use log::debug;
use regex::Regex;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

impl OpenVpnProvider for NordVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(103, 86, 96, 100)),
            IpAddr::V4(Ipv4Addr::new(103, 86, 99, 100)),
        ])
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {
            prompt: "NordVPN username".to_string(),
            validator: None,
        })?;

        let password = uiclient.get_password(Password {
            prompt: "Password".to_string(),
            confirm: true,
        })?;
        Ok((username, password))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let url = "https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip";
        let config_choice = ConfigType::index_to_variant(
            uiclient.get_configuration_choice(&ConfigType::default())?,
        );
        let zipfile = reqwest::blocking::get(url)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let protocol_dir = match config_choice.get_protocol() {
            OpenVpnProtocol::TCP => "ovpn_tcp",
            OpenVpnProtocol::UDP => "ovpn_udp",
        };
        let server_regex = Regex::new(r"([a-z]+)(?:-(onion|[a-z]+))?([0-9]+)").unwrap();
        for i in 0..zip.len() {
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            if !file.sanitized_name().starts_with(protocol_dir) {
                continue;
            }
            file.read_to_end(&mut file_contents)?;

            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                let fname = file
                    .enclosed_name()
                    .and_then(|x| x.file_name())
                    .and_then(|x| x.to_str());
                if fname.is_none() {
                    debug!("Could not parse filename: {}", file.name().to_string());
                    continue;
                }
                let fname = fname.unwrap();
                let server_name = fname.to_lowercase().replace(' ', "_");
                let server_name = server_name.split('.').next().unwrap();

                if let Some(cap) = server_regex.captures(server_name) {
                    // check whether the server is a special config type
                    // or not, and discard ones not in line with user's
                    // selection
                    if let Some(config_type) = cap.get(2) {
                        if (config_type.as_str() == "onion" && !config_choice.is_onion())
                            || !config_choice.is_double()
                        {
                            continue;
                        }
                    } else if config_choice.is_onion() || config_choice.is_double() {
                        continue;
                    }

                    if let Some(code) = cap.get(1) {
                        let country = country_map.get(code.as_str());
                        if country.is_none() {
                            debug!("Could not map country code to name: {}", code.as_str());
                            fname.to_string()
                        } else {
                            let server_name = server_name.replace('-', "_");
                            format!("{}-{}.ovpn", country.unwrap(), server_name)
                        }
                    } else {
                        debug!(
                            "Filename did not match established pattern: {}",
                            fname.to_string()
                        );
                        fname.to_string()
                    }
                } else {
                    debug!(
                        "Filename did not match established pattern: {}",
                        fname.to_string()
                    );
                    fname.to_string()
                }
            } else {
                file.name().to_string()
            };

            debug!("Reading file: {}", file.name());
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            outfile.write_all(file_contents.as_slice())?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;
        }
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    DefaultTcp,
    Udp,
    OnionTcp,
    OnionUdp,
    DoubleTcp,
    DoubleUdp,
}

impl ConfigType {
    fn get_protocol(&self) -> OpenVpnProtocol {
        match self {
            Self::DefaultTcp => OpenVpnProtocol::TCP,
            Self::Udp => OpenVpnProtocol::UDP,
            Self::OnionTcp => OpenVpnProtocol::TCP,
            Self::OnionUdp => OpenVpnProtocol::UDP,
            Self::DoubleTcp => OpenVpnProtocol::TCP,
            Self::DoubleUdp => OpenVpnProtocol::UDP,
        }
    }

    fn is_onion(&self) -> bool {
        matches!(self, Self::OnionTcp | Self::OnionUdp)
    }

    fn is_double(&self) -> bool {
        matches!(self, Self::DoubleTcp | Self::DoubleUdp)
    }
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DefaultTcp => "Default (TCP)",
            Self::Udp => "UDP",
            Self::OnionTcp => "Onion (TCP)",
            Self::OnionUdp => "Onion (UDP)",
            Self::DoubleTcp => "Double TCP",
            Self::DoubleUdp => "Double UDP",
        };
        write!(f, "{s}")
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::DefaultTcp
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt(&self) -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().map(|x| x.description().unwrap()).collect())
    }
    fn description(&self) -> Option<String> {
        Some( match self {
            Self::DefaultTcp => "These files connect over TCP.",
            Self::Udp => "These files connect over UDP.",
            Self::OnionTcp => "These files connect via Onion over VPN, using TCP.",
            Self::OnionUdp => "These files connect via Onion over VPN, using UDP.",
            Self::DoubleTcp => "These files connect over TCP across two separate VPN servers. The country listed is the initial outgoing VPN server.",
            Self::DoubleUdp => "These files connect over UDP across two separate VPN servers. The country listed is the initial outgoing VPN server.",
        }.to_string())
    }
}
