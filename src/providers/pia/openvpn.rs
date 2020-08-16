use super::PrivateInternetAccess;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::util::delete_all_files_in_dir;
use dialoguer::{Input, Password};
use log::debug;
use reqwest::Url;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

impl OpenVpnProvider for PrivateInternetAccess {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(209, 222, 18, 222)),
            IpAddr::V4(Ipv4Addr::new(209, 222, 18, 218)),
        ])
    }

    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)> {
        let username = Input::<String>::new()
            .with_prompt("PrivateInternetAccess username")
            .interact()?;

        let password = Password::new()
            .with_prompt("Password")
            .with_confirmation("Confirm password", "Passwords did not match")
            .interact()?;
        Ok((username, password))
    }

    fn auth_file_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.openvpn_dir()?.join("auth.txt"))
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let config_choice = ConfigType::choose_one()?;
        let zipfile = reqwest::blocking::get(config_choice.url()?)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        for i in 0..zip.len() {
            // For each file, detect if ovpn, crl or crt
            // Modify auth line for config
            // Write to config dir
            // it detects the crt and crl files
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();
            file.read_to_end(&mut file_contents)?;

            let filename = file.name();
            debug!("Reading file: {}", file.name());
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            outfile.write_all(file_contents.as_slice())?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth()?;
        let mut outfile = File::create(self.auth_file_path()?)?;
        write!(outfile, "{}\n{}", user, pass)?;
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    DefaultConf,
    Ip,
    Strong,
    Tcp,
    StrongTcp,
    LegacyIp,
    LegacyTcpIp,
}

impl ConfigType {
    fn url(&self) -> anyhow::Result<Url> {
        let s = match self {
            Self::DefaultConf => "https://www.privateinternetaccess.com/openvpn/openvpn.zip",
            Self::Ip => "https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip",
            Self::Strong => "https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip",
            Self::Tcp => "https://www.privateinternetaccess.com/openvpn/openvpn-tcp.zip",
            Self::StrongTcp => {
                "https://www.privateinternetaccess.com/openvpn/openvpn-strong-tcp.zip"
            }
            Self::LegacyIp => "https://www.privateinternetaccess.com/openvpn/openvpn-ip-lport.zip",
            Self::LegacyTcpIp => "https://www.privateinternetaccess.com/openvpn/openvpn-ip-tcp.zip",
        };

        Ok(s.parse()?)
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DefaultConf => "Default",
            Self::Ip => "IP",
            Self::Strong => "Strong",
            Self::Tcp => "TCP",
            Self::StrongTcp => "Strong TCP",
            Self::LegacyIp => "Legacy IP",
            Self::LegacyTcpIp => "Legacy TCP IP",
        };
        write!(f, "{}", s)
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::DefaultConf
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt() -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn variants() -> Vec<Self> {
        ConfigType::iter().collect()
    }
    fn description(&self) -> Option<String> {
        Some( match self {
            Self::DefaultConf => "These files connect over UDP port 1198 with AES-128-CBC+SHA1, using the server name to connect.",
            Self::Ip => "These files connect over UDP port 1198 with AES-128-CBC+SHA1, and connect via an IP address instead of the server name.",
            Self::Strong => "These files connect over UDP port 1197 with AES-256-CBC+SHA256, using the server name to connect.",
            Self::Tcp => "These files connect over TCP port 502 with AES-128-CBC+SHA1, using the server name to connect.",
            Self::StrongTcp => "These files connect over TCP port 501 with AES-256-CBC+SHA256, using the server name to connect.",
            Self::LegacyIp => "These files connect over UDP port 8080 with BF-CBC+SHA1 and connect via an IP address instead of the server name.",
            Self::LegacyTcpIp => "These files connect over TCP port 443 with BF-CBC+SHA1 and connect via an IP address instead of the server name.",
        }.to_string())
    }
}
