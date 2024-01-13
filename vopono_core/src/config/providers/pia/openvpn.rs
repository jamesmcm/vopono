use super::PrivateInternetAccess;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::UiClient;
use crate::util::delete_all_files_in_dir;
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

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        self.prompt_for_auth(uiclient)
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let config_choice = ConfigType::index_to_variant(
            uiclient.get_configuration_choice(&ConfigType::default())?,
        );
        let zipfile = reqwest::blocking::get(config_choice.url()?)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::country_to_code_map();
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

            // Convert country name to country code
            // TODO: Handle cases where already code_city
            // uk_london.ovpn
            // uae.ovpn

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                let fname = file.name();
                let country = fname.to_lowercase().replace(' ', "_");
                let country = country.split('.').next().unwrap();
                let code = country_map.get(country);
                if code.is_none() {
                    debug!("Could not find country in country map: {}", country);
                    file.name().to_string()
                } else {
                    format!("{}-{}.ovpn", country, code.unwrap())
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
        if let Some(auth_file) = auth_file {
            let mut outfile = File::create(auth_file)?;
            write!(outfile, "{user}\n{pass}")?;
        }
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
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
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
        write!(f, "{s}")
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::DefaultConf
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
