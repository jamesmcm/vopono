use super::ProtonVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::util::delete_all_files_in_dir;
use crate::vpn::OpenVpnProtocol;
use dialoguer::{Input, Password};
use log::{debug, info};
use reqwest::Url;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

impl ProtonVPN {
    fn build_url(
        &self,
        category: &ConfigType,
        tier: &Tier,
        feature: &Feature,
        protocol: &OpenVpnProtocol,
    ) -> anyhow::Result<Url> {
        let cat = if tier == &Tier::Free {
            "Server".to_string()
        } else {
            category.url_part()
        };
        let fet = if tier == &Tier::Free {
            "Normal".to_string()
        } else {
            feature.url_part()
        };
        Ok(Url::parse(&format!("https://account.protonvpn.com/api/vpn/config?Category={}&Tier={}&Feature={}&Platform=Linux&Protocol={}", cat, tier.url_part(), fet, protocol))?)
    }
}
impl OpenVpnProvider for ProtonVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        // None will use DNS from OpenVPN headers if present
        None
        // TODO: ProtonVPN DNS servers do not respond
        // let path = self.openvpn_dir().ok()?.join("dns.txt");
        // let ip_str = match std::fs::read_to_string(&path) {
        //     Err(x) => {
        //         error!("Failed to read DNS file: {}: {:?}", path.display(), x);
        //         return None;
        //     }
        //     Ok(x) => x,
        // };

        // let ip = match Ipv4Addr::from_str(&ip_str.trim()) {
        //     Err(x) => {
        //         error!("Failed to convert IP string: {}: {:?}", ip_str, x);
        //         return None;
        //     }
        //     Ok(x) => x,
        // };

        // Some(vec![IpAddr::V4(ip)])
    }

    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)> {
        let username = Input::<String>::new()
            .with_prompt(
                "ProtonVPN OpenVPN username (see: https://account.protonvpn.com/account#openvpn )",
            )
            .interact()?;

        let password = Password::new()
            .with_prompt("OpenVPN Password")
            .with_confirmation("Confirm password", "Passwords did not match")
            .interact()?;
        Ok((username.trim().to_string(), password.trim().to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.openvpn_dir()?.join("auth.txt"))
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let code_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let tier = Tier::choose_one()?;
        let config_choice = if tier != Tier::Free {
            ConfigType::choose_one()?
        } else {
            // Dummy as not used for Free
            ConfigType::Standard
        };
        let feature_choice = if tier != Tier::Free {
            Feature::choose_one()?
        } else {
            Feature::Normal
        };
        let protocol = OpenVpnProtocol::choose_one()?;
        let url = self.build_url(&config_choice, &tier, &feature_choice, &protocol)?;
        let zipfile = reqwest::blocking::get(url)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        for i in 0..zip.len() {
            // Modify auth line for config
            // Write to config dir
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();
            file.read_to_end(&mut file_contents)?;

            let file_contents = std::str::from_utf8(&file_contents)?;
            let file_contents = file_contents
                .split('\n')
                .filter(|&x| !(x.starts_with("up ") || x.starts_with("down ")))
                .collect::<Vec<&str>>()
                .join("\n");

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                // Also handle server case from free servers
                let mut hostname = None;
                let mut code = file.name().split('.').next().unwrap();
                if code.contains('-') {
                    let mut iter_split = code.split('-');
                    let fcode = iter_split.next().unwrap();
                    hostname = Some(iter_split.next().unwrap());
                    code = fcode;
                }
                let country = code_map
                    .get(code)
                    .unwrap_or_else(|| panic!("Could not find code in map: {}", code));
                let host_str = if let Some(host) = hostname {
                    format!("-{}", host)
                } else {
                    String::new()
                };
                format!("{}-{}{}.ovpn", country, code, &host_str)
            } else {
                file.name().to_string()
            };

            debug!("Reading file: {}", file.name());
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{}", file_contents)?;
        }

        // TODO: ProtonVPN DNS servers do not connect
        // Write DNS file (protocol dependent)
        // let dns_string = match protocol {
        //     OpenVpnProtocol::TCP => "10.7.7.1",
        //     OpenVpnProtocol::UDP => "10.8.8.1",
        // };

        // let mut dns_file = File::create(self.openvpn_dir()?.join("dns.txt"))?;
        // write!(dns_file, "{}", dns_string)?;

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth()?;
        let mut outfile = File::create(self.auth_file_path()?)?;
        write!(outfile, "{}\n{}", user, pass)?;
        info!(
            "ProtonVPN OpenVPN config written to {}",
            openvpn_dir.display()
        );
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum Tier {
    Plus,
    Basic,
    Free,
}

impl Tier {
    fn url_part(&self) -> String {
        match self {
            Self::Plus => "2".to_string(),
            Self::Basic => "1".to_string(),
            Self::Free => "0".to_string(),
        }
    }
}

impl Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Plus => "Plus",
            Self::Basic => "Basic",
            Self::Free => "Free",
        };
        write!(f, "{}", s)
    }
}

impl Default for Tier {
    fn default() -> Self {
        Self::Basic
    }
}

impl ConfigurationChoice for Tier {
    fn prompt() -> String {
        "Choose your ProtonVPN account tier".to_string()
    }

    fn variants() -> Vec<Self> {
        Tier::iter().collect()
    }
    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::Plus => "Plus Account provides more VPN servers and SecureCore configuration",
                Self::Basic => "Provides core VPN servers",
                Self::Free => "Free VPN servers only",
            }
            .to_string(),
        )
    }
}
// {0: "Normal", 1: "Secure-Core", 2: "Tor", 4: "P2P"}
#[derive(EnumIter, PartialEq)]
enum Feature {
    P2P,
    Tor,
    Normal,
}

impl Feature {
    fn url_part(&self) -> String {
        match self {
            Self::P2P => "4".to_string(),
            Self::Tor => "2".to_string(),
            Self::Normal => "0".to_string(),
        }
    }
}

impl Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::P2P => "P2P",
            Self::Tor => "Tor",
            Self::Normal => "Normal",
        };
        write!(f, "{}", s)
    }
}

impl Default for Feature {
    fn default() -> Self {
        Self::Normal
    }
}

impl ConfigurationChoice for Feature {
    fn prompt() -> String {
        "Please choose a server feature".to_string()
    }

    fn variants() -> Vec<Self> {
        Feature::iter().collect()
    }
    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::P2P => "Connect via torrent optmized network (Plus accounts only)",
                Self::Tor => "Connect via Tor network (Plus accounts only)",
                Self::Normal => "Standard (available servers depend on account tier)",
            }
            .to_string(),
        )
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    SecureCore,
    Standard,
}

impl ConfigType {
    fn url_part(&self) -> String {
        match self {
            Self::SecureCore => "SecureCore".to_string(),
            Self::Standard => "Country".to_string(),
        }
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SecureCore => "SecureCore",
            Self::Standard => "Standard",
        };
        write!(f, "{}", s)
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::Standard
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
        Some(
            match self {
                Self::SecureCore => {
                    "Connect via SecureCore bridge for additional security (Plus accounts only)"
                }
                Self::Standard => {
                    "Standard OpenVPN connection (available servers depend on account tier)"
                }
            }
            .to_string(),
        )
    }
}
