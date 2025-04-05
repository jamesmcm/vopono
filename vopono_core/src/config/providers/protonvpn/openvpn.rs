use super::ProtonVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::{Input, Password, UiClient};
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use anyhow::anyhow;
use log::{debug, info};
use regex::Regex;
use reqwest::Url;
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use std::fmt::Display;
use std::fs::File;
use std::fs::create_dir_all;
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
        protocol: &OpenVpnProtocol,
    ) -> anyhow::Result<Url> {
        let cat = if tier == &Tier::Free {
            "Server".to_string()
        } else {
            category.url_part()
        };
        Ok(Url::parse(&format!(
            "https://account.protonvpn.com/api/vpn/config?Category={}&Tier={}&Platform=Linux&Protocol={}",
            cat,
            tier.url_part(),
            protocol
        ))?)
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

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {
            prompt:
                "ProtonVPN OpenVPN username (see: https://account.protonvpn.com/account#openvpn ) - add +pmp suffix if using --port-forwarding - note not all servers support this feature"
                    .to_string(),
            validator: None,
        })?;

        let password = uiclient.get_password(Password {
            prompt: "OpenVPN Password".to_string(),
            confirm: true,
        })?;
        Ok((username.trim().to_string(), password.trim().to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let code_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let tier = Tier::index_to_variant(uiclient.get_configuration_choice(&Tier::default())?);
        let config_choice = if tier != Tier::Free {
            ConfigType::index_to_variant(uiclient.get_configuration_choice(&ConfigType::default())?)
        } else {
            // Dummy as not used for Free
            ConfigType::Standard
        };
        let protocol = OpenVpnProtocol::index_to_variant(
            uiclient.get_configuration_choice(&OpenVpnProtocol::default())?,
        );

        let auth_cookie: &'static str = Box::leak(uiclient.get_input(Input {
            prompt: "Please log-in at https://account.protonvpn.com/dashboard and then visit https://account.protonvpn.com/account and copy the value of the cookie of the form \"AUTH-xxx=yyy\" where xxx is equal to the value of the \"x-pm-uid\" request header, in the request from your browser's network request inspector (check the request it makes to https://account.protonvpn.com/api/vpn for example). Note there may be multiple AUTH-xxx=yyy request headers, copy the one where xxx is equal to the value of the x-pm-uid header.".to_owned(),
             validator: Some(Box::new(|s: &String| if s.starts_with("AUTH-") {Ok(())} else {Err("AUTH cookie must start with AUTH-".to_owned())}))
             })?.replace(';', "").trim().to_owned().into_boxed_str());
        debug!("Using AUTH cookie: {}", &auth_cookie);

        let uid_re = Regex::new("AUTH-([^=]+)=").unwrap();
        let uid = uid_re
            .captures(auth_cookie)
            .and_then(|c| c.get(1))
            .ok_or(anyhow!("Failed to parse uid from auth cookie"))?;
        info!(
            "x-pm-uid should be {} according to AUTH cookie: {}",
            uid.as_str(),
            auth_cookie
        );
        let url = self.build_url(&config_choice, &tier, &protocol)?;

        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static(auth_cookie));

        headers.insert(
            HeaderName::from_static("x-pm-uid"),
            HeaderValue::from_static(uid.as_str()),
        );
        let client = reqwest::blocking::Client::new();

        let zipfile = client.get(url).headers(headers).send()?;

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
                let mut hostname: Option<String> = None;
                let mut code = file.name().split('.').next().unwrap();
                if code.contains("free") {
                    // Free case
                    let mut iter_split = code.split('-');
                    let fcode = iter_split.next().unwrap();
                    hostname = Some(iter_split.next().unwrap().to_owned());
                    code = fcode;
                } else if code.contains('-') {
                    // SecureCore
                    let mut iter_split = code.split('-');
                    let start = iter_split.next().unwrap();
                    let end = iter_split.next().unwrap();
                    let number = iter_split.next().unwrap();
                    hostname = Some(format!("{}_{}", start, number));
                    code = end;
                }
                let country = code_map
                    .get(code)
                    .unwrap_or_else(|| panic!("Could not find code in map: {code}"));
                let host_str = if let Some(host) = hostname {
                    format!("-{host}")
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
            write!(outfile, "{file_contents}")?;
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
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;
            info!(
                "ProtonVPN OpenVPN config written to {}",
                openvpn_dir.display()
            );
        }
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum Tier {
    Plus,
    Free,
}

impl Tier {
    fn url_part(&self) -> String {
        match self {
            Self::Plus => "2".to_string(),
            Self::Free => "0".to_string(),
        }
    }
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Plus => "Plus",
            Self::Free => "Free",
        };
        write!(f, "{s}")
    }
}

impl Default for Tier {
    fn default() -> Self {
        Self::Free
    }
}

impl ConfigurationChoice for Tier {
    fn prompt(&self) -> String {
        "Choose your ProtonVPN account tier".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().map(|x| x.description().unwrap()).collect())
    }

    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::Plus => "Plus Account provides more VPN servers and SecureCore configuration",
                Self::Free => "Free VPN servers only",
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
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SecureCore => "SecureCore",
            Self::Standard => "Standard",
        };
        write!(f, "{s}")
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::Standard
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
