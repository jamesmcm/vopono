use super::providers::ConfigurationChoice;
use super::util::config_dir;
use anyhow::{anyhow, Context};
use clap::arg_enum;
use dialoguer::{Input, Password};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, EnumIter)]
pub enum OpenVpnProtocol {
    UDP,
    TCP,
}

impl Default for OpenVpnProtocol {
    fn default() -> Self {
        Self::UDP
    }
}

impl ConfigurationChoice for OpenVpnProtocol {
    fn prompt() -> String {
        "Which OpenVPN connection protocol do you wish to use".to_string()
    }

    fn variants() -> Vec<Self> {
        OpenVpnProtocol::iter().collect()
    }

    fn description(&self) -> Option<String> {
        None
    }
}

impl FromStr for OpenVpnProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Self::UDP),
            "tcp-client" => Ok(Self::TCP),
            "tcp" => Ok(Self::TCP),
            _ => Err(anyhow!("Unknown VPN protocol: {}", s)),
        }
    }
}

impl Display for OpenVpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let out = match self {
            Self::UDP => "udp",
            Self::TCP => "tcp",
        };
        write!(f, "{}", out)
    }
}

arg_enum! {
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Protocol {
    OpenVpn,
    Wireguard,
}
}

// pub enum Firewall {
//     IpTables,
//     NfTables,
//     Ufw,
// }

#[derive(Serialize, Deserialize)]
pub struct VpnServer {
    pub name: String,
    pub alias: String,
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<OpenVpnProtocol>,
}

// TODO: Can we avoid storing plaintext passwords?
// TODO: Allow not storing credentials
// OpenVPN only
pub fn get_auth(provider: &VpnProvider) -> anyhow::Result<()> {
    let mut auth_path = config_dir()?;
    auth_path.push(format!("vopono/{}/openvpn/auth.txt", provider.alias()));
    let file = File::open(&auth_path);
    match file {
        Ok(f) => {
            debug!("Read auth file: {}", auth_path.to_string_lossy());
            let bufreader = BufReader::new(f);
            let mut iter = bufreader.lines();
            let _username = iter.next().with_context(|| "No username")??;
            let _password = iter.next().with_context(|| "No password")??;
            Ok(())
        }
        Err(_) => {
            debug!(
                "No auth file: {} - prompting user",
                auth_path.to_string_lossy()
            );

            let user_prompt = match provider {
                VpnProvider::Mullvad => "Mullvad account number",
                VpnProvider::TigerVpn => {
                    "OpenVPN username (see https://www.tigervpn.com/dashboard/geeks )"
                }
                VpnProvider::PrivateInternetAccess => "PrivateInternetAccess username",
                VpnProvider::Custom => "OpenVPN username",
            };
            let mut username = Input::<String>::new().with_prompt(user_prompt).interact()?;
            if *provider == VpnProvider::Mullvad {
                username.retain(|c| !c.is_whitespace() && c.is_digit(10));
                if username.len() != 16 {
                    return Err(anyhow!(
                        "Mullvad account number should be 16 digits!, parsed: {}",
                        username
                    ));
                }
            }

            let password = if *provider == VpnProvider::Mullvad {
                String::from("m")
            } else {
                Password::new()
                    .with_prompt("Password")
                    .with_confirmation("Confirm password", "Passwords did not match")
                    .interact()?
            };

            let mut writefile = File::create(&auth_path)
                .with_context(|| format!("Could not create auth file: {}", auth_path.display()))?;
            write!(writefile, "{}\n{}\n", username, password)?;
            info!("Credentials written to: {}", auth_path.to_string_lossy());
            Ok(())
        }
    }
}
