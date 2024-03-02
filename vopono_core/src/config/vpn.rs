use super::providers::OpenVpnProvider;
use super::providers::{ConfigurationChoice, UiClient};
use anyhow::{anyhow, Context};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::Display;
use strum_macros::EnumIter;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize, EnumIter)]
pub enum OpenVpnProtocol {
    UDP,
    TCP,
}

impl OpenVpnProtocol {
    pub fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}
impl Default for OpenVpnProtocol {
    fn default() -> Self {
        Self::UDP
    }
}

impl ConfigurationChoice for OpenVpnProtocol {
    fn prompt(&self) -> String {
        "Which OpenVPN connection protocol do you wish to use".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        None
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
        write!(f, "{out}")
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Display, EnumIter)]
pub enum Protocol {
    OpenVpn,
    Wireguard,
    OpenConnect,
    OpenFortiVpn,
    Warp,
    None,
}

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
pub fn verify_auth(
    provider: Box<dyn OpenVpnProvider>,
    uiclient: &dyn UiClient,
) -> anyhow::Result<Option<PathBuf>> {
    let auth_file = provider.auth_file_path()?;
    if auth_file.is_none() {
        return Ok(None);
    }
    let auth_file = auth_file.unwrap();
    let file = File::open(&auth_file);
    match file {
        Ok(f) => {
            debug!("Read auth file: {}", auth_file.to_string_lossy());
            let bufreader = BufReader::new(f);
            let mut iter = bufreader.lines();
            // TODO: If thise fail, re-gen auth file
            let _username = iter.next().with_context(|| "No username")??;
            let _password = iter.next().with_context(|| "No password")??;
            Ok(Some(auth_file))
        }
        Err(_) => {
            debug!(
                "No auth file: {} - prompting user",
                auth_file.to_string_lossy()
            );

            // Write OpenVPN credentials file
            let (user, pass) = provider.prompt_for_auth(uiclient)?;
            let mut outfile = File::create(provider.auth_file_path()?.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;

            info!("Credentials written to: {}", auth_file.to_string_lossy());
            Ok(Some(auth_file))
        }
    }
}
