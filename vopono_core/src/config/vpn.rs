use super::providers::OpenVpnProvider;
use super::providers::{ConfigurationChoice, UiClient};
use anyhow::{Context, anyhow};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, FromRepr};

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize, EnumIter, FromRepr, Default)]
#[repr(usize)]
pub enum OpenVpnProtocol {
    #[default]
    UDP,
    TCP,
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
    AmneziaWG,
    OpenConnect,
    OpenFortiVpn,
    Ssh,
    Warp,
    None,
}

impl Protocol {
    // Keep these explicit because they are stable machine-facing API values.
    /// Stable, lower-case identifier for machine-facing interfaces.
    pub fn id(&self) -> &'static str {
        match self {
            Self::OpenVpn => "openvpn",
            Self::Wireguard => "wireguard",
            Self::AmneziaWG => "amneziawg",
            Self::OpenConnect => "openconnect",
            Self::OpenFortiVpn => "openfortivpn",
            Self::Ssh => "ssh",
            Self::Warp => "warp",
            Self::None => "none",
        }
    }
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
            let username = iter.next().with_context(|| "No username")??;
            let password = iter.next().with_context(|| "No password")??;
            provider.validate_auth(&username, &password)?;
            Ok(Some(auth_file))
        }
        Err(_) => {
            debug!(
                "No auth file: {} - prompting user",
                auth_file.to_string_lossy()
            );

            // Write OpenVPN credentials file
            let (user, pass) = provider.prompt_for_auth(uiclient)?;
            let contents = format!("{user}\n{pass}");
            if !crate::util::write_file_as_config_owner(&auth_file, &contents, Some(0o600))? {
                let mut outfile = crate::util::create_private_file(&auth_file)?;
                write!(outfile, "{contents}")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // Credentials file: restrict to the owning user.
                    std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
                }
            }

            info!("Credentials written to: {}", auth_file.to_string_lossy());
            Ok(Some(auth_file))
        }
    }
}
