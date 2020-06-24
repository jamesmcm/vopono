use super::util::config_dir;
use anyhow::{anyhow, Context};
use clap::arg_enum;
use dialoguer::{Input, Password};
use log::{debug, error, info, warn};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

arg_enum! {
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum VpnProvider {
    PrivateInternetAccess,
    Mullvad,
    TigerVpn,
    Custom,
}
}

impl VpnProvider {
    pub fn alias(&self) -> String {
        match self {
            Self::PrivateInternetAccess => String::from("pia"),
            Self::Mullvad => String::from("mv"),
            Self::TigerVpn => String::from("tig"),
            Self::Custom => String::from("cus"),
        }
    }
}

pub enum OpenVpnProtocol {
    UDP,
    TCP,
}

arg_enum! {
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Protocol {
    OpenVpn,
    Wireguard,
}
}

pub enum Firewall {
    IpTables,
    NfTables,
    Ufw,
}

#[derive(Deserialize)]
pub struct VpnServer {
    name: String,
    alias: String,
    host: String,
    port: Option<u32>,
}

pub fn get_serverlist(provider: &VpnProvider) -> anyhow::Result<Vec<VpnServer>> {
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/serverlist.csv", provider.alias()));
    let file = File::open(&list_path).with_context(|| {
        format!(
            "Could not get serverlist for provider: {}, path: {}",
            provider.to_string(),
            list_path.to_string_lossy()
        )
    })?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);
    let mut resultvec = Vec::new();

    for row in rdr.deserialize() {
        resultvec.push(row?);
    }
    Ok(resultvec)
}

// OpenVPN
pub fn find_host_from_alias(
    alias: &str,
    serverlist: &Vec<VpnServer>,
) -> anyhow::Result<(String, u32, String)> {
    let alias = alias.to_lowercase();
    let record = serverlist
        .into_iter()
        .filter(|x| {
            x.name.starts_with(&alias)
                || x.alias.starts_with(&alias)
                || x.name.replace("_", "-").starts_with(&alias)
        })
        .collect::<Vec<&VpnServer>>();

    if record.len() == 0 {
        Err(anyhow!(
            "Could not find server alias {} in serverlist",
            &alias
        ))
    } else {
        let record = record
            .choose(&mut rand::thread_rng())
            .expect("Could not find server alias");

        let port = if record.port.is_none() {
            warn!(
                "Using default OpenVPN port 1194 for {}, as no port provided",
                &record.host
            );
            1194
        } else {
            record.port.unwrap()
        };
        debug!("Chosen server: {}:{}", record.host, port);
        Ok((record.host.clone(), port, record.alias.clone()))
    }
}

// TODO: Can we avoid storing plaintext passwords?
// TODO: Allow not storing credentials
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
            let username = Input::<String>::new().with_prompt("Username").interact()?;
            let password = Password::new()
                .with_prompt("Password")
                .with_confirmation("Confirm password", "Passwords did not match")
                .interact()?;

            let mut writefile = File::create(&auth_path)
                .with_context(|| format!("Could not create auth file: {}", auth_path.display()))?;
            write!(writefile, "{}\n{}\n", username, password)?;
            info!("Credentials written to: {}", auth_path.to_string_lossy());
            Ok(())
        }
    }
}

// TODO: For providers that provide both, check if system has wireguard capability first for
// default
pub fn get_protocol(
    provider: &VpnProvider,
    protocol: Option<Protocol>,
) -> anyhow::Result<Protocol> {
    match protocol {
        Some(Protocol::Wireguard) => match provider {
            VpnProvider::Mullvad => Ok(Protocol::Wireguard),
            VpnProvider::TigerVpn => {
                error!("Wireguard not implemented for TigerVPN");
                Err(anyhow!("Wireguard not implemented for TigerVPN"))
            }
            VpnProvider::PrivateInternetAccess => {
                error!("Wireguard not implemented for PrivateInternetAccess");
                Err(anyhow!(
                    "Wireguard not implemented for PrivateInternetAccess"
                ))
            }
            VpnProvider::Custom => Ok(Protocol::Wireguard),
        },
        Some(Protocol::OpenVpn) => Ok(Protocol::OpenVpn),
        None => match provider {
            VpnProvider::Mullvad => Ok(Protocol::Wireguard),
            VpnProvider::TigerVpn => Ok(Protocol::OpenVpn),
            VpnProvider::PrivateInternetAccess => Ok(Protocol::OpenVpn),
            VpnProvider::Custom => Ok(Protocol::Wireguard),
        },
    }
}
