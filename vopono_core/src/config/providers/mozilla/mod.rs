mod wireguard;

use super::{Provider, WireguardProvider};
use crate::config::vpn::Protocol;
use crate::util::get_username;
use anyhow::anyhow;
use log::{info, warn};
use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct LoginURLs {
    login_url: String,
    verification_url: String,
    poll_interval: u64,
}

#[derive(Deserialize, Debug)]
struct User {
    devices: Vec<Device>,
}

#[derive(Deserialize, Debug)]
struct Login {
    user: User,
    token: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Device {
    name: String,
    pubkey: String,
    ipv4_address: ipnet::Ipv4Net,
    ipv6_address: ipnet::Ipv6Net,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Error {
    errno: u32,
    error: String,
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.pubkey,)
    }
}

/// MozillaVPN is a wrapper for Wireguard using OAuth authentication with Mozilla services
/// Supports Wireguard only
pub struct MozillaVPN {}

impl Provider for MozillaVPN {
    fn alias(&self) -> String {
        "mozilla".to_string()
    }
    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

impl MozillaVPN {
    fn base_url(&self) -> &'static str {
        "https://vpn.mozilla.org/api/v1"
    }

    /// Login with OAuth login (adapted from MozWire crate: https://github.com/NilsIrl/MozWire/blob/trunk/src/main.rs )
    fn get_login(&self, client: &Client) -> anyhow::Result<Login> {
        let login = client
            .post(&format!("{}/vpn/login", self.base_url()))
            .send()
            .unwrap()
            .json::<LoginURLs>()
            .unwrap();
        info!(
            "MozillaVPN requires an OAuth login to get the authentication token. Please visit: {}.",
            login.login_url
        );
        // Set directory permissions before dropping out of sudo so we can launch browser
        crate::util::set_config_permissions()?;
        let nixuser = nix::unistd::User::from_name(&get_username()?)?.expect("Failed to get user");

        nix::unistd::setgid(nixuser.gid)?;
        nix::unistd::setuid(nixuser.uid)?;

        // Need to drop out of sudo to launch browser: https://github.com/amodm/webbrowser-rs/issues/30
        match webbrowser::open(&login.login_url) {
            Ok(_) => info!("Link opened in browser: {}", &login.login_url),
            Err(_) => warn!(
                "Failed to open link in browser, please visit it manually: {}",
                &login.login_url
            ),
        }

        let poll_interval = std::time::Duration::from_secs(login.poll_interval);
        loop {
            let response = client.get(&login.verification_url).send().unwrap();
            if response.status() == reqwest::StatusCode::OK {
                info!("Mozilla Login successful");
                break Ok(response.json::<Login>().unwrap());
            } else {
                match response.json::<Error>().unwrap() {
                    // errno 126 is pending verification
                    Error { errno: 126, .. } => {}
                    error => break Err(anyhow!("Login failed: {:?}", error)),
                }
            }
            std::thread::sleep(poll_interval);
        }
    }
}

fn validate_hostname(hostname: &str) -> bool {
    hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
}
