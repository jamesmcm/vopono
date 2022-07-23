use super::AzireVPN;
use super::{ConnectResponse, WgResponse, WireguardProvider};
use crate::config::providers::UiClient;
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::country_map::code_to_country_map;
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, WgKey};
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use std::fs::create_dir_all;
use std::io::Write;
use std::str::FromStr;

impl WireguardProvider for AzireVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = Client::new();

        // TODO: Hardcoded list, can this be retrieved from the API?
        let aliases = self.server_aliases();
        let country_map = code_to_country_map();
        let (username, password) = self.request_userpass(uiclient)?;
        let keypair: WgKey = generate_keypair()?;
        debug!("Chosen keypair: {:?}", keypair);

        let mut peers: Vec<(String, WgResponse)> = vec![];
        for alias in aliases {
            let response = client
                .post(reqwest::Url::parse(&format!(
                    "https://api.azirevpn.com/v1/wireguard/connect/{}",
                    alias
                ))?)
                .form(&[
                    ("username", &username),
                    ("password", &password),
                    ("pubkey", &keypair.public),
                ])
                .send()?;
            debug!("Response: {:?}", response);
            let response: ConnectResponse = response.json()?;

            peers.push((alias.to_string(), response.data));
        }

        // TODO: Allow custom port - need to check AzireVPN's restrictions
        // let port = 51820;

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];

        // TODO: avoid hacky regex for TOML -> wireguard config conversion
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for (alias, wg_peer) in peers {
            let interface = WireguardInterface {
                private_key: keypair.private.clone(),
                address: wg_peer.address,
                dns: wg_peer.dns,
            };

            let wireguard_peer = WireguardPeer {
                public_key: wg_peer.public_key.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: wg_peer.endpoint,
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };

            let country = country_map
                .get(&alias[0..2])
                .expect("Could not map country code");

            let path = wireguard_dir.join(format!("{}-{}.conf", country, alias));

            let mut toml = toml::to_string(&wireguard_conf)?;
            toml.retain(|c| c != '"');
            let toml = toml.replace(", ", ",");
            let toml = re.replace_all(&toml, "= $value").to_string();
            // Create file, write TOML
            {
                let mut f = std::fs::File::create(path)?;
                write!(f, "{}", toml)?;
            }
        }

        info!(
            "AzireVPN Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}
