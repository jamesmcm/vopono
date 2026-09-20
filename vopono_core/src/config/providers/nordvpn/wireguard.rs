use super::{NordVPN, ServiceCredentials};
use crate::config::providers::{UiClient, WireguardProvider};
use crate::network::wireguard_config::{
    WireguardConfig, WireguardEndpoint, WireguardInterface, WireguardPeer,
};
use anyhow::{Context, anyhow};
use ipnet::IpNet;
use log::info;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

const WIREGUARD_PORT: u16 = 51820;
const SERVER_PAGE_SIZE: usize = 1000;

#[derive(Deserialize)]
struct Server {
    id: u64,
    hostname: String,
    station: IpAddr,
    status: String,
    locations: Vec<Location>,
    technologies: Vec<Technology>,
}

#[derive(Deserialize)]
struct Location {
    country: Country,
}

#[derive(Deserialize)]
struct Country {
    code: String,
}

#[derive(Deserialize)]
struct Technology {
    identifier: String,
    metadata: Vec<Metadata>,
}

#[derive(Deserialize)]
struct Metadata {
    name: String,
    value: String,
}

fn fetch_servers(client: &Client) -> anyhow::Result<Vec<Server>> {
    let mut servers = Vec::new();
    let mut seen_ids = HashSet::new();
    let mut offset = 0;

    loop {
        let page: Vec<Server> = client
            .get("https://api.nordvpn.com/v1/servers")
            .query(&[
                ("limit", SERVER_PAGE_SIZE.to_string()),
                ("offset", offset.to_string()),
                (
                    "filters[servers_technologies][identifier]",
                    "wireguard_udp".to_string(),
                ),
            ])
            .send()
            .context("Failed to request NordVPN WireGuard servers")?
            .error_for_status()
            .context("NordVPN rejected the WireGuard server list request")?
            .json()
            .context("Failed to parse NordVPN WireGuard server list")?;

        let page_len = page.len();
        let new_servers = page
            .into_iter()
            .filter(|server| seen_ids.insert(server.id))
            .collect::<Vec<_>>();
        if page_len > 0 && new_servers.is_empty() {
            return Err(anyhow!(
                "NordVPN server list pagination did not return new servers"
            ));
        }
        servers.extend(new_servers);

        if page_len < SERVER_PAGE_SIZE {
            break;
        }
        offset += page_len;
    }

    Ok(servers)
}

fn public_key(server: &Server) -> Option<&str> {
    server
        .technologies
        .iter()
        .find(|technology| technology.identifier == "wireguard_udp")?
        .metadata
        .iter()
        .find(|metadata| metadata.name == "public_key")
        .map(|metadata| metadata.value.as_str())
}

fn config_for_server(
    server: &Server,
    private_key: &str,
    country_map: &std::collections::HashMap<&str, &str>,
) -> anyhow::Result<Option<(String, String)>> {
    if server.status != "online" {
        return Ok(None);
    }
    let Some(country_code) = server
        .locations
        .first()
        .map(|location| location.country.code.to_ascii_lowercase())
    else {
        return Ok(None);
    };
    let Some(public_key) = public_key(server) else {
        return Ok(None);
    };

    let country = country_map
        .get(country_code.as_str())
        .copied()
        .unwrap_or(country_code.as_str());
    let server_name = server
        .hostname
        .split('.')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(&server.hostname);

    let interface = WireguardInterface {
        private_key: private_key.to_string(),
        address: vec![IpNet::from_str("10.5.0.2/32")?],
        dns: Some(vec![
            IpAddr::V4(Ipv4Addr::new(103, 86, 96, 100)),
            IpAddr::V4(Ipv4Addr::new(103, 86, 99, 100)),
        ]),
        mtu: Some("1420".to_string()),
    };
    let peer = WireguardPeer {
        public_key: public_key.to_string(),
        allowed_ips: vec![IpNet::from_str("0.0.0.0/0")?],
        endpoint: WireguardEndpoint::IpWithPort(SocketAddr::new(server.station, WIREGUARD_PORT)),
        keepalive: Some("25".to_string()),
    };
    let config = WireguardConfig { interface, peer }.to_string();
    let filename = format!("{country}-{country_code}-{server_name}.conf");

    Ok(Some((filename, config)))
}

impl WireguardProvider for NordVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let credentials: ServiceCredentials = self.service_credentials(uiclient)?;
        let private_key = credentials
            .nordlynx_private_key
            .as_deref()
            .context("NordVPN did not return a NordLynx private key")?;
        crate::util::wireguard::generate_public_key(private_key)
            .context("NordVPN returned an invalid NordLynx private key")?;

        let servers = fetch_servers(&Client::new())?;
        let country_map = crate::util::country_map::code_to_country_map();
        let configs = servers
            .iter()
            .filter_map(|server| config_for_server(server, private_key, &country_map).transpose())
            .collect::<anyhow::Result<Vec<_>>>()?;
        if configs.is_empty() {
            return Err(anyhow!(
                "NordVPN returned no usable WireGuard server configurations"
            ));
        }

        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        crate::util::delete_all_files_in_dir(&wireguard_dir)?;
        for (filename, config) in &configs {
            let path = wireguard_dir.join(filename.to_ascii_lowercase());
            let mut file = crate::util::create_private_file(&path)?;
            file.write_all(config.as_bytes())?;
        }

        info!(
            "NordVPN WireGuard configs written to {} ({} servers)",
            wireguard_dir.display(),
            configs.len()
        );
        Ok(())
    }
}
