use super::{PrivateInternetAccess, Provider, WireguardProvider};
use crate::config::providers::{BoolChoice, UiClient};
use crate::network::wireguard_config::{
    WireguardConfig, WireguardEndpoint, WireguardInterface, WireguardPeer,
};
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::generate_keypair;
use anyhow::{Context, anyhow};
use ipnet::IpNet;
use log::info;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::blocking::ClientBuilder;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;

use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct VpnInfo {
    pub regions: Vec<Region>,
}

#[derive(Debug, Deserialize)]
pub struct Region {
    pub id: String,
    #[allow(unused)]
    pub name: String,
    #[allow(unused)]
    pub country: String,
    #[allow(unused)]
    pub auto_region: bool,
    pub dns: String,
    pub port_forward: bool,
    #[allow(unused)]
    pub geo: bool,
    #[allow(unused)]
    pub offline: bool,
    pub servers: Servers,
}

#[derive(Debug, Deserialize)]
pub struct Servers {
    pub wg: Option<Vec<WireguardServer>>,
}

#[derive(Debug, Deserialize)]
pub struct WireguardServer {
    pub ip: IpAddr,
    pub cn: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status")]
pub enum PiaToken {
    #[serde(rename = "OK")]
    Ok { token: String },
    #[serde(rename = "ERROR")]
    Err { message: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status")]
pub enum WireguardServerInfoRequest {
    #[serde(rename = "OK")]
    Ok(WireguardServerInfo),
    #[serde(rename = "ERROR")]
    Err { message: String },
}

#[derive(Debug, Deserialize)]
pub struct WireguardServerInfo {
    pub server_key: String,
    pub server_port: u16,
    pub server_ip: IpAddr,
    #[allow(unused)]
    pub server_vip: IpAddr,
    pub peer_ip: IpAddr,
    #[allow(unused)]
    pub peer_pubkey: String,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub user: String,
    pub pass: String,
    pub pubkey: String,
    pub cn_lookup: HashMap<IpAddr, String>,
    pub hostname_lookup: HashMap<String, String>,
}

impl PrivateInternetAccess {
    const PORT: u16 = 1337;
    const CERT: &'static [u8] = include_bytes!("ca.rsa.4096.crt");

    pub fn get_pia_token(user: &str, pass: &str) -> anyhow::Result<String> {
        let token: PiaToken = Client::new()
            .get("https://www.privateinternetaccess.com/gtoken/generateToken")
            .basic_auth(user, Some(pass))
            .send()?
            .json()?;

        match token {
            PiaToken::Ok { token } => Ok(token),
            PiaToken::Err { message } => Err(anyhow!("{}", message)),
        }
    }

    pub fn pia_cert_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.provider_dir()?.join("ca.rsa.4096.crt"))
    }

    pub fn write_pia_cert(&self) -> anyhow::Result<()> {
        let mut cert_file = File::create(self.pia_cert_path()?)?;
        cert_file.write_all(Self::CERT)?;
        Ok(())
    }

    fn add_key(
        ip: &IpAddr,
        cn: &str,
        token: &str,
        pubkey: &str,
    ) -> anyhow::Result<WireguardServerInfo> {
        let cert = reqwest::Certificate::from_pem(PrivateInternetAccess::CERT)?;

        // The server has a self-signed certificate and doesn't have a valid domain
        // so you need to manually set the certificate as well as telling the client
        // what IP the domain should resolve to if you want it to validate properly
        let key_client = ClientBuilder::new()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .resolve(cn, (*ip, PrivateInternetAccess::PORT).into())
            .build()?;

        let url = format!("https://{}:{}/addKey", cn, PrivateInternetAccess::PORT);
        let params = [("pt", token), ("pubkey", pubkey)];
        let url = Url::parse_with_params(&url, params)?;

        let server_info: WireguardServerInfoRequest = key_client.get(url).send()?.json()?;
        match server_info {
            WireguardServerInfoRequest::Ok(server_info) => Ok(server_info),
            WireguardServerInfoRequest::Err { message } => Err(anyhow!("{}", message)),
        }
    }

    fn wireguard_config_file_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.wireguard_dir()?.join("config.txt"))
    }

    pub fn load_wireguard_auth(&self) -> anyhow::Result<(String, String)> {
        let config_file = File::open(self.wireguard_config_file_path()?)?;
        let config: Config = serde_json::from_reader(config_file)?;
        Ok((config.user, config.pass))
    }

    //This only works if wireguard was sync'd
    pub fn hostname_for_wireguard_conf(&self, config_file: &String) -> anyhow::Result<String> {
        let pia_config_file = File::open(self.wireguard_config_file_path()?)?;
        let pia_config: Config = serde_json::from_reader(pia_config_file)?;

        let hostname = pia_config
            .hostname_lookup
            .get(config_file)
            .with_context(|| {
                format!("Could not find matching hostname for wireguard conf {config_file}")
            })?;

        Ok(hostname.to_string())
    }
}

impl WireguardProvider for PrivateInternetAccess {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let (user, pass) = self.prompt_for_auth(uiclient)?;

        let client = Client::new();
        let vpn_info: String = client
            .get("https://serverlist.piaservers.net/vpninfo/servers/v6")
            .send()?
            .text()?;

        // JSON response on first line
        let vpn_info: VpnInfo =
            serde_json::from_str(vpn_info.lines().next().context("Invalid response")?)?;

        let only_port_forwarding = uiclient.get_bool_choice(BoolChoice {
            prompt: "Only use servers that have port forwarding enabled?".into(),
            default: false,
        })?;

        let keypair = generate_keypair()?;

        // Use localhost as a placeholder value
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![IpNet::new(Ipv4Addr::LOCALHOST.into(), 32)?],
            dns: Some(vec![Ipv4Addr::LOCALHOST.into()]),
            mtu: Some(1420.to_string()),
        };

        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?];

        // We need to call PIA's addKey API on connect which needs the user, pass, pubkey, and common name.
        // Wireguard's config doesn't allow us to save the common name so we need a map to look up the
        // common name later
        let mut config = Config {
            user,
            pass,
            pubkey: keypair.public,
            cn_lookup: HashMap::new(),
            hostname_lookup: HashMap::new(),
        };

        for region in vpn_info.regions {
            let id = region.id;
            if only_port_forwarding && !region.port_forward {
                continue;
            }

            info!("Associating {id} with hostname {}", region.dns);
            config
                .hostname_lookup
                .insert(format!("{id}.conf"), region.dns);

            // The servers are randomized on each request so we can just use the first one
            if let Some(wg_server) = region.servers.wg.as_ref().and_then(|s| s.first()) {
                let wireguard_peer = WireguardPeer {
                    public_key: "".into(), // Empty, will be filled in on connect later
                    allowed_ips: allowed_ips.clone(),
                    endpoint: WireguardEndpoint::IpWithPort(SocketAddr::new(
                        wg_server.ip,
                        PrivateInternetAccess::PORT,
                    )),
                    keepalive: Some(25.to_string()),
                };

                let wireguard_conf = WireguardConfig {
                    interface: interface.clone(),
                    peer: wireguard_peer,
                };

                // Create file, write TOML
                let path = wireguard_dir.join(format!("{id}.conf"));
                let wireguard_conf: String = wireguard_conf.to_string();
                let mut f = File::create(path)?;
                f.write_all(wireguard_conf.as_bytes())?;

                config.cn_lookup.insert(wg_server.ip, wg_server.cn.clone());
            }
        }

        info!(
            "PrivateInternetAccess Wireguard config written to {}",
            wireguard_dir.display()
        );

        // Write PrivateInternetAccess wireguard config file
        let pia_config_file = File::create(self.wireguard_config_file_path()?)?;
        serde_json::to_writer(pia_config_file, &config)?;

        // Write PIA certificate
        self.write_pia_cert()?;

        Ok(())
    }

    fn wireguard_preup(&self, wg_config_file: &Path) -> anyhow::Result<()> {
        let pia_config_file = File::open(self.wireguard_config_file_path()?)?;
        let pia_config: Config = serde_json::from_reader(pia_config_file)?;

        let token = PrivateInternetAccess::get_pia_token(&pia_config.user, &pia_config.pass)?;

        let mut wg_config: WireguardConfig = std::fs::read_to_string(wg_config_file)?.parse()?;
        let ip = &wg_config.peer.endpoint.resolve_ip()?;
        let cn = pia_config
            .cn_lookup
            .get(ip)
            .with_context(|| format!("Could not find matching common name for IP {ip}"))?;

        let server_info = PrivateInternetAccess::add_key(ip, cn, &token, &pia_config.pubkey)?;

        wg_config.interface.address = vec![IpNet::new(server_info.peer_ip, 32)?];
        wg_config.interface.dns = Some(
            server_info
                .dns_servers
                .iter()
                .filter_map(|ip| ip.parse().ok())
                .collect(),
        );
        wg_config.peer.public_key = server_info.server_key.clone();
        wg_config.peer.endpoint =
            format!("{}:{}", server_info.server_ip, server_info.server_port).parse()?;

        // Overwrite the existing invalid wg config with a new one that is now valid
        let new_wg_config: String = wg_config.to_string();
        let mut f = File::create(wg_config_file)?;
        f.write_all(new_wg_config.as_bytes())?;

        Ok(())
    }
}
