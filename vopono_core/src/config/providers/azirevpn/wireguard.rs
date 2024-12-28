use super::AzireVPN;
use super::{AccessTokenResponse, ConnectResponse, DeviceResponse, WireguardProvider};
use crate::config::providers::azirevpn::LocationResponse;
use crate::config::providers::UiClient;
use crate::network::wireguard::{WireguardConfig, WireguardInterface, WireguardPeer};
use crate::util::country_map::code_to_country_map;
use crate::util::delete_all_files_in_dir;
use crate::util::wireguard::{generate_keypair, WgKey};
use anyhow::Context;
use ipnet::IpNet;
use log::{debug, info};
use regex::Regex;
use reqwest::blocking::Client;
use std::fs::create_dir_all;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

impl WireguardProvider for AzireVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let wireguard_dir = self.wireguard_dir()?;
        create_dir_all(&wireguard_dir)?;
        delete_all_files_in_dir(&wireguard_dir)?;

        let client = Client::new();

        let country_map = code_to_country_map();
        let (username, password) = self.request_userpass(uiclient)?;

        // TODO: Allow user to specify existing device and provide private key

        // Start device and keypair generation
        let keypair: WgKey = generate_keypair()?;
        debug!("Chosen keypair: {:?}", keypair);

        // This creates an API token for the user
        let auth_response: AccessTokenResponse = client
            .post("https://api.azirevpn.com/v2/auth/client")
            .form(&[
                ("username", &username),
                ("password", &password),
                ("comment", &"web generator".to_string()),
            ])
            .send()?
            .json()
            .with_context(|| {
                "Authentication error: Ensure your AzireVPN credentials are correct"
            })?;

        debug!("auth_response: {:?}", &auth_response);

        let mut outfile = std::fs::File::create(self.token_file_path())?;
        write!(outfile, "{}", auth_response.token)?;
        info!(
            "AzireVPN Auth Token written to {}",
            self.token_file_path().display()
        );

        // This adds device for Token on VPN page and returns JSON network data - note max devices is limited to 10 registered, 5 concurrent connections
        let device_response: DeviceResponse = client
            .post("https://api.azirevpn.com/v2/ip/add")
            .form(&[("key", &keypair.public), ("token", &auth_response.token)])
            .send()?
            .json()?;

        debug!("device_response: {:?}", &device_response);
        let location_resp: ConnectResponse = client.get(self.locations_url()).send()?.json()?;

        debug!("locations_response: {:?}", &location_resp);
        let locations: Vec<LocationResponse> = location_resp.locations;

        let v4_net = IpNet::new(
            IpAddr::V4(Ipv4Addr::from_str(&device_response.ipv4.address)?),
            device_response.ipv4.netmask,
        )?;
        let interface = WireguardInterface {
            private_key: keypair.private.clone(),
            address: vec![v4_net],
            dns: Some(device_response.dns),
        };
        let allowed_ips = vec![IpNet::from_str("0.0.0.0/0")?, IpNet::from_str("::0/0")?];
        let re = Regex::new(r"=\s\[(?P<value>[^\]]+)\]")?;
        for location in locations {
            // TODO: Port Forwarding - https://www.azirevpn.com/docs/api/portforwardings

            // TODO: Can we avoid DNS lookup here?
            let host_lookup = dns_lookup::lookup_host(&location.pool);
            if host_lookup.is_err() {
                log::error!("Could not resolve hostname: {}, skipping...", location.pool);
                continue;
            }
            let host_ip = host_lookup.unwrap().first().cloned().unwrap();
            log::debug!("Resolved hostname: {} to IP: {}", &location.pool, &host_ip);
            // TODO: avoid hacky regex for TOML -> wireguard config conversion
            let wireguard_peer = WireguardPeer {
                public_key: location.pubkey.clone(),
                allowed_ips: allowed_ips.clone(),
                endpoint: SocketAddr::new(host_ip, 51820),
                keepalive: None,
            };

            let wireguard_conf = WireguardConfig {
                interface: interface.clone(),
                peer: wireguard_peer,
            };
            let location_name = location.name.as_str();

            let country = country_map
                .get(&location_name[0..2])
                .expect("Could not map country code");

            let path = wireguard_dir.join(format!("{country}-{location_name}.conf"));

            let mut toml = toml::to_string(&wireguard_conf)?;
            toml.retain(|c| c != '"');
            let toml = toml.replace(", ", ",");
            let toml = re.replace_all(&toml, "= $value").to_string();
            // Create file, write TOML
            {
                let mut f = std::fs::File::create(path)?;
                write!(f, "{toml}")?;
            }
        }

        info!(
            "AzireVPN Wireguard config written to {}",
            wireguard_dir.display()
        );

        Ok(())
    }
}
