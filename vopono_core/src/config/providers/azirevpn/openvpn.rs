use super::AzireVPN;
use super::ConnectResponse;
use super::OpenVpnProvider;
use crate::config::providers::Input;
use crate::config::providers::UiClient;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use log::{debug, info};
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::header::COOKIE;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

impl OpenVpnProvider for AzireVPN {
    // AzireVPN details: https://www.azirevpn.com/docs/servers
    // TODO: Add IPv6 DNS
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(91, 231, 153, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 211, 0, 2)),
        ])
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        self.request_userpass(uiclient)
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        // OpenVPN:
        // https://manager.azirevpn.com/account/openvpn/generate?country=ca-tor&os=linux-cli&port=random&protocol=udp
        let protocol = OpenVpnProtocol::index_to_variant(
            uiclient.get_configuration_choice(&OpenVpnProtocol::default())?,
        );

        let mut auth_cookie: &'static str = Box::leak(uiclient.get_input(Input {
            prompt: "Please log-in at https://manager.azirevpn.com/account/openvpn and copy the value of the 'az' cookie in the request data from your browser's network request inspector.".to_owned(),
             validator: None
             })?.replace(';', "").trim().to_owned().into_boxed_str());

        debug!("Using az cookie: {}", &auth_cookie);
        if !auth_cookie.starts_with("az=") {
            auth_cookie = Box::leak(format!("az={}", auth_cookie).into_boxed_str());
        }

        // TODO: Allow port selection, TLS version selection
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::code_to_country_map();
        let client = reqwest::blocking::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static(auth_cookie));
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let locations_resp: ConnectResponse = client.get(self.locations_url()).send()?.json()?;
        let locations = locations_resp.locations;
        for location in locations {
            let location_name = &location.name;
            let url = format!("https://manager.azirevpn.com/account/openvpn/generate?country={location_name}&os=linux-cli&port=random&protocol={protocol}");

            let response = client.get(url).headers(headers.clone()).send()?;
            let new_cookie = response.headers().get_all(COOKIE);
            new_cookie.iter().for_each(|x| {
                if x.to_str().unwrap().starts_with("az=") && auth_cookie != x.to_str().unwrap() {
                    log::debug!("New az cookie: {}", x.to_str().unwrap());
                    auth_cookie = Box::leak(x.to_str().unwrap().to_owned().into_boxed_str());
                }
            });
            let file = response.bytes()?;

            let file_contents = std::str::from_utf8(&file)?;
            log::debug!("File contents: {}", &file_contents);
            if !file_contents.contains("BEGIN CERTIFICATE") {
                log::error!("Failed to get valid OpenVPN config for location: {} - check the az cookie is given correctly. Sleeping 10s to avoid rate limiting.", location_name);
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
            let file_contents = file_contents
                .split('\n')
                .filter(|&x| !(x.starts_with("up ") || x.starts_with("down ")))
                .collect::<Vec<&str>>()
                .join("\n");

            let country = country_map
                .get(&location_name[0..2])
                .expect("Could not map country to name");
            let filename = format!("{country}-{location_name}.ovpn");
            debug!("Writing file: {}", filename);
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{file_contents}")?;
            std::thread::sleep(Duration::from_millis(500));
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;
            info!(
                "AzireVPN OpenVPN config written to {}",
                openvpn_dir.display()
            );
        }
        Ok(())
    }
}
