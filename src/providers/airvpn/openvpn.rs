use super::AirVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::util::delete_all_files_in_dir;
use log::debug;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;
use std::env;

extern crate rustc_serialize;
use rustc_serialize::json::Json;

impl OpenVpnProvider for AirVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // TODO AirVPN provider dns
        ])
    }

    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)> {
        //NOTE: not required for AirVPN
        Ok(("unused".to_string(), "unused".to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<PathBuf> {
        //NOTE: not required for AirVPN auth is inside ovpn file
        Ok(self.openvpn_dir()?.join("unused.txt"))
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let use_country_code :bool = true;
        let config_choice = ConfigType::choose_one()?;
        let client = reqwest::blocking::Client::new();

        let status_response = client
            .get("https://airvpn.org/api/status/")
            .send()?
            .text()?;

        let status_response_json = Json::from_str(&status_response).unwrap();
        let status_response_obj = status_response_json.as_object().unwrap();
        let all_servers_array = status_response_obj.get("servers").unwrap().as_array().unwrap();
        let mut request_server_names = "".to_string();
        for item in all_servers_array {
            let public_name = item.as_object().unwrap().get("public_name").unwrap().as_string().unwrap();
            if !request_server_names.is_empty() {
                // separate server names with '%2C'
                request_server_names.push_str("%2C");
            }
            request_server_names.push_str(&public_name);
        }

        let generator_url = config_choice.url()?.replace("{servers}", request_server_names.as_str());
        let zipfile = client.get(generator_url)
            .header("API-KEY", env::var("AIRVPN_API_KEY").expect("AIRVPN_API_KEY is not defined in your environment variables"))
            .send()?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        for i in 0..zip.len() {
            let mut file_contents: Vec<u8> = Vec::with_capacity(4096);
            let mut file = zip.by_index(i).unwrap();
            file.read_to_end(&mut file_contents)?;

            //TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                let fname = file.name();
                let fname_vec: Vec<&str> = fname.split('_').collect();
                let country_code = fname_vec[1].split('-').next().unwrap().to_lowercase();
                let city = fname_vec[1].split('-').collect::<Vec<&str>>()[1];
                let server_name = fname_vec[2];
                debug!("country_code: {}", country_code.to_string());
                debug!("city: {}", city.to_string());
                debug!("server_name: {}", server_name.to_string());
                let country = country_map.get(country_code.as_str());
                if country.is_none() || use_country_code {
                    format!("{}-{}.ovpn", country_code, server_name)
                } else {
                    format!("{}-{}.ovpn", country.unwrap(), server_name)
                }
            } else {
                file.name().to_string()
            };

            debug!("Reading file: {}", file.name());
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            outfile.write_all(file_contents.as_slice())?;
        }

        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    UDP443,
    TCP443
}

impl ConfigType {
    fn url(&self) -> anyhow::Result<String> {
        let s = match self {
            Self::UDP443 => "https://airvpn.org/api/generator/?protocols=openvpn_1_udp_443&download=zip&system=linux&iplayer_exit=ipv4&servers={servers}",
            Self::TCP443 => "https://airvpn.org/api/generator/?protocols=openvpn_1_tcp_443&download=zip&system=linux&iplayer_exit=ipv4&servers={servers}",
        };

        Ok(s.parse()?)
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UDP443 => "UDP",
            Self::TCP443 => "TCP",
        };
        write!(f, "{}", s)
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::TCP443
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt() -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn variants() -> Vec<Self> {
        ConfigType::iter().collect()
    }
    fn description(&self) -> Option<String> {
        Some( match self {
            Self::UDP443 => "Protocol: UDP, Port: 443, Entry IP: 1",
            Self::TCP443 => "Protocol: TCP, Port: 443, Entry IP: 1",
        }.to_string())
    }
}
