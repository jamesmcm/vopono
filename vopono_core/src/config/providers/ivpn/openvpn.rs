use super::IVPN;
use super::OpenVpnProvider;
use crate::config::providers::Input;
use crate::config::providers::UiClient;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use log::{debug, info};
use reqwest::Url;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use zip::ZipArchive;

// TODO: Multi-hop support
impl IVPN {
    fn build_url(&self, protocol: &OpenVpnProtocol) -> anyhow::Result<Url> {
        let tcp_str = match protocol {
            OpenVpnProtocol::TCP => "-tcp",
            OpenVpnProtocol::UDP => "",
        };
        Ok(Url::parse(&format!(
            "https://www.ivpn.net/releases/config/ivpn-openvpn-config{tcp_str}.zip"
        ))?)
    }
}
impl OpenVpnProvider for IVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        // https://www.ivpn.net/setup/gnu-linux-terminal.html
        // Some(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 254, 1))])
        // Return None and we will read from OpenVPN headers
        None
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {prompt:"IVPN account ID (starts with \"ivpn\" see: https://www.ivpn.net/clientarea/vpn/273887 )".to_string(), validator: None})?;

        Ok((username, "password".to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::country_to_code_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let protocol = uiclient.get_configuration_choice(&OpenVpnProtocol::default())?;
        let url = self.build_url(&OpenVpnProtocol::index_to_variant(protocol))?;
        let zipfile = reqwest::blocking::get(url)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        for i in 0..zip.len() {
            // Modify auth line for config
            // Write to config dir
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();
            if file.is_dir() {
                continue;
            }
            file.read_to_end(&mut file_contents)?;
            let file_contents = std::str::from_utf8(&file_contents)?;
            let file_contents = file_contents
                .split('\n')
                .filter(|&x| {
                    !(x.starts_with("up ")
                        || x.starts_with("down ")
                        || x.starts_with("auth-user-pass"))
                })
                .collect::<Vec<&str>>()
                .join("\n");

            let enclosed = file.enclosed_name();
            let fname = enclosed
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let filename = if let Some("ovpn") = enclosed
                .as_ref()
                .and_then(|p| p.extension())
                .and_then(|x| x.to_str())
            {
                let country = fname.to_lowercase().replace(' ', "_");
                let filename = country.split('.').next().unwrap();
                let mut citer = filename.split('-');
                let country = citer.next().unwrap();

                let city = match citer.next() {
                    None => String::new(),
                    Some(x) => format!("-{x}"),
                };

                if let Some(code) = country_map.get(country) {
                    format!("{}-{}{}.ovpn", country, code, city)
                } else {
                    debug!("Could not find country in country map: {country}");
                    fname.to_lowercase()
                }
            } else {
                fname.to_lowercase()
            };

            debug!("Reading file: {}, {}", file.name(), fname);
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{file_contents}")?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        if let Some(auth_file) = self.auth_file_path()? {
            let mut outfile = File::create(auth_file)?;
            write!(outfile, "{user}\n{pass}")?;
            info!("IVPN OpenVPN config written to {}", openvpn_dir.display());
        }
        Ok(())
    }
}
