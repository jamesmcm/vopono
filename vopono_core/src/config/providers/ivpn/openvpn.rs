use super::IVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use dialoguer::Input;
use log::{debug, info};
use reqwest::Url;
use std::fs::create_dir_all;
use std::fs::File;
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
            "https://www.ivpn.net/releases/config/ivpn-openvpn-config{}.zip",
            tcp_str
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

    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)> {
        let username = Input::<String>::new()
            .with_prompt(
                "IVPN account ID (starts with \"ivpn\" see: https://www.ivpn.net/clientarea/vpn/273887 )",
            )
            .interact()?;

        Ok((username, "password".to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::country_to_code_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let protocol = OpenVpnProtocol::choose_one()?;
        let url = self.build_url(&protocol)?;
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

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            let fname = file
                .sanitized_name()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                let country = fname.to_lowercase().replace(' ', "_");
                let filename = country.split('.').next().unwrap();
                let mut citer = filename.split('-');
                let country = citer.next().unwrap();

                let city = match citer.next() {
                    None => String::new(),
                    Some(x) => format!("-{}", x),
                };

                let code = country_map.get(country);
                if code.is_none() {
                    debug!("Could not find country in country map: {}", country);
                    fname.to_lowercase()
                } else {
                    format!("{}-{}{}.ovpn", country, code.unwrap(), city)
                }
            } else {
                fname.to_lowercase()
            };

            debug!("Reading file: {}, {}", file.name(), fname);
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{}", file_contents)?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth()?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{}\n{}", user, pass)?;
            info!("IVPN OpenVPN config written to {}", openvpn_dir.display());
        }
        Ok(())
    }
}
