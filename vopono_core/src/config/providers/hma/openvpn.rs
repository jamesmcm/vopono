use super::HMA;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::{Input, Password, UiClient};
use crate::util::delete_all_files_in_dir;
use log::{debug, info};
use std::fmt::Display;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

impl OpenVpnProvider for HMA {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        // None will use DNS from OpenVPN headers if present
        // HMA recommend OpenDNS:
        // 208.67.222.222 + 208.67.220.220
        None
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {
            prompt: "HMA username".to_string(),
            validator: None,
        })?;
        let password = uiclient.get_password(Password {
            prompt: "HMA password".to_string(),
            confirm: true,
        })?;
        Ok((username.trim().to_string(), password.trim().to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        debug!("Requesting ConfigType");
        let config_choice = uiclient.get_configuration_choice(&ConfigType::default())?;
        let url = "https://vpn.hidemyass.com/vpn-config/vpn-configs.zip";
        let zipfile = reqwest::blocking::get(url)?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        for i in 0..zip.len() {
            // Modify auth line for config
            // Write to config dir
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();
            debug!(
                "Reading file: {}",
                file.mangled_name().to_str().unwrap_or("Invalid path")
            );
            file.read_to_end(&mut file_contents)?;

            let file_contents = std::str::from_utf8(&file_contents)?;

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            let path = file.mangled_name();
            #[allow(deprecated)]
            if path
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
                == Some("ovpn")
                && path
                    .parent()
                    .and_then(|x| x.file_name().map(|x| x.to_str()))
                    .flatten()
                    == Some(&ConfigType::index_to_variant(config_choice).dir_name())
                && !path.starts_with("OpenVPN-2.4")
            {
                let filename = path
                    .file_name()
                    .expect("Invalid filename")
                    .to_str()
                    .expect("Invalid filename");
                let mut filename_iter = filename.split('.');
                let country = filename_iter.next().unwrap();
                let country = country.replace(['\'', '`'], "").to_lowercase();
                let city = filename_iter.next().unwrap();
                let city = city.replace(['\'', '`'], "").to_lowercase();
                let filename = format!("{country}-{city}.ovpn");
                let outpath = openvpn_dir.join(filename.to_lowercase().replace(' ', "_"));
                debug!(
                    "Writing file: {}",
                    outpath.to_str().unwrap_or("Invalid path")
                );
                let mut outfile = File::create(outpath)?;
                write!(outfile, "{file_contents}")?;
            };
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;
            info!("HMA OpenVPN config written to {}", openvpn_dir.display());
        }
        Ok(())
    }
}

#[derive(EnumIter, PartialEq)]
enum ConfigType {
    Tcp,
    Udp,
}

impl ConfigType {
    fn dir_name(&self) -> String {
        match self {
            Self::Udp => "UDP".to_string(),
            Self::Tcp => "TCP".to_string(),
        }
    }
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dir_name())
    }
}

impl Default for ConfigType {
    fn default() -> Self {
        Self::Udp
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt(&self) -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }
    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().map(|x| x.description().unwrap()).collect())
    }

    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::Udp => "Connect via UDP. Port 553, AES-256-CBC cipher.",
                Self::Tcp => "Connect via TCP. Port 8080, AES-256-CBC cipher.",
            }
            .to_string(),
        )
    }
}
