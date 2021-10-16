use super::HMA;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::util::delete_all_files_in_dir;
use dialoguer::{Input, Password};
use log::{debug, info};
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
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

    fn prompt_for_auth(&self) -> anyhow::Result<(String, String)> {
        let username = Input::<String>::new()
            .with_prompt("HMA username ")
            .interact()?;

        let password = Password::new()
            .with_prompt("HMA Password")
            .with_confirmation("Confirm password", "Passwords did not match")
            .interact()?;
        Ok((username.trim().to_string(), password.trim().to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.openvpn_dir()?.join("auth.txt"))
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        debug!("Requesting ConfigType");
        let config_choice = ConfigType::choose_one()?;
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
                    .map(|x| x.file_name().map(|x| x.to_str()))
                    .flatten()
                    .flatten()
                    == Some(&config_choice.dir_name())
                && !path.starts_with("OpenVPN-2.4")
            {
                let filename = path
                    .file_name()
                    .expect("Invalid filename")
                    .to_str()
                    .expect("Invalid filename");
                let mut filename_iter = filename.split('.');
                let country = filename_iter.next().unwrap();
                let country = country.replace("'", "").to_lowercase();
                let city = filename_iter.next().unwrap();
                let city = city.replace("'", "").to_lowercase();
                let filename = format!("{}-{}.ovpn", country, city);
                let outpath = openvpn_dir.join(filename.to_lowercase().replace(' ', "_"));
                debug!(
                    "Writing file: {}",
                    outpath.to_str().unwrap_or("Invalid path")
                );
                let mut outfile = File::create(outpath)?;
                write!(outfile, "{}", file_contents)?;
            };
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth()?;
        let mut outfile = File::create(self.auth_file_path()?)?;
        write!(outfile, "{}\n{}", user, pass)?;
        info!("HMA OpenVPN config written to {}", openvpn_dir.display());
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
    fn prompt() -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn variants() -> Vec<Self> {
        ConfigType::iter().collect()
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
