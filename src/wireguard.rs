use super::netns::NetworkNamespace;
use super::util::{config_dir, sudo_command};
use super::vpn::VpnProvider;
use anyhow::anyhow;
use log::{debug, error};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct Wireguard {
    ns_name: String,
    config_file: PathBuf,
}

// TODO: Implement wg-quick commands for network namespace
impl Wireguard {
    pub fn run(namespace: &NetworkNamespace, config_file: PathBuf) -> anyhow::Result<Self> {
        namespace.exec(&[
            "wg-quick",
            "up",
            &config_file.to_str().expect("No Wireguard config path"),
        ])?;
        Ok(Self {
            config_file,
            ns_name: namespace.name.clone(),
        })
    }
}

impl Drop for Wireguard {
    fn drop(&mut self) {
        if sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "wg-quick",
            "down",
            self.config_file.to_str().expect("No Wireguard config path"),
        ])
        .is_err()
        {
            {
                error!(
                    "Failed to kill Wireguard, config: {}",
                    self.config_file.to_str().expect("No Wireguard config path")
                );
            }
        }
    }
}

pub fn get_config_from_alias(provider: &VpnProvider, alias: &str) -> anyhow::Result<PathBuf> {
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/wireguard", provider.alias()));
    let paths = WalkDir::new(&list_path)
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
        .filter(|x| {
            x.path().is_file()
                && x.path().extension().is_some()
                && x.path().extension().expect("No file extension") == "conf"
        })
        .map(|x| {
            (
                x.clone(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split("-")
                    .into_iter()
                    .nth(1)
                    .expect("No - in filename")
                    .to_string(),
            )
        })
        .filter(|x| x.1.starts_with(alias))
        .map(|x| PathBuf::from(x.0.path()))
        .collect::<Vec<PathBuf>>();

    if paths.len() == 0 {
        Err(anyhow!(
            "Could not find Wireguard config file for alias {}",
            &alias
        ))
    } else {
        let config = paths
            .choose(&mut rand::thread_rng())
            .expect("Could not find Wireguard config");

        debug!("Chosen Wireguard config: {}", config.display());
        Ok(config.clone())
    }
}
