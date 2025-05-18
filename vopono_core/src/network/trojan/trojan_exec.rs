use std::path::Path;

use anyhow::Context;
use log::warn;
use serde::{Deserialize, Serialize};
use which::which;

use crate::network::{netns::NetworkNamespace, wireguard::WireguardPeer};

use super::{TrojanHost, get_cert, trojan_config::TrojanConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct Trojan {
    pid: u32,
    pub config: TrojanConfig,
}

impl Trojan {
    pub fn run_in_netns(
        netns: &NetworkNamespace,
        host: Option<TrojanHost>,
        password: Option<&str>,
        config_path: Option<&Path>,
        no_verify: bool,
        peer: Option<WireguardPeer>,
    ) -> anyhow::Result<Trojan> {
        let mut config = TrojanConfig::new(config_path)?;
        let config_path_buf;

        if let Some(cpath) = config_path {
            warn!("Using custom Trojan config file: {cpath:?}");
            config_path_buf = config_path.unwrap().to_path_buf();
        } else {
            let h = host
                .clone()
                .expect("Host must be provided if no config path is given");
            if h.is_ip() {
                log::error!(
                    "IP address provided for trojan host, but SSL verification is not disabled. Disabling SSL verification."
                );
            } else {
                let cert = get_cert::get_cert(h.host(), h.port())?;
                config.set_cert(&cert)?;
            }
            config.set_verify_fields(!no_verify);
            config.set_remote_fields(&host.unwrap());
            config.set_password(password.unwrap());
            config.set_wg_forwarding_fields(peer.as_ref().unwrap());

            let cpath = std::env::temp_dir().join("trojan_forward.json");
            std::fs::write(&cpath, serde_json::to_string(&config)?)
                .with_context(|| format!("Failed to write Trojan config to {:?}", &cpath))?;
            config_path_buf = cpath;
        }

        let trojan_exec = which("trojan").with_context(|| {
                "trojan executable not found in PATH. Please install trojan and ensure it is in your PATH."
                    })?;

        let handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &[
                trojan_exec.to_str().unwrap(),
                "-c",
                config_path_buf.to_str().unwrap(),
            ],
            None, // Need to pass root?
            None,
            false,
            false,
            false,
            None,
        )?;

        Ok(Trojan {
            pid: handle.id(),
            config,
        })
    }
}

impl Drop for Trojan {
    fn drop(&mut self) {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .expect("Failed to kill trojan process");
    }
}
