use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
use dialoguer::Password;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenConnect {
    pid: u32,
}

impl OpenConnect {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        server: &str,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("openconnect") {
            error!("OpenConnect not found. Is OpenConnect installed and on PATH?");
            return Err(anyhow!(
                "OpenConnect not found. Is OpenConnect installed and on PATH?: {:?}",
                x
            ));
        }

        let pass = request_creds();

        let password = pass.expect("Provide password via Stdin!");

        info!("Launching OpenConnect...");
        let mut command_vec = [
            "openconnect",
            "--config",
            config_file.to_str().expect("Invalid config path"),
            "--passwd-on-stdin",
        ]
        .to_vec();

        if !server.is_empty() {
            command_vec.push(server.as_ref());
        }

        let handle = netns
            .exec_no_block(&command_vec, None, false, false, None)
            .context("Failed to launch OpenConnect - is openconnect installed?")?;

        handle
            .stdin
            .as_ref()
            .unwrap()
            .write_all(password.as_bytes())
            .expect("Failed to write to stdin");

        let id = handle.id();

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            crate::util::open_ports(netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
        }

        Ok(Self { pid: id })
    }
}

fn request_creds() -> anyhow::Result<String> {
    let password = Password::new()
        .with_prompt("OpenConnect password")
        .interact()?;
    let password = password.trim();
    Ok(password.to_string())
}

impl Drop for OpenConnect {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenConnect (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenConnect (pid: {}): {:?}", self.pid, e),
        }
    }
}
