use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
use dialoguer::{Input, Password};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct OpenConnect {
    pid: u32,
}

impl OpenConnect {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: Option<PathBuf>,
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

        let handle;

        let creds = {
            if let Some(config_file) = config_file {
                let config_file_path = config_file.canonicalize().context("Invalid path given")?;
                get_creds_from_file(&config_file_path)
            } else {
                request_creds()
            }
        }?;

        info!("Launching OpenConnect...");
        // TODO: Auth
        let user_arg = format!("--user={}", creds.0);
        let command_vec = (&["openconnect", &user_arg, "--passwd-on-stdin", server]).to_vec();

        handle = netns
            .exec_no_block(&command_vec, None, false, None)
            .context("Failed to launch OpenConnect - is openconnect installed?")?;
        let id = handle.id();

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            super::util::open_ports(&netns, forwards.as_slice(), firewall)?;
        }

        Ok(Self { pid: id })
    }
}

fn get_creds_from_file(auth_file: &PathBuf) -> anyhow::Result<(String, String)> {
    let s = std::fs::read_to_string(auth_file)?;
    let mut iter = s.split('\n');
    let user = iter.next().expect("No username in auth file");
    let pass = iter.next().expect("No password in auth file");
    Ok((user.to_string(), pass.to_string()))
}

fn request_creds() -> anyhow::Result<(String, String)> {
    let username = Input::<String>::new()
        .with_prompt("OpenConnect username")
        .interact()?;
    let username = username.trim();
    let password = Password::new()
        .with_prompt("OpenConnect password")
        .interact()?;
    let password = password.trim();
    Ok((username.to_string(), password.to_string()))
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
