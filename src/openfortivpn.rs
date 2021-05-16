use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct OpenFortiVpn {
    pid: u32,
}

impl OpenFortiVpn {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("openfortivpn") {
            error!("OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?");
            return Err(anyhow!(
                "OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?: {:?}",
                x
            ));
        }

        let handle;

        info!("Launching OpenFortiVPN...");
        // TODO: DNS + default route
        // Must run as root - https://github.com/adrienverge/openfortivpn/issues/650
        let command_vec = (&[
            "openfortivpn",
            "-v",
            "-v",
            "-c",
            config_file.to_str().expect("Invalid config path"),
        ])
            .to_vec();

        // TODO - better handle blocking for input and waiting until connection established
        handle = netns
            .exec_no_block(&command_vec, None, false, None)
            .context("Failed to launch OpenFortiVPN - is openfortivpn installed?")?;
        let id = handle.id();

        // TODO: Handle default route
        // sudo ip route | grep "ppp0 proto kernel"
        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            super::util::open_ports(&netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            super::util::open_ports(&netns, forwards.as_slice(), firewall)?;
        }

        Ok(Self { pid: id })
    }
}

impl Drop for OpenFortiVpn {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenFortiVPN (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenFortiVPN (pid: {}): {:?}", self.pid, e),
        }
    }
}
