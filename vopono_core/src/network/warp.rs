use std::path::Path;

use crate::util::unix::run_program_in_netns_with_path_redirect;

use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

// Cloudflare Warp

#[derive(Serialize, Deserialize, Debug)]
pub struct Warp {
    pid: u32,
}

impl Warp {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        // TODO: Add Killswitch using - https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/

        if let Err(x) = which::which("warp-svc") {
            error!("Cloudflare Warp warp-svc not found. Is warp-svc installed and on PATH?");
            return Err(anyhow!(
                "warp-svc not found. Is warp-svc installed and on PATH?: {:?}",
                x
            ));
        }

        // Ensure /etc/netns/{netns.name}/resolv.conf exists
        let resolv_conf_path = format!("/etc/netns/{}/resolv.conf", netns.name);
        let dir_path = format!("/etc/netns/{}", netns.name);
        if !std::path::Path::new(&resolv_conf_path).exists() {
            std::fs::create_dir_all(Path::new(&dir_path))?;
            std::fs::File::create(&resolv_conf_path)
                .with_context(|| format!("Failed to create resolv.conf: {}", &resolv_conf_path))?;
        }

        info!("Launching Warp...");
        let id = run_program_in_netns_with_path_redirect(
            "warp-svc",
            &[],
            &netns.name,
            "/etc/resolv.conf",
            &resolv_conf_path,
        )
        .context("Failed to launch warp-svc - is warp-svc installed?")?;
        info!("Warp launched with PID: {}", id);
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

impl Drop for Warp {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed warp-svc (pid: {})", self.pid),
            Err(e) => error!("Failed to kill warp-svc (pid: {}): {:?}", self.pid, e),
        }
    }
}
