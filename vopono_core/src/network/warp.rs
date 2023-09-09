use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
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

        info!("Launching Warp...");

        let handle = netns
            .exec_no_block(&["warp-svc"], None, None, false, false, false, None)
            .context("Failed to launch warp-svc - is waro-svc installed?")?;

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
