use std::{ffi::CString, path::Path, ptr};

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
        Self::redirect_resolv_conf(&netns.name).context("Failed to redirect /etc/resolv.conf")?;

        info!("Launching Warp...");

        let handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &["warp-svc"],
            None,
            None,
            false,
            false,
            false,
            None,
        )
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

    // Extremely hacky fix to redirect /etc/resolv.conf to /etc/netns/{netns.name}/resolv.conf
    // So wrap-svc writes to the file we want
    fn redirect_resolv_conf(netns_name: &str) -> anyhow::Result<()> {
        let res = unsafe { libc::unshare(libc::CLONE_NEWNS) };
        if res == -1 {
            return Err(anyhow!(std::io::Error::last_os_error()));
        }

        // Mark the mount namespace as private to avoid affecting the parent namespace
        let mount_proc = CString::new("/proc/self/ns/mnt")?;
        unsafe {
            libc::mount(
                ptr::null(),
                mount_proc.as_ptr(),
                ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                ptr::null(),
            );
        }

        // Create mount binding
        let source = CString::new(format!("/etc/netns/{}/resolv.conf", netns_name))?;
        let target = CString::new("/etc/resolv.conf")?;

        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                ptr::null(),
                libc::MS_BIND,
                ptr::null(),
            )
        };

        if result == -1 {
            return Err(anyhow!(std::io::Error::last_os_error()));
        };
        Ok(())
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
