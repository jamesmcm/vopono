use std::io::Write;
use std::path::Path;

use anyhow::Context;
use log::warn;
use serde::{Deserialize, Serialize};
use which::which;

use crate::network::{netns::NetworkNamespace, wireguard_config::WireguardPeer};

use super::{TrojanHost, get_cert, trojan_config::TrojanConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct Trojan {
    pub(crate) pid: u32,
    pub config: TrojanConfig,
    #[serde(default)]
    runtime_dir: Option<std::path::PathBuf>,
    #[serde(default)]
    ns_name: Option<String>,
    #[serde(skip)]
    _temporary_files: Vec<tempfile::NamedTempFile>,
    #[serde(skip)]
    cleanup_enabled: bool,
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
        let temporary_files = Vec::new();
        let runtime_dir = crate::network::etc_overlay::trusted_runtime_dir("trojan-")?;

        if let Some(cpath) = config_path {
            warn!("Using custom Trojan config file: {cpath:?}");
            // Snapshot any custom SSL cert via dropped-privilege read so root
            // `trojan` never opens a user-writable path directly.
            if let Some(cert_path) = config.ssl_cert_path() {
                let cert_bytes =
                    crate::util::owner_write::read_file_as_config_owner(Path::new(cert_path))
                        .with_context(|| format!("Failed to read Trojan SSL cert {cert_path}"))?;
                let frozen_cert = runtime_dir.path().join("cert.pem");
                let mut f = crate::util::create_private_file(&frozen_cert)?;
                f.write_all(&cert_bytes)?;
                config.set_cert_path(&frozen_cert);
            }
        } else {
            let h = host
                .clone()
                .context("Host must be provided if no config path is given")?;
            if h.is_ip() {
                log::error!(
                    "IP address provided for trojan host, but SSL verification is not disabled. Disabling SSL verification."
                );
            } else {
                let cert = get_cert::get_cert(h.host(), h.port())?;
                let frozen_cert = runtime_dir.path().join("cert.pem");
                let mut f = crate::util::create_private_file(&frozen_cert)?;
                f.write_all(cert.as_bytes())?;
                config.set_cert_path(&frozen_cert);
            }
            config.set_verify_fields(!no_verify);
            config.set_remote_fields(&h);
            config.set_password(
                password.context("Trojan password must be provided if no config path is given")?,
            );
            config.set_wg_forwarding_fields(
                peer.as_ref()
                    .context("WireGuard peer must be provided for Trojan forwarding")?,
            );
        }

        // Always freeze the validated Trojan config into a root-owned 0600 file
        // under /run/vopono/runtime to prevent TOCTOU against user-writable paths.
        let frozen_config = runtime_dir.path().join("config.json");
        {
            let mut config_file = crate::util::create_private_file(&frozen_config)?;
            config_file.write_all(serde_json::to_string(&config)?.as_bytes())?;
        }
        let config_path_str = frozen_config
            .to_str()
            .context("Invalid frozen Trojan config path")?;

        let trojan_exec = which("trojan").with_context(|| {
            "trojan executable not found in PATH. Please install trojan and ensure it is in your PATH."
        })?;
        let trojan_exec_str = trojan_exec
            .to_str()
            .context("trojan executable path is not valid UTF-8")?;

        let handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &[trojan_exec_str, "-c", config_path_str],
            None,
            None,
            false,
            false,
            false,
            None,
        )?;

        Ok(Trojan {
            pid: handle.id(),
            config,
            runtime_dir: Some(runtime_dir.keep()),
            ns_name: Some(netns.name.clone()),
            _temporary_files: temporary_files,
            cleanup_enabled: true,
        })
    }
}

impl Drop for Trojan {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let pid = nix::unistd::Pid::from_raw(self.pid as i32);
        let pid_matches = self.ns_name.as_deref().is_none_or(|ns| {
            crate::util::process_is_in_network_namespace(self.pid, ns).unwrap_or(false)
        });
        if pid_matches {
            if let Err(error) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
                && error != nix::errno::Errno::ESRCH
            {
                warn!("Failed to terminate trojan process {}: {error}", self.pid);
            }
            for _ in 0..10 {
                match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, _))
                    | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _))
                    | Err(nix::errno::Errno::ECHILD) => break,
                    _ => std::thread::sleep(std::time::Duration::from_millis(25)),
                }
            }
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        }
        while matches!(
            nix::sys::wait::waitpid(pid, None),
            Err(nix::errno::Errno::EINTR)
        ) {}
        if let Some(runtime) = &self.runtime_dir {
            let _ = std::fs::remove_dir_all(runtime);
        }
    }
}

impl Trojan {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}
