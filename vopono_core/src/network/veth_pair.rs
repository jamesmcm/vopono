use super::netns::NetworkNamespace;
use crate::util::sudo_command;
use anyhow::Context;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
pub struct VethPair {
    pub source: String,
    pub dest: String,
    pub nm_unmanaged: Option<NetworkManagerUnmanaged>,
    #[serde(default)]
    firewalld_added: bool,
    #[serde(skip)]
    cleanup_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkManagerUnmanaged {
    pub backup_file: Option<PathBuf>,
    #[serde(default)]
    drop_in_interface: Option<String>,
    #[serde(skip)]
    cleanup_enabled: bool,
}

// Linux interface names must be <= 15 bytes (excluding the trailing NUL).
impl VethPair {
    pub fn new(source: String, dest: String, netns: &NetworkNamespace) -> anyhow::Result<Self> {
        // Return an error rather than panicking: in the daemon this must
        // surface as a per-client error response instead of aborting the
        // connection thread.
        anyhow::ensure!(source.len() <= 15, "ifname must be <= 15 chars: {source}");
        anyhow::ensure!(dest.len() <= 15, "ifname must be <= 15 chars: {dest}");

        // NetworkManager device management
        // If NetworkManager used, add destination veth to unmanaged devices
        // Avoids NM overriding our IP assignment
        // TODO: Check with systemd instead of nmcli directly?
        let nm_path = PathBuf::from_str("/etc/NetworkManager")?;
        let nm_running = if which::which("nmcli").is_ok() {
            std::process::Command::new("nmcli")
                .arg("general")
                .arg("status")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|x| x.success())
                .unwrap_or(false)
        } else {
            false
        };

        if nm_running {
            debug!("Detected NetworkManager running");
        } else {
            debug!("NetworkManager not detected running");
        }

        let nm_unmanaged = if nm_path.exists() && nm_running {
            let _nm_guard = nm_config_lock();
            debug!(
                "NetworkManager detected, adding {} to unmanaged devices",
                dest
            );
            let config_dir = nm_path.join("conf.d");
            std::fs::create_dir_all(&config_dir)?;
            let drop_in = network_manager_drop_in(&config_dir, &dest)?;
            let mut config = tempfile::NamedTempFile::new_in(&config_dir)?;
            writeln!(config, "[device-vopono-{dest}]")?;
            writeln!(config, "match-device=interface-name:{dest}")?;
            writeln!(config, "managed=0")?;
            config.persist(&drop_in)?;
            reload_network_manager();
            Some(NetworkManagerUnmanaged {
                backup_file: None,
                drop_in_interface: Some(dest.clone()),
                cleanup_enabled: true,
            })
        } else {
            None
        };

        // systemd firewalld device management
        let firewalld_running = if which::which("firewall-cmd").is_ok() {
            std::process::Command::new("firewall-cmd")
                .arg("--state")
                .status()
                .map(|x| x.success())
                .unwrap_or(false)
        } else {
            false
        };

        if firewalld_running {
            debug!("Detected firewalld running");
        } else {
            debug!("firewalld not detected running");
        }

        sudo_command(&[
            "ip",
            "link",
            "add",
            dest.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            source.as_str(),
        ])
        .with_context(|| format!("Failed to create veth pair {}, {}", source, dest))?;

        let mut pair = Self {
            source: source.clone(),
            dest: dest.clone(),
            nm_unmanaged,
            firewalld_added: false,
            cleanup_enabled: true,
        };

        if firewalld_running {
            debug!("Detected firewalld running, adding {dest} veth device to trusted zone");
            // Permit new interface only after the veth exists and `pair`'s Drop guard is active.
            match std::process::Command::new("firewall-cmd")
                .arg("--zone=trusted")
                .arg(format!("--add-interface={dest}").as_str())
                .status()
                .map(|x| x.success())
            {
                Err(e) => {
                    warn!("Failed to add veth device {dest} to firewalld trusted zone, error: {e}")
                }
                Ok(false) => warn!(
                    "Possibly failed to add veth device {dest} to firewalld trusted zone (non-zero exit code)"
                ),
                Ok(true) => pair.firewalld_added = true,
            }
        }

        sudo_command(&["ip", "link", "set", dest.as_str(), "up"])
            .with_context(|| format!("Failed to bring up destination veth: {}", dest))?;

        sudo_command(&[
            "ip",
            "link",
            "set",
            source.as_str(),
            "netns",
            &netns.name,
            "up",
        ])
        .with_context(|| format!("Failed to bring up source veth: {}", dest))?;

        Ok(pair)
    }
}

fn link_is_missing(name: &str) -> anyhow::Result<bool> {
    let output = std::process::Command::new("ip")
        .args(["link", "show", name])
        .output()
        .with_context(|| format!("Failed to inspect veth pair: {name}"))?;
    if output.status.success() {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.to_ascii_lowercase();
    if normalized.contains("does not exist") || normalized.contains("cannot find device") {
        return Ok(true);
    }

    Err(anyhow::anyhow!(
        "ip link show {name} failed with status {}: {}",
        output.status,
        stderr.trim()
    ))
}

impl Drop for VethPair {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        // Concurrent teardowns (e.g. `vopono stop` racing the session that
        // owns the namespace) can legitimately delete this interface first;
        // a missing veth must not panic inside Drop, which would abort the
        // daemon connection thread mid-response.
        if let Err(error) = sudo_command(&["ip", "link", "delete", &self.dest]) {
            match link_is_missing(&self.dest) {
                Ok(true) => {
                    debug!("Veth pair {} was already removed", self.dest);
                }
                Ok(false) => {
                    log::error!("Failed to delete veth pair {}: {error}", self.dest);
                }
                Err(inspect_error) => {
                    log::error!(
                        "Failed to delete veth pair {}: {error}; could not verify whether it was removed: {inspect_error}",
                        self.dest
                    );
                }
            }
        }
        if self.firewalld_added {
            let _ = std::process::Command::new("firewall-cmd")
                .arg("--zone=trusted")
                .arg(format!("--remove-interface={}", self.dest))
                .status();
        }
    }
}

impl Drop for NetworkManagerUnmanaged {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let _nm_guard = nm_config_lock();
        let config_dir = std::path::Path::new("/etc/NetworkManager/conf.d");
        if let Some(interface) = &self.drop_in_interface {
            let Ok(drop_in) = network_manager_drop_in(config_dir, interface) else {
                return;
            };
            match std::fs::remove_file(&drop_in) {
                Ok(()) => reload_network_manager(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => warn!(
                    "Could not remove NetworkManager drop-in {}: {error}",
                    drop_in.display()
                ),
            }
            return;
        }

        // Older daemon snapshots share unmanaged.conf. Its appended veth
        // entries, rather than ownership records, determine when it is idle.
        let nm_path = config_dir.join("unmanaged.conf");
        let Ok(contents) = std::fs::read_to_string(&nm_path) else {
            return;
        };
        let original = match &self.backup_file {
            Some(backup) => {
                if backup != &config_dir.join("unmanaged.conf.vopono.bak") {
                    return;
                }
                match std::fs::read_to_string(backup) {
                    Ok(value) => value,
                    Err(error) => {
                        debug!("Could not read legacy NetworkManager backup: {error}");
                        return;
                    }
                }
            }
            None => String::new(),
        };
        let Some(appended) = contents.strip_prefix(&original) else {
            warn!("NetworkManager unmanaged.conf changed since vopono saved its backup");
            return;
        };
        let mut lines = appended.lines();
        while let Some(section) = lines.next() {
            let Some(interface) = lines
                .next()
                .and_then(|line| line.strip_prefix("unmanaged-devices=interface-name:"))
            else {
                return;
            };
            if section != "[keyfile]"
                || !interface.ends_with("_d")
                || !link_is_missing(interface).unwrap_or(false)
            {
                return;
            }
        }

        if let Some(backup_file) = self.backup_file.as_ref() {
            // Concurrent teardowns (e.g. `vopono stop` racing the owning
            // session) may already have restored and removed the backup;
            // cleanup must never panic inside Drop.
            match std::fs::copy(backup_file, &nm_path) {
                Ok(_) => {
                    if let Err(error) = std::fs::remove_file(backup_file)
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        log::warn!(
                            "Failed to delete NetworkManager unmanaged.conf backup {}: {error}",
                            backup_file.display()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    debug!(
                        "NetworkManager unmanaged.conf backup {} already consumed by another teardown",
                        backup_file.display()
                    );
                }
                Err(error) => {
                    log::warn!(
                        "Failed to restore NetworkManager unmanaged.conf from {}: {error}",
                        backup_file.display()
                    );
                }
            }
        } else {
            if let Err(error) = std::fs::remove_file(&nm_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                log::warn!("Failed to delete NetworkManager unmanaged.conf: {error}");
            }
            let _ =
                std::fs::remove_file("/etc/NetworkManager/conf.d/unmanaged.conf.vopono.created");
        }
        reload_network_manager();
    }
}

fn network_manager_drop_in(dir: &std::path::Path, interface: &str) -> anyhow::Result<PathBuf> {
    super::network_interface::NetworkInterface::new(interface.to_owned())?;
    Ok(dir.join(format!("90-vopono-{interface}.conf")))
}

fn reload_network_manager() {
    if let Err(error) = sudo_command(&["nmcli", "general", "reload", "conf"]) {
        warn!("Failed to reload NetworkManager configuration: {error}");
    }
}

fn nm_config_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl VethPair {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
        if let Some(network_manager) = &mut self.nm_unmanaged {
            network_manager.cleanup_enabled = enabled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VethPair;
    use crate::network::netns::NetworkNamespace;

    #[test]
    fn overlong_interface_names_return_errors() {
        let namespace = NetworkNamespace::attach_unmanaged("vo_test".to_string()).unwrap();

        let source_error = VethPair::new("s".repeat(16), "dest".to_string(), &namespace)
            .unwrap_err()
            .to_string();
        assert!(source_error.contains("ifname must be <= 15 chars"));

        let dest_error = VethPair::new("source".to_string(), "d".repeat(16), &namespace)
            .unwrap_err()
            .to_string();
        assert!(dest_error.contains("ifname must be <= 15 chars"));
    }
}
