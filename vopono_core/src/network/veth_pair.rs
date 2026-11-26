use super::netns::NetworkNamespace;
use crate::util::sudo_command;
use anyhow::Context;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
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
            let mut nm_config_path = nm_path.clone();
            nm_config_path.push("conf.d");
            std::fs::create_dir_all(&nm_config_path)?;
            nm_config_path.push("unmanaged.conf");

            let created_marker = nm_path.join("conf.d/unmanaged.conf.vopono.created");
            let backup_file = if nm_config_path.exists() {
                if created_marker.exists() {
                    // Earlier vopono namespace created unmanaged.conf from scratch;
                    // do not snapshot vopono's own generated file as a user backup.
                    None
                } else {
                    // Backup existing unmanaged.conf only if a backup does not already
                    // exist so concurrent launches do not overwrite the original.
                    let mut backup_path = nm_path;
                    backup_path.push("conf.d/unmanaged.conf.vopono.bak");
                    if !backup_path.exists() {
                        std::fs::copy(&nm_config_path, &backup_path)?;
                    }
                    Some(backup_path)
                }
            } else {
                let _ = std::fs::File::create(&created_marker);
                None
            };

            {
                let mut file = if nm_config_path.exists() {
                    debug!(
                        "Appending to existing NetworkManager config file: {}",
                        nm_config_path.as_path().to_string_lossy()
                    );
                    OpenOptions::new().append(true).open(nm_config_path)?
                } else {
                    debug!(
                        "Creating new NetworkManager config file: {}",
                        nm_config_path.as_path().to_string_lossy()
                    );
                    std::fs::File::create(nm_config_path)?
                };

                write!(file, "[keyfile]\nunmanaged-devices=interface-name:{dest}\n")?;
            }

            if let Err(e) = sudo_command(&["nmcli", "connection", "reload"])
                .context("Failed to reload NetworkManager configuration")
            {
                warn!(
                    "Tried but failed to reload NetworkManager configuration - is NetworkManager running? : {e}"
                );
            }
            Some(NetworkManagerUnmanaged {
                backup_file,
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

        let mut firewalld_added = false;
        if firewalld_running {
            debug!("Detected firewalld running, adding {dest} veth device to trusted zone");
            // Permit new interface
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
                Ok(true) => firewalld_added = true,
            }
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

        let pair = Self {
            source: source.clone(),
            dest: dest.clone(),
            nm_unmanaged,
            firewalld_added,
            cleanup_enabled: true,
        };

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
        // Only restore settings if there are no other active vopono namespaces
        // globally (across all users, not just the current user's lock dir).
        let other_active = has_other_active_vopono_namespaces();
        if other_active {
            return;
        }
        if let Ok(namespaces) = crate::util::get_lock_namespaces()
            && !namespaces.is_empty()
        {
            return;
        }

        let nm_path = PathBuf::from("/etc/NetworkManager/conf.d/unmanaged.conf");
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
        if let Err(error) = sudo_command(&["nmcli", "connection", "reload"]) {
            log::warn!("Failed to reload NetworkManager configuration: {error}");
        }
    }
}

fn nm_config_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn has_other_active_vopono_namespaces() -> bool {
    let owners_dir = std::path::Path::new("/run/vopono/namespace-owners");
    if let Ok(entries) = std::fs::read_dir(owners_dir) {
        let count = entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| !name.starts_with('.'))
            })
            .count();
        if count > 1 {
            return true;
        }
    }
    false
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
