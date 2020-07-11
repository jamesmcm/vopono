use super::util::sudo_command;
use super::NetworkNamespace;
use anyhow::Context;
use log::debug;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct VethPair {
    pub source: String,
    pub dest: String,
    pub nm_unmanaged: Option<NetworkManagerUnmanaged>,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkManagerUnmanaged {
    pub backup_file: Option<PathBuf>,
}

// ifname must be less <= 15 chars
impl VethPair {
    pub fn new(source: String, dest: String, netns: &NetworkNamespace) -> anyhow::Result<Self> {
        assert!(source.len() <= 15, "ifname must be <= 15 chars: {}", source);
        assert!(dest.len() <= 15, "ifname must be <= 15 chars: {}", dest);

        // If NetworkManager used, add destination veth to unmanaged devices
        // Avoids NM overriding our IP assignment
        // TODO: Check with systemd?
        let nm_path = PathBuf::from_str("/etc/NetworkManager")?;
        let nm_unmanaged = if nm_path.exists() {
            debug!(
                "NetworkManager detected, adding {} to unmanaged devices",
                &dest
            );
            let mut nm_config_path = nm_path.clone();
            nm_config_path.push("conf.d/unmanaged.conf");

            let backup_file = if nm_config_path.exists() {
                // Backup existing unmanaged.conf
                let mut backup_path = nm_path;
                backup_path.push("conf.d/unmanaged.conf.vopono.bak");
                std::fs::copy(&nm_config_path, &backup_path)?;
                Some(backup_path)
            } else {
                None
            };

            let mut file = if nm_config_path.exists() {
                OpenOptions::new().append(true).open(nm_config_path)?
            } else {
                std::fs::File::create(nm_config_path)?
            };

            write!(
                file,
                "[keyfile]\nunmanaged-devices=interface-name:{}\n",
                dest
            )?;

            Some(NetworkManagerUnmanaged { backup_file })
        } else {
            None
        };

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
        .with_context(|| format!("Failed to create veth pair {}, {}", &source, &dest))?;

        sudo_command(&["ip", "link", "set", dest.as_str(), "up"])
            .with_context(|| format!("Failed to bring up destination veth: {}", &dest))?;

        sudo_command(&[
            "ip",
            "link",
            "set",
            source.as_str(),
            "netns",
            &netns.name,
            "up",
        ])
        .with_context(|| format!("Failed to bring up source veth: {}", &dest))?;

        Ok(Self {
            source,
            dest,
            nm_unmanaged,
        })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        sudo_command(&["ip", "link", "delete", &self.dest])
            .unwrap_or_else(|_| panic!("Failed to delete veth pair: {}", &self.dest));
    }
}

impl Drop for NetworkManagerUnmanaged {
    fn drop(&mut self) {
        let nm_path = PathBuf::from_str("/etc/NetworkManager/conf.d/unmanaged.conf")
            .expect("Failed to build path");
        if self.backup_file.is_some() {
            std::fs::copy(self.backup_file.as_ref().unwrap(), &nm_path)
                .expect("Failed to restore backup of NetworkManager unmanaged.conf");
            std::fs::remove_file(self.backup_file.as_ref().unwrap())
                .expect("Failed to delete backup of NetworkManager unmanaged.conf");
        } else {
            std::fs::remove_file(&nm_path).expect("Failed to delete NetworkManager unmanaged.conf");
        }
    }
}
