use super::util::sudo_command;
use super::NetworkNamespace;
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VethPair {
    pub source: String,
    pub dest: String,
}

// ifname must be less <= 15 chars
impl VethPair {
    pub fn new(source: String, dest: String, netns: &NetworkNamespace) -> anyhow::Result<Self> {
        assert!(source.len() <= 15, "ifname must be <= 15 chars: {}", source);
        assert!(dest.len() <= 15, "ifname must be <= 15 chars: {}", dest);
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

        Ok(Self { source, dest })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        sudo_command(&["ip", "link", "delete", &self.dest])
            .expect(&format!("Failed to delete veth pair: {}", &self.dest));
    }
}
