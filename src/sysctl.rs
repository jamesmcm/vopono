use super::sudo_command;
use anyhow::Context;

pub struct SysCtl {}

impl SysCtl {
    pub fn enable_ipv4_forwarding() -> anyhow::Result<Self> {
        sudo_command(&["sysctl", "-q", "net.ipv4.ip_forward=1"])
            .with_context(|| "Failed to enable ipv4 forwarding via sysctl")?;
        Ok(Self {})
    }
}

// TODO: Do not overwrite if ipv4 forwarding was enabled to begin with
impl Drop for SysCtl {
    fn drop(&mut self) {
        sudo_command(&["sysctl", "-q", "net.ipv4.ip_forward=0"])
            .expect("Failed to disable ipv4 forwarding via sysctl");
    }
}
