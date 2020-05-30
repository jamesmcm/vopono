use super::util::sudo_command;
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
        // Do not reset since can affect other namespaces
        // TODO: Detect if other namespaces still running and
        // if we were originally set to forward
        // sudo_command(&["sysctl", "-q", "net.ipv4.ip_forward=0"])
        //     .expect("Failed to disable ipv4 forwarding via sysctl");
    }
}
