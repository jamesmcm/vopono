use crate::util::sudo_command;
use anyhow::{Context, anyhow};

pub struct SysCtl {}

impl SysCtl {
    pub fn enable_forwarding(enable_ipv6: bool) -> anyhow::Result<Self> {
        ensure_forwarding_enabled("/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward")?;

        if enable_ipv6 {
            ensure_forwarding_enabled(
                "/proc/sys/net/ipv6/conf/all/forwarding",
                "net.ipv6.conf.all.forwarding",
            )?;
        }

        Ok(Self {})
    }

    pub fn enable_ipv4_forwarding() -> anyhow::Result<Self> {
        Self::enable_forwarding(false)
    }
}

fn ensure_forwarding_enabled(path: &str, sysctl_name: &str) -> anyhow::Result<()> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {sysctl_name} from {path}"))?;
    match parse_forwarding_value(&value, sysctl_name)? {
        true => {
            log::debug!("{sysctl_name} is already enabled");
            Ok(())
        }
        false => sudo_command(&["sysctl", "-q", &format!("{sysctl_name}=1")])
            .with_context(|| format!("Failed to enable forwarding via {sysctl_name}")),
    }
}

fn parse_forwarding_value(value: &str, sysctl_name: &str) -> anyhow::Result<bool> {
    match value.trim() {
        "1" => Ok(true),
        "0" => Ok(false),
        value => Err(anyhow!("Unexpected value for {sysctl_name}: {value:?}")),
    }
}

// Forwarding is a host-global setting. It is intentionally left enabled after
// setup: resetting it when one namespace exits can break another namespace or
// another network service. The namespace-specific routes, firewall rules, and
// masquerade rules are still removed with the namespace.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_forwarding_values() {
        assert!(parse_forwarding_value("1\n", "test.forwarding").unwrap());
        assert!(!parse_forwarding_value(" 0 ", "test.forwarding").unwrap());
    }

    #[test]
    fn rejects_invalid_forwarding_values() {
        assert!(parse_forwarding_value("enabled", "test.forwarding").is_err());
    }
}
