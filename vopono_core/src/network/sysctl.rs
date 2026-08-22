use crate::util::sudo_command;
use anyhow::{Context, anyhow};
use log::{debug, info};
use std::process::Command;

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

    /// VPN return traffic enters the namespace unmarked via the veth interface,
    /// while tunnel policy routing (e.g. WireGuard's fwmark rules) can direct
    /// the reverse lookup for the remote endpoint to the tunnel device instead.
    /// With strict reverse-path filtering (rp_filter=1) such packets are
    /// silently dropped before reaching the application, which breaks
    /// connectivity when the host enables strict mode (e.g. via ufw's
    /// sysctl.conf overriding the distro default of loose mode).
    /// Loose mode (2) keeps anti-spoofing checks but tolerates this asymmetry,
    /// so only relax settings that are actually strict.
    pub fn relax_strict_rp_filter(netns_name: &str) -> anyhow::Result<()> {
        for key in [
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
        ] {
            let value = read_netns_sysctl(netns_name, key)?;
            match parse_rp_filter_value(&value, key)? {
                1 => {
                    info!(
                        "Strict reverse-path filtering detected ({key}=1) in netns {netns_name}, relaxing to loose mode (2)"
                    );
                    sudo_command(&[
                        "ip",
                        "netns",
                        "exec",
                        netns_name,
                        "sysctl",
                        "-q",
                        &format!("{key}=2"),
                    ])
                    .with_context(|| format!("Failed to set {key}=2 in netns: {netns_name}"))?;
                }
                value => {
                    debug!("{key}={value} in netns {netns_name}: no change needed");
                }
            }
        }
        Ok(())
    }
}

fn read_netns_sysctl(netns_name: &str, key: &str) -> anyhow::Result<String> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns_name, "sysctl", "-n", key])
        .output()
        .with_context(|| format!("Failed to read {key} in netns: {netns_name}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to read {key} in netns {netns_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_rp_filter_value(value: &str, sysctl_name: &str) -> anyhow::Result<u8> {
    match value.trim() {
        "0" => Ok(0),
        "1" => Ok(1),
        "2" => Ok(2),
        value => Err(anyhow!("Unexpected value for {sysctl_name}: {value:?}")),
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

    #[test]
    fn parses_rp_filter_values() {
        assert_eq!(parse_rp_filter_value("0\n", "test.rp_filter").unwrap(), 0);
        assert_eq!(parse_rp_filter_value(" 1 ", "test.rp_filter").unwrap(), 1);
        assert_eq!(parse_rp_filter_value("2", "test.rp_filter").unwrap(), 2);
    }

    #[test]
    fn rejects_invalid_rp_filter_values() {
        assert!(parse_rp_filter_value("strict", "test.rp_filter").is_err());
        assert!(parse_rp_filter_value("", "test.rp_filter").is_err());
    }
}
