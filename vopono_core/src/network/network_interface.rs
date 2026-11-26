use anyhow::{Context, anyhow, ensure};
use log::{debug, warn};
use serde::{Deserialize, Deserializer, Serialize};
use std::ffi::CString;
use std::process::Command;
use std::str::FromStr;

#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
}

impl<'de> Deserialize<'de> for NetworkInterface {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawNetworkInterface {
            name: String,
        }

        let raw = RawNetworkInterface::deserialize(deserializer)?;
        validate_interface_name(&raw.name).map_err(serde::de::Error::custom)?;
        Ok(Self { name: raw.name })
    }
}

pub fn validate_interface_name(name: &str) -> anyhow::Result<()> {
    ensure!(!name.is_empty(), "Network interface name cannot be empty");
    ensure!(
        name.len() < libc::IFNAMSIZ,
        "Network interface name '{name}' exceeds maximum length ({})",
        libc::IFNAMSIZ - 1
    );
    ensure!(
        !name.starts_with('-'),
        "Network interface name cannot start with '-'"
    );
    ensure!(
        name != "." && name != "..",
        "Network interface name cannot be '.' or '..'"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "Network interface name contains unsupported characters"
    );
    Ok(())
}

impl NetworkInterface {
    pub fn new(name: String) -> anyhow::Result<Self> {
        validate_interface_name(&name)?;
        Ok(Self { name })
    }

    pub fn verify_exists_on_host(&self) -> anyhow::Result<()> {
        validate_interface_name(&self.name)?;
        let c_name = CString::new(self.name.as_str())
            .context("Network interface name contains an interior NUL byte")?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        ensure!(
            index != 0,
            "Network interface '{}' does not exist on the host",
            self.name
        );
        Ok(())
    }
}

impl FromStr for NetworkInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        validate_interface_name(s)?;
        let interfaces = get_active_interfaces();

        let cond = interfaces.map(|is| is.iter().any(|x| x == s));

        match cond {
            Ok(true) => {}
            _ => {
                warn!(
                    "{s} may not be an active network interface, using anyway since manually set"
                );
            }
        }
        Ok(Self {
            name: String::from(s),
        })
    }
}

pub fn get_active_interfaces() -> anyhow::Result<Vec<String>> {
    debug!("ip addr");
    let output = Command::new("ip")
        .arg("addr")
        .output()
        .with_context(|| "Failed to run command: ip addr".to_string())?
        .stdout;

    let out = parse_active_interfaces(std::str::from_utf8(&output)?);

    if !out.is_empty() {
        Ok(out)
    } else {
        Err(anyhow!(
            "Failed to get active network interface - consider using -i argument to override network interface"
        ))
    }
}

pub fn interface_has_default_route(interface: &str) -> anyhow::Result<bool> {
    let v4_output = Command::new("ip")
        .args(["-o", "route", "show", "default", "dev", interface])
        .output()
        .with_context(|| {
            format!("Failed to run command: ip -o route show default dev {interface}")
        })?;
    let v6_output = Command::new("ip")
        .args(["-o", "-6", "route", "show", "default", "dev", interface])
        .output()
        .with_context(|| {
            format!("Failed to run command: ip -o -6 route show default dev {interface}")
        })?;

    Ok(
        route_output_has_default(std::str::from_utf8(&v4_output.stdout)?)
            || route_output_has_default(std::str::from_utf8(&v6_output.stdout)?),
    )
}

fn parse_active_interfaces(ip_addr_output: &str) -> Vec<String> {
    ip_addr_output
        .split('\n')
        .filter(|line| line.contains("state UP"))
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|iface| String::from(&iface[..iface.len() - 1]))
        .collect()
}

fn route_output_has_default(route_output: &str) -> bool {
    route_output
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("default "))
}

#[cfg(test)]
mod tests {
    use super::{parse_active_interfaces, route_output_has_default};

    #[test]
    fn parse_active_interfaces_extracts_up_links() {
        let ip_addr_output = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
2: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
3: eno1: <BROADCAST,MULTICAST> mtu 1500 state DOWN
4: tailscale0: <POINTOPOINT,UP,LOWER_UP> mtu 1280 state UNKNOWN";

        let active = parse_active_interfaces(ip_addr_output);

        assert_eq!(active, vec!["wlp2s0"]);
    }

    #[test]
    fn route_output_has_default_detects_default_line() {
        let routes = "default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.100 metric 600";
        assert!(route_output_has_default(routes));
    }

    #[test]
    fn route_output_has_default_returns_false_when_missing() {
        let routes = "192.168.1.0/24 dev wlp2s0 proto kernel scope link src 192.168.1.100";
        assert!(!route_output_has_default(routes));
    }

    #[test]
    fn network_interface_rejects_injection_and_invalid_names() {
        for bad in [
            "",
            "-eth0",
            ".",
            "..",
            "eth0; flush ruleset",
            "eth0\" drop",
            "eth+",
            "eth*",
            "eth 0",
            "0123456789abcdef",
        ] {
            assert!(
                super::NetworkInterface::new(bad.to_string()).is_err(),
                "expected rejection for {bad:?}"
            );
            let json = serde_json::json!({ "name": bad });
            assert!(
                serde_json::from_value::<super::NetworkInterface>(json).is_err(),
                "expected deserialization rejection for {bad:?}"
            );
        }

        for good in ["eth0", "wlp2s0", "eth0.100", "wg-mullvad_0"] {
            assert!(
                super::NetworkInterface::new(good.to_string()).is_ok(),
                "expected acceptance for {good:?}"
            );
        }
    }
}
