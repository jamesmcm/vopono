use anyhow::{Context, anyhow};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NetworkInterface {
    pub name: String,
}

impl NetworkInterface {
    pub fn new(name: String) -> anyhow::Result<Self> {
        Ok(Self { name })
    }
}

impl FromStr for NetworkInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
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
}
