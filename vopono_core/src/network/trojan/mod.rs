use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

pub mod get_cert;
pub mod trojan_config;
pub mod trojan_exec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrojanHost {
    HostnameWithPort(String, u16),
    Hostname(String),
    IpWithPort(SocketAddr),
    Ip(IpAddr),
}

impl TrojanHost {
    pub fn host(&self) -> String {
        match self {
            TrojanHost::HostnameWithPort(hostname, _) => hostname.clone(),
            TrojanHost::Hostname(hostname) => hostname.clone(),
            TrojanHost::IpWithPort(addr) => addr.ip().to_string(),
            TrojanHost::Ip(addr) => addr.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TrojanHost::HostnameWithPort(_, port) => *port,
            TrojanHost::Hostname(_) => 443, // Default port
            TrojanHost::IpWithPort(addr) => addr.port(),
            TrojanHost::Ip(_) => 443, // Default port
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, TrojanHost::Ip(_) | TrojanHost::IpWithPort(_))
    }

    // TODO: Handle multiple addresses
    pub fn resolve_ip(&self) -> anyhow::Result<IpAddr> {
        match self {
            TrojanHost::HostnameWithPort(hostname, port) => format!("{hostname}:{port}")
                .to_socket_addrs()
                .map_err(|e| anyhow!("Failed to resolve hostname: {hostname}: {e}"))?
                .next()
                .ok_or_else(|| anyhow!("No address found for hostname: {hostname}"))
                .map(|addr| addr.ip()),
            TrojanHost::Hostname(hostname) => format!("{hostname}:80")
                .to_socket_addrs()
                .map_err(|e| anyhow!("Failed to resolve hostname: {hostname}: {e}"))?
                .next()
                .ok_or_else(|| anyhow!("No address found for hostname: {hostname}"))
                .map(|addr| addr.ip()),
            TrojanHost::Ip(addr) => Ok(*addr),
            TrojanHost::IpWithPort(addr) => Ok(addr.ip()),
        }
    }
}

impl FromStr for TrojanHost {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            Ok(TrojanHost::IpWithPort(addr))
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(TrojanHost::Ip(ip))
        } else if let Some((host, port)) = s.split_once(':') {
            let port = port
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("Invalid port"))?;
            Ok(TrojanHost::HostnameWithPort(host.to_string(), port))
        } else {
            Ok(TrojanHost::Hostname(s.to_string()))
        }
    }
}
