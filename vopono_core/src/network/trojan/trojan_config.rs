use anyhow::Context;
use log::warn;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
};

use crate::network::wireguard_config::WireguardPeer;

use super::TrojanHost; // Required for IpAddr type

static FORWARD_TEMPLATE: &str = include_str!("./forward_template.json");

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)] // Added PartialEq for potential testing/comparison
#[serde(rename_all = "snake_case")] // Ensures "forward" maps to Forward, etc.
pub enum RunType {
    Forward,
    // TODO:
    // Client for SOCKS
    // NAT for Transparent Proxy
    // https://trojan-gfw.github.io/trojan/config
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrojanConfig {
    run_type: RunType,
    local_addr: IpAddr,
    local_port: u16, // For forwarding, should match local Wireguard config for endpoint peer
    remote_addr: String, // String as can be hostname or IP
    remote_port: u16, // Usually 443
    target_addr: String, // String as can be hostname or IP
    target_port: u16,
    password: Vec<String>,
    udp_timeout: u32,
    log_level: u8,
    ssl: TrojanSslConfig,
    tcp: TrojanTcpConfig,
}

impl TrojanConfig {
    pub fn new(override_path: Option<&Path>) -> anyhow::Result<TrojanConfig> {
        let override_config_str = match override_path {
            Some(path) => {
                let bytes = crate::util::owner_write::read_file_as_config_owner(path)
                    .with_context(|| format!("Failed to read Trojan config {}", path.display()))?;
                Some(String::from_utf8(bytes).with_context(|| {
                    format!("Trojan config {} is not valid UTF-8", path.display())
                })?)
            }
            None => None,
        };

        let config_str = override_config_str.as_deref().unwrap_or(FORWARD_TEMPLATE);

        let config: TrojanConfig = serde_json::from_str(config_str)
            .context("Failed to parse Trojan JSON configuration")?;
        Ok(config)
    }

    pub fn get_local_socketaddr(&self) -> anyhow::Result<SocketAddr> {
        let local_addr = SocketAddr::new(self.local_addr, self.local_port);
        Ok(local_addr)
    }

    pub fn set_remote_fields(&mut self, trojan_host: &TrojanHost) {
        self.remote_addr = trojan_host.host();
        self.remote_port = trojan_host.port();
        if trojan_host.is_ip() {
            warn!(
                "Using IP address for remote trojan host: {} - disabling SSL verification",
                self.remote_addr
            );
            self.set_verify_fields(false);
        }
    }

    pub fn get_remote_trojanhost(&self) -> anyhow::Result<TrojanHost> {
        TrojanHost::from_str(self.remote_addr.as_str())
    }

    pub fn set_verify_fields(&mut self, verify: bool) {
        self.ssl.verify = verify;
        self.ssl.verify_hostname = verify;
    }

    pub fn set_wg_forwarding_fields(&mut self, wg: &WireguardPeer) {
        self.target_addr = wg.endpoint.ip_or_hostname();
        self.target_port = wg.endpoint.port();
    }

    pub fn set_password(&mut self, password: &str) {
        self.password = vec![password.to_string()];
    }

    pub fn set_cert(&mut self, cert: &str) -> anyhow::Result<tempfile::NamedTempFile> {
        let mut cert_file = tempfile::NamedTempFile::new()
            .context("Failed to create temporary Trojan certificate")?;
        cert_file
            .write_all(cert.as_bytes())
            .context("Failed to write temporary Trojan certificate")?;
        self.ssl.cert = cert_file.path().to_string_lossy().to_string();
        Ok(cert_file)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrojanSslConfig {
    verify: bool,
    verify_hostname: bool,
    cert: String,
    cipher: String,
    cipher_tls13: String,
    sni: String,
    alpn: Vec<String>,
    reuse_session: bool,
    session_ticket: bool,
    curves: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrojanTcpConfig {
    no_delay: bool,
    keep_alive: bool,
    reuse_port: bool,
    fast_open: bool,
    fast_open_qlen: u32,
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_trojan_template() {
        let config: TrojanConfig = serde_json::from_str(FORWARD_TEMPLATE).unwrap();
        assert_eq!(config.run_type, RunType::Forward);
        assert_eq!(config.local_addr.to_string(), "127.0.0.1");
        assert_eq!(config.local_port, 1637);
        assert_eq!(config.password, vec!["replaceme".to_string()]);
        assert!(config.ssl.verify);
        assert_eq!(config.ssl.sni, "");
        assert_eq!(config.tcp.fast_open_qlen, 20);
    }

    #[test]
    fn trojan_config_returns_err_without_leaking_file_contents() {
        let missing = Path::new("/nonexistent/vopono/trojan_config_missing.json");
        assert!(TrojanConfig::new(Some(missing)).is_err());

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "SECRET_TROJAN_PASSWORD_VALUE not json").unwrap();
        let err = TrojanConfig::new(Some(file.path())).unwrap_err();
        assert!(!format!("{err:#}").contains("SECRET_TROJAN_PASSWORD_VALUE"));
    }
}
