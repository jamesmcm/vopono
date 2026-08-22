//! Namespace connectivity checks.
//!
//! The probe runs this same binary inside the target namespace via
//! `ip netns exec` and performs a single TCP connect, so it works for every
//! protocol and requires no extra dependencies. It needs root privileges to
//! enter the namespace: direct calls therefore come from the daemon (or the
//! sudo fallback path), never from unprivileged callers.

use crate::args::ProbeCommand;
use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::{Duration, Instant};
use vopono_core::util::hostname_to_ip;

pub const DEFAULT_CHECK_HOST: &str = "1.1.1.1";
pub const DEFAULT_CHECK_PORT: u16 = 443;
pub const DEFAULT_CHECK_TIMEOUT_MS: u64 = 3000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectivityStatus {
    pub id: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Versioned JSON document for `vopono check`.
#[derive(Debug, Serialize)]
pub struct ConnectivityDocument {
    pub version: u8,
    pub result: ConnectivityStatus,
}

impl ConnectivityStatus {
    pub fn human_line(&self) -> String {
        let state = if self.connected {
            "connected"
        } else {
            "no connectivity"
        };
        let latency = self
            .latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".to_string());
        format!("{}\t{state}\t{latency}\t{}", self.id, self.target)
    }
}

/// Entry point of the hidden `__connectivity-probe` subcommand.
///
/// Executes inside the target namespace: resolves `host` with the namespace's
/// own resolver, opens one TCP connection, prints the measured latency in ms
/// on success and exits non-zero on failure.
pub fn run_probe(command: ProbeCommand) -> anyhow::Result<()> {
    let started = Instant::now();
    connect(&command.host, command.port, command.timeout_ms)?;
    println!("{}", started.elapsed().as_millis());
    Ok(())
}

fn connect(host: &str, port: u16, timeout_ms: u64) -> anyhow::Result<TcpStream> {
    let ip = match IpAddr::from_str(host) {
        Ok(ip) => ip,
        Err(_) => hostname_to_ip(host)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Could not resolve host: {host}"))?,
    };
    TcpStream::connect_timeout(
        &SocketAddr::new(ip, port),
        Duration::from_millis(timeout_ms),
    )
    .with_context(|| format!("TCP connect to {ip}:{port} failed"))
}

/// Probe connectivity of an existing network namespace. Requires root.
pub fn probe_namespace(id: &str, host: &str, port: u16, timeout_ms: u64) -> ConnectivityStatus {
    let target = format!("tcp {host}:{port}");
    match probe_namespace_inner(id, host, port, timeout_ms) {
        Ok(latency_ms) => ConnectivityStatus {
            id: id.to_string(),
            connected: true,
            latency_ms: Some(latency_ms),
            target,
            error: None,
        },
        Err(error) => ConnectivityStatus {
            id: id.to_string(),
            connected: false,
            latency_ms: None,
            target,
            error: Some(format!("{error:#}")),
        },
    }
}

fn probe_namespace_inner(id: &str, host: &str, port: u16, timeout_ms: u64) -> anyhow::Result<u64> {
    let exe = std::env::current_exe().context("Failed to locate the vopono binary")?;
    let output = std::process::Command::new("ip")
        .args(["netns", "exec", id])
        .arg(&exe)
        .args([
            "__connectivity-probe",
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--timeout-ms",
            &timeout_ms.to_string(),
        ])
        .output()
        .with_context(|| format!("Failed to launch probe inside namespace '{id}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Probe in namespace '{id}' failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("Probe returned unexpected output: {:?}", stdout.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_line_renders_states() {
        let ok = ConnectivityStatus {
            id: "vo_a_r".to_string(),
            connected: true,
            latency_ms: Some(42),
            target: "tcp 1.1.1.1:443".to_string(),
            error: None,
        };
        assert_eq!(ok.human_line(), "vo_a_r\tconnected\t42ms\ttcp 1.1.1.1:443");

        let down = ConnectivityStatus {
            id: "vo_a_r".to_string(),
            connected: false,
            latency_ms: None,
            target: "tcp 1.1.1.1:443".to_string(),
            error: Some("boom".to_string()),
        };
        assert_eq!(
            down.human_line(),
            "vo_a_r\tno connectivity\t-\ttcp 1.1.1.1:443"
        );
    }

    #[test]
    fn json_document_omits_absent_fields() {
        let doc = ConnectivityDocument {
            version: crate::api::SCHEMA_VERSION,
            result: ConnectivityStatus {
                id: "vo_x".to_string(),
                connected: false,
                latency_ms: None,
                target: "t".to_string(),
                error: None,
            },
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert!(json["result"].get("latency_ms").is_none());
        assert!(json["result"].get("error").is_none());
        assert_eq!(json["version"], crate::api::SCHEMA_VERSION);
    }
}
