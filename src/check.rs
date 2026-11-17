//! Namespace connectivity checks.
//!
//! The probe runs this same binary inside the target namespace via
//! `ip netns exec` and performs three independent checks: a TCP connect over
//! IPv4, a TCP connect over IPv6, and a DNS resolution using the namespace's
//! own resolver. Results are reported per family even when siblings fail -
//! partial health is exactly what makes the probe useful for debugging.
//!
//! It needs root privileges to enter the namespace: direct calls therefore
//! come from the daemon (or the sudo fallback path), never from unprivileged
//! callers.
//!
// NOTE: A port-forwarding check (e.g. verifying that an automatically
// forwarded port actually accepts connections through the tunnel) could live
// alongside this probe in the future, but is out of scope for now.

use crate::args::ProbeCommand;
use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use vopono_core::diagnostics::{DiagnosticCode, DnsFailure, resolve_bounded};

pub const DEFAULT_CHECK_PORT: u16 = 443;
pub const DEFAULT_TIMEOUT_MS: u64 = 3000;
pub const DEFAULT_V4_HOST: &str = "1.1.1.1";
pub const DEFAULT_V6_HOST: &str = "2606:4700:4700::1111";
pub const DEFAULT_DNS_HOST: &str = "one.one.one.one";

/// Reachability of one address family.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FamilyStatus {
    /// Target that was probed (`ip:port`).
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<DiagnosticCode>,
}

impl FamilyStatus {
    fn ok(target: &str, latency_ms: u64) -> Self {
        Self {
            target: target.to_string(),
            latency_ms: Some(latency_ms),
            error: None,
            code: None,
        }
    }

    fn failed(target: &str, error: impl Display) -> Self {
        Self {
            target: target.to_string(),
            latency_ms: None,
            error: Some(error.to_string()),
            code: Some(DiagnosticCode::TunnelConnectivity),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsStatus {
    /// Host that was resolved inside the namespace.
    pub host: String,
    /// All returned addresses (A and AAAA), in resolver order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<DiagnosticCode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectivityStatus {
    pub id: String,
    /// True when at least one TCP probe succeeds. This does not verify VPN authentication or isolation.
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<FamilyStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<FamilyStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStatus>,
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
        let mut line = format!("{}\t{}", self.id, state);
        for (label, family) in [("v4", &self.ipv4), ("v6", &self.ipv6)] {
            if let Some(family) = family {
                match family.latency_ms {
                    Some(ms) => line.push_str(&format!("\t{label} {ms}ms")),
                    None => line.push_str(&format!(
                        "\t{label} failed ({})",
                        family.error.as_deref().unwrap_or("unknown")
                    )),
                }
            }
        }
        if let Some(dns) = &self.dns {
            if dns.resolved_ips.is_empty() {
                line.push_str(&format!(
                    "\tdns failed ({})",
                    dns.error.as_deref().unwrap_or("no addresses returned")
                ));
            } else {
                let latency = dns
                    .latency_ms
                    .map(|ms| format!(" {ms}ms"))
                    .unwrap_or_default();
                line.push_str(&format!("\tdns {}{}", dns.resolved_ips.join(","), latency));
            }
        }
        line
    }
}

/// What the child probe prints on stdout for the parent to parse. Families
/// that were skipped are absent; attempted families are present with either
/// timings or an error.
#[derive(Serialize, Deserialize)]
struct ProbeResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    v4: Option<ChildFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    v6: Option<ChildFamily>,
    /// Absent entirely when the DNS check was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    dns_addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_error: Option<DnsFailure>,
}

#[derive(Serialize, Deserialize)]
struct ChildFamily {
    ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,
}

/// Entry point of the hidden `__connectivity-probe` subcommand.
///
/// Executes inside the target namespace: opens one TCP connection per enabled
/// family and resolves a hostname through the namespace's own resolver,
/// printing a JSON summary of every result.
pub fn run_probe(command: ProbeCommand) -> anyhow::Result<()> {
    let mut report = ProbeResult {
        v4: None,
        v6: None,
        dns_ms: None,
        dns_addrs: Vec::new(),
        dns_error: None,
    };
    let mut any_success = false;

    if !command.skip_ipv4 {
        report.v4 = Some(probe_family(
            command.v4_host.as_deref().unwrap_or(DEFAULT_V4_HOST),
            command.port,
            command.timeout_ms,
            false,
        ));
        any_success |= report.v4.as_ref().and_then(|f| f.ms).is_some();
    }
    if !command.skip_ipv6 {
        report.v6 = Some(probe_family(
            command.v6_host.as_deref().unwrap_or(DEFAULT_V6_HOST),
            command.port,
            command.timeout_ms,
            true,
        ));
        any_success |= report.v6.as_ref().and_then(|f| f.ms).is_some();
    }

    if !command.skip_dns {
        let dns_host = command.dns_host.as_deref().unwrap_or(DEFAULT_DNS_HOST);
        let started = Instant::now();
        // Resolve through the namespace resolver (std uses /etc/netns/<name>
        // resolv.conf transparently under ip netns exec).
        match resolve_bounded(dns_host, Duration::from_millis(command.timeout_ms)) {
            Ok(ips) => {
                report.dns_addrs = ips.iter().map(ToString::to_string).collect();
                report.dns_ms = Some(started.elapsed().as_millis() as u64);
            }
            Err(error) => report.dns_error = Some(error),
        }
    }

    println!("{}", serde_json::to_string(&report)?);

    if any_success || (command.skip_ipv4 && command.skip_ipv6 && report.dns_error.is_none()) {
        Ok(())
    } else {
        Err(anyhow!("No connectivity through the namespace"))
    }
}

fn probe_family(host: &str, port: u16, timeout_ms: u64, v6: bool) -> ChildFamily {
    let started = Instant::now();
    let attempt = resolve_bounded(host, Duration::from_millis(timeout_ms))
        .map_err(anyhow::Error::from)
        .and_then(|ips| {
            ips.into_iter()
                .find(|ip| ip.is_ipv6() == v6)
                .context("No address for requested family")
        })
        .and_then(|ip| {
            TcpStream::connect_timeout(
                &SocketAddr::new(ip, port),
                Duration::from_millis(timeout_ms),
            )
            .with_context(|| format!("TCP connect to {ip}:{port} failed"))
        });
    match attempt {
        Ok(_) => ChildFamily {
            ms: Some(started.elapsed().as_millis() as u64),
            err: None,
        },
        Err(error) => ChildFamily {
            ms: None,
            err: Some(format!("{error:#}")),
        },
    }
}

/// Probe connectivity of an existing network namespace. Requires root.
#[allow(clippy::too_many_arguments)]
pub fn probe_namespace(
    id: &str,
    v4_host: &str,
    v6_host: &str,
    port: u16,
    timeout_ms: u64,
    dns_host: &str,
    skip_ipv4: bool,
    skip_ipv6: bool,
    skip_dns: bool,
) -> ConnectivityStatus {
    static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    struct Permit;
    impl Drop for Permit {
        fn drop(&mut self) {
            ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
    if ACTIVE
        .try_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |count| (count < 8).then_some(count + 1),
        )
        .is_err()
    {
        return ConnectivityStatus {
            id: id.into(),
            connected: false,
            ipv4: Some(FamilyStatus::failed(
                v4_host,
                "Concurrent connectivity probe limit reached",
            )),
            ipv6: None,
            dns: None,
        };
    }
    let _permit = Permit;
    // The namespace id reaches `ip netns exec` as argv (and would reach
    // /run/netns/<id> elsewhere); reject injection or traversal shapes.
    if let Err(error) = vopono_core::network::netns::validate_netns_name(id) {
        return ConnectivityStatus {
            id: id.to_string(),
            connected: false,
            ipv4: (!skip_ipv4).then(|| FamilyStatus::failed(&format!("{v4_host}:{port}"), error)),
            ipv6: None,
            dns: None,
        };
    }
    let outcome = probe_namespace_inner(
        id, v4_host, v6_host, port, timeout_ms, dns_host, skip_ipv4, skip_ipv6, skip_dns,
    );
    let mut status = ConnectivityStatus {
        id: id.to_string(),
        connected: false,
        ipv4: outcome
            .ipv4
            .map(|family| family.into_status(&format!("{v4_host}:{port}"))),
        ipv6: outcome
            .ipv6
            .map(|family| family.into_status(&format!("[{v6_host}]:{port}"))),
        dns: outcome.dns,
    };
    status.connected = [&status.ipv4, &status.ipv6]
        .into_iter()
        .flatten()
        .any(|family| family.latency_ms.is_some());
    status
}

/// Intermediate view combining the child report with the requested targets.
struct OutcomeView {
    ipv4: Option<FamilyOutcome>,
    ipv6: Option<FamilyOutcome>,
    dns: Option<DnsStatus>,
}

struct FamilyOutcome {
    ms: Option<u64>,
    err: Option<String>,
}

impl FamilyOutcome {
    fn into_status(self, target: &str) -> FamilyStatus {
        FamilyStatus {
            target: target.to_string(),
            latency_ms: self.ms,
            code: self
                .err
                .as_ref()
                .map(|_| DiagnosticCode::TunnelConnectivity),
            error: self.err,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_namespace_inner(
    id: &str,
    v4_host: &str,
    v6_host: &str,
    port: u16,
    timeout_ms: u64,
    dns_host: &str,
    skip_ipv4: bool,
    skip_ipv6: bool,
    skip_dns: bool,
) -> OutcomeView {
    let exe = std::env::current_exe().context("Failed to locate the vopono binary");
    let launched = exe.and_then(|exe| {
        let mut cmd = std::process::Command::new("ip");
        cmd.args(["netns", "exec", id]).arg(&exe).args([
            "__connectivity-probe",
            "--port",
            &port.to_string(),
            "--timeout-ms",
            &timeout_ms.to_string(),
        ]);
        if !skip_ipv4 {
            cmd.args(["--v4-host", v4_host]);
        } else {
            cmd.arg("--skip-ipv4");
        }
        if !skip_ipv6 {
            cmd.args(["--v6-host", v6_host]);
        } else {
            cmd.arg("--skip-ipv6");
        }
        if !skip_dns {
            cmd.args(["--dns-host", dns_host]);
        } else {
            cmd.arg("--skip-dns");
        }
        cmd.output()
            .with_context(|| format!("Failed to launch probe inside namespace '{id}'"))
    });

    let output = match launched {
        Ok(output) => output,
        Err(error) => {
            return OutcomeView {
                ipv4: (!skip_ipv4).then(|| FamilyOutcome::from_error(error)),
                ipv6: (!skip_ipv6).then(|| FamilyOutcome::from_error("probe did not run")),
                dns: (!skip_dns).then(|| DnsStatus {
                    host: dns_host.to_string(),
                    resolved_ips: Vec::new(),
                    latency_ms: None,
                    error: Some("Probe did not run".into()),
                    code: Some(DiagnosticCode::ProbeUnavailable),
                }),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Option<ProbeResult> = serde_json::from_str(stdout.trim()).ok();

    let family_outcome = |child: Option<&ChildFamily>| -> Option<FamilyOutcome> {
        child.map(|family| FamilyOutcome {
            ms: family.ms,
            err: family.err.clone(),
        })
    };

    // The parent owns the skip decision: an absent DNS section in the child
    // report means skipped, not failed.
    let dns = if skip_dns {
        None
    } else {
        parsed
            .as_ref()
            .map(|report| DnsStatus {
                host: dns_host.to_string(),
                resolved_ips: report.dns_addrs.clone(),
                latency_ms: report.dns_ms,
                error: report.dns_error.map(|error| error.to_string()).or_else(|| {
                    report
                        .dns_addrs
                        .is_empty()
                        .then(|| "DNS returned no addresses".into())
                }),
                code: report
                    .dns_addrs
                    .is_empty()
                    .then_some(DiagnosticCode::NamespaceDns),
            })
            .or_else(|| {
                Some(DnsStatus {
                    host: dns_host.into(),
                    resolved_ips: Vec::new(),
                    latency_ms: None,
                    error: Some("Probe produced no parsable output".into()),
                    code: Some(DiagnosticCode::ProbeUnavailable),
                })
            })
    };

    if parsed.is_none() {
        let error = anyhow!(
            "Probe in namespace '{id}' produced no parsable output: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return OutcomeView {
            ipv4: (!skip_ipv4).then(|| FamilyOutcome::from_error(error)),
            ipv6: (!skip_ipv6).then(|| FamilyOutcome::from_error("unavailable")),
            dns,
        };
    }

    let report = parsed.unwrap();
    OutcomeView {
        ipv4: family_outcome(report.v4.as_ref()),
        ipv6: family_outcome(report.v6.as_ref()),
        dns,
    }
}

impl FamilyOutcome {
    fn from_error(error: impl Display) -> Self {
        Self {
            ms: None,
            err: Some(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_child_report_with_both_families() {
        let raw = r#"{"v4":{"ms":12},"v6":{"ms":20},"dns_ms":3,"dns_addrs":["1.1.1.1","2606:4700:4700::1111"]}"#;
        let report: ProbeResult = serde_json::from_str(raw).unwrap();
        assert_eq!(report.v4.unwrap().ms, Some(12));
        assert_eq!(report.v6.unwrap().ms, Some(20));
        assert_eq!(report.dns_addrs.len(), 2);
    }

    #[test]
    fn parses_child_report_with_failures_and_skips() {
        let raw = r#"{"v4":{"ms":null,"err":"connect failed"},"dns_ms":null}"#;
        let report: ProbeResult = serde_json::from_str(raw).unwrap();
        assert_eq!(report.v4.unwrap().ms, None);
        assert!(report.v6.is_none(), "skipped families stay absent");
        assert!(report.dns_addrs.is_empty());
        assert!(serde_json::from_str::<ProbeResult>("garbage").is_err());
    }

    #[test]
    fn dns_failure_is_preserved_in_child_and_public_json() {
        let report: ProbeResult = serde_json::from_str(r#"{"dns_error":"timeout"}"#).unwrap();
        assert_eq!(report.dns_error, Some(DnsFailure::Timeout));
        let status = DnsStatus {
            host: "test.invalid".into(),
            resolved_ips: vec![],
            latency_ms: None,
            error: Some(report.dns_error.unwrap().to_string()),
            code: Some(DiagnosticCode::NamespaceDns),
        };
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["code"], "namespace_dns");
        assert_eq!(json["error"], "DNS resolution timed out");
        // Empty addresses are omitted on the daemon wire. A failed DNS probe
        // must deserialize as a failure report rather than an internal error.
        assert!(json.get("resolved_ips").is_none());
        let restored: DnsStatus = serde_json::from_value(json).unwrap();
        assert!(restored.resolved_ips.is_empty());
        assert_eq!(restored.code, Some(DiagnosticCode::NamespaceDns));
        assert_eq!(restored.error.as_deref(), Some("DNS resolution timed out"));
    }

    #[test]
    fn human_line_renders_dual_stack_states() {
        let status = ConnectivityStatus {
            id: "vo_a_r".to_string(),
            connected: true,
            ipv4: Some(FamilyStatus::ok("1.1.1.1:443", 42)),
            ipv6: Some(FamilyStatus::failed(
                "[2606:4700:4700::1111]:443",
                "network unreachable",
            )),
            dns: Some(DnsStatus {
                host: "one.one.one.one".to_string(),
                resolved_ips: vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()],
                latency_ms: Some(7),
                error: None,
                code: None,
            }),
        };
        assert_eq!(
            status.human_line(),
            "vo_a_r\tconnected\tv4 42ms\tv6 failed (network unreachable)\tdns 1.1.1.1,2606:4700:4700::1111 7ms"
        );

        let disconnected = ConnectivityStatus {
            id: "vo_a_r".to_string(),
            connected: false,
            ipv4: None,
            ipv6: None,
            dns: None,
        };
        assert_eq!(disconnected.human_line(), "vo_a_r\tno connectivity");
    }

    #[test]
    fn json_document_omits_absent_fields() {
        let doc = ConnectivityDocument {
            version: crate::api::SCHEMA_VERSION,
            result: ConnectivityStatus {
                id: "vo_x".to_string(),
                connected: false,
                ipv4: None,
                ipv6: None,
                dns: None,
            },
        };
        let json = serde_json::to_value(&doc).unwrap();
        assert!(json["result"].get("ipv4").is_none());
        assert!(json["result"].get("ipv6").is_none());
        assert!(json["result"].get("dns").is_none());
        assert_eq!(json["version"], crate::api::SCHEMA_VERSION);
    }
}
