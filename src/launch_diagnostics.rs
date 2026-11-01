//! Bounded launch-failure evidence with no raw configuration/protocol replies.
use crate::args::ExecCommand;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vopono_core::config::vpn::Protocol;
use vopono_core::diagnostics::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State};

#[derive(Debug)]
pub struct LaunchFailure {
    pub diagnostics: Vec<Diagnostic>,
}
impl std::fmt::Display for LaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                writeln!(formatter)?;
            }
            write!(
                formatter,
                "{:?} [{:?}]: {}",
                diagnostic.code, diagnostic.state, diagnostic.message
            )?;
            if let Some(action) = &diagnostic.action {
                write!(formatter, ". {action}")?;
            }
        }
        Ok(())
    }
}
impl std::error::Error for LaunchFailure {}

pub fn collect(
    error: anyhow::Error,
    path: Option<&Path>,
    protocol: Option<&Protocol>,
) -> anyhow::Error {
    if error.downcast_ref::<LaunchFailure>().is_some() {
        return error;
    }
    let primary = error.downcast_ref::<Diagnostic>().cloned().unwrap_or_else(|| Diagnostic::new(
        if matches!(protocol, Some(Protocol::Wireguard | Protocol::AmneziaWG)) { Code::TunnelHandshake } else { Code::ProviderConfig },
        State::Fail, "VPN setup failed; authentication and protection have not been established",
        Some("Inspect the diagnostic evidence below; use vopono doctor for additional checks")));
    let mut diagnostics = vec![primary];
    let deadline = Instant::now() + Duration::from_secs(2);
    if let (Some(path), Some(protocol)) = (path, protocol) {
        match vopono_core::diagnostics::validate_config(path, protocol) {
            Ok(endpoints) => {
                diagnostics.push(Diagnostic::new(
                    Code::ProviderConfig,
                    State::Pass,
                    "Local configuration and referenced inputs passed preflight validation",
                    None,
                ));
                if vopono_core::util::is_daemon_mode() {
                    // The daemon runs as root on the host network. Do not let a
                    // user-supplied endpoint turn launch diagnostics into a
                    // privileged probe of localhost or internal services.
                    diagnostics.push(Diagnostic::new(
                        Code::EndpointTransport,
                        State::Skipped,
                        "Endpoint transport probes are not run from the privileged daemon",
                        Some("Run vopono doctor as your user for endpoint DNS/transport checks"),
                    ));
                } else {
                    for endpoint in endpoints.iter().take(2) {
                        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                            break;
                        };
                        diagnostics.extend(vopono_core::diagnostics::endpoint_diagnostics(
                            endpoint,
                            left.min(Duration::from_millis(500)),
                        ));
                    }
                }
            }
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    } else {
        diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            State::Skipped,
            "No selected configuration was available for local preflight",
            None,
        ));
    }
    anyhow::Error::new(LaunchFailure { diagnostics })
}

pub fn command_failure(command: &ExecCommand, error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<LaunchFailure>().is_some() {
        return error;
    }
    let settings = crate::args_config::ArgsConfig::get_config_file(command).ok();
    let path = command
        .custom
        .clone()
        .or_else(|| settings.as_ref()?.get::<PathBuf>("custom").ok());
    let protocol = command
        .protocol
        .as_ref()
        .map(|p| p.to_variant())
        .or_else(|| settings.as_ref()?.get::<Protocol>("protocol").ok())
        .or_else(|| {
            path.as_ref()
                .and_then(|p| vopono_core::util::get_config_file_protocol(p).ok())
        });
    collect(error, path.as_deref(), protocol.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_typed_failures_and_local_evidence_without_retaining_secrets() {
        let config = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            config.path(),
            "[Interface]\nPrivateKey = NEVER_SHARE_THIS\n",
        )
        .unwrap();
        let diagnostic = Diagnostic::new(
            Code::TunnelAuthentication,
            State::Fail,
            "OpenVPN authentication rejected",
            None,
        );
        let error = collect(
            anyhow::anyhow!("AUTH_FAILED token=NEVER_SHARE_THIS").context(diagnostic),
            Some(config.path()),
            Some(&Protocol::Wireguard),
        );
        let report = error.downcast_ref::<LaunchFailure>().unwrap();
        assert_eq!(report.diagnostics[0].code, Code::TunnelAuthentication);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.code == Code::ProviderConfig && d.state == State::Fail)
        );
        assert!(!format!("{error:#}").contains("NEVER_SHARE_THIS"));
        assert!(
            !crate::errors::error_json_value(&error)
                .to_string()
                .contains("NEVER_SHARE_THIS")
        );
        assert!(error.chain().nth(1).is_none());
    }
}
