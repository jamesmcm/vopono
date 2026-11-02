//! Bounded launch-failure evidence with no raw configuration/protocol replies.
use crate::args::ExecCommand;
use std::path::Path;
use std::time::{Duration, Instant};
use vopono_core::config::vpn::Protocol;
use vopono_core::diagnostics::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State};

#[derive(Debug)]
pub struct LaunchFailure {
    pub diagnostics: Vec<Diagnostic>,
    pub code: crate::errors::ErrorCode,
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
    let setup = error.downcast_ref::<vopono_core::diagnostics::SetupError>();
    let typed = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::errors::CliError>());
    let code = setup
        .map(crate::errors::ErrorCode::from_setup)
        .or_else(|| typed.map(crate::errors::CliError::code))
        .unwrap_or(crate::errors::ErrorCode::VpnConnectionFailed);
    let primary = error.downcast_ref::<Diagnostic>().cloned().unwrap_or_else(|| {
        // Only typed local failures can supply their explanation. Preserve a
        // typed CLI category without copying its potentially tainted context.
        let message = setup.map(ToString::to_string).unwrap_or_else(|| match code {
            crate::errors::ErrorCode::ProtocolNotSupported => "Provider does not support the selected protocol".into(),
            crate::errors::ErrorCode::ServerNotFound => "No synchronized configuration matches the selected server".into(),
            crate::errors::ErrorCode::NamespaceNotFound => "The requested namespace does not exist".into(),
            _ => "VPN setup failed; authentication and protection have not been established".into(),
        });
        Diagnostic::new(
            if setup.is_none() && typed.is_none() && matches!(protocol, Some(Protocol::Wireguard | Protocol::AmneziaWG)) {
                Code::TunnelHandshake
            } else { Code::ProviderConfig },
            State::Fail, &message,
            Some("Inspect the diagnostic evidence below; use vopono doctor for additional checks"),
        )
    });
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
    anyhow::Error::new(LaunchFailure { diagnostics, code })
}

pub fn command_failure(command: &ExecCommand, error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<LaunchFailure>().is_some() {
        return error;
    }
    let connection = crate::args_config::ArgsConfig::get_config_file(command)
        .ok()
        .and_then(|config| crate::args_config::ConnectionSettings::read(command, &config).ok());
    let path = connection
        .as_ref()
        .and_then(|connection| connection.custom.as_deref());
    let protocol = connection
        .as_ref()
        .and_then(|connection| connection.detected_protocol().ok());
    collect(error, path, protocol.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn safe_setup_failures_keep_their_codes_and_drop_untrusted_context() {
        use crate::errors::ErrorCode;
        use vopono_core::config::providers::VpnProvider;
        use vopono_core::diagnostics::SetupError;

        for (failure, expected, message) in [
            (
                SetupError::ProtocolNotSupported {
                    provider: VpnProvider::Mullvad,
                    protocol: Protocol::OpenVpn,
                },
                ErrorCode::ProtocolNotSupported,
                "Mullvad does not support OpenVpn",
            ),
            (
                SetupError::DependencyMissing("wg"),
                ErrorCode::DependencyMissing,
                "wg is not installed",
            ),
            (
                SetupError::ProviderNotConfigured {
                    provider: VpnProvider::Mullvad,
                    protocol: Protocol::Wireguard,
                },
                ErrorCode::ProviderNotConfigured,
                "vopono sync mullvad",
            ),
            (
                SetupError::Configuration("An application or --profile is required"),
                ErrorCode::InternalError,
                "An application or --profile is required",
            ),
        ] {
            let error = collect(
                anyhow::anyhow!("private context NEVER_SHARE").context(failure),
                None,
                None,
            );
            assert_eq!(ErrorCode::from_anyhow(&error), expected);
            assert!(error.to_string().contains(message));
            assert!(!format!("{error:#}").contains("NEVER_SHARE"));
            assert!(
                !crate::errors::error_json_value(&error)
                    .to_string()
                    .contains("NEVER_SHARE")
            );
        }
        let error = collect(
            anyhow::anyhow!("AUTH_FAILED token=NEVER_SHARE"),
            None,
            Some(&Protocol::OpenVpn),
        );
        assert!(
            !crate::errors::error_json_value(&error)
                .to_string()
                .contains("NEVER_SHARE")
        );
    }

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
