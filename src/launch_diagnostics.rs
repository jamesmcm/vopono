//! Bounded launch-failure evidence with no raw configuration/protocol replies.
use crate::args::ExecCommand;
use std::path::Path;
use std::time::{Duration, Instant};
use vopono_core::config::vpn::Protocol;
use vopono_core::diagnostics::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State};

#[derive(Debug)]
pub struct LaunchFailure {
    pub diagnostics: Vec<Diagnostic>,
    pub original: Option<anyhow::Error>,
    pub code: crate::errors::ErrorCode,
}
impl std::fmt::Display for LaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(error) = &self.original {
            writeln!(formatter, "{error:#}")?;
        }
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
    openvpn_auth: Option<&Path>,
) -> anyhow::Error {
    if error.downcast_ref::<LaunchFailure>().is_some() {
        return error;
    }
    let setup = error
        .downcast_ref::<vopono_core::diagnostics::SetupError>()
        .or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<vopono_core::diagnostics::SetupError>())
        });
    let primary = error
        .downcast_ref::<Diagnostic>()
        .or_else(|| {
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<Diagnostic>())
        })
        .cloned()
        .or_else(|| {
            setup.map(|setup| {
                Diagnostic::new(Code::ProviderConfig, State::Fail, &setup.to_string(), None)
            })
        });
    if primary.is_none() && (path.is_none() || protocol.is_none()) {
        return error;
    }
    let code = crate::errors::ErrorCode::from_anyhow(&error);
    let original = primary.is_none().then_some(error);
    let mut diagnostics: Vec<_> = primary.into_iter().collect();
    let deadline = Instant::now() + Duration::from_secs(2);
    if let (Some(path), Some(protocol)) = (path, protocol) {
        match vopono_core::diagnostics::validate_config_for_launch(path, protocol, openvpn_auth) {
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
            Err(diagnostic) => {
                // Avoid emitting a false ProviderConfig [Fail] for PIA WireGuard
                // bootstrap templates, which intentionally omit PublicKey until addKey.
                if *protocol == Protocol::Wireguard
                    && vopono_core::diagnostics::validate_pia_template(path).is_ok()
                {
                    diagnostics.push(Diagnostic::new(
                        Code::ProviderConfig,
                        State::Pass,
                        "PIA WireGuard bootstrap template passed local preflight validation",
                        None,
                    ));
                } else {
                    diagnostics.push(diagnostic);
                }
            }
        }
    } else {
        diagnostics.push(Diagnostic::new(
            Code::ProviderConfig,
            State::Skipped,
            "No selected configuration was available for local preflight",
            None,
        ));
    }
    if matches!(protocol, Some(Protocol::Wireguard | Protocol::AmneziaWG)) {
        diagnostics.extend(vopono_core::diagnostics::host::apparmor_diagnostics());
    }
    anyhow::Error::new(LaunchFailure {
        diagnostics,
        original,
        code,
    })
}

pub fn command_failure(command: &ExecCommand, error: anyhow::Error) -> anyhow::Error {
    command_failure_with_env(command, error, None)
}

pub fn command_failure_with_env(
    command: &ExecCommand,
    error: anyhow::Error,
    client_env: Option<&std::collections::HashMap<String, String>>,
) -> anyhow::Error {
    if error.downcast_ref::<LaunchFailure>().is_some() {
        return error;
    }
    let connection = crate::args_config::ArgsConfig::get_config_file(command)
        .ok()
        .and_then(|config| {
            crate::args_config::ConnectionSettings::read_with_env(command, &config, client_env).ok()
        });
    let path = connection
        .as_ref()
        .and_then(|connection| connection.custom.as_deref());
    let protocol = connection
        .as_ref()
        .and_then(|connection| connection.detected_protocol().ok());
    collect(
        error,
        path,
        protocol.as_ref(),
        command.auth_user_pass.as_deref(),
    )
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
    }

    #[test]
    fn missing_server_prefix_keeps_the_lookup_error() {
        let directory = tempfile::tempdir().unwrap();
        let error =
            vopono_core::util::get_config_from_alias(directory.path(), "india").unwrap_err();
        let error = collect(error, None, Some(&Protocol::Wireguard), None);
        let message = "Could not find config matching server prefix \"india\"";
        assert_eq!(format!("{error:#}"), message);
        let value = crate::errors::error_json_value(&error);
        assert_eq!(value["error"]["code"], "server_not_found");
        assert_eq!(value["error"]["message"], message);
    }

    #[test]
    fn untyped_failures_keep_their_cause_alongside_preflight_evidence() {
        let config = tempfile::NamedTempFile::new().unwrap();
        let error = collect(
            anyhow::anyhow!("Permission denied").context("Failed to apply WireGuard routes"),
            Some(config.path()),
            Some(&Protocol::Wireguard),
            None,
        );
        assert!(
            format!("{error:#}").starts_with("Failed to apply WireGuard routes: Permission denied")
        );
        let value = crate::errors::error_json_value(&error);
        assert_eq!(
            value["error"]["message"],
            "Failed to apply WireGuard routes"
        );
        assert_eq!(value["error"]["context"][0], "Permission denied");
        assert_eq!(value["error"]["diagnostics"][0]["code"], "provider_config");
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
            None,
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
