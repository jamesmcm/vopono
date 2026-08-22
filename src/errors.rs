use anyhow::Error;
use serde::Serialize;
use thiserror::Error as ThisError;

/// Stable machine-readable error identifiers used by JSON command output.
///
/// The snake_case serialization **is** the wire contract for frontends; do not
/// rename variants without bumping [`crate::api::SCHEMA_VERSION`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    DaemonUnavailable,
    ProviderNotConfigured,
    CredentialsRequired,
    ProtocolNotSupported,
    ServerNotFound,
    DependencyMissing,
    PermissionDenied,
    InvalidApplicationId,
    ApplicationNotFound,
    NamespaceNotFound,
    ApplicationLaunchFailed,
    VpnConnectionFailed,
    ProcessControlFailed,
    NamespaceTeardownFailed,
    InternalError,
}

/// Errors originating in frontend/control operations.  Most of the older
/// execution code still returns `anyhow::Error`; `ErrorCode::from_anyhow`
/// keeps a small compatibility classifier for those legacy errors while new
/// frontend operations use this typed error directly.
#[derive(Debug, ThisError)]
pub enum CliError {
    #[error("Application id must be a numeric PID: {id}")]
    InvalidApplicationId { id: String },
    #[error("No running application with id {id}")]
    ApplicationNotFound { id: String },
    #[error("Process {pid} is not attached to network namespace {namespace_id}")]
    ProcessNotInNamespace { pid: u32, namespace_id: String },
    #[error("No running namespace with id {id}")]
    NamespaceNotFound { id: String },
    #[error("No synchronized server configuration was found for {provider}")]
    ServerNotFound { provider: String },
    #[error("{provider} does not support {protocol}")]
    ProtocolNotSupported { provider: String, protocol: String },
    #[error("Failed to signal process {pid}: {source}")]
    ProcessSignal {
        pid: u32,
        #[source]
        source: Error,
    },
    #[error("Process {pid} did not stop after termination was requested")]
    ProcessStillRunning { pid: u32 },
    #[error("Processes are still running in namespace {namespace_id}: {pids:?}")]
    NamespaceProcessesStillRunning {
        namespace_id: String,
        pids: Vec<i32>,
    },
    #[error("Network namespace {namespace_id} was not removed after teardown")]
    NamespaceTeardownFailed { namespace_id: String },
}

impl CliError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidApplicationId { .. } => ErrorCode::InvalidApplicationId,
            Self::ApplicationNotFound { .. } | Self::ProcessNotInNamespace { .. } => {
                ErrorCode::ApplicationNotFound
            }
            Self::NamespaceNotFound { .. } => ErrorCode::NamespaceNotFound,
            Self::ServerNotFound { .. } => ErrorCode::ServerNotFound,
            Self::ProtocolNotSupported { .. } => ErrorCode::ProtocolNotSupported,
            Self::ProcessSignal { .. } | Self::ProcessStillRunning { .. } => {
                ErrorCode::ProcessControlFailed
            }
            Self::NamespaceProcessesStillRunning { .. } | Self::NamespaceTeardownFailed { .. } => {
                ErrorCode::NamespaceTeardownFailed
            }
        }
    }
}

impl ErrorCode {
    /// Classify a legacy `anyhow` error into a stable code.
    ///
    /// Typed [`CliError`]s are matched first; everything else falls through to
    /// a deliberately narrow phrase-matching shim over human-readable messages
    /// from `vopono_core`. Every anchor below is pinned by the tests in this
    /// module - if you reword one of these messages in `vopono_core`, update
    /// both sides together. Follow-up: introduce typed errors in `vopono_core`
    /// at these boundaries and delete the string matching entirely.
    pub fn from_anyhow(error: &Error) -> Self {
        if let Some(code) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<CliError>().map(CliError::code))
        {
            return code;
        }

        let message = error.to_string().to_ascii_lowercase();
        // e.g. main.rs forward failure: "Daemon not running"
        if message.contains("daemon") && message.contains("not running") {
            Self::DaemonUnavailable
        // e.g. provider dirs: "Missing configuration ... run vopono sync"
        } else if message.contains("missing configuration") || message.contains("not configured") {
            Self::ProviderNotConfigured
        // e.g. AirVPN require_api_key, AzireVPN access tokens
        } else if message.contains("api key")
            || message.contains("api_key")
            || message.contains("credentials")
        {
            Self::CredentialsRequired
        // e.g. get_dyn_wireguard_provider: "... supports only the Warp protocol"
        } else if message.contains("does not support") {
            Self::ProtocolNotSupported
        // e.g. util::get_config_file: "Could not find config ..."
        } else if message.contains("could not find config") {
            Self::ServerNotFound
        // e.g. dependency checks: "... is not installed"
        } else if message.contains("is not installed") {
            Self::DependencyMissing
        // e.g. sudo/config permission failures: "Permission denied"
        } else if message.contains("permission denied") {
            Self::PermissionDenied
        } else if message.contains("failed to launch") {
            Self::ApplicationLaunchFailed
        // VPN protocol failures only when tied to connection wording; avoids
        // matching any message that merely mentions "vpn".
        } else if (message.contains("openvpn")
            || message.contains("wireguard")
            || message.contains("vpn"))
            && (message.contains("connection") || message.contains("connect"))
        {
            Self::VpnConnectionFailed
        } else {
            Self::InternalError
        }
    }
}

/// Build the versioned JSON error document used when a command fails in JSON
/// mode.
///
/// The top-level message plus any additional context chain entries are kept so
/// frontends do not lose `anyhow` context.
pub fn error_json_value(error: &Error) -> serde_json::Value {
    let context: Vec<String> = error
        .chain()
        .skip(1)
        .map(|cause| cause.to_string())
        .take(5)
        .collect();
    serde_json::json!({
        "version": crate::api::SCHEMA_VERSION,
        "error": {
            "code": ErrorCode::from_anyhow(error),
            "message": error.to_string(),
            "context": context,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{CliError, ErrorCode, error_json_value};

    #[test]
    fn typed_control_errors_produce_stable_codes() {
        let error = anyhow::Error::new(CliError::NamespaceNotFound {
            id: "missing".to_string(),
        });
        assert_eq!(ErrorCode::from_anyhow(&error), ErrorCode::NamespaceNotFound);
    }

    #[test]
    fn ownership_violations_report_as_missing_applications() {
        let error = anyhow::Error::new(CliError::ProcessNotInNamespace {
            pid: 4242,
            namespace_id: "vo_m_se".to_string(),
        });
        assert_eq!(
            ErrorCode::from_anyhow(&error),
            ErrorCode::ApplicationNotFound
        );
    }

    // The snake_case names are the frontend wire contract; pin them.
    #[test]
    fn error_codes_serialize_to_stable_snake_case_names() {
        for (code, expected) in [
            (ErrorCode::DaemonUnavailable, "daemon_unavailable"),
            (ErrorCode::ProviderNotConfigured, "provider_not_configured"),
            (ErrorCode::CredentialsRequired, "credentials_required"),
            (ErrorCode::ProtocolNotSupported, "protocol_not_supported"),
            (ErrorCode::ServerNotFound, "server_not_found"),
            (ErrorCode::DependencyMissing, "dependency_missing"),
            (ErrorCode::PermissionDenied, "permission_denied"),
            (ErrorCode::InvalidApplicationId, "invalid_application_id"),
            (ErrorCode::ApplicationNotFound, "application_not_found"),
            (ErrorCode::NamespaceNotFound, "namespace_not_found"),
            (
                ErrorCode::ApplicationLaunchFailed,
                "application_launch_failed",
            ),
            (ErrorCode::VpnConnectionFailed, "vpn_connection_failed"),
            (ErrorCode::ProcessControlFailed, "process_control_failed"),
            (
                ErrorCode::NamespaceTeardownFailed,
                "namespace_teardown_failed",
            ),
            (ErrorCode::InternalError, "internal_error"),
        ] {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    // Phrase anchors for the legacy anyhow classifier. If a vopono_core
    // message changes, update it here and in `from_anyhow`.
    #[test]
    fn legacy_messages_are_classified_by_pinned_phrases() {
        let cases = [
            ("Daemon not running", ErrorCode::DaemonUnavailable),
            (
                "Missing configuration files for Mullvad",
                ErrorCode::ProviderNotConfigured,
            ),
            (
                "AIRVPN_API_KEY is not defined",
                ErrorCode::CredentialsRequired,
            ),
            (
                "Mullvad does not support OpenVPN as of January 2026",
                ErrorCode::ProtocolNotSupported,
            ),
            (
                "Could not find config for se-got-wg-001",
                ErrorCode::ServerNotFound,
            ),
            ("wg is not installed", ErrorCode::DependencyMissing),
            ("sudo: Permission denied", ErrorCode::PermissionDenied),
            (
                "Failed to launch firefox",
                ErrorCode::ApplicationLaunchFailed,
            ),
            ("OpenVPN connection failed", ErrorCode::VpnConnectionFailed),
            (
                "Wireguard handshake did not connect",
                ErrorCode::VpnConnectionFailed,
            ),
        ];
        for (message, expected) in cases {
            let error = anyhow::anyhow!("{message}");
            assert_eq!(
                ErrorCode::from_anyhow(&error),
                expected,
                "message: {message}"
            );
        }
    }

    #[test]
    fn unanchored_messages_fall_back_to_internal_error() {
        // Previously matched the overly-broad "unsupported"/"launch"/"vpn"
        // tokens; these must no longer produce misleading codes.
        for message in ["Unsupported flag", "launchpad.net unreachable", "no vpn"] {
            let error = anyhow::anyhow!("{message}");
            assert_eq!(ErrorCode::from_anyhow(&error), ErrorCode::InternalError);
        }
    }

    #[test]
    fn error_documents_keep_chain_context_and_version() {
        let error = anyhow::Error::new(CliError::NamespaceNotFound {
            id: "missing".to_string(),
        })
        .context("while stopping namespace");
        let value = error_json_value(&error);
        assert_eq!(value["version"], crate::api::SCHEMA_VERSION);
        assert_eq!(value["error"]["code"], "namespace_not_found");
        assert_eq!(value["error"]["message"], "while stopping namespace");
        let context = value["error"]["context"].as_array().unwrap();
        assert!(
            context
                .iter()
                .any(|entry| entry.as_str().unwrap().contains("No running namespace"))
        );
    }
}
