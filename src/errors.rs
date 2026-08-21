use anyhow::Error;
use serde::Serialize;
use thiserror::Error as ThisError;

// TODO: Do we need the renames here? Are they for JSON mode?
/// Stable machine-readable error identifiers used by JSON command output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ErrorCode {
    #[serde(rename = "vopono_daemon_unavailable")]
    DaemonUnavailable,
    #[serde(rename = "provider_not_configured")]
    ProviderNotConfigured,
    #[serde(rename = "credentials_required")]
    CredentialsRequired,
    #[serde(rename = "protocol_not_supported")]
    ProtocolNotSupported,
    #[serde(rename = "server_not_found")]
    ServerNotFound,
    #[serde(rename = "dependency_missing")]
    DependencyMissing,
    #[serde(rename = "permission_denied")]
    PermissionDenied,
    #[serde(rename = "invalid_application_id")]
    InvalidApplicationId,
    #[serde(rename = "application_not_found")]
    ApplicationNotFound,
    #[serde(rename = "namespace_not_found")]
    NamespaceNotFound,
    #[serde(rename = "application_launch_failed")]
    ApplicationLaunchFailed,
    #[serde(rename = "vpn_connection_failed")]
    VpnConnectionFailed,
    #[serde(rename = "process_control_failed")]
    ProcessControlFailed,
    #[serde(rename = "namespace_teardown_failed")]
    NamespaceTeardownFailed,
    #[serde(rename = "internal_error")]
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
            Self::ApplicationNotFound { .. } => ErrorCode::ApplicationNotFound,
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
    pub fn from_anyhow(error: &Error) -> Self {
        if let Some(code) = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<CliError>().map(CliError::code))
        {
            return code;
        }

        // TODO: Implement the typed errors everywhere else and make the entire crate use typed
        // errors and remove the string matching here
        // The core crate predates the JSON frontend and intentionally exposes
        // anyhow errors. Keep this fallback narrow until those APIs can grow
        // their own typed error enums without a larger public-API change.
        let message = error.to_string().to_ascii_lowercase();
        if message.contains("daemon") && message.contains("not running") {
            Self::DaemonUnavailable
        } else if message.contains("missing configuration") || message.contains("not configured") {
            Self::ProviderNotConfigured
        } else if message.contains("credentials") || message.contains("api key") {
            Self::CredentialsRequired
        } else if message.contains("does not support") || message.contains("unsupported") {
            Self::ProtocolNotSupported
        } else if message.contains("could not find config") {
            Self::ServerNotFound
        } else if message.contains("not installed") {
            Self::DependencyMissing
        } else if message.contains("permission") {
            Self::PermissionDenied
        } else if message.contains("launch") {
            Self::ApplicationLaunchFailed
        } else if message.contains("vpn")
            || message.contains("openvpn")
            || message.contains("wireguard")
        {
            Self::VpnConnectionFailed
        } else {
            Self::InternalError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CliError, ErrorCode};

    #[test]
    fn typed_control_errors_produce_stable_codes() {
        let error = anyhow::Error::new(CliError::NamespaceNotFound {
            id: "missing".to_string(),
        });
        assert_eq!(ErrorCode::from_anyhow(&error), ErrorCode::NamespaceNotFound);
        assert_eq!(
            serde_json::to_string(&ErrorCode::NamespaceNotFound).unwrap(),
            r#""namespace_not_found""#
        );
    }
}
