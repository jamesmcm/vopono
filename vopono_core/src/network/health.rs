//! Health telemetry shared by CLI and GUI. Stale samples never count as current health.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Sidecar file holding the latest monitor result for a namespace.
pub const HEALTH_FILE: &str = "health.json";
/// The health writer uses an atomic temporary file named `health.tmp-<pid>`.
pub const HEALTH_TEMP_PREFIX: &str = "health.tmp-";
/// A monitor result older than this is reported as degraded.
pub const HEALTH_STALE_AFTER_SECONDS: u64 = 90;

/// Whether `name` is health telemetry rather than namespace session state.
pub fn is_health_sidecar(name: &str) -> bool {
    name == HEALTH_FILE
        || name.strip_prefix(HEALTH_TEMP_PREFIX).is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Connected,
    Degraded,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub state: State,
    pub checked_at: u64,
    pub last_successful_probe: Option<u64>,
    pub handshake_age_seconds: Option<u64>,
    pub reconnect_attempts: u32,
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<crate::diagnostics::Diagnostic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics_checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_pid: Option<u32>,
}

pub fn read_health(name: &str) -> Option<Health> {
    crate::network::netns::validate_netns_name(name).ok()?;
    let path: PathBuf = crate::util::vopono_dir()
        .ok()?
        .join("locks")
        .join(name)
        .join(HEALTH_FILE);
    let bytes =
        crate::util::owner_write::read_bounded_regular_file_nofollow(&path, 64 * 1024).ok()?;
    let mut health: Health = serde_json::from_slice(&bytes).ok()?;
    if now().saturating_sub(health.checked_at) > HEALTH_STALE_AFTER_SECONDS {
        health.state = State::Degraded;
        health.last_error = Some("Monitoring result is stale; daemon may have stopped".into());
    }
    Some(health)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_health_sidecars_remain_readable() {
        let health: Health = serde_json::from_str(r#"{"state":"connected","checked_at":1,"last_successful_probe":1,"handshake_age_seconds":2,"reconnect_attempts":0,"last_error":null}"#).unwrap();
        assert!(health.diagnostics.is_empty());
        assert!(health.diagnostics_checked_at.is_none());
        assert!(health.daemon_version.is_none());
        assert!(health.daemon_pid.is_none());
    }

    #[test]
    fn health_sidecar_matches_alphanumeric_temp_suffixes() {
        assert!(is_health_sidecar("health.json"));
        assert!(is_health_sidecar("health.tmp-1234"));
        assert!(is_health_sidecar("health.tmp-aB3xYz"));
        assert!(!is_health_sidecar("health.tmp-"));
        assert!(!is_health_sidecar("health.tmp-../evil"));
    }
}
