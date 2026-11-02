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
        || name
            .strip_prefix(HEALTH_TEMP_PREFIX)
            .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
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
}

pub fn read_health(name: &str) -> Option<Health> {
    crate::network::netns::validate_netns_name(name).ok()?;
    let path: PathBuf = crate::util::vopono_dir()
        .ok()?
        .join("locks")
        .join(name)
        .join(HEALTH_FILE);
    let metadata = std::fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return None;
    }
    let mut health: Health = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
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
