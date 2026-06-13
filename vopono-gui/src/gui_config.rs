use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GuiConfig {
    #[serde(default)]
    pub custom_vpn_configs: Vec<CustomVpnConfig>,
    #[serde(default)]
    pub vpn_config_usage: Vec<VpnConfigUsage>,
    #[serde(default)]
    pub applications: Vec<ApplicationProfile>,
    #[serde(default)]
    pub launch: LaunchConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaunchConfig {
    #[serde(default = "default_gamepad_enabled")]
    pub gamepad_enabled: bool,
    #[serde(default)]
    pub port_forwarding: bool,
    #[serde(default)]
    pub open_ports: Vec<u16>,
}

impl Default for LaunchConfig {
    fn default() -> Self {
        Self {
            gamepad_enabled: true,
            port_forwarding: false,
            open_ports: Vec::new(),
        }
    }
}

fn default_gamepad_enabled() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustomVpnConfig {
    pub name: String,
    pub path: PathBuf,
    pub protocol: String,
    #[serde(default)]
    pub usage_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnConfigUsage {
    pub key: String,
    #[serde(default)]
    pub usage_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplicationProfile {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env_vars: Vec<ApplicationEnvVar>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub usage_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplicationEnvVar {
    pub key: String,
    pub value: String,
}

impl ApplicationProfile {
    pub fn command_line(&self) -> String {
        std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn env_line(&self) -> String {
        self.env_vars
            .iter()
            .map(|env_var| format!("{}={}", env_var.key, env_var.value))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn gui_config_path() -> anyhow::Result<PathBuf> {
    Ok(vopono_core::util::vopono_dir()?.join("gui.toml"))
}

pub fn vopono_config_path() -> anyhow::Result<PathBuf> {
    Ok(vopono_core::util::vopono_dir()?.join("config.toml"))
}

pub fn load_gui_config(path: &Path) -> anyhow::Result<GuiConfig> {
    if !path.exists() {
        return Ok(GuiConfig::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read GUI config from {}", path.display()))?;
    toml_edit::de::from_str(&raw)
        .with_context(|| format!("Failed to parse GUI config from {}", path.display()))
}

pub fn save_gui_config(path: &Path, config: &GuiConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let raw = toml_edit::ser::to_string_pretty(config)?;
    fs::write(path, raw)
        .with_context(|| format!("Failed to write GUI config to {}", path.display()))?;
    Ok(())
}

pub fn load_vopono_config_text(path: &Path) -> anyhow::Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(path)
        .with_context(|| format!("Failed to read vopono config from {}", path.display()))
}

pub fn save_vopono_config_text(path: &Path, text: &str) -> anyhow::Result<()> {
    let _: toml_edit::DocumentMut = text.parse().context("Config is not valid TOML")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    fs::write(path, text)
        .with_context(|| format!("Failed to write vopono config to {}", path.display()))?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderForwardedPort {
    pub port: u16,
    pub updated_at: SystemTime,
}

impl ProviderForwardedPort {
    pub fn age(&self) -> Option<Duration> {
        SystemTime::now().duration_since(self.updated_at).ok()
    }
}

pub fn ensure_port_forwarding_callback() -> anyhow::Result<PathBuf> {
    let callback_path = port_forwarding_callback_path()?;
    let status_path = forwarded_port_status_path()?;
    if let Some(parent) = callback_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    let status_path_text = status_path.to_string_lossy();
    let status_path = shell_words::quote(status_path_text.as_ref());
    let script = format!(
        r#"#!/bin/sh
set -eu
case "${{1:-}}" in
    ''|*[!0-9]*) exit 0 ;;
esac
status_file={status_path}
tmp="${{status_file}}.$$"
{{
    printf 'timestamp=%s\n' "$(date +%s)"
    printf 'port=%s\n' "$1"
}} > "$tmp"
mv "$tmp" "$status_file"
"#
    );
    fs::write(&callback_path, script)
        .with_context(|| format!("Failed to write {}", callback_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&callback_path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to make {} executable", callback_path.display()))?;
    }

    Ok(callback_path)
}

pub fn read_provider_forwarded_port() -> anyhow::Result<Option<ProviderForwardedPort>> {
    let path = forwarded_port_status_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to read provider forwarded port from {}",
            path.display()
        )
    })?;
    provider_forwarded_port_from_status(&raw).with_context(|| {
        format!(
            "Failed to parse provider forwarded port from {}",
            path.display()
        )
    })
}

fn port_forwarding_callback_path() -> anyhow::Result<PathBuf> {
    Ok(vopono_core::util::vopono_dir()?.join("gui-port-forwarding-callback"))
}

fn forwarded_port_status_path() -> anyhow::Result<PathBuf> {
    Ok(vopono_core::util::vopono_dir()?.join("gui-forwarded-port"))
}

fn provider_forwarded_port_from_status(raw: &str) -> anyhow::Result<Option<ProviderForwardedPort>> {
    let mut timestamp = None;
    let mut port = None;

    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "timestamp" => timestamp = Some(value.trim().parse::<u64>()?),
            "port" => port = Some(value.trim().parse::<u16>()?),
            _ => {}
        }
    }

    let Some(port) = port else {
        return Ok(None);
    };
    let updated_at = timestamp
        .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap_or(UNIX_EPOCH);
    Ok(Some(ProviderForwardedPort { port, updated_at }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_port_status_parses_callback_output() {
        let status = provider_forwarded_port_from_status("timestamp=123\nport=51413\n")
            .expect("status should parse")
            .expect("status should contain a port");

        assert_eq!(status.port, 51413);
        assert_eq!(status.updated_at, UNIX_EPOCH + Duration::from_secs(123));
    }

    #[test]
    fn forwarded_port_status_ignores_empty_files() {
        assert!(provider_forwarded_port_from_status("").unwrap().is_none());
    }
}
