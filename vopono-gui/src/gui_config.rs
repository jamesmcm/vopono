use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GuiConfig {
    #[serde(default)]
    pub custom_vpn_configs: Vec<CustomVpnConfig>,
    #[serde(default)]
    pub applications: Vec<ApplicationProfile>,
    #[serde(default)]
    pub launch: LaunchConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaunchConfig {
    #[serde(default = "default_gamepad_enabled")]
    pub gamepad_enabled: bool,
    // TODO: When using provider port forwarding, we need to get and display the port being
    // forwarded by the provider in the GUI
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
pub struct ApplicationProfile {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub usage_count: u64,
}

impl ApplicationProfile {
    pub fn command_line(&self) -> String {
        std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
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
