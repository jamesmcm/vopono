use crate::gui_config::{ApplicationProfile, CustomVpnConfig, LaunchConfig};
use anyhow::{Context, anyhow};
use std::path::PathBuf;
use std::process::Command;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;

pub fn launch_custom_config(
    config: &CustomVpnConfig,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<String> {
    let vopono = find_vopono_binary()?;
    let mut command = Command::new(&vopono);
    command.arg("exec").arg("--custom").arg(&config.path);
    add_launch_args(&mut command, launch);

    if let Some(working_directory) = &app.working_directory {
        command
            .arg("--working-directory")
            .arg(working_directory.as_os_str());
    }

    command.arg(application_command(app));
    command
        .spawn()
        .with_context(|| format!("Failed to launch {}", app.name))?;

    Ok(format!(
        "Started {} through {} using {}",
        app.name,
        vopono.display(),
        config.path.display()
    ))
}

pub fn launch_provider_config(
    provider: VpnProvider,
    protocol: Protocol,
    server: &str,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<String> {
    // TODO: Do not shell out - but this is okay for now (since vopono also still shells out)
    let vopono = find_vopono_binary()?;
    let mut command = Command::new(&vopono);
    command
        .arg("exec")
        .arg("--provider")
        .arg(provider.to_string())
        .arg("--protocol")
        .arg(protocol.to_string())
        .arg("--server")
        .arg(server);
    add_launch_args(&mut command, launch);

    if let Some(working_directory) = &app.working_directory {
        command
            .arg("--working-directory")
            .arg(working_directory.as_os_str());
    }

    command.arg(application_command(app));
    command
        .spawn()
        .with_context(|| format!("Failed to launch {}", app.name))?;

    Ok(format!(
        "Started {} through {} {} {}",
        app.name, provider, protocol, server
    ))
}

fn add_launch_args(command: &mut Command, launch: &LaunchConfig) {
    if launch.port_forwarding {
        command.arg("--port-forwarding");
    }
    if !launch.open_ports.is_empty() {
        command.arg("--open-ports").arg(
            launch
                .open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
}

pub fn sync_provider(provider: VpnProvider, protocol: Option<Protocol>) -> anyhow::Result<String> {
    let vopono = find_vopono_binary()?;
    let mut command = Command::new(&vopono);
    command.arg("sync").arg(provider.to_string());
    if let Some(protocol) = protocol {
        command.arg("--protocol").arg(protocol.to_string());
    }
    command
        .spawn()
        .with_context(|| format!("Failed to start sync for {provider}"))?;

    Ok(format!(
        "Started sync for {provider} through {}",
        vopono.display()
    ))
}

fn find_vopono_binary() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("VOPONO_BIN") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = which::which("vopono") {
        return Ok(path);
    }

    let dev_path = std::env::current_dir()?.join("target/debug/vopono");
    if dev_path.exists() {
        return Ok(dev_path);
    }

    Err(anyhow!(
        "Could not find vopono binary. Set VOPONO_BIN or install vopono on PATH."
    ))
}

fn application_command(app: &ApplicationProfile) -> String {
    let mut words = Vec::with_capacity(1 + app.args.len());
    words.push(app.command.as_str());
    words.extend(app.args.iter().map(String::as_str));
    shell_words::join(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_command_serializes_args_as_one_positional_string() {
        let app = ApplicationProfile {
            name: "Firefox".to_string(),
            command: "firefox".to_string(),
            args: vec![
                "--private-window".to_string(),
                "https://example.com/a b".to_string(),
            ],
            working_directory: None,
            usage_count: 0,
        };

        let command = application_command(&app);
        assert_eq!(
            shell_words::split(&command).expect("command should parse"),
            vec!["firefox", "--private-window", "https://example.com/a b"]
        );
    }
}
