use crate::gui_config::{
    ApplicationProfile, CustomVpnConfig, LaunchConfig, ensure_port_forwarding_callback,
};
use anyhow::{Context, anyhow};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;

pub struct LaunchResult {
    pub message: String,
    pub command_line: String,
    pub child: Child,
}

pub fn launch_custom_config(
    config: &CustomVpnConfig,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<LaunchResult> {
    let vopono = find_vopono_binary()?;
    let mut command = Command::new(&vopono);
    command.arg("exec").arg("--custom").arg(&config.path);
    add_launch_args(&mut command, launch)?;

    if let Some(working_directory) = &app.working_directory {
        command
            .arg("--working-directory")
            .arg(working_directory.as_os_str());
    }

    command.arg(application_command(app));
    let command_line = display_command(&command);
    prepare_background_command(&mut command, true);
    let child = command
        .spawn()
        .with_context(|| format!("Failed to launch {}", app.name))?;

    Ok(LaunchResult {
        message: format!(
            "Started {} through {} using {}",
            app.name,
            vopono.display(),
            config.path.display()
        ),
        command_line,
        child,
    })
}

pub fn launch_provider_config(
    provider: VpnProvider,
    protocol: Protocol,
    server: &str,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<LaunchResult> {
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
    add_launch_args(&mut command, launch)?;

    if let Some(working_directory) = &app.working_directory {
        command
            .arg("--working-directory")
            .arg(working_directory.as_os_str());
    }

    command.arg(application_command(app));
    let command_line = display_command(&command);
    prepare_background_command(&mut command, true);
    let child = command
        .spawn()
        .with_context(|| format!("Failed to launch {}", app.name))?;

    Ok(LaunchResult {
        message: format!(
            "Started {} through {} {} {}",
            app.name, provider, protocol, server
        ),
        command_line,
        child,
    })
}

fn add_launch_args(command: &mut Command, launch: &LaunchConfig) -> anyhow::Result<()> {
    if launch.port_forwarding {
        command.arg("--port-forwarding");
        command
            .arg("--port-forwarding-callback")
            .arg(ensure_port_forwarding_callback()?);
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
    Ok(())
}

pub fn sync_provider(provider: VpnProvider, protocol: Option<Protocol>) -> anyhow::Result<String> {
    let vopono = find_vopono_binary()?;
    let mut command = Command::new(&vopono);
    command.arg("sync").arg(provider.to_string());
    if let Some(protocol) = protocol {
        command.arg("--protocol").arg(protocol.to_string());
    }
    prepare_background_command(&mut command, false);
    command
        .spawn()
        .with_context(|| format!("Failed to start sync for {provider}"))?;

    Ok(format!(
        "Started sync for {provider} through {}",
        vopono.display()
    ))
}

fn prepare_background_command(command: &mut Command, pipe_output: bool) {
    command.stdin(Stdio::null());
    if pipe_output {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
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
    let command_words =
        shell_words::split(&app.command).unwrap_or_else(|_| vec![app.command.clone()]);
    let app_words = command_words
        .iter()
        .cloned()
        .chain(app.args.iter().cloned())
        .collect::<Vec<_>>();
    let env_vars = effective_env_vars(app, &app_words);
    let mut words = Vec::with_capacity(2 + env_vars.len() + command_words.len() + app.args.len());
    if !env_vars.is_empty() {
        words.push("env".to_string());
        words.extend(
            env_vars
                .iter()
                .filter(|env_var| !env_var.key.trim().is_empty())
                .map(|env_var| format!("{}={}", env_var.key.trim(), env_var.value)),
        );
    }
    words.extend(command_words);
    words.extend(app.args.iter().cloned());
    shell_words::join(words.iter().map(String::as_str))
}

fn effective_env_vars(
    app: &ApplicationProfile,
    app_words: &[String],
) -> Vec<crate::gui_config::ApplicationEnvVar> {
    let mut env_vars = app.env_vars.clone();
    if crate::desktop::uses_flatpak_run(app_words) {
        env_vars = crate::desktop::sudo_env_reset_vars()
            .into_iter()
            .chain(env_vars)
            .fold(Vec::new(), |mut merged, env_var| {
                if let Some(existing) = merged.iter_mut().find(|item| item.key == env_var.key) {
                    existing.value = env_var.value;
                } else {
                    merged.push(env_var);
                }
                merged
            });
    }
    env_vars
}

fn display_command(command: &Command) -> String {
    let mut words = Vec::with_capacity(1 + command.get_args().count());
    words.push(command.get_program().to_string_lossy().into_owned());
    words.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );
    shell_words::join(words.iter().map(String::as_str))
}

pub fn pipe_child_output(log_id: u64, child: &mut Child, sender: Sender<(u64, String)>) {
    if let Some(stdout) = child.stdout.take() {
        let sender = sender.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = sender.send((log_id, line));
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = sender.send((log_id, line));
            }
        });
    }
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
            env_vars: Vec::new(),
            working_directory: None,
            usage_count: 0,
        };

        let command = application_command(&app);
        assert_eq!(
            shell_words::split(&command).expect("command should parse"),
            vec!["firefox", "--private-window", "https://example.com/a b"]
        );
    }

    #[test]
    fn application_command_prefixes_env_vars() {
        let app = ApplicationProfile {
            name: "Flatpak".to_string(),
            command: "flatpak run org.example.App".to_string(),
            args: Vec::new(),
            env_vars: vec![crate::gui_config::ApplicationEnvVar {
                key: "SUDO_USER".to_string(),
                value: String::new(),
            }],
            working_directory: None,
            usage_count: 0,
        };

        let command = application_command(&app);
        assert_eq!(
            shell_words::split(&command).expect("command should parse"),
            vec![
                "env",
                "SUDO_COMMAND=",
                "SUDO_USER=",
                "SUDO_UID=",
                "SUDO_GID=",
                "SUDO_HOME=",
                "SUDO_TTY=",
                "flatpak",
                "run",
                "org.example.App"
            ]
        );
    }

    #[test]
    fn application_command_resets_sudo_env_for_flatpak_args() {
        let app = ApplicationProfile {
            name: "Flatpak".to_string(),
            command: "flatpak".to_string(),
            args: vec!["run".to_string(), "org.example.App".to_string()],
            env_vars: Vec::new(),
            working_directory: None,
            usage_count: 0,
        };

        let command = application_command(&app);
        assert_eq!(
            shell_words::split(&command).expect("command should parse"),
            vec![
                "env",
                "SUDO_COMMAND=",
                "SUDO_USER=",
                "SUDO_UID=",
                "SUDO_GID=",
                "SUDO_HOME=",
                "SUDO_TTY=",
                "flatpak",
                "run",
                "org.example.App"
            ]
        );
    }
}
