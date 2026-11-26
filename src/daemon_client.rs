//! Client-side preparation and authenticated transport shared by CLI and MCP.
use crate::args::ExecCommand;
use crate::daemon::{self, DaemonRequest};
use anyhow::{Context, ensure};
use interprocess::local_socket::{ToFsName, prelude::*};
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use std::os::fd::AsFd;

#[derive(Clone, Copy)]
pub(crate) enum Compatibility {
    /// Ordinary CLI requests retain the existing version-skew warnings.
    Warn,
    /// MCP must never launch through a mismatched daemon or fall back to sudo.
    Exact,
    ProfileOrMonitor,
}

#[derive(Debug)]
pub(crate) struct UnsupportedLaunch;

impl std::fmt::Display for UnsupportedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Profiles and monitoring require a compatible vopono daemon (1.1.0 or later in the 1.x series). Restart or update the daemon.")
    }
}

impl std::error::Error for UnsupportedLaunch {}

pub(crate) fn connect(policy: Compatibility) -> anyhow::Result<LocalSocketStream> {
    let mut conn =
        LocalSocketStream::connect(crate::SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?)
            .context("Daemon not running; start it separately as an administrator")?;
    let LocalSocketStream::UdSocket(socket) = &conn;
    ensure!(
        nix::sys::socket::getsockopt(&socket.as_fd(), nix::sys::socket::sockopt::PeerCredentials)?
            .uid()
            == 0,
        "Daemon socket peer is not root"
    );
    match policy {
        Compatibility::Warn => daemon::exchange_versions_with_daemon(&mut conn)?,
        Compatibility::Exact | Compatibility::ProfileOrMonitor => {
            daemon::set_socket_timeouts_for(&conn, daemon::DAEMON_HANDSHAKE_TIMEOUT_SECONDS)?;
            let version = daemon::client_handshake(&mut conn)?;
            let _ = daemon::clear_socket_timeouts(&conn);
            match policy {
                Compatibility::ProfileOrMonitor => {
                    if !crate::daemon::version_at_least(&version, (1, 1, 0)) {
                        return Err(UnsupportedLaunch.into());
                    }
                }
                _ => ensure!(
                    version == env!("CARGO_PKG_VERSION"),
                    "MCP requires a matching daemon version; restart or update the daemon"
                ),
            }
        }
    }
    Ok(conn)
}

pub(crate) fn prepare_execute(command: ExecCommand, silent: bool) -> anyhow::Result<DaemonRequest> {
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    prepare_execute_with_env(command, silent, env)
}

pub(crate) fn prepare_execute_with_env(
    mut command: ExecCommand,
    silent: bool,
    mut env: std::collections::HashMap<String, String>,
) -> anyhow::Result<DaemonRequest> {
    let working_dir = std::env::current_dir()?;
    crate::resolve_custom_path_for_daemon(&mut command, &working_dir, &env);
    if command.working_directory.is_none() {
        command.working_directory = Some(working_dir.to_string_lossy().into_owned());
    }
    command.silent = silent;
    // Expansion belongs to the invoking user's environment, never root's.
    if !command.literal_application && !command.application.is_empty() {
        let home = env.get("HOME").cloned();
        command.application = shellexpand::full_with_context(
            &command.application,
            || home.clone(),
            |var| -> Result<Option<String>, std::env::VarError> { Ok(env.get(var).cloned()) },
        )
        .map_err(|_| anyhow::anyhow!("Shell expansion failed for the application command"))?
        .into_owned();
        command.literal_application = true;
    }
    if !env.contains_key("PULSE_SERVER")
        && let Ok(server) = vopono_core::util::pulseaudio::get_pulseaudio_server()
    {
        env.insert("PULSE_SERVER".into(), server);
    }
    Ok(DaemonRequest::Execute {
        cmd: serde_json::to_vec(&command)?,
        env,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn preparation_resolves_paths_and_preserves_literal_argv() {
        let app = crate::args::App::try_parse_from([
            "vopono",
            "exec",
            "--custom",
            "vpn.conf",
            "--working-directory",
            "work",
            "printf '$HOME'",
        ])
        .unwrap();
        let crate::args::Command::Exec(mut command) = app.cmd.unwrap() else {
            unreachable!()
        };
        command.literal_application = true;
        let DaemonRequest::Execute { cmd, env } = prepare_execute(command, true).unwrap() else {
            unreachable!()
        };
        let command: ExecCommand = serde_json::from_slice(&cmd).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(command.custom, Some(cwd.join("vpn.conf")));
        assert_eq!(
            command.working_directory.as_deref(),
            cwd.join("work").to_str()
        );
        assert_eq!(command.application, "printf '$HOME'");
        assert!(command.literal_application && command.silent);
        assert_eq!(env.get("HOME"), std::env::var("HOME").ok().as_ref());
    }

    #[test]
    fn preparation_with_filtered_env_never_expands_unlisted_host_vars() {
        let app = crate::args::App::try_parse_from([
            "vopono",
            "exec",
            "--custom",
            "/$PATH/vpn.conf",
            "--postup",
            "echo $PATH",
            "true",
        ])
        .unwrap();
        let crate::args::Command::Exec(command) = app.cmd.unwrap() else {
            unreachable!()
        };
        // Empty env does not include host PATH, so it must never expand from std::env.
        let DaemonRequest::Execute { cmd, .. } =
            prepare_execute_with_env(command, false, std::collections::HashMap::new()).unwrap()
        else {
            unreachable!()
        };
        let command: ExecCommand = serde_json::from_slice(&cmd).unwrap();
        assert_eq!(
            command.custom.as_deref(),
            Some(std::path::Path::new("/$PATH/vpn.conf"))
        );
        assert_eq!(command.postup.as_deref(), Some("echo $PATH"));
    }
}
