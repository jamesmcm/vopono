#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]
#![allow(dead_code)]

mod api;
mod args;
mod args_config;
mod check;
mod cli_client;
mod control;
mod daemon;
mod errors;
mod exec;
mod list;
mod list_configs;
mod namespace_ownership;
mod providers;
mod server_metadata;
mod sync;

use crate::args::ExecCommand;
use anyhow::anyhow;
use clap::Parser;
use cli_client::CliClient;
use interprocess::TryClone;
use interprocess::local_socket::ToFsName;
use interprocess::local_socket::prelude::*;
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use list::{output_list, output_status};
use list_configs::print_configs;
use log::{LevelFilter, debug, info, warn};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM, SIGTSTP};
use signal_hook::iterator::Signals;
use std::io::IoSlice;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use sync::{sync_menu, synch};
use vopono_core::util::clean_dead_locks;
use vopono_core::util::clean_dead_namespaces;
use vopono_core::util::elevate_privileges;

pub const SOCKET_PATH: &str = "/run/vopono.sock";

fn main() -> anyhow::Result<()> {
    let app = args::App::parse();
    // The daemon process itself must keep logging to journald even when it is
    // launched with --silent; only forwarded client requests honour it.
    let daemon_start = matches!(
        &app.cmd,
        Some(args::Command::Daemon(d))
            if d.command.is_none() || matches!(d.command, Some(args::DaemonSubcommand::Start))
    );
    let mut builder = pretty_env_logger::formatted_timed_builder();
    builder.parse_default_env();
    if app.verbose {
        builder.filter_level(LevelFilter::Debug);
    }
    if app.silent {
        if daemon_start {
            if !app.verbose {
                builder.filter_level(LevelFilter::Info);
            }
        } else {
            if app.verbose {
                warn!("Verbose and silent flags are mutually exclusive, ignoring verbose flag");
            }
            builder.filter_level(LevelFilter::Off);
        }
    }
    builder.init();

    let uiclient = CliClient {};
    let cmd = app
        .cmd
        .expect("Subcommand is required when not in daemon mode.");

    match cmd {
        args::Command::Daemon(command) => match command.command {
            Some(args::DaemonSubcommand::Status(status)) => {
                handle_result(daemon::print_status(status.json), status.json)?;
            }
            Some(args::DaemonSubcommand::Start) | None => {
                if !nix::unistd::getuid().is_root() {
                    eprintln!("Error: The daemon command requires root privileges.");
                    std::process::exit(1);
                }
                // Mark process context so libraries can adjust behavior (e.g., logging verbosity)
                vopono_core::util::set_daemon_mode(true);
                info!("Starting vopono in daemon mode.");
                return daemon::start();
            }
        },
        args::Command::Exec(cmd) => {
            // If we're not root, try to forward the command to the running daemon.
            if !nix::unistd::getuid().is_root() {
                match forward_to_daemon(&cmd, app.silent) {
                    Ok(DaemonForward::Exit(exit_code)) => {
                        std::process::exit(exit_code);
                    }
                    Ok(DaemonForward::ExecutionError(message)) => {
                        return Err(anyhow!("Daemon execution failed: {message}"));
                    }
                    Err(e) => {
                        info!("Falling back to sudo (daemon forward failed): {e}");
                    }
                }
            }

            // If we are root, or if the daemon isn't running, execute directly.
            info!("Executing with sudo escalation path.");
            clean_dead_locks()?;
            let verbose = app.verbose && !app.silent;
            elevate_privileges(app.askpass)?;
            clean_dead_namespaces()?;
            let exit_code = exec::exec(cmd, &uiclient, verbose, app.silent)?;
            std::process::exit(exit_code);
        }
        args::Command::List(listcmd) => {
            // Restore dead-lock cleanup so list output does not resurrect
            // stale applications (and stop cannot act on recycled PIDs).
            clean_dead_locks()?;
            let json = listcmd.json;
            handle_result(output_list(listcmd), json)?;
        }
        args::Command::Status(status) => {
            handle_result(output_status(status.json), status.json)?;
        }
        args::Command::Check(check) => {
            handle_check(check, app.askpass)?;
        }
        args::Command::Probe(probe) => {
            // Hidden helper: always runs in-place (the daemon launches it
            // inside the target namespace); never forward or escalate.
            check::run_probe(probe)?;
        }
        args::Command::WriteUserFile => {
            // Hidden helper spawned by the daemon with the connecting user's
            // credentials. It performs exactly one validated write request
            // from stdin and must never run as root.
            vopono_core::util::run_owner_write_from_stdin()?;
        }
        args::Command::Providers(providerscmd) => {
            handle_result(
                providers::print_providers(providerscmd.json),
                providerscmd.json,
            )?;
        }
        args::Command::Provider(providercmd) => match providercmd.command {
            args::ProviderSubcommand::Status(status) => {
                handle_result(
                    providers::print_provider_status(status.vpn_provider.to_variant(), status.json),
                    status.json,
                )?;
            }
        },
        args::Command::Stop(stopcmd) => {
            let (json, request): (bool, StopRequest) = match stopcmd.target {
                args::StopTarget::Application(command) => {
                    (command.json, StopRequest::Application(command.id))
                }
                args::StopTarget::Namespace(command) => {
                    (command.json, StopRequest::Namespace(command.id))
                }
            };

            // Prefer the running root daemon: no sudo prompt and lifecycle
            // stays serialized through a single control plane. Fall back to
            // local execution when the daemon is unavailable.
            let mut exit_code = 0;
            if !nix::unistd::getuid().is_root() {
                match forward_stop_to_daemon(request.clone(), json) {
                    Ok(code) => exit_code = code,
                    Err(StopForwardError::Retry(error)) => {
                        info!("Falling back to sudo (daemon stop forward failed): {error}");
                        run_stop_locally(request, json, app.askpass)?;
                    }
                    Err(StopForwardError::Indeterminate(error)) => {
                        // The request reached the daemon, but its result could
                        // not be read. Retrying locally could race the daemon's
                        // teardown and stop the wrong process/namespace.
                        handle_result(Err(error), json)?;
                    }
                }
            } else {
                run_stop_locally(request, json, app.askpass)?;
            }
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        args::Command::Synch(synchcmd) => {
            let json = synchcmd.json;
            handle_result(
                match synchcmd.vpn_provider {
                    Some(vpn_provider) => synch(
                        vpn_provider.to_variant(),
                        &synchcmd.protocol.map(|x| x.to_variant()),
                        &uiclient,
                    ),
                    None => sync_menu(&uiclient, synchcmd.protocol.map(|x| x.to_variant())),
                },
                json,
            )?;
            if json {
                api::print_success_json();
            }
        }
        args::Command::Servers(serverscmd) => {
            let json = serverscmd.json;
            handle_result(print_configs(serverscmd), json)?;
        }
    }
    Ok(())
}

fn handle_result(result: anyhow::Result<()>, json: bool) -> anyhow::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&errors::error_json_value(&error))?
            );
            std::process::exit(1);
        }
        Err(error) => Err(error),
    }
}

/// Connectivity check: prefer the running root daemon (unprivileged callers
/// cannot enter a namespace themselves), fall back to sudo like `exec`.
fn handle_check(command: args::CheckCommand, askpass: bool) -> anyhow::Result<()> {
    let v4_host = command
        .v4_host
        .clone()
        .unwrap_or_else(|| check::DEFAULT_V4_HOST.to_string());
    let v6_host = command
        .v6_host
        .clone()
        .unwrap_or_else(|| check::DEFAULT_V6_HOST.to_string());
    let dns_host = command
        .dns_host
        .clone()
        .unwrap_or_else(|| check::DEFAULT_DNS_HOST.to_string());
    let local = || {
        check::probe_namespace(
            &command.id,
            &v4_host,
            &v6_host,
            command.port,
            command.timeout_ms,
            &dns_host,
            command.skip_ipv4,
            command.skip_ipv6,
            command.skip_dns,
        )
    };

    let status = if nix::unistd::getuid().is_root() {
        local()
    } else {
        match forward_check_to_daemon(&command, &v4_host, &v6_host, &dns_host) {
            Ok(status) => status,
            Err(forward_error) => {
                info!("Falling back to sudo (daemon check forward failed): {forward_error}");
                clean_dead_locks()?;
                elevate_privileges(askpass)?;
                local()
            }
        }
    };

    if command.json {
        api::print_json(&check::ConnectivityDocument {
            version: api::SCHEMA_VERSION,
            result: status,
        })?;
    } else {
        println!("{}", status.human_line());
    }
    Ok(())
}

/// Route a connectivity check through the root daemon over `/run/vopono.sock`.
/// Returns `Err` when the daemon is unreachable so the caller can fall back;
/// daemon-side failures are reported as a disconnected result.
fn forward_check_to_daemon(
    command: &args::CheckCommand,
    v4_host: &str,
    v6_host: &str,
    dns_host: &str,
) -> anyhow::Result<check::ConnectivityStatus> {
    let name = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?;
    let mut conn =
        LocalSocketStream::connect(name).map_err(|e| anyhow!("Daemon not running: {e}"))?;
    daemon::set_socket_timeouts_for(&conn, daemon::DAEMON_STOP_TIMEOUT_SECONDS)?;
    daemon::exchange_versions_with_daemon(&mut conn);

    let request = daemon::DaemonRequest::CheckNamespace(daemon::CheckNamespaceRequest {
        id: command.id.clone(),
        port: Some(command.port),
        timeout_ms: Some(command.timeout_ms),
        v4_host: Some(v4_host.to_string()),
        v6_host: Some(v6_host.to_string()),
        skip_ipv4: Some(command.skip_ipv4),
        skip_ipv6: Some(command.skip_ipv6),
        dns_host: Some(dns_host.to_string()),
        skip_dns: Some(command.skip_dns),
    });
    let bytes = wincode::serialize(&request)?;
    daemon::write_framed(&mut conn, &bytes)?;

    let response_bytes = daemon::read_framed(&mut conn, daemon::MAX_FRAME_LEN)?;
    match wincode::deserialize::<daemon::DaemonResponse>(&response_bytes)? {
        daemon::DaemonResponse::Json(payload) => Ok(serde_json::from_slice(&payload)?),
        daemon::DaemonResponse::Error(message) => Err(anyhow!("Daemon reported: {message}")),
        _ => Err(anyhow!("Unexpected daemon response to check request")),
    }
}

/// A lifecycle stop request, independent of transport (daemon RPC or local).
#[derive(Clone, Debug)]
enum StopRequest {
    Application(String),
    Namespace(String),
}

impl StopRequest {
    fn daemon_target(&self) -> daemon::DaemonStopTarget {
        match self {
            StopRequest::Application(id) => daemon::DaemonStopTarget::Application(id.clone()),
            StopRequest::Namespace(id) => daemon::DaemonStopTarget::Namespace(id.clone()),
        }
    }
}

fn run_stop_locally(request: StopRequest, json: bool, askpass: bool) -> anyhow::Result<()> {
    if !nix::unistd::getuid().is_root() {
        clean_dead_locks()?;
        elevate_privileges(askpass)?;
    } else {
        clean_dead_locks()?;
    }
    let result = match request {
        StopRequest::Application(id) => control::stop_application(&id, None),
        StopRequest::Namespace(id) => control::stop_namespace(&id, None),
    };
    match result {
        Ok(result) => control::print_result(&result, json),
        Err(error) if json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&errors::error_json_value(&error))?
            );
            std::process::exit(1);
        }
        Err(error) => Err(error),
    }
}

/// Route a stop through the root daemon over `/run/vopono.sock`.
///
/// Returns the exit code the client should use. Errors before the request is
/// written permit local fallback; errors after that point are indeterminate and
/// must be reported without retrying, since the daemon may still be tearing
/// down the requested process or namespace.
fn forward_stop_to_daemon(request: StopRequest, json: bool) -> Result<i32, StopForwardError> {
    let name = SOCKET_PATH
        .to_fs_name::<FilesystemUdSocket>()
        .map_err(|error| StopForwardError::Retry(error.into()))?;
    let mut conn = LocalSocketStream::connect(name)
        .map_err(|_| StopForwardError::Retry(anyhow!("Daemon not running")))?;
    daemon::set_socket_timeouts_for(&conn, daemon::DAEMON_STOP_TIMEOUT_SECONDS)
        .map_err(StopForwardError::Retry)?;
    daemon::exchange_versions_with_daemon(&mut conn);

    let daemon_request = daemon::DaemonRequest::Stop(daemon::DaemonStopRequest {
        target: request.daemon_target(),
        config_home: std::env::var("XDG_CONFIG_HOME").ok(),
    });
    let bytes = wincode::serialize(&daemon_request)
        .map_err(|error| StopForwardError::Retry(error.into()))?;
    daemon::write_framed(&mut conn, &bytes).map_err(StopForwardError::Indeterminate)?;

    let response_bytes = daemon::read_framed(&mut conn, daemon::MAX_FRAME_LEN)
        .map_err(StopForwardError::Indeterminate)?;
    match wincode::deserialize::<daemon::DaemonResponse>(&response_bytes)
        .map_err(|error| StopForwardError::Indeterminate(error.into()))?
    {
        daemon::DaemonResponse::Json(payload) => {
            let value: serde_json::Value = serde_json::from_slice(&payload)
                .map_err(|error| StopForwardError::Indeterminate(error.into()))?;
            if value.get("error").is_some() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value)
                            .map_err(|error| StopForwardError::Indeterminate(error.into()))?
                    );
                } else {
                    eprintln!(
                        "Error: {}",
                        value["error"]["message"]
                            .as_str()
                            .unwrap_or("unknown error")
                    );
                }
                Ok(1)
            } else {
                let result: control::StopResult = serde_json::from_value(value)
                    .map_err(|error| StopForwardError::Indeterminate(error.into()))?;
                control::print_result(&result, json).map_err(StopForwardError::Indeterminate)?;
                Ok(0)
            }
        }
        daemon::DaemonResponse::Error(message) => Err(StopForwardError::Indeterminate(anyhow!(
            "Daemon reported: {message}"
        ))),
        _ => Err(StopForwardError::Indeterminate(anyhow!(
            "Unexpected daemon response to stop request"
        ))),
    }
}

enum StopForwardError {
    Retry(anyhow::Error),
    Indeterminate(anyhow::Error),
}

enum DaemonForward {
    Exit(i32),
    ExecutionError(String),
}

fn forward_to_daemon(cmd: &ExecCommand, silent: bool) -> anyhow::Result<DaemonForward> {
    let name = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?;
    let mut conn = match LocalSocketStream::connect(name) {
        Ok(c) => c,
        Err(_) => return Err(anyhow!("Daemon not running")),
    };

    debug!("Connected to daemon, forwarding command.");
    if let Some(user) = &cmd.user {
        warn!(
            "--user '{user}' is ignored when forwarding to the daemon; \
             the application will run as the connecting user"
        );
    }
    if let Some(group) = &cmd.group {
        warn!(
            "--group '{group}' is ignored when forwarding to the daemon; \
             the application will run as the connecting group"
        );
    }
    daemon::exchange_versions_with_daemon(&mut conn);
    let mut daemon_cmd = cmd.clone();
    let client_working_dir = std::env::current_dir()?;
    resolve_custom_path_for_daemon(&mut daemon_cmd, &client_working_dir);
    // Match the sudo/CLI path, where the application inherits the client's
    // working directory when --working-directory is not given.
    if daemon_cmd.working_directory.is_none() {
        daemon_cmd.working_directory = Some(client_working_dir.to_string_lossy().into_owned());
    }
    daemon_cmd.silent = silent;

    // Forward the client's environment so daemon-launched applications match the
    // sudo/CLI path, where the child inherits the invoking user's environment.
    // The daemon only applies these to the child process (which runs as the
    // authenticated connecting user) and re-applies its own VOPONO_* variables
    // afterwards, so nothing here affects the daemon's own execution.
    let fwd_env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let request = daemon::DaemonRequest::Execute {
        // Encode `ExecCommand` as JSON bytes carried inside the wincode daemon frame.
        cmd: serde_json::to_vec(&daemon_cmd)?,
        env: fwd_env,
    };
    let bytes = wincode::serialize(&request)?;
    conn.write_all(&(bytes.len() as u32).to_be_bytes())?;
    conn.write_all(&bytes)?;

    // Send our stdio FDs to the daemon using SCM_RIGHTS
    let fds = [
        std::io::stdin().as_raw_fd(),
        std::io::stdout().as_raw_fd(),
        std::io::stderr().as_raw_fd(),
    ];
    send_fds_over_unix_socket(&conn, &fds)?;

    // Keep the user's TTY in cooked mode; rely on daemon PTY + signal forwarding.

    // Spawn a signal forwarder thread to deliver user signals to the daemon/child
    let mut sigs = Signals::new([SIGINT, SIGQUIT, SIGTERM, SIGTSTP])?;
    let mut conn_ctrl = conn.try_clone()?;
    std::thread::spawn(move || {
        for sig in &mut sigs {
            let ctrl = daemon::DaemonControl::Signal(sig);
            let req = daemon::DaemonRequest::Control(ctrl);
            if let Ok(bytes) = wincode::serialize(&req) {
                let _ = conn_ctrl.write_all(&(bytes.len() as u32).to_be_bytes());
                let _ = conn_ctrl.write_all(&bytes);
            }
        }
    });

    // Read a single final response (length-prefixed) containing the exit code
    let mut len_bytes = [0u8; 4];
    conn.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buffer = vec![0; len];
    conn.read_exact(&mut buffer)?;

    match wincode::deserialize::<daemon::DaemonResponse>(&buffer)? {
        daemon::DaemonResponse::Exit(code) => Ok(DaemonForward::Exit(code)),
        daemon::DaemonResponse::Error(message) => Ok(DaemonForward::ExecutionError(message)),
        _ => Err(anyhow!("Unexpected daemon response to exec request")),
    }
}

fn resolve_custom_path_for_daemon(cmd: &mut ExecCommand, client_working_dir: &std::path::Path) {
    for path in [&mut cmd.custom, &mut cmd.vopono_config]
        .into_iter()
        .flatten()
    {
        if path.is_relative() {
            *path = client_working_dir.join(&*path);
        }
    }
}

fn send_fds_over_unix_socket(conn: &LocalSocketStream, fds: &[RawFd]) -> anyhow::Result<()> {
    let LocalSocketStream::UdSocket(sock) = conn;
    let fd = sock.as_fd();
    // send a single dummy byte alongside the FD rights
    let buf = [0u8; 1];
    let iov = [IoSlice::new(&buf)];
    let cmsg = ControlMessage::ScmRights(fds);
    sendmsg::<()>(fd.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)
        .map(|_| ())
        .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn resolves_relative_custom_path_for_daemon() {
        let app =
            args::App::try_parse_from(["vopono", "exec", "--custom", "./foo.conf", "firefox"])
                .unwrap();
        let args::Command::Exec(mut command) = app.cmd.unwrap() else {
            panic!("expected exec command");
        };

        resolve_custom_path_for_daemon(&mut command, Path::new("/home/example"));

        assert_eq!(
            command.custom.as_deref(),
            Some(Path::new("/home/example/./foo.conf"))
        );
    }
}
