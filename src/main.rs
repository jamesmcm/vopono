#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]
#![allow(dead_code)]

mod args;
mod args_config;
mod cli_client;
mod daemon;
mod exec;
mod list;
mod list_configs;
mod sync;

use crate::args::ExecCommand;
use anyhow::anyhow;
use clap::Parser;
use cli_client::CliClient;
use interprocess::TryClone;
use interprocess::local_socket::ToFsName;
use interprocess::local_socket::prelude::*;
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use list::output_list;
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
    let mut builder = pretty_env_logger::formatted_timed_builder();
    builder.parse_default_env();
    if app.verbose {
        builder.filter_level(LevelFilter::Debug);
    }
    if app.silent {
        if app.verbose {
            warn!("Verbose and silent flags are mutually exclusive, ignoring verbose flag");
        }
        builder.filter_level(LevelFilter::Off);
    }
    builder.init();

    let uiclient = CliClient {};
    let cmd = app
        .cmd
        .expect("Subcommand is required when not in daemon mode.");

    match cmd {
        args::Command::Daemon => {
            if !nix::unistd::getuid().is_root() {
                eprintln!("Error: The daemon command requires root privileges.");
                std::process::exit(1);
            }
            info!("Starting vopono in daemon mode.");
            return daemon::start();
        }
        args::Command::Exec(cmd) => {
            // If we're not root, try to forward the command to the running daemon.
            if !nix::unistd::getuid().is_root() {
                match forward_to_daemon(&cmd) {
                    Ok(exit_code) => {
                        std::process::exit(exit_code);
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
            clean_dead_locks()?;
            output_list(listcmd)?;
        }
        args::Command::Synch(synchcmd) => {
            if synchcmd.vpn_provider.is_none() {
                sync_menu(&uiclient, synchcmd.protocol.map(|x| x.to_variant()))?;
            } else {
                synch(
                    synchcmd.vpn_provider.unwrap().to_variant(),
                    &synchcmd.protocol.map(|x| x.to_variant()),
                    &uiclient,
                )?;
            }
        }
        args::Command::Servers(serverscmd) => {
            print_configs(serverscmd)?;
        }
    }
    Ok(())
}

fn forward_to_daemon(cmd: &ExecCommand) -> anyhow::Result<i32> {
    let name = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?;
    let mut conn = match LocalSocketStream::connect(name) {
        Ok(c) => c,
        Err(_) => return Err(anyhow!("Daemon not running")),
    };

    debug!("Connected to daemon, forwarding command.");
    let request = daemon::DaemonRequest::Execute(cmd.clone());
    let bytes = bincode::serde::encode_to_vec(&request, bincode::config::standard())?;
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
            if let Ok(bytes) = bincode::serde::encode_to_vec(&req, bincode::config::standard()) {
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

    #[derive(serde::Deserialize)]
    enum FinalResponse {
        ExitCode(i32),
    }
    let (response, _): (FinalResponse, usize) =
        bincode::serde::decode_from_slice(&buffer, bincode::config::standard())?;
    match response {
        FinalResponse::ExitCode(code) => Ok(code),
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
