use crate::SOCKET_PATH;
use crate::args::ExecCommand;
use crate::exec::execute_as_daemon_with_stdio;
use anyhow::{Context, anyhow};
use interprocess::TryClone;
use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, ToFsName};
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use log::{error, info};
use nix::pty::openpty;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::isatty as nix_isatty;
use nix::unistd::{Gid, Group, Uid, User};
use nix::{
    cmsg_space,
    sys::socket::{ControlMessageOwned, MsgFlags, recvmsg},
};
use serde::{Deserialize, Serialize};
use signal_hook::{
    consts::{SIGINT, SIGQUIT, SIGTERM},
    iterator::Signals,
};
use std::io::IoSliceMut;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::os::fd::{BorrowedFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

// Do not change user's terminal modes; rely on PTY + signal/control forwarding

#[derive(Serialize, Deserialize, Debug)]
pub enum DaemonRequest {
    Execute(ExecCommand),
    Control(DaemonControl),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DaemonControl {
    Signal(i32),
}

// Note: Output is bridged via passed file descriptors; no streaming over the socket.

/// Starts the vopono daemon and listens for client connections.
pub fn start() -> anyhow::Result<()> {
    // Clean up any stale socket file from a previous unclean shutdown.
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Set up a signal handler to clean up the socket file on exit.
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGQUIT])?;
    let socket_path = SOCKET_PATH.to_string();
    std::thread::spawn(move || {
        // Block until the first signal is received, then exit.
        if let Some(signal) = signals.forever().next() {
            info!(
                "Received signal {}, cleaning up socket and exiting.",
                signal
            );
            let _ = std::fs::remove_file(&socket_path);
            std::process::exit(0);
        }
    });

    let name = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?;

    let listener = ListenerOptions::new()
        .name(name)
        .create_sync()
        .with_context(|| format!("Failed to bind to socket at {}", SOCKET_PATH))?;

    let mut perms = std::fs::metadata(SOCKET_PATH)?.permissions();
    // Set permissions to 777 to allow any user to connect to the daemon socket.
    // The daemon itself will then check the user's credentials upon connection.
    perms.set_mode(0o777);
    std::fs::set_permissions(SOCKET_PATH, perms)?;
    info!("Daemon listening on {}", SOCKET_PATH);

    for conn in listener.incoming().filter_map(handle_accept_error) {
        thread::spawn(move || {
            if let Err(e) = handle_client(conn) {
                error!("Error handling client: {}", e);
            }
        });
    }
    Ok(())
}

fn handle_accept_error(
    conn: Result<LocalSocketStream, std::io::Error>,
) -> Option<LocalSocketStream> {
    match conn {
        Ok(c) => Some(c),
        Err(e) => {
            error!("Failed to accept connection: {}", e);
            None
        }
    }
}

/// Get peer credentials from a Unix domain socket
fn get_peer_credentials(stream: &LocalSocketStream) -> anyhow::Result<(Uid, Gid)> {
    let LocalSocketStream::UdSocket(s) = stream;
    let creds =
        getsockopt(&s.as_fd(), PeerCredentials).context("Failed to get peer credentials")?;
    Ok((Uid::from_raw(creds.uid()), Gid::from_raw(creds.gid())))
}

/// Handles a single client connection.
fn handle_client(mut conn: LocalSocketStream) -> anyhow::Result<()> {
    let (uid, gid) = get_peer_credentials(&conn)?;
    let user = User::from_uid(uid)?.ok_or(anyhow!("Invalid UID"))?;
    let group = Group::from_gid(gid)?.ok_or(anyhow!("Invalid GID"))?;
    info!(
        "Accepted connection from user='{}' (uid={}), group='{}' (gid={})",
        user.name, uid, group.name, gid
    );

    // Read a framed request (length-prefixed u32 then payload)
    let mut len_bytes = [0u8; 4];
    conn.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buffer = vec![0u8; len];
    conn.read_exact(&mut buffer)?;
    let (request, _len): (DaemonRequest, usize) =
        bincode::serde::decode_from_slice(&buffer, bincode::config::standard())?;

    // Receive stdin, stdout, stderr FDs via SCM_RIGHTS
    let [client_stdin_fd, client_stdout_fd, client_stderr_fd] =
        recv_fds_over_unix_socket(&conn, 3)?;

    match request {
        DaemonRequest::Execute(mut exec_command) => {
            exec_command.user = Some(user.name);
            exec_command.group = Some(group.name);

            // Take ownership of the NetworkNamespace object (`_ns`).
            // It will now be dropped only when `handle_client` finishes,
            // which happens after the child process has exited.
            // If the client stdin is a TTY, run the child on a dedicated PTY and bridge I/O.
            // This preserves job control and avoids stealing the user's controlling TTY.
            let client_has_tty =
                nix_isatty(unsafe { BorrowedFd::borrow_raw(client_stdin_fd) }).unwrap_or(false);
            let (application, ns): (
                vopono_core::network::application_wrapper::ApplicationWrapper,
                vopono_core::network::netns::NetworkNamespace,
            );
            let mut pty_master: Option<std::os::fd::RawFd> = None;
            if client_has_tty {
                let p = openpty(None, None).map_err(|e| anyhow!("openpty failed: {e}"))?;
                let master = p.master.into_raw_fd();
                let slave = p.slave.into_raw_fd();
                // Spawn child with PTY slave as stdio, and let it take controlling TTY in pre_exec
                (application, ns) = execute_as_daemon_with_stdio(
                    exec_command,
                    false,
                    Some((slave, slave, slave)),
                    true,
                )?;
                // Do not close the slave here: it's owned by the spawned child via Stdio::from_raw_fd
                // and will be closed by the child/OS when appropriate.
                pty_master = Some(master);
            } else {
                (application, ns) = execute_as_daemon_with_stdio(
                    exec_command,
                    false,
                    Some((client_stdin_fd, client_stdout_fd, client_stderr_fd)),
                    false,
                )?;
            }

            // Keep port-forwarding alive for the lifetime of this handler
            let port_forward_keepalive = application.port_forwarding;
            // Inform the client about the forwarded port too (not only daemon logs)
            if let Some(ref fwd) = port_forward_keepalive
                && let Ok(dup_fd) =
                    nix::unistd::dup(unsafe { BorrowedFd::borrow_raw(client_stdout_fd) })
            {
                let mut out = std::fs::File::from(dup_fd);
                let _ = writeln!(out, "Port Forwarding on port {}", fwd.forwarded_port());
                let _ = out.flush();
            }

            let mut child = application.handle;

            // Keep the namespace alive while the child runs
            let _ns_guard = ns;

            // Create a per-client lock file under ~/.config/vopono/locks/<ns>/client-<pid>
            // so dropping this handler does not delete the namespace if other clients are active.
            let client_lock_path: Option<PathBuf> = (|| -> anyhow::Result<PathBuf> {
                let mut lock_dir = vopono_core::util::config_dir()?;
                lock_dir.push(format!("vopono/locks/{}", _ns_guard.name));
                std::fs::create_dir_all(&lock_dir)?;
                let path = lock_dir.join(format!("client-{}", child.id()));
                std::fs::File::create(&path)?;
                Ok(path)
            })()
            .ok();

            // If using PTY, bridge between client FDs and PTY master
            let mut exit_status: Option<std::process::ExitStatus> = None;
            if let Some(master_fd) = pty_master {
                use std::io::{Read as _, Write as _};
                // Duplicate client FDs so we don't close the originals when Files drop
                let client_stdin_dup: OwnedFd =
                    nix::unistd::dup(unsafe { BorrowedFd::borrow_raw(client_stdin_fd) })?;
                let client_stdout_dup: OwnedFd =
                    nix::unistd::dup(unsafe { BorrowedFd::borrow_raw(client_stdout_fd) })?;
                let client_stdin = std::fs::File::from(client_stdin_dup);
                let client_stdout = std::fs::File::from(client_stdout_dup);
                // We own master_fd; wrap in OwnedFd then File
                let master_owned = unsafe { OwnedFd::from_raw_fd(master_fd) };
                let pty_master_file_r = std::fs::File::from(master_owned);
                let pty_master_file_w = pty_master_file_r.try_clone()?;

                // Do not change user terminal modes; inject control bytes into PTY on signals

                // Control listener: on SIGINT/SIGTSTP/SIGQUIT inject termios cc into PTY master; others killpg
                let mut ctrl_conn = conn.try_clone()?;
                let mut pty_writer_for_ctrl = pty_master_file_w.try_clone()?;
                let child_pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
                thread::spawn(move || {
                    loop {
                        let mut len_bytes = [0u8; 4];
                        if ctrl_conn.read_exact(&mut len_bytes).is_err() {
                            break;
                        }
                        let len = u32::from_be_bytes(len_bytes) as usize;
                        let mut buf = vec![0u8; len];
                        if ctrl_conn.read_exact(&mut buf).is_err() {
                            break;
                        }
                        if let Ok((DaemonRequest::Control(ctrl), _)) =
                            bincode::serde::decode_from_slice::<DaemonRequest, _>(
                                &buf,
                                bincode::config::standard(),
                            )
                        {
                            match ctrl {
                                DaemonControl::Signal(sig) => {
                                    if let Ok(sig_enum) = nix::sys::signal::Signal::try_from(sig) {
                                        match sig_enum {
                                            nix::sys::signal::Signal::SIGINT => {
                                                let _ = pty_writer_for_ctrl.write_all(&[0x03]);
                                                let _ = pty_writer_for_ctrl.flush();
                                            }
                                            nix::sys::signal::Signal::SIGTSTP => {
                                                let _ = pty_writer_for_ctrl.write_all(&[0x1A]);
                                                let _ = pty_writer_for_ctrl.flush();
                                            }
                                            nix::sys::signal::Signal::SIGQUIT => {
                                                let _ = pty_writer_for_ctrl.write_all(&[0x1C]);
                                                let _ = pty_writer_for_ctrl.flush();
                                            }
                                            _ => {
                                                let _ =
                                                    nix::sys::signal::kill(child_pgid, sig_enum);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                let (tx_done, _rx_done) = mpsc::channel::<()>();
                // stdin copier: client stdin -> pty master
                let tx_done_stdin = tx_done.clone();
                let mut stdin_reader = client_stdin;
                let mut pty_writer = pty_master_file_w;
                let child_pgid_for_stdin = child_pgid; // Pid is Copy; used for optional SIGHUP on EOF
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = stdin_reader.read(&mut buf) {
                        if n == 0 {
                            // Client reached EOF (Ctrl-D in cooked mode or client closed input).
                            // Inject EOT into the child's TTY so interactive shells exit cleanly.
                            let _ = pty_writer.write_all(&[0x04]); // EOT
                            let _ = pty_writer.flush();
                            // Optional: also send SIGHUP to the child's process group
                            let _ = nix::sys::signal::kill(
                                child_pgid_for_stdin,
                                nix::sys::signal::Signal::SIGHUP,
                            );
                            break;
                        }
                        if pty_writer.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = tx_done_stdin.send(());
                });

                // output copier: pty master -> client stdout (stderr merges on TTY)
                let tx_done_out = tx_done.clone();
                let mut pty_reader = pty_master_file_r;
                let mut stdout_writer = client_stdout;
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = pty_reader.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if stdout_writer.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = stdout_writer.flush();
                    }
                    let _ = tx_done_out.send(());
                });

                // Wait for child to exit; do not block on copier threads
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            exit_status = Some(status);
                            break;
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                        Err(e) => {
                            log::debug!("try_wait error: {e}");
                            break;
                        }
                    }
                }
                // Close fds so copier threads unwind promptly
                // Copiers own their fds; nothing more to drop here
            }

            let status = match exit_status {
                Some(s) => s,
                None => child.wait()?,
            };
            #[derive(Serialize)]
            enum FinalResponse {
                ExitCode(i32),
            }
            // Remove per-client lock now that this client has finished
            if let Some(path) = client_lock_path {
                let _ = std::fs::remove_file(path);
            }

            // Ensure port forwarder is dropped before namespace teardown
            drop(port_forward_keepalive);

            let response = FinalResponse::ExitCode(status.code().unwrap_or(1));
            let bytes = bincode::serde::encode_to_vec(&response, bincode::config::standard())?;
            conn.write_all(&(bytes.len() as u32).to_be_bytes())?;
            conn.write_all(&bytes)?;
        }
        DaemonRequest::Control(_) => {
            // Ignore unexpected control frame sent as the first message
        }
    }
    Ok(())
}

fn recv_fds_over_unix_socket(
    conn: &LocalSocketStream,
    expected: usize,
) -> anyhow::Result<[RawFd; 3]> {
    let LocalSocketStream::UdSocket(sock) = conn;
    let fd = sock.as_fd();

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = cmsg_space!([RawFd; 3]);
    let msg = recvmsg::<()>(
        fd.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )?;

    let mut fds: Vec<RawFd> = Vec::new();
    if let Ok(iter) = msg.cmsgs() {
        for c in iter {
            if let ControlMessageOwned::ScmRights(fdlist) = c {
                for &f in fdlist.iter() {
                    fds.push(f);
                }
            }
        }
    }
    if fds.len() != expected {
        return Err(anyhow!(
            "Did not receive expected number of FDs: got {} expected {}",
            fds.len(),
            expected
        ));
    }
    Ok([fds[0], fds[1], fds[2]])
}
