use crate::SOCKET_PATH;
use crate::args::ExecCommand;
use crate::exec::execute_as_daemon_with_stdio;
use anyhow::{Context, anyhow};
use interprocess::TryClone;
use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, ToFsName};
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use log::{error, info, warn};
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
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::fd::{BorrowedFd, IntoRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

// Do not change user's terminal modes; rely on PTY + signal/control forwarding

/// Machine-readable health snapshot of the privileged daemon.
///
/// `version` is the daemon's *reported* version (not this binary's); when the
/// daemon cannot answer the handshake it stays `None` and `compatible` is
/// `false`.
#[derive(Clone, Debug, Serialize)]
pub struct DaemonStatus {
    pub available: bool,
    pub pid: Option<u32>,
    pub socket: String,
    pub version: Option<String>,
    pub compatible: bool,
}

impl DaemonStatus {
    /// Single human-readable rendering shared by `daemon status` and the
    /// aggregate `status` output.
    pub fn human_line(&self) -> String {
        format!(
            "daemon\t{}\tpid={}\tsocket={}\tversion={}\tcompatible={}",
            if self.available {
                "available"
            } else {
                "unavailable"
            },
            self.pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.socket,
            self.version.as_deref().unwrap_or("-"),
            self.compatible,
        )
    }
}

/// Return a machine-readable health snapshot without requiring systemd.
pub fn status() -> DaemonStatus {
    let mut snapshot = DaemonStatus {
        available: false,
        pid: None,
        socket: SOCKET_PATH.to_string(),
        version: None,
        compatible: false,
    };

    if !Path::new(SOCKET_PATH).exists() {
        return snapshot;
    }

    let Ok(name) = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>() else {
        return snapshot;
    };
    let Ok(mut stream) = LocalSocketStream::connect(name) else {
        return snapshot;
    };
    let LocalSocketStream::UdSocket(socket) = &stream;
    if set_socket_timeouts(&stream).is_err() {
        return snapshot;
    }
    snapshot.available = true;
    snapshot.pid = getsockopt(&socket.as_fd(), PeerCredentials)
        .ok()
        .map(|credentials| credentials.pid() as u32);

    // Handshake so `compatible` compares the daemon's real version against
    // this client instead of unconditionally reporting success.
    if let Some(version) = query_daemon_version(&mut stream) {
        snapshot.compatible = versions_compatible(&version, env!("CARGO_PKG_VERSION"));
        snapshot.version = Some(version);
    }
    // A daemon that does not answer the handshake predates it: leave
    // version unset and compatible=false while still reporting availability.
    snapshot
}

/// Compatible means an identical major version (breaking-change proxy).
fn versions_compatible(daemon_version: &str, client_version: &str) -> bool {
    fn major(version: &str) -> Option<u64> {
        let core = version.split(['-', '+']).next()?;
        let mut components = core.split('.');
        let major = components.next()?.parse().ok()?;
        components.next()?.parse::<u64>().ok()?;
        components.next()?.parse::<u64>().ok()?;
        components.next().is_none().then_some(major)
    }

    major(daemon_version)
        .zip(major(client_version))
        .is_some_and(|(daemon_major, client_major)| daemon_major == client_major)
}

/// Outcome of comparing a peer's version against ours.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum VersionSkew {
    /// Identical version strings.
    Match,
    /// Same major, different minor/patch: feature skew only.
    MinorMismatch,
    /// Different major (or unparsable): protocol incompatibility is likely.
    MajorMismatch,
}

fn classify_version_skew(peer: &str, own: &str) -> VersionSkew {
    if peer == own {
        VersionSkew::Match
    } else if versions_compatible(peer, own) && versions_compatible(own, peer) {
        VersionSkew::MinorMismatch
    } else {
        VersionSkew::MajorMismatch
    }
}

/// Daemon side: warn when a client's version differs from this daemon's.
fn warn_on_client_version_mismatch(client_version: &str) {
    let own = env!("CARGO_PKG_VERSION");
    match classify_version_skew(client_version, own) {
        VersionSkew::Match => {}
        VersionSkew::MinorMismatch => warn!(
            "Client vopono version {client_version} differs from daemon version {own}; consider restarting the daemon ('sudo systemctl restart vopono') to match."
        ),
        VersionSkew::MajorMismatch => error!(
            "Client vopono version {client_version} is incompatible with daemon version {own}; requests may fail unexpectedly. Update vopono and restart the daemon."
        ),
    }
}

/// Client side: announce our version and warn when the daemon's differs.
///
/// Best-effort and time-bounded: a wedged daemon must not hang the client,
/// and a daemon too old to understand `ClientVersion` simply drops the
/// connection so the caller falls back to sudo; the local warning below
/// still fires whenever the daemon's reported version can be read.
pub(crate) fn exchange_versions_with_daemon(conn: &mut LocalSocketStream) {
    let own = env!("CARGO_PKG_VERSION");
    if set_socket_timeouts_for(conn, DAEMON_HANDSHAKE_TIMEOUT_SECONDS).is_err() {
        return;
    }
    let sent = wincode::serialize(&DaemonRequest::ClientVersion(own.to_string()))
        .ok()
        .and_then(|bytes| write_framed(conn, &bytes).ok());
    // The daemon answers the handshake with its own version directly.
    let daemon_version = sent.and_then(|_| {
        read_framed(conn, MAX_FRAME_LEN)
            .ok()
            .and_then(|response| wincode::deserialize::<DaemonResponse>(&response).ok())
            .and_then(|parsed| match parsed {
                DaemonResponse::Version(version) => Some(version),
                _ => None,
            })
    });
    // Restore blocking mode for the long-lived session that follows.
    let _ = clear_socket_timeouts(conn);
    let Some(daemon_version) = daemon_version else {
        return;
    };
    match classify_version_skew(&daemon_version, own) {
        VersionSkew::Match => {}
        VersionSkew::MinorMismatch => log::warn!(
            "Daemon vopono version {daemon_version} differs from client version {own}; restart the daemon ('sudo systemctl restart vopono') to align them."
        ),
        VersionSkew::MajorMismatch => log::error!(
            "Daemon vopono version {daemon_version} is incompatible with client version {own}; update vopono and restart the daemon."
        ),
    }
}

/// Clear send/receive timeouts (value 0 = block indefinitely).
pub(crate) fn clear_socket_timeouts(stream: &LocalSocketStream) -> anyhow::Result<()> {
    use nix::sys::socket::sockopt::{ReceiveTimeout, SendTimeout};
    use nix::sys::time::TimeValLike;
    let zero = nix::sys::time::TimeVal::seconds(0);
    let LocalSocketStream::UdSocket(socket) = stream;
    nix::sys::socket::setsockopt(&socket.as_fd(), ReceiveTimeout, &zero)
        .context("Failed to clear daemon receive timeout")?;
    nix::sys::socket::setsockopt(&socket.as_fd(), SendTimeout, &zero)
        .context("Failed to clear daemon send timeout")?;
    Ok(())
}

pub(crate) const DAEMON_HANDSHAKE_TIMEOUT_SECONDS: i64 = 2;
pub(crate) const DAEMON_STOP_TIMEOUT_SECONDS: i64 = 30;

pub(crate) fn set_socket_timeouts(stream: &LocalSocketStream) -> anyhow::Result<()> {
    // Bound the handshake so a wedged daemon cannot hang status/list polling.
    set_socket_timeouts_for(stream, DAEMON_HANDSHAKE_TIMEOUT_SECONDS)
}

/// Lifecycle operations (stop) may legitimately outlast the handshake bound:
/// teardown can terminate processes and retry namespace deletion for several
/// seconds before responding.
pub(crate) fn set_socket_timeouts_for(
    stream: &LocalSocketStream,
    seconds: i64,
) -> anyhow::Result<()> {
    use nix::sys::socket::sockopt::{ReceiveTimeout, SendTimeout};
    use nix::sys::time::TimeValLike;
    let timeout = nix::sys::time::TimeVal::seconds(seconds);
    let LocalSocketStream::UdSocket(socket) = stream;
    nix::sys::socket::setsockopt(&socket.as_fd(), ReceiveTimeout, &timeout)
        .context("Failed to set daemon receive timeout")?;
    nix::sys::socket::setsockopt(&socket.as_fd(), SendTimeout, &timeout)
        .context("Failed to set daemon send timeout")?;
    Ok(())
}

fn query_daemon_version(stream: &mut LocalSocketStream) -> Option<String> {
    let request = wincode::serialize(&DaemonRequest::Version).ok()?;
    write_framed(stream, &request).ok()?;
    let response = read_framed(stream, MAX_FRAME_LEN).ok()?;
    let parsed = wincode::deserialize::<DaemonResponse>(&response).ok()?;
    match parsed {
        DaemonResponse::Version(version) => Some(version),
        _ => None,
    }
}

pub(crate) const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

pub(crate) fn write_framed(stream: &mut LocalSocketStream, payload: &[u8]) -> anyhow::Result<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    Ok(())
}

pub(crate) fn read_framed(
    stream: &mut LocalSocketStream,
    max_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    anyhow::ensure!(len <= max_len, "Daemon frame too large: {len}");
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn read_request(stream: &mut LocalSocketStream) -> anyhow::Result<DaemonRequest> {
    Ok(wincode::deserialize(&read_framed(stream, MAX_FRAME_LEN)?)?)
}

fn write_response(stream: &mut LocalSocketStream, response: &DaemonResponse) -> anyhow::Result<()> {
    write_framed(stream, &wincode::serialize(response)?)
}

pub fn print_status(json: bool) -> anyhow::Result<()> {
    let status = status();
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("{}", status.human_line());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug)]
pub enum DaemonRequest {
    Execute {
        // JSON-serialized `ExecCommand`. Keeping this as raw bytes lets the outer IPC
        // frame use wincode without deriving Schema* across the entire CLI type graph.
        cmd: Vec<u8>,
        env: std::collections::HashMap<String, String>,
    },
    Control(DaemonControl),
    /// Ask the daemon for its own version (handshake for `compatible`).
    Version,
    /// Lifecycle control executed with the daemon's root privileges.
    Stop(DaemonStopRequest),
    /// Probe connectivity of an existing network namespace (requires root).
    CheckNamespace(CheckNamespaceRequest),
    /// First frame sent by every client: its own crate version, so the
    /// daemon can warn about client/daemon version skew. Must stay the
    /// LAST variant - older clients never send it, and appended variants
    /// preserve the wire indices of all earlier ones.
    ClientVersion(String),
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug, Clone)]
pub enum DaemonControl {
    Signal(i32),
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug, Clone)]
pub enum DaemonStopTarget {
    Application(String),
    Namespace(String),
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug)]
pub struct DaemonStopRequest {
    pub target: DaemonStopTarget,
    /// Client's XDG_CONFIG_HOME so the daemon reads the caller's lockfiles
    /// rather than root's.
    pub config_home: Option<String>,
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug, Clone)]
pub struct CheckNamespaceRequest {
    pub id: String,
    pub port: Option<u16>,
    pub timeout_ms: Option<u64>,
    /// IPv4 target for the tunnel reachability check.
    pub v4_host: Option<String>,
    /// IPv6 target for the tunnel reachability check.
    pub v6_host: Option<String>,
    pub skip_ipv4: Option<bool>,
    pub skip_ipv6: Option<bool>,
    /// Hostname resolved via the namespace's own DNS configuration.
    pub dns_host: Option<String>,
    pub skip_dns: Option<bool>,
}

#[derive(Serialize, Deserialize, wincode::SchemaWrite, wincode::SchemaRead, Debug)]
pub enum DaemonResponse {
    Exit(i32),
    Error(String),
    Version(String),
    /// Serialized JSON document (e.g. a stop result or error document).
    Json(Vec<u8>),
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
            let mut error_conn = conn.try_clone().ok();
            if let Err(e) = handle_client(conn) {
                error!("Error handling client: {}", e);
                if let Some(conn) = error_conn.as_mut() {
                    let response = DaemonResponse::Error(format!("{e:#}"));
                    if let Ok(bytes) = wincode::serialize(&response) {
                        let _ = conn.write_all(&(bytes.len() as u32).to_be_bytes());
                        let _ = conn.write_all(&bytes);
                    }
                }
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

    // Read a framed request (length-prefixed u32 then payload). Newer
    // clients announce their version first so skew can be flagged here.
    let mut request = read_request(&mut conn)?;
    if let DaemonRequest::ClientVersion(client_version) = &request {
        // Handshake: flag skew on our side, tell the client ours, then read
        // the actual request frame.
        warn_on_client_version_mismatch(client_version);
        let response = DaemonResponse::Version(env!("CARGO_PKG_VERSION").to_string());
        let _ = write_response(&mut conn, &response);
        request = read_request(&mut conn)?;
    }

    // Only execute/stop requests access the client's config tree. Version
    // and connectivity requests must not create or require ~/.config.
    if matches!(
        &request,
        DaemonRequest::Execute { .. } | DaemonRequest::Stop(_)
    ) {
        // Writes use a dropped-privilege subprocess so the kernel, rather
        // than a post-hoc chown, enforces ownership.
        vopono_core::util::set_helper_exe_override(std::env::current_exe().ok());
        vopono_core::util::set_config_owner_override(Some((uid, gid)));
        let provided_config_home = request_client_config_home(&request);
        let config_base = adopt_client_config_base(provided_config_home, &user, uid)
            .context("No usable config directory for client")?;
        vopono_core::util::set_config_dir_override(Some(config_base));
    }

    match request {
        DaemonRequest::Execute {
            cmd,
            env: forwarded_env,
        } => {
            // Receive stdin, stdout, stderr FDs via SCM_RIGHTS (exec only)
            let [client_stdin_fd, client_stdout_fd, client_stderr_fd] =
                recv_fds_over_unix_socket(&conn, 3)?;

            // Decode the command payload from the JSON bytes carried by `DaemonRequest::Execute`.
            let mut exec_command: ExecCommand = serde_json::from_slice(&cmd)?;
            exec_command.user = Some(user.name);
            exec_command.group = Some(group.name);
            let requested_application = exec_command.application.clone();

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
                    Some(forwarded_env.clone()),
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
                    Some(forwarded_env.clone()),
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

            // Create a per-client RON lock file under ~/.config/vopono/locks/<ns>/client-<pid>
            // so status readers can report daemon-launched applications and Drop can see
            // other active clients before tearing down the namespace.
            let client_lock_path: Option<PathBuf> =
                match _ns_guard.write_client_lockfile(child.id(), &requested_application) {
                    Ok(path) => path,
                    Err(error) => {
                        log::warn!("Failed to write daemon client status lockfile: {error}");
                        None
                    }
                };

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
                        if let Ok(DaemonRequest::Control(ctrl)) =
                            wincode::deserialize::<DaemonRequest>(&buf)
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

                // stdin copier: client stdin -> pty master
                let mut stdin_reader = client_stdin;
                let mut pty_writer = pty_master_file_w;
                let child_pgid_for_stdin = child_pgid; // Pid is Copy; used for optional SIGHUP on EOF
                let child_done = Arc::new(AtomicBool::new(false));
                let child_done_for_stdin = Arc::clone(&child_done);
                let stdin_copier = thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while !child_done_for_stdin.load(Ordering::Acquire) {
                        if !fd_readable(stdin_reader.as_raw_fd(), 50) {
                            continue;
                        }
                        let Ok(n) = stdin_reader.read(&mut buf) else {
                            break;
                        };
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
                });

                // output copier: pty master -> client stdout (stderr merges on TTY)
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
                });

                // Wait for child to exit.
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
                // Stop and join the terminal reader before replying to the client. Leaving this
                // thread alive would let it steal terminal-query responses from the caller's
                // shell after the command has completed.
                child_done.store(true, Ordering::Release);
                let _ = stdin_copier.join();
            }

            let status = match exit_status {
                Some(s) => s,
                None => child.wait()?,
            };
            // Remove per-client lock now that this client has finished
            if let Some(path) = client_lock_path {
                let _ = std::fs::remove_file(path);
            }

            // Ensure port forwarder is dropped before namespace teardown
            drop(port_forward_keepalive);

            let response_code = status.code().unwrap_or(1);
            write_response(&mut conn, &DaemonResponse::Exit(response_code))?;
        }
        DaemonRequest::Version => {
            write_response(
                &mut conn,
                &DaemonResponse::Version(env!("CARGO_PKG_VERSION").to_string()),
            )?;
        }
        DaemonRequest::Stop(stop_request) => {
            // The config base was already adopted and validated for this
            // connection; lockfile operations hit the same state the client
            // sees. Run the privileged control op.
            let outcome = match stop_request.target {
                DaemonStopTarget::Application(id) => {
                    crate::control::stop_application(&id, Some(uid))
                }
                DaemonStopTarget::Namespace(id) => crate::control::stop_namespace(&id, Some(uid)),
            };
            let payload = match outcome {
                Ok(result) => serde_json::to_vec(&result)?,
                Err(error) => serde_json::to_vec(&crate::errors::error_json_value(&error))?,
            };
            write_response(&mut conn, &DaemonResponse::Json(payload))?;
        }
        DaemonRequest::CheckNamespace(request) => {
            // The probe needs root to enter the namespace, so it can only run
            // here (or in the sudo fallback path of the CLI).
            let status = crate::check::probe_namespace(
                &request.id,
                request
                    .v4_host
                    .as_deref()
                    .unwrap_or(crate::check::DEFAULT_V4_HOST),
                request
                    .v6_host
                    .as_deref()
                    .unwrap_or(crate::check::DEFAULT_V6_HOST),
                request.port.unwrap_or(crate::check::DEFAULT_CHECK_PORT),
                request
                    .timeout_ms
                    .unwrap_or(crate::check::DEFAULT_TIMEOUT_MS),
                request
                    .dns_host
                    .as_deref()
                    .unwrap_or(crate::check::DEFAULT_DNS_HOST),
                request.skip_ipv4.unwrap_or(false),
                request.skip_ipv6.unwrap_or(false),
                request.skip_dns.unwrap_or(false),
            );
            let payload = serde_json::to_vec(&status)?;
            write_response(&mut conn, &DaemonResponse::Json(payload))?;
        }
        DaemonRequest::Control(_) => {
            // Ignore unexpected control frame sent as the first message
        }
        DaemonRequest::ClientVersion(_) => {
            // Handshake-only frame; a bare one carries no request payload.
        }
    }
    // Clear any thread-local override before exiting the handler
    vopono_core::util::set_config_dir_override(None);
    vopono_core::util::set_config_owner_override(None);
    vopono_core::util::set_helper_exe_override(None);
    Ok(())
}

/// Extract the client-supplied config-home candidate from the request.
///
/// Both relevant request types carry one: the Execute environment
/// (`XDG_CONFIG_HOME`) and the Stop request (`config_home`). The value is
/// only a candidate - [`adopt_client_config_base`] validates it against the
/// authenticated peer before it is used.
fn request_client_config_home(request: &DaemonRequest) -> Option<String> {
    match request {
        DaemonRequest::Execute { env, .. } => env.get("XDG_CONFIG_HOME").cloned(),
        DaemonRequest::Stop(stop_request) => stop_request.config_home.clone(),
        _ => None,
    }
}

/// Adopt the base directory for this client's vopono config tree.
///
/// The client-supplied candidate (from the Execute environment or the Stop
/// request) is only honoured when it canonically resolves to a directory
/// owned by the authenticated peer - symlinks into root- or foreign-owned
/// locations are rejected. Otherwise the peer's passwd home `.config` is
/// used, creating it via the dropped-privilege helper if needed. Fails
/// closed when neither candidate works so the daemon never writes lockfiles
/// on behalf of one user into a directory another principal controls.
fn adopt_client_config_base(
    provided: Option<String>,
    user: &User,
    uid: Uid,
) -> anyhow::Result<PathBuf> {
    let home_candidate = user.dir.join(".config");
    let provided_candidate = provided.map(PathBuf::from);
    let candidates = [provided_candidate.as_ref(), Some(&home_candidate)];

    for candidate in candidates.into_iter().flatten() {
        match vopono_core::util::validated_user_owned_dir(candidate, uid) {
            Ok(dir) => return Ok(dir),
            Err(error) => warn!(
                "Ignoring client config dir {}: {}",
                candidate.display(),
                error
            ),
        }
    }

    // Missing (rather than invalid) candidates: try to create them as the
    // client before giving up.
    for candidate in candidates.into_iter().flatten() {
        if !candidate.exists()
            && vopono_core::util::ensure_dir_as_config_owner(candidate, None)?
            && let Ok(dir) = vopono_core::util::validated_user_owned_dir(candidate, uid)
        {
            return Ok(dir);
        }
    }

    anyhow::bail!(
        "Client config directory could not be validated for uid {}",
        uid.as_raw()
    )
}

fn fd_readable(fd: RawFd, timeout_ms: i32) -> bool {
    let mut poll_fd = nix::libc::pollfd {
        fd,
        events: nix::libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll_fd points to one initialized pollfd for the duration of this call.
    unsafe { nix::libc::poll(&mut poll_fd, 1, timeout_ms) > 0 }
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

#[cfg(test)]
mod tests {
    use super::versions_compatible;

    #[test]
    fn compatibility_requires_matching_major_version() {
        assert!(versions_compatible("0.10.20", "0.10.20"));
        assert!(versions_compatible("0.10.20", "0.9.1"));
        assert!(!versions_compatible("1.0.0", "0.10.20"));
        // An empty/garbage daemon answer is never treated as compatible.
        assert!(!versions_compatible("", "0.10.20"));
    }

    use super::{VersionSkew, classify_version_skew};

    #[test]
    fn version_skew_classification() {
        assert_eq!(
            classify_version_skew("0.10.22", "0.10.22"),
            VersionSkew::Match
        );
        assert_eq!(
            classify_version_skew("0.10.21", "0.10.22"),
            VersionSkew::MinorMismatch
        );
        assert_eq!(
            classify_version_skew("0.11.0", "0.10.22"),
            VersionSkew::MinorMismatch,
            "same major stays a minor mismatch"
        );
        assert_eq!(
            classify_version_skew("1.0.0", "0.10.22"),
            VersionSkew::MajorMismatch
        );
        assert_eq!(
            classify_version_skew("", "0.10.22"),
            VersionSkew::MajorMismatch,
            "unparsable peer versions are treated as incompatible"
        );
        assert_eq!(
            classify_version_skew("garbage.10.22", "0.10.22"),
            VersionSkew::MajorMismatch
        );
    }

    mod config_adoption {
        use super::super::{adopt_client_config_base, request_client_config_home};
        use crate::daemon::DaemonRequest;
        use nix::unistd::{Gid, Uid, User};
        use std::path::{Path, PathBuf};
        use std::time::{SystemTime, UNIX_EPOCH};

        fn unique_temp_base(name: &str) -> std::path::PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let base = std::env::temp_dir().join(format!("vopono-daemon-test-{name}-{nanos}"));
            std::fs::create_dir_all(&base).unwrap();
            base
        }

        fn current_user(home: &Path) -> User {
            User {
                uid: Uid::current(),
                gid: Gid::current(),
                name: "testuser".to_string(),
                gecos: std::ffi::CString::new("").unwrap(),
                passwd: std::ffi::CString::new("").unwrap(),
                dir: home.to_path_buf(),
                shell: std::path::PathBuf::new(),
            }
        }

        fn skip_when_root() -> bool {
            // Ownership-based assertions assume the test runner's own uid.
            nix::unistd::Uid::current().is_root()
        }

        #[test]
        fn adopts_provided_directory_owned_by_peer() {
            if skip_when_root() {
                return;
            }
            let base = unique_temp_base("owned");
            let provided = base.join("xdg");
            std::fs::create_dir_all(&provided).unwrap();
            let home = base.join("home");
            std::fs::create_dir_all(&home).unwrap();

            let adopted = adopt_client_config_base(
                Some(provided.display().to_string()),
                &current_user(&home),
                Uid::current(),
            )
            .unwrap();
            assert_eq!(adopted, provided.canonicalize().unwrap());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn rejects_symlink_into_foreign_owned_directory_and_falls_back_to_home() {
            if skip_when_root() {
                return;
            }
            let base = unique_temp_base("symlink");
            let link = base.join("evil");
            std::os::unix::fs::symlink("/etc", &link).unwrap();
            let home = base.join("home");
            let home_config = home.join(".config");
            std::fs::create_dir_all(&home_config).unwrap();

            let adopted = adopt_client_config_base(
                Some(link.display().to_string()),
                &current_user(&home),
                Uid::current(),
            )
            .unwrap();
            assert_eq!(adopted, home_config.canonicalize().unwrap());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn fails_closed_when_no_candidate_is_valid() {
            if skip_when_root() {
                return;
            }
            let base = unique_temp_base("invalid");
            // A system directory owned by root: rejected by the ownership
            // check for any non-root requester.
            let foreign = PathBuf::from("/etc");
            // Home `.config` exists but is a file: neither usable nor
            // creatable, so adoption must fail rather than pick anything.
            let home = base.join("home");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(home.join(".config"), "not a directory").unwrap();

            assert!(
                adopt_client_config_base(
                    Some(foreign.display().to_string()),
                    &current_user(&home),
                    Uid::current()
                )
                .is_err()
            );
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn extracts_candidate_from_both_request_types() {
            let mut env = std::collections::HashMap::new();
            env.insert("XDG_CONFIG_HOME".to_string(), "/tmp/some-xdg".to_string());
            assert_eq!(
                request_client_config_home(&DaemonRequest::Execute {
                    cmd: Vec::new(),
                    env: env.clone()
                })
                .as_deref(),
                Some("/tmp/some-xdg")
            );
            assert_eq!(
                request_client_config_home(&DaemonRequest::Stop(
                    crate::daemon::DaemonStopRequest {
                        target: crate::daemon::DaemonStopTarget::Namespace("vo_x".to_string()),
                        config_home: Some("/tmp/stop-xdg".to_string()),
                    }
                ))
                .as_deref(),
                Some("/tmp/stop-xdg")
            );
            assert!(request_client_config_home(&DaemonRequest::Version).is_none());
        }
    }
}
