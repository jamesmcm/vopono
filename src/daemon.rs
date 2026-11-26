use crate::SOCKET_PATH;
use crate::args::ExecCommand;
use crate::exec::execute_as_daemon_with_stdio;
use anyhow::{Context, anyhow};
use interprocess::TryClone;
use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, ToFsName};
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use log::{error, info, warn};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
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
use std::fs::{File, OpenOptions};
use std::io::IoSliceMut;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

// Do not change user's terminal modes; rely on PTY + signal/control forwarding

/// Removes a daemon client's status lockfile when the handler exits.
///
/// The `client-<pid>` lockfile lets other sessions see the application. If the
/// handler returns early or unwinds after writing it, leaving the lock behind
/// would make the namespace look busy forever and block teardown.
struct ClientLockfileGuard(Option<PathBuf>);

impl Drop for ClientLockfileGuard {
    fn drop(&mut self) {
        let Some(path) = self.0.take() else {
            return;
        };
        if let Err(error) = vopono_core::util::owner_write::remove_file_as_config_owner(&path) {
            log::warn!(
                "Failed to remove client lockfile {}: {error}",
                path.display()
            );
        }
    }
}

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

fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let mut components = core.split('.');
    let parsed = (
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
    );
    components.next().is_none().then_some(parsed)
}

pub(crate) fn version_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    parse_version(version).is_some_and(|version| version.0 == minimum.0 && version >= minimum)
}

/// Compatible means an identical major version (breaking-change proxy).
fn versions_compatible(daemon_version: &str, client_version: &str) -> bool {
    parse_version(daemon_version)
        .zip(parse_version(client_version))
        .is_some_and(|(daemon, client)| daemon.0 == client.0)
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

fn sanitize_version_for_log(version: &str) -> String {
    version
        .chars()
        .take(64)
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Daemon side: warn when a client's version differs from this daemon's.
fn warn_on_client_version_mismatch(client_version: &str) {
    let own = env!("CARGO_PKG_VERSION");
    let safe_client = sanitize_version_for_log(client_version);
    match classify_version_skew(client_version, own) {
        VersionSkew::Match => {}
        VersionSkew::MinorMismatch => warn!(
            "Client vopono version {safe_client} differs from daemon version {own}; consider restarting the daemon ('sudo systemctl restart vopono') to match."
        ),
        VersionSkew::MajorMismatch => error!(
            "Client vopono version {safe_client} is incompatible with daemon version {own}; requests may fail unexpectedly. Update vopono and restart the daemon."
        ),
    }
}

/// Client side: announce our version and warn when the daemon's differs.
///
/// Propagates handshake transport/timeout errors so callers never reuse a
/// dropped or protocol-desynchronized socket.
pub(crate) fn exchange_versions_with_daemon(conn: &mut LocalSocketStream) -> anyhow::Result<()> {
    let own = env!("CARGO_PKG_VERSION");
    set_socket_timeouts_for(conn, DAEMON_HANDSHAKE_TIMEOUT_SECONDS)?;
    let daemon_version = client_handshake(conn);
    // Restore blocking mode for the long-lived session that follows.
    let _ = clear_socket_timeouts(conn);
    let daemon_version = daemon_version?;
    match classify_version_skew(&daemon_version, own) {
        VersionSkew::Match => {}
        VersionSkew::MinorMismatch => log::warn!(
            "Daemon vopono version {daemon_version} differs from client version {own}; restart the daemon ('sudo systemctl restart vopono') to align them."
        ),
        VersionSkew::MajorMismatch => log::error!(
            "Daemon vopono version {daemon_version} is incompatible with client version {own}; update vopono and restart the daemon."
        ),
    }
    Ok(())
}

/// Version handshake on an already authenticated connection.
pub(crate) fn client_handshake(conn: &mut LocalSocketStream) -> anyhow::Result<String> {
    write_framed(
        conn,
        &wincode::serialize(&DaemonRequest::ClientVersion(
            env!("CARGO_PKG_VERSION").into(),
        ))?,
    )?;
    match wincode::deserialize::<DaemonResponse>(&read_framed(conn, MAX_FRAME_LEN)?)? {
        DaemonResponse::Version(version) => Ok(version),
        _ => anyhow::bail!("Unexpected daemon version response"),
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

pub(crate) const MAX_FRAME_LEN: usize = 1024 * 1024;
const MAX_CONTROL_FRAME_LEN: usize = 64 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 32;
const MAX_CLIENTS_PER_UID: usize = 8;
static CLIENT_ADMISSION: LazyLock<ClientAdmission> = LazyLock::new(ClientAdmission::default);
// Long-running applications must not consume the slots needed to admit stop,
// status and probe requests. Retained namespace controllers consume neither.
static EXECUTION_ADMISSION: LazyLock<ClientAdmission> = LazyLock::new(ClientAdmission::default);
static PROBE_ADMISSION: LazyLock<ClientAdmission> = LazyLock::new(ClientAdmission::default);

#[derive(Default)]
struct ClientAdmission {
    state: Mutex<ClientAdmissionState>,
}

#[derive(Default)]
struct ClientAdmissionState {
    total: usize,
    by_uid: std::collections::HashMap<u32, usize>,
}

struct ClientSlot<'a> {
    admission: &'a ClientAdmission,
    uid: u32,
}

impl ClientAdmission {
    fn acquire(&self, uid: Uid) -> Option<ClientSlot<'_>> {
        self.acquire_with_limits(uid, MAX_CLIENTS_PER_UID, MAX_CONCURRENT_CLIENTS)
    }
    fn acquire_with_limits(
        &self,
        uid: Uid,
        per_uid: usize,
        total: usize,
    ) -> Option<ClientSlot<'_>> {
        let mut state = self.state.lock().expect("client admission lock poisoned");
        let uid = uid.as_raw();
        let uid_count = state.by_uid.get(&uid).copied().unwrap_or_default();
        if state.total >= total || uid_count >= per_uid {
            return None;
        }
        state.total += 1;
        state.by_uid.insert(uid, uid_count + 1);
        Some(ClientSlot {
            admission: self,
            uid,
        })
    }
}

impl Drop for ClientSlot<'_> {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .expect("client admission lock poisoned");
        state.total -= 1;
        if let Some(count) = state.by_uid.get_mut(&self.uid) {
            *count -= 1;
            if *count == 0 {
                state.by_uid.remove(&self.uid);
            }
        }
    }
}

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
    let len = checked_frame_len(len_bytes, max_len)?;
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn checked_frame_len(len_bytes: [u8; 4], max_len: usize) -> anyhow::Result<usize> {
    let len = u32::from_be_bytes(len_bytes) as usize;
    anyhow::ensure!(len <= max_len, "Daemon frame too large: {len}");
    Ok(len)
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
    /// daemon can warn about client/daemon version skew. New variants must
    /// be appended after this one to preserve all existing wire indices.
    ClientVersion(String),
    /// Return sanitized, read-only host firewall/AppArmor evidence. No network probes.
    HostDiagnostics {
        skip_ipv6: bool,
    },
    NamespaceDiagnostics {
        id: String,
        offline: bool,
        skip_ipv6: bool,
        timeout_ms: u64,
    },
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
    // A second daemon must never unlink the first daemon's live socket.
    std::fs::create_dir_all("/run/vopono")?;
    use std::os::unix::fs::OpenOptionsExt;
    let daemon_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open("/run/vopono/daemon.lock")?;
    anyhow::ensure!(
        unsafe {
            nix::libc::flock(
                daemon_lock.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        } == 0,
        "Another vopono daemon is already running"
    );
    // Clean up any stale socket file from a previous unclean shutdown.
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Set up a signal handler to quiesce in-flight transitions, clean up the socket, and exit.
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGQUIT])?;
    let socket_path = SOCKET_PATH.to_string();
    std::thread::spawn(move || {
        // Block until the first signal is received, wait briefly for active
        // namespace setup/teardown transitions to finish, then clean up and exit.
        if let Some(signal) = signals.forever().next() {
            info!(
                "Received signal {}, waiting for active transitions before exiting.",
                signal
            );
            let _ = std::fs::remove_file(&socket_path);
            crate::namespace_sessions::wait_for_idle_transitions(std::time::Duration::from_secs(3));
            std::process::exit(0);
        }
    });

    crate::namespace_sessions::restore_all()?;

    let name = SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?;

    let listener = ListenerOptions::new()
        .name(name)
        .create_sync()
        .with_context(|| format!("Failed to bind to socket at {}", SOCKET_PATH))?;

    let mut perms = std::fs::metadata(SOCKET_PATH)?.permissions();
    // Set permissions to 666 to allow any local user to connect to the daemon socket
    // (execute bits are unnecessary on Unix sockets). The daemon checks SO_PEERCRED.
    perms.set_mode(0o666);
    std::fs::set_permissions(SOCKET_PATH, perms)?;
    info!("Daemon listening on {}", SOCKET_PATH);

    for conn in listener.incoming().filter_map(handle_accept_error) {
        let (peer_uid, _) = match get_peer_credentials(&conn) {
            Ok(credentials) => credentials,
            Err(error) => {
                warn!("Rejecting daemon connection without peer credentials: {error}");
                continue;
            }
        };
        let Some(client_slot) = CLIENT_ADMISSION.acquire(peer_uid) else {
            warn!(
                "Rejecting daemon connection for uid {}: client limit reached (per uid {}, total {})",
                peer_uid.as_raw(),
                MAX_CLIENTS_PER_UID,
                MAX_CONCURRENT_CLIENTS
            );
            continue;
        };
        thread::spawn(move || {
            // Keep namespace resources on this thread, but outside the request
            // handler's scope. Its admission slots and client descriptors must
            // close before the controller waits for the namespace's last user.
            let mut session = None;
            let mut error_conn = conn.try_clone().ok();
            if let Err(e) = handle_client(conn, client_slot, &mut session) {
                error!("Error handling client: {}", e);
                if let Some(conn) = error_conn.as_mut() {
                    let response = DaemonResponse::Error(format!("{e:#}"));
                    if let Ok(bytes) = wincode::serialize(&response) {
                        let _ = conn.write_all(&(bytes.len() as u32).to_be_bytes());
                        let _ = conn.write_all(&bytes);
                    }
                }
            }
            drop(error_conn);
            if let Some(session) = session {
                session.run_until_unused();
            }
            // Namespace cleanup still uses the creating client's config tree
            // and dropped-privilege helpers after the request has finished.
            vopono_core::util::set_config_dir_override(None);
            vopono_core::util::set_config_owner_override(None);
            vopono_core::util::set_helper_exe_override(None);
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

struct PtyOutput {
    file: File,
    socket: bool,
}

impl PtyOutput {
    fn new(file: File) -> std::io::Result<Self> {
        let kind = file.metadata()?.file_type();
        let flags = OFlag::from_bits_truncate(fcntl(&file, FcntlArg::F_GETFL)?);
        let access = flags & OFlag::O_ACCMODE;
        if flags.intersects(OFlag::O_PATH) || !matches!(access, OFlag::O_WRONLY | OFlag::O_RDWR) {
            return Err(std::io::Error::from_raw_os_error(nix::libc::EBADF));
        }
        let file = if kind.is_fifo() || kind.is_char_device() {
            // dup() shares status flags with the client. Open a separate file
            // description so relay writes can never set its stdout nonblocking.
            OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
                .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?
        } else {
            // Keep the shared file offset and append semantics for regular files.
            file
        };
        Ok(Self {
            file,
            socket: kind.is_socket(),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.socket {
            Ok(nix::sys::socket::send(
                self.file.as_raw_fd(),
                bytes,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            )?)
        } else {
            self.file.write(bytes)
        }
    }

    fn write_all_bounded(&mut self, mut bytes: &[u8], timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout;
        while !bytes.is_empty() {
            match self.write(bytes) {
                Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                    };
                    let wait_ms = remaining.as_millis().clamp(1, 25) as i32;
                    fd_writable(self.file.as_raw_fd(), wait_ms);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn write_client_notice(fd: OwnedFd, bytes: &[u8]) {
    if let Ok(mut out) = PtyOutput::new(File::from(fd)) {
        let _ = out.write_all_bounded(bytes, Duration::from_millis(250));
    }
}

fn copy_pty_output(mut reader: File, mut output: PtyOutput, prefix: &[u8], done: &AtomicBool) {
    let mut buffer = [0; 4096];
    let mut prefix = prefix;
    let mut pending = 0..0;
    let mut deadline = None;
    loop {
        if done.load(Ordering::Acquire)
            && Instant::now()
                >= *deadline.get_or_insert_with(|| Instant::now() + Duration::from_millis(250))
        {
            return;
        }
        if prefix.is_empty() && pending.is_empty() {
            if !fd_readable(reader.as_raw_fd(), 50) {
                if deadline.is_some() {
                    return;
                }
                continue;
            }
            match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => pending = 0..count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            }
        }
        let bytes = if prefix.is_empty() {
            &buffer[pending.clone()]
        } else {
            prefix
        };
        match output.write(bytes) {
            Ok(0) => return,
            Ok(count) if !prefix.is_empty() => prefix = &prefix[count..],
            Ok(count) => pending.start += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                fd_writable(output.file.as_raw_fd(), 25);
            }
            Err(_) => return,
        }
    }
}

fn write_pty_input(terminal: &mut File, mut bytes: &[u8], done: &AtomicBool) -> bool {
    while !bytes.is_empty() && !done.load(Ordering::Acquire) {
        match terminal.write(bytes) {
            Ok(0) => return false,
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                fd_writable(terminal.as_raw_fd(), 25);
            }
            Err(_) => return false,
        }
    }
    bytes.is_empty()
}

/// Wait for an application, bridging terminal I/O only for interactive clients.
fn wait_for_application(
    child: &mut std::process::Child,
    conn: &LocalSocketStream,
    pty_master: Option<OwnedFd>,
    client_fds: Option<&(OwnedFd, OwnedFd, OwnedFd)>,
    launch_notice: Option<String>,
    pty_output_fd: Option<&OwnedFd>,
) -> anyhow::Result<std::process::ExitStatus> {
    let Some(master_fd) = pty_master else {
        // Non-TTY executions still receive client signals (Ctrl-C / SIGTERM)
        // over the control socket; forward them to the child's process group.
        let ctrl_conn = conn.try_clone()?;
        let child_pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
        let child_done = Arc::new(AtomicBool::new(false));
        let child_done_for_ctrl = Arc::clone(&child_done);
        let ctrl_thread = thread::spawn(move || {
            forward_non_tty_signals(ctrl_conn, child_pgid, child_done_for_ctrl);
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => {
                    log::debug!("try_wait error: {e}");
                    break None;
                }
            }
        };
        child_done.store(true, Ordering::Release);
        let _ = ctrl_thread.join();
        return match status {
            Some(status) => Ok(status),
            None => Ok(child.wait()?),
        };
    };
    let mut exit_status = None;
    // Duplicate client FDs so we don't close the originals when Files drop
    let (client_stdin_fd, _, _) = client_fds.expect("PTY client fds retained");
    let client_stdin_dup: OwnedFd = nix::unistd::dup(client_stdin_fd.as_fd())?;
    let client_stdin = File::from(client_stdin_dup);
    let pty_master_file_r = File::from(master_fd);
    // The master belongs to the daemon, so its clones can share nonblocking mode.
    let flags = OFlag::from_bits_truncate(fcntl(&pty_master_file_r, FcntlArg::F_GETFL)?);
    fcntl(
        &pty_master_file_r,
        FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
    )?;
    let pty_master_file_w = pty_master_file_r.try_clone()?;

    // Do not change user terminal modes; inject control bytes into PTY on signals

    // Control listener: on SIGINT/SIGTSTP/SIGQUIT inject termios cc into PTY master; others killpg
    let ctrl_conn = conn.try_clone()?;
    let pty_writer_for_ctrl = pty_master_file_w.try_clone()?;
    let child_pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
    let child_done = Arc::new(AtomicBool::new(false));
    let child_done_for_ctrl = Arc::clone(&child_done);
    let ctrl_thread = thread::spawn(move || {
        forward_terminal_signals(
            ctrl_conn,
            pty_writer_for_ctrl,
            child_pgid,
            child_done_for_ctrl,
        )
    });

    // stdin copier: client stdin -> pty master
    let mut stdin_reader = client_stdin;
    let mut pty_writer = pty_master_file_w;
    let child_pgid_for_stdin = child_pgid; // Pid is Copy; used for optional SIGHUP on EOF
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
                if !write_pty_input(&mut pty_writer, &[0x04], &child_done_for_stdin) {
                    break;
                }
                // Optional: also send SIGHUP to the child's process group
                let _ =
                    nix::sys::signal::kill(child_pgid_for_stdin, nix::sys::signal::Signal::SIGHUP);
                break;
            }
            if !write_pty_input(&mut pty_writer, &buf[..n], &child_done_for_stdin) {
                break;
            }
        }
    });

    // Send terminal output to the caller's terminal, preserving redirected streams.
    let child_done_for_output = Arc::clone(&child_done);
    let terminal_fd = pty_output_fd.or_else(|| {
        // With both output streams redirected, /dev/tty still goes to the
        // terminal when the caller supplied it as a read-write input FD.
        let flags = OFlag::from_bits_truncate(fcntl(client_stdin_fd, FcntlArg::F_GETFL).ok()?);
        (flags & OFlag::O_ACCMODE == OFlag::O_RDWR).then_some(client_stdin_fd)
    });
    let output_copier = if let Some(terminal) = terminal_fd {
        let terminal = File::from(nix::unistd::dup(terminal.as_fd())?);
        thread::spawn(move || match PtyOutput::new(terminal) {
            Ok(output) => copy_pty_output(
                pty_master_file_r,
                output,
                launch_notice.as_deref().unwrap_or_default().as_bytes(),
                &child_done_for_output,
            ),
            Err(error) => log::debug!("Could not open client PTY output: {error}"),
        })
    } else {
        thread::spawn(move || {
            let mut pty_r = pty_master_file_r;
            let mut buf = [0u8; 4096];
            while !child_done_for_output.load(Ordering::Acquire) {
                if !fd_readable(pty_r.as_raw_fd(), 50) {
                    continue;
                }
                match pty_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
        })
    };

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
    // Stop and join all PTY helper threads before replying to the client:
    // - stdin_copier must stop so it cannot steal input from the caller's shell.
    // - ctrl_thread must stop so a kept-open socket cannot send signals after
    //   PID reuse or leak threads/FDs past admission limits.
    // - output_copier must drain remaining PTY output so fast commands don't truncate.
    child_done.store(true, Ordering::Release);
    let _ = stdin_copier.join();
    let _ = ctrl_thread.join();
    let _ = output_copier.join();
    match exit_status {
        Some(status) => Ok(status),
        None => Ok(child.wait()?),
    }
}

/// Forward allowlisted signals from a non-TTY client to the child's process group.
fn forward_non_tty_signals(
    conn: LocalSocketStream,
    group: nix::unistd::Pid,
    done: Arc<AtomicBool>,
) {
    let LocalSocketStream::UdSocket(ref sock) = conn;
    let raw_fd = sock.as_fd().as_raw_fd();
    let mut pending = Vec::new();
    let mut chunk = [0u8; 256];
    while !done.load(Ordering::Acquire) {
        if !fd_readable(raw_fd, 50) {
            continue;
        }
        match nix::sys::socket::recv(raw_fd, &mut chunk, MsgFlags::MSG_DONTWAIT) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        while pending.len() >= 4 {
            let len = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
            if len > MAX_CONTROL_FRAME_LEN {
                return;
            }
            if pending.len() < 4 + len {
                break;
            }
            let bytes: Vec<u8> = pending.drain(..4 + len).skip(4).collect();
            if done.load(Ordering::Acquire) {
                return;
            }
            let Ok(DaemonRequest::Control(DaemonControl::Signal(signal))) =
                wincode::deserialize::<DaemonRequest>(&bytes)
            else {
                continue;
            };
            let Ok(signal) = nix::sys::signal::Signal::try_from(signal) else {
                continue;
            };
            if matches!(
                signal,
                nix::sys::signal::Signal::SIGINT
                    | nix::sys::signal::Signal::SIGQUIT
                    | nix::sys::signal::Signal::SIGTSTP
                    | nix::sys::signal::Signal::SIGTERM
                    | nix::sys::signal::Signal::SIGHUP
                    | nix::sys::signal::Signal::SIGCONT
                    | nix::sys::signal::Signal::SIGUSR1
                    | nix::sys::signal::Signal::SIGUSR2
            ) {
                let _ = nix::sys::signal::kill(group, signal);
            }
        }
    }
}

/// Preserve terminal-generated signals and forward allowlisted signals to the process group.
fn forward_terminal_signals(
    conn: LocalSocketStream,
    mut terminal: std::fs::File,
    group: nix::unistd::Pid,
    done: Arc<AtomicBool>,
) {
    let LocalSocketStream::UdSocket(ref sock) = conn;
    let raw_fd = sock.as_fd().as_raw_fd();
    let mut pending = Vec::new();
    let mut chunk = [0u8; 256];
    while !done.load(Ordering::Acquire) {
        if !fd_readable(raw_fd, 50) {
            continue;
        }
        // Use non-blocking per-call recv so a stalled partial frame cannot block
        // ctrl_thread.join() after the child exits, without mutating shared socket flags.
        match nix::sys::socket::recv(raw_fd, &mut chunk, MsgFlags::MSG_DONTWAIT) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        while pending.len() >= 4 {
            let len = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
            if len > MAX_CONTROL_FRAME_LEN {
                return;
            }
            if pending.len() < 4 + len {
                break;
            }
            let bytes: Vec<u8> = pending.drain(..4 + len).skip(4).collect();
            if done.load(Ordering::Acquire) {
                return;
            }
            let Ok(DaemonRequest::Control(DaemonControl::Signal(signal))) =
                wincode::deserialize::<DaemonRequest>(&bytes)
            else {
                continue;
            };
            let Ok(signal) = nix::sys::signal::Signal::try_from(signal) else {
                continue;
            };
            let control_byte = match signal {
                nix::sys::signal::Signal::SIGINT => Some(0x03),
                nix::sys::signal::Signal::SIGTSTP => Some(0x1A),
                nix::sys::signal::Signal::SIGQUIT => Some(0x1C),
                _ => None,
            };
            if let Some(byte) = control_byte {
                let _ = write_pty_input(&mut terminal, &[byte], &done);
            } else if matches!(
                signal,
                nix::sys::signal::Signal::SIGTERM
                    | nix::sys::signal::Signal::SIGHUP
                    | nix::sys::signal::Signal::SIGCONT
                    | nix::sys::signal::Signal::SIGWINCH
                    | nix::sys::signal::Signal::SIGUSR1
                    | nix::sys::signal::Signal::SIGUSR2
            ) {
                let _ = nix::sys::signal::kill(group, signal);
            }
        }
    }
}

/// Handles a single client connection.
fn handle_client(
    mut conn: LocalSocketStream,
    client_slot: ClientSlot<'_>,
    session: &mut Option<crate::namespace_sessions::Session>,
) -> anyhow::Result<()> {
    // An unauthenticated local peer must not be able to occupy a daemon
    // worker indefinitely by connecting without sending a complete request.
    set_socket_timeouts(&conn)?;
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
                recv_fds_over_unix_socket(&conn)?;
            let mut client_fds = Some((client_stdin_fd, client_stdout_fd, client_stderr_fd));
            // Decode the command payload from the JSON bytes carried by `DaemonRequest::Execute`.
            let mut exec_command: ExecCommand = serde_json::from_slice(&cmd)?;
            exec_command.user = Some(user.name);
            exec_command.group = Some(group.name);
            let json = exec_command.json;
            let execution = (|| -> anyhow::Result<()> {
                // Read the execution request and its descriptors before refusing
                // admission, so the client can receive the structured error.
                let _execution_slot = EXECUTION_ADMISSION.acquire(uid).context(
                    "Concurrent daemon execution limit reached; wait for a running command to exit",
                )?;
                drop(client_slot);
                // Execution may wait for an application for an arbitrary duration.
                clear_socket_timeouts(&conn)?;
                crate::profiles::prepare(&mut exec_command)?;
                let requested_application = exec_command.application.clone();
                let silent = exec_command.silent;
                let keep_alive = exec_command.keep_alive;
                let monitor = exec_command.monitor;
                let recover = exec_command.recover;
                let transition = crate::namespace_sessions::begin_setup();

                // `--create-netns-only`: bring up the namespace and leave it alive
                // without spawning an application. The client learns the namespace
                // name and exits; `vopono stop --namespace` tears it down later.
                if exec_command.create_netns_only {
                    let mut setup = crate::exec::setup_daemon_namespace_only(
                        exec_command,
                        Some(forwarded_env.clone()),
                    )?;
                    let existing_session = crate::namespace_sessions::contains(&setup.ns.name);
                    let proxies = if !setup.parsed_command.no_proxy {
                        match crate::exec::restore_host_proxies(
                            &setup.ns,
                            setup.parsed_command.forward.as_deref().unwrap_or_default(),
                        ) {
                            Ok(proxies) => proxies,
                            Err(error) => {
                                if existing_session {
                                    setup.ns.detach();
                                }
                                return Err(error);
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    if existing_session && !proxies.is_empty() {
                        let new_ports: Vec<u16> = proxies.iter().map(|(port, _)| *port).collect();
                        if let Err(error) =
                            vopono_core::util::open_ports(&setup.ns, &new_ports, setup.ns.firewall)
                        {
                            setup.ns.detach();
                            return Err(error);
                        }
                    }
                    if let Err(error) =
                        crate::namespace_ownership::mark_persistent(&setup.ns.name, uid)
                    {
                        if existing_session {
                            setup.ns.detach();
                        }
                        return Err(error);
                    }
                    let session = session.insert(crate::namespace_sessions::Session::register(
                        setup.ns,
                        uid,
                        setup.forwarder,
                        monitor,
                        recover,
                    ));
                    session.retain_proxies(proxies);
                    session.persist_options()?;
                    drop(transition);
                    // No child will consume the received SCM_RIGHTS descriptors in
                    // this branch, so take ownership and close all three locally.
                    let (_client_stdin, client_stdout, _client_stderr) =
                        client_fds.take().expect("client fds present");
                    if json {
                        let report = crate::exec::launch_report_for_daemon(
                            &session.ns,
                            0,
                            session.forwarded_port(),
                            setup.reused,
                        );
                        write_client_notice(client_stdout, format!("{report}\n").as_bytes());
                    } else if !silent {
                        write_client_notice(
                            client_stdout,
                            format!(
                                "{}\n",
                                crate::exec::human_launch_report(&session.ns, setup.reused)
                            )
                            .as_bytes(),
                        );
                    }
                    write_response(&mut conn, &DaemonResponse::Exit(0))?;
                    return Ok(());
                }

                // The caller retains namespace resources after this handler
                // closes its client descriptors and execution admission slot.
                // Check stdin/stdout/stderr individually so redirected stdout or
                // stderr streams are never routed through the PTY or merged.
                let (stdin_is_tty, stdout_is_tty, stderr_is_tty) = {
                    let fds = client_fds.as_ref().expect("client fds present");
                    (
                        nix_isatty(fds.0.as_fd()).unwrap_or(false),
                        nix_isatty(fds.1.as_fd()).unwrap_or(false),
                        nix_isatty(fds.2.as_fd()).unwrap_or(false),
                    )
                };
                let client_has_tty = stdin_is_tty;
                let pty_bridges_stdout = client_has_tty && stdout_is_tty;
                let client_report_out = if !pty_bridges_stdout && (!silent || json) {
                    Some(nix::unistd::dup(
                        client_fds.as_ref().expect("client fds present").1.as_fd(),
                    )?)
                } else {
                    None
                };
                let human_notice_fd = if !json && !silent {
                    Some(nix::unistd::dup(
                        client_fds.as_ref().expect("client fds present").2.as_fd(),
                    )?)
                } else {
                    None
                };
                let (mut application, ns, host_proxies, reused): (
                    vopono_core::network::application_wrapper::ApplicationWrapper,
                    vopono_core::network::netns::NetworkNamespace,
                    crate::exec::HostProxies,
                    bool,
                );
                let mut pty_master: Option<OwnedFd> = None;
                if client_has_tty {
                    let p = openpty(None, None).map_err(|e| anyhow!("openpty failed: {e}"))?;
                    // Assign PTY slave ownership to the connecting user so apps
                    // opening /dev/tty (ssh, gpg, less, getpass) succeed.
                    let _ = nix::unistd::fchown(p.slave.as_fd(), Some(uid), Some(gid));
                    let _ = nix::sys::stat::fchmod(
                        p.slave.as_fd(),
                        nix::sys::stat::Mode::from_bits_truncate(0o600),
                    );
                    let fds = client_fds.as_ref().expect("client fds present");
                    let child_out = if stdout_is_tty {
                        nix::unistd::dup(p.slave.as_fd())?
                    } else {
                        nix::unistd::dup(fds.1.as_fd())?
                    };
                    let child_err = if stderr_is_tty {
                        nix::unistd::dup(p.slave.as_fd())?
                    } else {
                        nix::unistd::dup(fds.2.as_fd())?
                    };
                    // Spawn child with PTY slave as stdin (and TTY outputs), letting it take controlling TTY in pre_exec
                    (application, ns, host_proxies, reused) = execute_as_daemon_with_stdio(
                        exec_command,
                        false,
                        Some((p.slave, child_out, child_err)),
                        true,
                        Some(forwarded_env.clone()),
                    )?;
                    pty_master = Some(p.master);
                } else {
                    (application, ns, host_proxies, reused) = execute_as_daemon_with_stdio(
                        exec_command,
                        false,
                        client_fds.take(),
                        false,
                        Some(forwarded_env.clone()),
                    )?;
                }

                // Create a per-client RON lock file under ~/.config/vopono/locks/<ns>/client-<pid>
                // so status readers can report daemon-launched applications and Drop can see
                // other active clients before tearing down the namespace. The guard removes
                // it on every exit path, including early errors and unwinds.
                let _client_lock = ClientLockfileGuard(
                    match ns.write_client_lockfile(application.handle.id(), &requested_application)
                    {
                        Ok(path) => path,
                        Err(error) => {
                            log::warn!("Failed to write daemon client status lockfile: {error}");
                            None
                        }
                    },
                );

                let session = session.insert(crate::namespace_sessions::Session::register(
                    ns,
                    uid,
                    application.port_forwarding,
                    monitor,
                    recover,
                ));
                if keep_alive {
                    info!(
                        "Keep-alive flag active - marking network namespace {} persistent",
                        session.ns.name
                    );
                    if let Err(error) =
                        crate::namespace_ownership::mark_persistent(&session.ns.name, uid)
                    {
                        let _ = application.handle.kill();
                        let _ = application.handle.wait();
                        return Err(error);
                    }
                }
                session.retain_proxies(host_proxies);
                if let Err(error) = session.persist_options() {
                    let _ = application.handle.kill();
                    let _ = application.handle.wait();
                    return Err(error);
                }
                let forwarded_port = session.forwarded_port();
                let mut launch_notice = if json {
                    let report = crate::exec::launch_report_for_daemon(
                        &session.ns,
                        application.handle.id(),
                        forwarded_port,
                        reused,
                    );
                    Some(format!("{report}\n"))
                } else if !silent {
                    forwarded_port.map(|port| format!("Port Forwarding on port {port}\n"))
                } else {
                    None
                };
                drop(transition);
                if let Some(fd) = human_notice_fd {
                    write_client_notice(
                        fd,
                        format!(
                            "{}\n",
                            crate::exec::human_launch_report(&session.ns, reused)
                        )
                        .as_bytes(),
                    );
                }
                // Write launch summary / forwarded port notice AFTER releasing the
                // namespace transition lock so a stalled client pipe cannot deadlock
                // operations on this namespace.
                if let Some(dup_fd) = client_report_out
                    && let Some(notice) = launch_notice.take()
                {
                    write_client_notice(dup_fd, notice.as_bytes());
                }

                let status = wait_for_application(
                    &mut application.handle,
                    &conn,
                    pty_master,
                    client_fds.as_ref(),
                    launch_notice,
                    client_fds.as_ref().and_then(|(_, stdout, stderr)| {
                        if stdout_is_tty {
                            Some(stdout)
                        } else {
                            stderr_is_tty.then_some(stderr)
                        }
                    }),
                )?;

                // Remove this application's status before the namespace controller
                // waits for other clients, detached children or explicit persistence.
                drop(_client_lock);

                let response_code = status.code().unwrap_or(1);
                write_response(&mut conn, &DaemonResponse::Exit(response_code))?;
                Ok(())
            })();
            if let Err(error) = execution {
                if json {
                    write_response(
                        &mut conn,
                        &DaemonResponse::Json(serde_json::to_vec(
                            &crate::errors::error_json_value(&error),
                        )?),
                    )?;
                } else {
                    return Err(error);
                }
            }
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
                DaemonStopTarget::Namespace(id) => stop_daemon_namespace(&id, uid),
            };
            let payload = match outcome {
                Ok(result) => serde_json::to_vec(&result)?,
                Err(error) => serde_json::to_vec(&crate::errors::error_json_value(&error))?,
            };
            write_response(&mut conn, &DaemonResponse::Json(payload))?;
        }
        DaemonRequest::CheckNamespace(request) => {
            let _probe_slot = PROBE_ADMISSION
                .acquire_with_limits(uid, 2, 8)
                .context("Concurrent connectivity probe limit reached")?;
            drop(client_slot);
            anyhow::ensure!(
                (1..=30000).contains(
                    &request
                        .timeout_ms
                        .unwrap_or(crate::check::DEFAULT_TIMEOUT_MS)
                ),
                "Probe timeout must be between 1 and 30000 milliseconds"
            );
            anyhow::ensure!(request.port != Some(0), "Probe port must be nonzero");
            for host in [&request.v4_host, &request.v6_host, &request.dns_host]
                .into_iter()
                .flatten()
            {
                anyhow::ensure!(
                    !host.is_empty()
                        && host.len() <= 253
                        && !host.starts_with('-')
                        && !host.chars().any(|c| c.is_control() || c.is_whitespace()),
                    "Invalid probe host"
                );
            }
            // The probe needs root to enter the namespace, so it can only run
            // here (or in the sudo fallback path of the CLI).
            crate::namespace_ownership::authorize(&request.id, uid)?;
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
        DaemonRequest::HostDiagnostics { skip_ipv6 } => {
            let _probe_slot = PROBE_ADMISSION
                .acquire_with_limits(uid, 2, 8)
                .context("Concurrent host inspection limit reached")?;
            drop(client_slot);
            let diagnostics = vopono_core::diagnostics::host::inspect(skip_ipv6);
            write_response(
                &mut conn,
                &DaemonResponse::Json(serde_json::to_vec(&diagnostics)?),
            )?;
        }
        DaemonRequest::NamespaceDiagnostics {
            id,
            offline,
            skip_ipv6,
            timeout_ms,
        } => {
            let _probe_slot = PROBE_ADMISSION
                .acquire_with_limits(uid, 2, 8)
                .context("Concurrent namespace inspection limit reached")?;
            drop(client_slot);
            anyhow::ensure!(
                (1..=30000).contains(&timeout_ms),
                "Invalid diagnostic timeout"
            );
            let snapshot = crate::namespace_ownership::diagnostic_snapshot(&id, uid)?;
            let report = vopono_core::diagnostics::topology::namespace_network(
                &snapshot, offline, skip_ipv6, timeout_ms,
            )?;
            write_response(
                &mut conn,
                &DaemonResponse::Json(serde_json::to_vec(&report)?),
            )?;
        }
        DaemonRequest::Control(_) => {
            // Ignore unexpected control frame sent as the first message
        }
        DaemonRequest::ClientVersion(_) => {
            // Handshake-only frame; a bare one carries no request payload.
        }
    }
    Ok(())
}

fn stop_daemon_namespace(id: &str, uid: Uid) -> anyhow::Result<crate::control::StopResult> {
    let transition = crate::namespace_sessions::lock_namespace(id);
    crate::namespace_ownership::authorize(id, uid)?;
    let path = Path::new("/run/netns").join(id);
    // Hold the original generation open while the forwarder releases its lease.
    let original = File::open(&path)?;
    let identity = original.metadata()?;
    crate::control::mark_namespace_stopping(id, uid)?;
    crate::namespace_sessions::stop_monitor(id)?;
    let forwarder = crate::namespace_sessions::request_forwarder_release(id);
    drop(transition);
    if let Some(released) = forwarder {
        crate::namespace_sessions::wait_forwarder_released(&released, Duration::from_secs(5));
    }

    let transition = crate::namespace_sessions::lock_namespace(id);
    let same_generation = match std::fs::metadata(&path) {
        Ok(current) => current.dev() == identity.dev() && current.ino() == identity.ino(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !same_generation {
        return Ok(crate::control::StopResult {
            version: crate::api::SCHEMA_VERSION,
            target: crate::control::StopTargetKind::Namespace,
            application_id: None,
            namespace_id: id.to_owned(),
            namespace_removed: true,
        });
    }

    let result = crate::control::stop_namespace(id, Some(uid))?;
    let released = crate::namespace_sessions::invalidate(id);
    drop(transition);
    if let Some(released) = released {
        crate::namespace_sessions::wait_released(&released)?;
    }
    Ok(result)
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
    // Per XDG Base Directory spec, empty or relative XDG_CONFIG_HOME is ignored.
    let provided_candidate = provided
        .filter(|path| !path.is_empty() && Path::new(path).is_absolute())
        .map(PathBuf::from);
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
    // client before giving up. Failure on an uncreatable XDG_CONFIG_HOME
    // falls through to ~/.config rather than aborting immediately.
    for candidate in candidates.into_iter().flatten() {
        if !candidate.exists() {
            match vopono_core::util::ensure_dir_as_config_owner(candidate, None) {
                Ok(true) => {
                    if let Ok(dir) = vopono_core::util::validated_user_owned_dir(candidate, uid) {
                        return Ok(dir);
                    }
                }
                Ok(false) => {
                    if (!nix::unistd::geteuid().is_root() || uid.is_root())
                        && std::fs::create_dir_all(candidate).is_ok()
                        && let Ok(dir) = vopono_core::util::validated_user_owned_dir(candidate, uid)
                    {
                        return Ok(dir);
                    }
                }
                Err(error) => {
                    warn!(
                        "Could not create client config dir {}: {error}",
                        candidate.display()
                    );
                }
            }
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

fn fd_writable(fd: RawFd, timeout_ms: i32) -> bool {
    let mut poll_fd = nix::libc::pollfd {
        fd,
        events: nix::libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: poll_fd points to one initialized pollfd for the duration of this call.
    unsafe { nix::libc::poll(&mut poll_fd, 1, timeout_ms) > 0 }
}

fn recv_fds_over_unix_socket(conn: &LocalSocketStream) -> anyhow::Result<[OwnedFd; 3]> {
    let LocalSocketStream::UdSocket(sock) = conn;
    let fd = sock.as_fd();

    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = cmsg_space!([RawFd; 3]);
    let msg = recvmsg::<()>(
        fd.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;
    anyhow::ensure!(
        !msg.flags.contains(MsgFlags::MSG_CTRUNC),
        "Received truncated descriptor control message"
    );

    let mut fds: Vec<OwnedFd> = Vec::new();
    if let Ok(iter) = msg.cmsgs() {
        for c in iter {
            if let ControlMessageOwned::ScmRights(fdlist) = c {
                for &f in fdlist.iter() {
                    // SCM_RIGHTS transfers ownership to this process. Wrap it
                    // immediately so every later error path closes it.
                    fds.push(unsafe { OwnedFd::from_raw_fd(f) });
                }
            }
        }
    }
    if fds.len() != 3 {
        return Err(anyhow!(
            "Did not receive expected number of FDs: got {} expected {}",
            fds.len(),
            3
        ));
    }
    fds.try_into().map_err(|fds: Vec<OwnedFd>| {
        anyhow!("Could not convert {} received descriptors", fds.len())
    })
}

#[cfg(test)]
mod tests {
    use super::{ClientAdmission, MAX_CLIENTS_PER_UID, checked_frame_len, versions_compatible};
    use nix::unistd::Uid;

    #[test]
    fn host_diagnostics_appends_to_the_wire_protocol_without_changing_old_indices() {
        use super::DaemonRequest;
        for (request, index) in [
            (DaemonRequest::Version, 2u32),
            (DaemonRequest::ClientVersion("1.0.3".into()), 5u32),
            (DaemonRequest::HostDiagnostics { skip_ipv6: true }, 6u32),
            (
                DaemonRequest::NamespaceDiagnostics {
                    id: "vo_test".into(),
                    offline: true,
                    skip_ipv6: false,
                    timeout_ms: 3000,
                },
                7u32,
            ),
        ] {
            let bytes = wincode::serialize(&request).unwrap();
            assert_eq!(&bytes[..4], &index.to_le_bytes());
            let decoded: DaemonRequest = wincode::deserialize(&bytes).unwrap();
            assert_eq!(wincode::serialize(&decoded).unwrap(), bytes);
        }
    }

    #[test]
    fn framed_messages_are_rejected_before_oversized_allocation() {
        assert_eq!(checked_frame_len(16u32.to_be_bytes(), 16).unwrap(), 16);
        let error = checked_frame_len(17u32.to_be_bytes(), 16)
            .unwrap_err()
            .to_string();
        assert!(error.contains("frame too large"));
    }

    #[test]
    fn client_lock_guard_removes_lockfile_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "vopono-client-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client-4242");
        std::fs::write(&path, "lock").unwrap();
        {
            let _guard = super::ClientLockfileGuard(Some(path.clone()));
        }
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn daemon_admission_is_bounded_per_uid_and_released_on_drop() {
        let admission = ClientAdmission::default();
        let uid = Uid::from_raw(1000);
        let slots = (0..MAX_CLIENTS_PER_UID)
            .map(|_| admission.acquire(uid).expect("slot should be admitted"))
            .collect::<Vec<_>>();
        assert!(admission.acquire(uid).is_none());
        assert!(admission.acquire(Uid::from_raw(1001)).is_some());
        drop(slots);
        assert!(admission.acquire(uid).is_some());
    }

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
    fn profile_and_monitor_launches_require_daemon_support() {
        use super::version_at_least;
        let minimum = (1, 1, 0);
        assert!(!version_at_least("1.0.3", minimum));
        assert!(!version_at_least("2.0.0", minimum));
        assert!(!version_at_least("unknown", minimum));
        assert!(version_at_least("1.1.0", minimum));
        assert!(version_at_least("1.2.0+packaged", minimum));
    }

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

    #[test]
    fn pty_child_exit_does_not_wait_for_a_full_stdout_pipe() {
        use super::{File, OwnedFd, PtyOutput};
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let (stdin, _stdin_writer) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (stdout_reader, stdout) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let stdout = File::from(stdout);
        let mut filling_writer = PtyOutput::new(stdout.try_clone().unwrap()).unwrap();
        let capacity = fcntl(&stdout, FcntlArg::F_GETPIPE_SZ).unwrap() as usize;
        assert_eq!(
            filling_writer.write(&vec![b'x'; capacity]).unwrap(),
            capacity
        );
        assert!(
            !OFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFL).unwrap())
                .contains(OFlag::O_NONBLOCK)
        );
        drop(filling_writer);

        let pty = nix::pty::openpty(None, None).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf output; sleep 0.2"])
            .stdout(Stdio::from(pty.slave))
            .spawn()
            .unwrap();
        let (server, _client) = UnixStream::pair().unwrap();
        let server: OwnedFd = server.into();
        let conn = super::LocalSocketStream::UdSocket(server.into());
        let client_fds = (
            stdin,
            stdout.into(),
            File::open("/dev/null").unwrap().into(),
        );
        let (finished, result) = std::sync::mpsc::channel();
        let handler = std::thread::spawn(move || {
            let result = super::wait_for_application(
                &mut child,
                &conn,
                Some(pty.master),
                Some(&client_fds),
                Some("launch notice\n".into()),
                Some(&client_fds.1),
            );
            let _ = finished.send(result);
        });
        let status = result.recv_timeout(Duration::from_secs(3));
        // Release any blocked output write before joining even if the check fails.
        drop(stdout_reader);
        handler.join().unwrap();
        assert!(
            status
                .expect("PTY handler blocked on stdout")
                .unwrap()
                .success()
        );
    }

    #[test]
    fn partial_control_frame_does_not_block_terminal_signal_shutdown() {
        use super::{
            Arc, AtomicBool, LocalSocketStream, Ordering, OwnedFd, Write, forward_terminal_signals,
            thread,
        };
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("ctrl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let server_fd: OwnedFd = server.into();
        let stream = LocalSocketStream::UdSocket(server_fd.into());
        let terminal = std::fs::File::open("/dev/null").unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let handle = thread::spawn(move || {
            forward_terminal_signals(stream, terminal, nix::unistd::Pid::from_raw(-1), done_clone);
        });
        // Send only 2 bytes of a 4-byte length prefix and keep the socket open.
        client.write_all(&[0x00, 0x00]).unwrap();
        thread::sleep(std::time::Duration::from_millis(60));
        done.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            handle.is_finished(),
            "forward_terminal_signals blocked on stalled partial frame"
        );
        handle.join().unwrap();
        drop(client);
    }

    #[test]
    fn pty_output_rejects_non_writable_and_accmode_fds() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        std::fs::write(&path, "ok").unwrap();

        let readonly = std::fs::File::open(&path).unwrap();
        assert_eq!(
            super::PtyOutput::new(readonly)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(nix::libc::EBADF)
        );

        // Linux mode 3 (O_ACCMODE = O_WRONLY | O_RDWR) opens an FD that is
        // neither readable nor writable; PtyOutput must reject it.
        if let Ok(mode3) = std::fs::OpenOptions::new()
            .custom_flags(nix::libc::O_ACCMODE)
            .open(&path)
        {
            assert_eq!(
                super::PtyOutput::new(mode3).err().unwrap().raw_os_error(),
                Some(nix::libc::EBADF)
            );
        }
    }
}
