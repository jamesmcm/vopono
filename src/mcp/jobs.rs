//! Bounded, session-local jobs over the existing authenticated daemon protocol.
use crate::args::ExecCommand;
use crate::daemon::{self, DaemonRequest, DaemonResponse};
use anyhow::{Context, ensure};
use interprocess::local_socket::ToFsName;
use interprocess::local_socket::prelude::*;
use interprocess::os::unix::local_socket::FilesystemUdSocket;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::unistd::pipe2;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const CAPTURE_BYTES: usize = 64 * 1024;
const HISTORY: usize = 64;

#[derive(Default)]
pub(super) struct Capture {
    bytes: VecDeque<u8>,
    total: u64,
}
impl Capture {
    pub(super) fn append(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        let bytes = &bytes[bytes.len().saturating_sub(CAPTURE_BYTES)..];
        let excess = (self.bytes.len() + bytes.len()).saturating_sub(CAPTURE_BYTES);
        self.bytes.drain(..excess);
        self.bytes.extend(bytes);
    }
    pub(super) fn output(&self, offset: u64, limit: usize) -> Value {
        let oldest = self.total - self.bytes.len() as u64;
        let start = offset.max(oldest).min(self.total);
        let bytes: Vec<_> = self
            .bytes
            .iter()
            .skip((start - oldest) as usize)
            .take(limit)
            .copied()
            .collect();
        json!({"text": String::from_utf8_lossy(&bytes), "start_offset": start,
            "next_offset": start + bytes.len() as u64, "total_bytes": self.total,
            "dropped_bytes": oldest.saturating_sub(offset)})
    }
    pub(super) fn complete_bytes(&self) -> Option<Vec<u8>> {
        (self.total == self.bytes.len() as u64).then(|| self.bytes.iter().copied().collect())
    }
}

struct State {
    phase: &'static str,
    exit_code: Option<i32>,
    error: Option<Value>,
    cleanup_error: bool,
}
pub(super) struct Job {
    pub id: String,
    pub namespace: String,
    profile: String,
    state: Mutex<State>,
    stdout: Mutex<Capture>,
    stderr: Mutex<Capture>,
    cancel: AtomicBool,
    done: AtomicBool,
}
impl Job {
    pub fn status(&self) -> Value {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        json!({"version":1, "job_id":self.id, "profile":self.profile,
            "namespace":self.namespace, "state":state.phase,
            "exit_code":state.exit_code, "error":state.error,
            "cleanup_pending":state.cleanup_error,
            "finished":self.done.load(Ordering::Acquire)})
    }
    pub fn output(&self, stdout: u64, stderr: u64, limit: usize) -> Value {
        json!({"version":1,"job_id":self.id,
            "stdout":self.stdout.lock().unwrap_or_else(|p|p.into_inner()).output(stdout,limit),
            "stderr":self.stderr.lock().unwrap_or_else(|p|p.into_inner()).output(stderr,limit),
            "finished":self.done.load(Ordering::Acquire)})
    }
    pub fn cancel(&self) -> Value {
        if !self.done.load(Ordering::Acquire) {
            self.cancel.store(true, Ordering::Release);
        } else if self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cleanup_error
            && std::path::Path::new("/run/netns")
                .join(&self.namespace)
                .try_exists()
                .unwrap_or(false)
            && cleanup_namespace(&self.namespace, std::env::var("XDG_CONFIG_HOME").ok()).is_ok()
        {
            // Retry only an actually present namespace. Absence alone cannot
            // rule out a still-pending launch after an indeterminate response.
            self.cancel.store(true, Ordering::Release);
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .cleanup_error = false;
        }
        let mut report = self.status();
        report["cancel_requested"] = json!(self.cancel.load(Ordering::Acquire));
        report
    }
}

pub(super) struct Jobs {
    nonce: String,
    sequence: u64,
    jobs: BTreeMap<u64, Arc<Job>>,
    limit: usize,
}
impl Jobs {
    pub fn new(limit: usize) -> anyhow::Result<Self> {
        let mut nonce = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        Ok(Self {
            nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
            sequence: 0,
            jobs: BTreeMap::new(),
            limit,
        })
    }
    pub fn get(&self, id: &str) -> anyhow::Result<&Arc<Job>> {
        self.jobs
            .values()
            .find(|job| job.id == id)
            .context("Unknown or expired job ID in this MCP session")
    }
    pub fn start(
        &mut self,
        mut command: ExecCommand,
        profile: String,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        ensure!(
            self.jobs
                .values()
                .filter(|j| !j.done.load(Ordering::Acquire))
                .count()
                < self.limit,
            "MCP active job limit reached; cancel or wait for an existing job"
        );
        self.reserve_history()?;
        // Refuse any launch without the daemon, including an incompatible peer.
        // No CLI subprocess, sudo fallback or automatic provider sync is used.
        let status = daemon::status();
        ensure!(
            status.available && status.compatible,
            "A compatible vopono daemon must already be running"
        );
        self.sequence += 1;
        let id = format!("{}-{}", self.nonce, self.sequence);
        let namespace = crate::namespace_ownership::name_for_uid(
            &format!("mcp-{id}"),
            nix::unistd::Uid::current(),
        )?;
        command.custom_netns_name = Some(format!("mcp-{id}"));
        command.json = true;
        command.silent = false;
        if command.working_directory.is_none() {
            command.working_directory =
                Some(std::env::current_dir()?.to_string_lossy().into_owned());
        }
        crate::resolve_custom_path_for_daemon(&mut command, &std::env::current_dir()?);
        if !command.literal_application && !command.application.is_empty() {
            command.application = shellexpand::full(&command.application)
                .map_err(|_| anyhow::anyhow!("Shell expansion failed for the profile command"))?
                .into_owned();
            command.literal_application = true;
        }
        let mut conn = connect()?;
        let (stdout_read, stdout_write) = pipe2(OFlag::O_CLOEXEC)?;
        let (stderr_read, stderr_write) = pipe2(OFlag::O_CLOEXEC)?;
        let stdin = File::open("/dev/null")?;
        let request = DaemonRequest::Execute {
            cmd: serde_json::to_vec(&command)?,
            env: std::env::vars().collect(),
        };
        daemon::write_framed(&mut conn, &wincode::serialize(&request)?)?;
        // Once Execute has been sent, descriptor delivery is part of that
        // request. Never fall back or retry the launch on an ambiguous failure.
        crate::send_fds_over_unix_socket(
            &conn,
            &[
                stdin.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
            ],
        )?;
        drop((stdin, stdout_write, stderr_write));
        conn.set_nonblocking(true)?;
        let mut stdout = File::from(stdout_read);
        let mut stderr = File::from(stderr_read);
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let job = Arc::new(Job {
            id,
            namespace,
            profile,
            state: Mutex::new(State {
                phase: "starting",
                exit_code: None,
                error: None,
                cleanup_error: false,
            }),
            stdout: Mutex::new(Capture::default()),
            stderr: Mutex::new(Capture::default()),
            cancel: AtomicBool::new(false),
            done: AtomicBool::new(false),
        });
        self.jobs.insert(self.sequence, job.clone());
        let worker_job = job.clone();
        let config_home = std::env::var("XDG_CONFIG_HOME").ok();
        std::thread::spawn(move || {
            let result = supervise(&worker_job, &mut conn, &mut stdout, &mut stderr, timeout);
            drop(conn);
            let cleaned = cleanup_namespace(&worker_job.namespace, config_home).is_ok();
            // Drain pending bytes, but descendants holding a pipe open cannot
            // pin a worker or defeat the capture budget.
            for _ in 0..16 {
                drain(&mut stdout, &worker_job.stdout);
                drain(&mut stderr, &worker_job.stderr);
            }
            let mut state = worker_job.state.lock().unwrap_or_else(|p| p.into_inner());
            match result {
                Ok(DaemonResponse::Exit(code)) => {
                    state.exit_code = Some(code);
                    state.phase = if worker_job.cancel.load(Ordering::Acquire) {
                        "cancelled"
                    } else if code == 0 {
                        "completed"
                    } else {
                        "failed"
                    };
                }
                Ok(DaemonResponse::Json(bytes)) => {
                    // An explicit stop can make a keep-alive handler reject
                    // its final persistence update. Confirmed cleanup still
                    // completes cancellation; retain the daemon's diagnosis.
                    state.phase = if worker_job.cancel.load(Ordering::Acquire) && cleaned {
                        "cancelled"
                    } else {
                        "failed"
                    };
                    state.error = serde_json::from_slice(&bytes).ok();
                }
                _ => {
                    state.phase = "indeterminate";
                    state.error = Some(
                        json!({"message":"Daemon result unavailable; do not automatically relaunch. Inspect this namespace with vopono status."}),
                    );
                }
            }
            state.cleanup_error = !cleaned || state.phase == "indeterminate";
            drop(state);
            worker_job.done.store(true, Ordering::Release);
        });
        Ok(job.status())
    }
    fn reserve_history(&mut self) -> anyhow::Result<()> {
        if self.jobs.len() >= HISTORY
            && let Some(key) = self
                .jobs
                .iter()
                .find(|(_, job)| {
                    job.done.load(Ordering::Acquire)
                        && !job
                            .state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .cleanup_error
                })
                .map(|(key, _)| *key)
        {
            self.jobs.remove(&key);
        }
        ensure!(
            self.jobs.len() < HISTORY,
            "MCP job history is full of unresolved cleanups; inspect namespaces before restarting this session"
        );
        Ok(())
    }
    pub fn shutdown(&self) {
        for job in self
            .jobs
            .values()
            .filter(|job| !job.done.load(Ordering::Acquire))
        {
            job.cancel();
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while self.jobs.values().any(|j| !j.done.load(Ordering::Acquire))
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        for job in self.jobs.values().filter(|j| {
            !j.done.load(Ordering::Acquire)
                || j.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .cleanup_error
        }) {
            log::warn!(
                "MCP shutdown could not confirm cleanup of {}; inspect vopono status and stop this namespace if necessary",
                job.namespace
            );
        }
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(super) fn connect() -> anyhow::Result<LocalSocketStream> {
    let mut conn =
        LocalSocketStream::connect(crate::SOCKET_PATH.to_fs_name::<FilesystemUdSocket>()?)
            .context("Vopono daemon is unavailable; start it separately as an administrator")?;
    // Check the credentials on this exact connection, not just the path.
    let LocalSocketStream::UdSocket(socket) = &conn;
    ensure!(
        nix::sys::socket::getsockopt(&socket.as_fd(), nix::sys::socket::sockopt::PeerCredentials)?
            .uid()
            == 0,
        "Vopono daemon socket must belong to a root process"
    );
    daemon::set_socket_timeouts_for(&conn, 2)?;
    daemon::write_framed(
        &mut conn,
        &wincode::serialize(&DaemonRequest::ClientVersion(
            env!("CARGO_PKG_VERSION").into(),
        ))?,
    )?;
    let version = daemon::read_framed(&mut conn, daemon::MAX_FRAME_LEN)?;
    ensure!(
        matches!(wincode::deserialize::<DaemonResponse>(&version)?,DaemonResponse::Version(ref version) if version==env!("CARGO_PKG_VERSION")),
        "MCP requires a matching daemon version; restart or update the daemon"
    );
    Ok(conn)
}

fn cleanup_namespace(name: &str, config_home: Option<String>) -> anyhow::Result<()> {
    let path = std::path::Path::new("/run/netns").join(name);
    if !path.try_exists()? {
        return Ok(());
    }
    let result = (|| -> anyhow::Result<()> {
        let mut conn = connect()?;
        daemon::set_socket_timeouts_for(&conn, 3)?;
        let request = DaemonRequest::Stop(daemon::DaemonStopRequest {
            target: daemon::DaemonStopTarget::Namespace(name.into()),
            config_home,
        });
        daemon::write_framed(&mut conn, &wincode::serialize(&request)?)?;
        let response = daemon::read_framed(&mut conn, daemon::MAX_FRAME_LEN)?;
        ensure!(
            matches!(
                wincode::deserialize::<DaemonResponse>(&response)?,
                DaemonResponse::Json(_)
            ),
            "Namespace stop failed"
        );
        Ok(())
    })();
    // Completion and stop can race; verified absence is authoritative.
    ensure!(!path.try_exists()?, "Namespace cleanup is pending");
    let _ = result;
    Ok(())
}

pub(super) fn nonblocking(file: &File) -> anyhow::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL)?);
    fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}
// Limit bytes per tick as well as retained bytes: a noisy application must not
// starve cancellation or monopolize the worker indefinitely.
fn drain(file: &mut File, capture: &Mutex<Capture>) {
    let mut bytes = [0u8; 4096];
    for _ in 0..16 {
        match file.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => capture
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(&bytes[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}
fn supervise(
    job: &Job,
    conn: &mut LocalSocketStream,
    stdout: &mut File,
    stderr: &mut File,
    timeout: Duration,
) -> anyhow::Result<DaemonResponse> {
    let deadline = Instant::now() + timeout;
    let mut cancellation = None;
    let mut killed = false;
    let mut response = Vec::new();
    loop {
        drain(stdout, &job.stdout);
        drain(stderr, &job.stderr);
        let now = Instant::now();
        if cancellation.is_none() && (job.cancel.load(Ordering::Acquire) || now >= deadline) {
            job.cancel.store(true, Ordering::Release);
            job.state.lock().unwrap_or_else(|p| p.into_inner()).phase = "cancelling";
            // Stop this job's dedicated namespace through the existing control
            // path, which terminates and reaps the application's descendants.
            // Non-TTY daemon executions do not consume signal control frames.
            let _ = cleanup_namespace(&job.namespace, std::env::var("XDG_CONFIG_HOME").ok());
            cancellation = Some(now);
        }
        if let Some(started) = cancellation {
            if !killed && now.duration_since(started) >= Duration::from_secs(2) {
                let _ = cleanup_namespace(&job.namespace, std::env::var("XDG_CONFIG_HOME").ok());
                killed = true;
            }
            ensure!(
                now.duration_since(started) < Duration::from_secs(5),
                "Cancellation result is indeterminate"
            );
        } else if crate::mcp::job_application_registered(&job.namespace) {
            job.state.lock().unwrap_or_else(|p| p.into_inner()).phase = "running";
        }
        let mut chunk = [0u8; 4096];
        match conn.read(&mut chunk) {
            Ok(0) => anyhow::bail!("Daemon disconnected"),
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
        if response.len() >= 4 {
            let size = u32::from_be_bytes(response[..4].try_into()?) as usize;
            ensure!(size <= daemon::MAX_FRAME_LEN, "Oversized daemon reply");
            if response.len() >= size + 4 {
                return Ok(wincode::deserialize(&response[4..size + 4])?);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read-only CLI commands use the same bounded capture without borrowing MCP
/// stdout. Killing a process group also closes descendants' inherited pipes.
pub(super) fn json_command(args: &[String], timeout: Duration) -> anyhow::Result<(Value, bool)> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut child = Command::new(std::env::current_exe()?)
        .args(args)
        .env("RUST_LOG", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let pid = nix::unistd::Pid::from_raw(-(child.id() as i32));
    let stdout = child.stdout.take().context("Missing command output")?;
    let mut stdout = File::from(std::os::fd::OwnedFd::from(stdout));
    nonblocking(&stdout)?;
    let capture = Mutex::new(Capture::default());
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        drain(&mut stdout, &capture);
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                break Err(anyhow::anyhow!(
                    "Diagnostic command timed out or could not be inspected"
                ));
            }
        }
    };
    if outcome.is_err() {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
    }
    let status = outcome?;
    drain(&mut stdout, &capture);
    let bytes = capture
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .complete_bytes()
        .context("Diagnostic result exceeded output limit")?;
    Ok((
        serde_json::from_slice(&bytes).context("Diagnostic command did not return JSON")?,
        !status.success(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_bounds_memory_and_reports_lost_bytes_and_polling_offsets() {
        let mut capture = Capture::default();
        capture.append(&vec![b'x'; CAPTURE_BYTES + 30]);
        assert_eq!(capture.bytes.len(), CAPTURE_BYTES);
        let first = capture.output(0, 10);
        assert_eq!(first["dropped_bytes"], 30);
        assert_eq!(first["next_offset"], 40);
        capture.append(b"tail");
        assert_eq!(
            capture.output((CAPTURE_BYTES + 30) as u64, 4)["text"],
            "tail"
        );
        assert!(capture.complete_bytes().is_none());
    }

    #[test]
    fn history_preserves_unresolved_namespace_identities_and_rejects_overflow() {
        let mut jobs = Jobs::new(1).unwrap();
        for id in 0..HISTORY as u64 {
            jobs.jobs.insert(
                id,
                Arc::new(Job {
                    id: id.to_string(),
                    namespace: format!("unresolved-{id}"),
                    profile: "test".into(),
                    state: Mutex::new(State {
                        phase: "indeterminate",
                        exit_code: None,
                        error: None,
                        cleanup_error: true,
                    }),
                    stdout: Mutex::default(),
                    stderr: Mutex::default(),
                    cancel: AtomicBool::new(false),
                    done: AtomicBool::new(true),
                }),
            );
        }
        assert!(jobs.reserve_history().is_err());
        assert_eq!(jobs.jobs.len(), HISTORY);
        jobs.jobs[&0].state.lock().unwrap().cleanup_error = false;
        jobs.reserve_history().unwrap();
        assert_eq!(jobs.jobs.len(), HISTORY - 1);
        assert!(jobs.get("1").is_ok());
        assert!(jobs.get("0").is_err());
    }
}
