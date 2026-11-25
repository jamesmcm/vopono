//! Bounded, session-local jobs over the existing authenticated daemon protocol.
use crate::args::ExecCommand;
use crate::daemon::{self, DaemonRequest, DaemonResponse};
use anyhow::{Context, ensure};
use interprocess::local_socket::prelude::*;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::unistd::pipe2;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
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
        let mut bytes: Vec<_> = self
            .bytes
            .iter()
            .skip((start - oldest) as usize)
            .take(limit)
            .copied()
            .collect();
        // Avoid splitting a multi-byte UTF-8 character across pagination boundaries
        // when more bytes follow in the capture buffer.
        if bytes.len() == limit && start + (bytes.len() as u64) < self.total {
            let floor = bytes.len().saturating_sub(3);
            if let Some(lead) = (floor..bytes.len())
                .rev()
                .find(|&idx| (bytes[idx] & 0xC0) != 0x80)
                && lead > 0
                && let Err(err) = std::str::from_utf8(&bytes[lead..])
                && err.error_len().is_none()
            {
                bytes.truncate(lead);
            }
        }
        json!({"text": String::from_utf8_lossy(&bytes), "start_offset": start,
            "next_offset": start + bytes.len() as u64, "total_bytes": self.total,
            "dropped_bytes": oldest.saturating_sub(offset)})
    }
    #[cfg(test)]
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
    timed_out: AtomicBool,
    done: AtomicBool,
    stop_in_flight: Arc<AtomicBool>,
}
impl Job {
    fn finish(&self, result: anyhow::Result<DaemonResponse>, cleaned: bool) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok(DaemonResponse::Exit(code)) => {
                state.exit_code = Some(code);
                state.phase = if self.cancel.load(Ordering::Acquire) {
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
                state.phase = if self.cancel.load(Ordering::Acquire) && cleaned {
                    "cancelled"
                } else {
                    "failed"
                };
                state.error = Some(
                    serde_json::from_slice::<Value>(&bytes)
                        .map(|mut error| {
                            // Preserve the existing job-level message alongside the
                            // full daemon error document and its diagnostic context.
                            if let Some(message) = error.pointer("/error/message").cloned() {
                                error["message"] = message;
                            }
                            error
                        })
                        .unwrap_or_else(
                            |_| json!({"message": "Daemon reported an unparsable error"}),
                        ),
                );
            }
            Ok(DaemonResponse::Error(message)) => {
                state.phase = "failed";
                state.error = Some(json!({"message": refusal_reason(&message)}));
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
        self.done.store(true, Ordering::Release);
    }

    pub fn status(&self) -> Value {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        json!({"version":1, "job_id":self.id, "profile":self.profile,
            "namespace":self.namespace, "state":state.phase,
            "exit_code":state.exit_code, "error":state.error,
            "timed_out":self.timed_out.load(Ordering::Acquire),
            "cleanup_pending":state.cleanup_error,
            "finished":self.done.load(Ordering::Acquire)})
    }
    pub fn output(&self, stdout: u64, stderr: u64, limit: usize) -> Value {
        json!({"version":1,"job_id":self.id,
            "stdout":self.stdout.lock().unwrap_or_else(|p|p.into_inner()).output(stdout,limit),
            "stderr":self.stderr.lock().unwrap_or_else(|p|p.into_inner()).output(stderr,limit),
            "finished":self.done.load(Ordering::Acquire)})
    }
    pub fn cancel(self: &Arc<Self>) -> Value {
        if !self.done.load(Ordering::Acquire) {
            self.cancel.store(true, Ordering::Release);
        } else {
            let (needs_cleanup, is_indeterminate) = {
                let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                (state.cleanup_error, state.phase == "indeterminate")
            };
            if needs_cleanup {
                let exists = std::path::Path::new("/run/netns")
                    .join(&self.namespace)
                    .try_exists()
                    .unwrap_or(true);
                if exists {
                    let config_home = std::env::var("XDG_CONFIG_HOME").ok();
                    // Keep synchronous retry bounded so a slow daemon teardown cannot
                    // freeze the single-threaded MCP stdio loop for 30s.
                    if cleanup_namespace_with_timeout(&self.namespace, config_home.clone(), 5)
                        .is_ok()
                    {
                        self.cancel.store(true, Ordering::Release);
                        self.state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .cleanup_error = false;
                    } else {
                        spawn_stop_request(
                            self.namespace.clone(),
                            config_home,
                            Arc::clone(&self.stop_in_flight),
                            Some(Arc::clone(self)),
                        );
                    }
                } else if !is_indeterminate {
                    // For a definite terminal state whose cleanup timed out while the
                    // daemon finished tearing down, confirmed absence clears the flag.
                    self.state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .cleanup_error = false;
                }
            }
        }
        let mut report = self.status();
        report["cancel_requested"] = json!(self.cancel.load(Ordering::Acquire));
        report
    }
}

// Raw daemon errors can contain user-controlled paths/context. Keep only
// reviewed, fixed refusal reasons; an unknown refusal is still a definite result.
fn refusal_reason(message: &str) -> &'static str {
    match message.split([':', ';']).next().unwrap_or("").trim() {
        "Concurrent daemon execution limit reached" => "Concurrent daemon execution limit reached",
        "No usable config directory for client" => "No usable config directory for client",
        _ => "Daemon rejected the execution request",
    }
}

/// Allowlist only safe runtime/desktop variables for MCP-launched jobs so agent
/// harness secrets (API keys, cloud tokens) are never forwarded to applications.
fn filtered_mcp_env() -> std::collections::HashMap<String, String> {
    const EXACT: &[&str] = &[
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TERM",
        "COLORTERM",
        "LANG",
        "TZ",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "PULSE_SERVER",
        "PIPEWIRE_REMOTE",
        "TMPDIR",
        "NO_COLOR",
    ];
    std::env::vars()
        .filter(|(k, _)| {
            EXACT.contains(&k.as_str()) || k.starts_with("LC_") || k.starts_with("XDG_")
        })
        .collect()
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
        // Connect with exact version match; no CLI subprocess, sudo fallback or sync.
        let mut conn = connect()?;
        self.sequence += 1;
        let id = format!("{}-{}", self.nonce, self.sequence);
        let namespace = crate::namespace_ownership::name_for_uid(
            &format!("mcp-{id}"),
            nix::unistd::Uid::current(),
        )?;
        command.custom_netns_name = Some(format!("mcp-{id}"));
        command.json = true;
        command.silent = false;
        let request =
            crate::daemon_client::prepare_execute_with_env(command, false, filtered_mcp_env())?;
        // Set O_NONBLOCK on pipe read ends before sending Execute so no post-send
        // setup call can fail and leak an untracked job.
        let (stdout_read, stdout_write) = pipe2(OFlag::O_CLOEXEC)?;
        let (stderr_read, stderr_write) = pipe2(OFlag::O_CLOEXEC)?;
        let mut stdout = File::from(stdout_read);
        let mut stderr = File::from(stderr_read);
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let stdin = File::open("/dev/null")?;
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
            timed_out: AtomicBool::new(false),
            done: AtomicBool::new(false),
            stop_in_flight: Arc::new(AtomicBool::new(false)),
        });
        daemon::write_framed(&mut conn, &wincode::serialize(&request)?)?;
        // Once Execute has been sent, track the job immediately so any later
        // setup failure transitions to indeterminate with tracked cleanup.
        self.jobs.insert(self.sequence, job.clone());
        let post_send = (|| -> anyhow::Result<()> {
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
            Ok(())
        })();
        if let Err(error) = post_send {
            drop(conn);
            let cleaned =
                cleanup_namespace(&job.namespace, std::env::var("XDG_CONFIG_HOME").ok()).is_ok();
            job.finish(Err(error), cleaned);
            return Ok(job.status());
        }
        let worker_job = job.clone();
        let config_home = std::env::var("XDG_CONFIG_HOME").ok();
        let spawn_result = std::thread::Builder::new()
            .name("mcp-job".into())
            .spawn(move || {
                let result = supervise(&worker_job, &mut conn, &mut stdout, &mut stderr, timeout);
                drop(conn);
                let cleaned = if result.is_err() && worker_job.cancel.load(Ordering::Acquire) {
                    // Cancellation already timed out in `supervise` with an in-flight stop;
                    // do a short final check rather than stacking another 30s blocking stop
                    // past `Jobs::shutdown`'s deadline.
                    cleanup_namespace_with_timeout(&worker_job.namespace, config_home, 4).is_ok()
                } else {
                    cleanup_namespace(&worker_job.namespace, config_home).is_ok()
                };
                // Drain pending bytes, but descendants holding a pipe open cannot
                // pin a worker or defeat the capture budget.
                for _ in 0..16 {
                    drain(&mut stdout, &worker_job.stdout);
                    drain(&mut stderr, &worker_job.stderr);
                }
                worker_job.finish(result, cleaned);
            });
        if let Err(error) = spawn_result {
            let cleaned =
                cleanup_namespace(&job.namespace, std::env::var("XDG_CONFIG_HOME").ok()).is_ok();
            job.finish(Err(error.into()), cleaned);
        }
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
        // Exceeds supervise()'s 16s cancellation window plus the 4s final cleanup
        // check so shutdown waits cleanly for worker completion.
        let deadline = Instant::now() + Duration::from_secs(25);
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
    crate::daemon_client::connect(crate::daemon_client::Compatibility::Exact)
}

fn cleanup_namespace(name: &str, config_home: Option<String>) -> anyhow::Result<()> {
    cleanup_namespace_with_timeout(name, config_home, daemon::DAEMON_STOP_TIMEOUT_SECONDS)
}

fn cleanup_namespace_with_timeout(
    name: &str,
    config_home: Option<String>,
    timeout_seconds: i64,
) -> anyhow::Result<()> {
    let path = std::path::Path::new("/run/netns").join(name);
    if !path.try_exists()? {
        return Ok(());
    }
    let result = (|| -> anyhow::Result<()> {
        let mut conn = connect()?;
        daemon::set_socket_timeouts_for(&conn, timeout_seconds)?;
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

struct ClearOnDrop(Arc<AtomicBool>);
impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn spawn_stop_request(
    name: String,
    config_home: Option<String>,
    in_flight: Arc<AtomicBool>,
    completion_job: Option<Arc<Job>>,
) {
    // At most one in-flight Stop per job so retries never exhaust daemon MAX_CLIENTS_PER_UID.
    if in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let guard = ClearOnDrop(in_flight);
    if let Err(error) = std::thread::Builder::new()
        .name("mcp-stop".into())
        .spawn(move || {
            let _guard = guard;
            if cleanup_namespace(&name, config_home).is_ok()
                && let Some(job) = completion_job
            {
                job.cancel.store(true, Ordering::Release);
                job.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .cleanup_error = false;
            }
        })
    {
        log::warn!("Failed to spawn MCP namespace stop thread: {error}");
    }
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
    let mut cancellation: Option<Instant> = None;
    let mut last_stop_attempt: Option<Instant> = None;
    let mut running = false;
    let mut response = Vec::new();
    let config_home = std::env::var("XDG_CONFIG_HOME").ok();
    loop {
        drain(stdout, &job.stdout);
        drain(stderr, &job.stderr);
        // Always check for a daemon response BEFORE enforcing cancellation timeout
        // so an already-buffered Exit/Error is never misclassified as indeterminate.
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
        let now = Instant::now();
        let cancel_requested = job.cancel.load(Ordering::Acquire);
        if cancellation.is_none() && (cancel_requested || now >= deadline) {
            if !cancel_requested && now >= deadline {
                job.timed_out.store(true, Ordering::Release);
            }
            job.cancel.store(true, Ordering::Release);
            job.state.lock().unwrap_or_else(|p| p.into_inner()).phase = "cancelling";
            // Send stop asynchronously so pipe draining and conn reads never stall.
            spawn_stop_request(
                job.namespace.clone(),
                config_home.clone(),
                Arc::clone(&job.stop_in_flight),
                None,
            );
            cancellation = Some(now);
            last_stop_attempt = Some(now);
        }
        if let Some(started) = cancellation {
            // Re-issue stop if the namespace appears during a slow "starting" phase
            // or if the initial stop raced namespace creation.
            if last_stop_attempt
                .is_none_or(|prev| now.duration_since(prev) >= Duration::from_secs(2))
                && std::path::Path::new("/run/netns")
                    .join(&job.namespace)
                    .try_exists()
                    .unwrap_or(false)
            {
                spawn_stop_request(
                    job.namespace.clone(),
                    config_home.clone(),
                    Arc::clone(&job.stop_in_flight),
                    None,
                );
                last_stop_attempt = Some(now);
            }
            ensure!(
                now.duration_since(started) < Duration::from_secs(16),
                "Cancellation result is indeterminate"
            );
        } else if !running && crate::mcp::job_application_registered(&job.namespace) {
            running = true;
            job.state.lock().unwrap_or_else(|p| p.into_inner()).phase = "running";
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read-only CLI commands use bounded JSON capture without borrowing MCP stdout.
/// Killing a process group also closes descendants' inherited pipes.
pub(super) fn json_command(
    args: &[String],
    timeout: Duration,
    stopping: &AtomicBool,
) -> anyhow::Result<(Value, bool)> {
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
    let mut bytes = Vec::new();
    let mut reaped = false;
    let outcome = (|| -> anyhow::Result<std::process::ExitStatus> {
        let stdout = child.stdout.take().context("Missing command output")?;
        let mut stdout = File::from(std::os::fd::OwnedFd::from(stdout));
        nonblocking(&stdout)?;
        // A namespace report includes both current diagnostics and cached monitor
        // evidence. Keep this larger than job log history, without truncating JSON
        // or increasing the per-job stdout/stderr buffers.
        const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
        let deadline = Instant::now() + timeout;
        loop {
            read_diagnostics(&mut stdout, &mut bytes, MAX_DIAGNOSTIC_BYTES)?;
            if stopping.load(Ordering::Acquire) {
                anyhow::bail!("Diagnostic command interrupted by MCP shutdown");
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    reaped = true;
                    read_diagnostics(&mut stdout, &mut bytes, MAX_DIAGNOSTIC_BYTES)?;
                    return Ok(status);
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    anyhow::bail!("Diagnostic command timed out or could not be inspected");
                }
            }
        }
    })();
    if outcome.is_err() && !reaped {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
    }
    let status = outcome?;
    Ok((
        serde_json::from_slice(&bytes).context("Diagnostic command did not return JSON")?,
        !status.success(),
    ))
}

fn read_diagnostics(
    input: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
) -> anyhow::Result<()> {
    let mut chunk = [0u8; 8192];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                ensure!(
                    output.len() + count <= limit,
                    "Diagnostic result exceeded output limit"
                );
                output.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_reports_exceeding_job_history_are_complete_but_bounded() {
        let bytes = vec![b'x'; CAPTURE_BYTES + 8192];
        let mut output = Vec::new();
        read_diagnostics(&mut std::io::Cursor::new(&bytes), &mut output, 1024 * 1024).unwrap();
        assert_eq!(output, bytes);
        let mut output = Vec::new();
        assert!(
            read_diagnostics(
                &mut std::io::Cursor::new(&bytes),
                &mut output,
                CAPTURE_BYTES
            )
            .is_err()
        );
        assert!(output.len() <= CAPTURE_BYTES);
    }
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
                    timed_out: AtomicBool::new(false),
                    done: AtomicBool::new(true),
                    stop_in_flight: Arc::new(AtomicBool::new(false)),
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

    #[test]
    fn explicit_refusals_are_failed_redacted_and_evictable_but_disconnects_are_not() {
        let mut jobs = Jobs::new(1).unwrap();
        for id in 0..=HISTORY as u64 {
            jobs.reserve_history().unwrap();
            let job = Arc::new(Job {
                id: id.to_string(),
                namespace: format!("refused-{id}"),
                profile: "test".into(),
                state: Mutex::new(State {
                    phase: "starting",
                    exit_code: None,
                    error: None,
                    cleanup_error: false,
                }),
                stdout: Mutex::default(),
                stderr: Mutex::default(),
                cancel: AtomicBool::new(false),
                timed_out: AtomicBool::new(false),
                done: AtomicBool::new(false),
                stop_in_flight: Arc::new(AtomicBool::new(false)),
            });
            job.finish(
                Ok(DaemonResponse::Error(
                    "Concurrent daemon execution limit reached: NEVER_SHARE".into(),
                )),
                true,
            );
            let report = job.status();
            assert_eq!(report["state"], "failed");
            assert_eq!(report["cleanup_pending"], false);
            assert!(
                report["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("execution limit")
            );
            assert!(!report.to_string().contains("NEVER_SHARE"));
            jobs.jobs.insert(id, job);
        }
        assert!(jobs.get("0").is_err());
        let job = jobs.jobs.values().next().unwrap();
        job.finish(
            Ok(DaemonResponse::Error("unreviewed NEVER_SHARE".into())),
            false,
        );
        assert_eq!(job.status()["cleanup_pending"], true);
        assert!(!job.status().to_string().contains("NEVER_SHARE"));
        job.finish(Err(anyhow::anyhow!("Daemon disconnected")), true);
        assert_eq!(job.status()["state"], "indeterminate");
        assert_eq!(job.status()["cleanup_pending"], true);
    }

    #[test]
    fn capture_pagination_preserves_multibyte_utf8_boundaries() {
        let mut capture = Capture::default();
        // Splits both a 3-byte ('€') and a 4-byte ('😀') character on 4-byte chunk boundaries.
        let text = "ab€cd😀e";
        capture.append(text.as_bytes());
        let mut reassembled = String::new();
        let mut offset = 0u64;
        while offset < text.len() as u64 {
            let chunk = capture.output(offset, 4);
            let piece = chunk["text"].as_str().unwrap();
            let next = chunk["next_offset"].as_u64().unwrap();
            assert!(next > offset, "pagination must make forward progress");
            assert!(
                !piece.contains('\u{FFFD}'),
                "chunk must not split UTF-8 codepoint: {piece:?}"
            );
            reassembled.push_str(piece);
            offset = next;
        }
        assert_eq!(reassembled, text);
    }
}
