use anyhow::Result;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use vopono_core::network::netns::NetworkNamespace;
use vopono_core::status::read_lock_namespaces;
use vopono_core::util::{
    check_process_running, get_existing_namespaces, get_pids_in_namespace,
    process_is_in_network_namespace, remove_lock_files,
};

use crate::api::SCHEMA_VERSION;
use crate::errors::CliError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopTargetKind {
    Application,
    Namespace,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StopResult {
    pub version: u8,
    pub target: StopTargetKind,
    pub application_id: Option<String>,
    pub namespace_id: String,
    pub namespace_removed: bool,
}

pub fn stop_application(
    application_id: &str,
    requester_uid: Option<nix::unistd::Uid>,
) -> Result<StopResult> {
    let pid = application_id
        .parse::<u32>()
        .map_err(|_| CliError::InvalidApplicationId {
            id: application_id.to_string(),
        })?;
    let status = read_lock_namespaces()?;
    let Some((namespace_id, _)) = status.namespaces.iter().find_map(|(namespace, locks)| {
        locks
            .iter()
            .find(|lock| lock.application_pid == Some(pid))
            .map(|lock| (namespace.clone(), lock))
    }) else {
        return Err(CliError::ApplicationNotFound {
            id: application_id.to_string(),
        }
        .into());
    };

    vopono_core::network::netns::validate_netns_name(&namespace_id)?;

    if let Some(uid) = requester_uid {
        crate::namespace_ownership::authorize(&namespace_id, uid)?;
    }

    // Open a pidfd before verifying identity so both SIGTERM and SIGKILL target
    // this exact process instance and cannot hit an unrelated recycled PID.
    let pidfd = open_pidfd(pid);

    // Lockfiles live in a user-writable directory and PIDs can be recycled:
    // in daemon mode the request may come from any local user, so only
    // signal processes owned by the authenticated requester.
    if let Some(uid) = requester_uid {
        match process_real_uid(pid) {
            Some(owner) if owner == uid.as_raw() => {}
            other => {
                return Err(anyhow::anyhow!(
                    "Refusing to stop PID {pid} in namespace {namespace_id}: process owner {:?} does not match requesting uid {}",
                    other,
                    uid.as_raw()
                ));
            }
        }
    }

    // Lockfiles may be stale and PIDs can be recycled; never signal a process
    // that is not verifiably attached to the recorded network namespace.
    match process_is_in_network_namespace(pid, &namespace_id) {
        Ok(true) => {}
        Ok(false) => {
            return Err(CliError::ProcessNotInNamespace {
                pid,
                namespace_id: namespace_id.clone(),
            }
            .into());
        }
        Err(error) => {
            return Err(error.context(format!(
                "Refusing to stop unverified PID {pid} in namespace {namespace_id}"
            )));
        }
    }

    send_signal_verified(pid, pidfd.as_ref(), Signal::SIGTERM)?;
    wait_for_process_verified(pid, pidfd.as_ref())?;
    // Do not stall 10 seconds waiting for teardown if the namespace is explicitly
    // persistent or still hosts other live applications.
    let kept_alive = requester_uid.is_some_and(|uid| {
        crate::namespace_ownership::is_persistent(&namespace_id, uid).unwrap_or(false)
    }) || status.namespaces.get(&namespace_id).is_some_and(|locks| {
        locks.iter().any(|lock| {
            lock.application_pid.is_some_and(|other| {
                other != pid && vopono_core::status::lockfile_application_is_live(lock)
            })
        })
    });
    let namespace_removed = if kept_alive {
        !namespace_exists(&namespace_id)?
    } else {
        wait_for_namespace_removal(&namespace_id)?
    };

    Ok(StopResult {
        version: SCHEMA_VERSION,
        target: StopTargetKind::Application,
        application_id: Some(application_id.to_string()),
        namespace_id,
        namespace_removed,
    })
}

pub(crate) fn mark_namespace_stopping(namespace_id: &str, uid: nix::unistd::Uid) -> Result<()> {
    crate::namespace_ownership::mark_stopping(namespace_id, uid)?;
    let lock_dir = vopono_core::util::vopono_dir()?
        .join("locks")
        .join(namespace_id);
    if let Err(error) = vopono_core::status::record_namespace_stopping(&lock_dir) {
        log::debug!("Could not publish stopping status for {namespace_id}: {error:#}");
    }
    Ok(())
}

pub fn stop_namespace(
    namespace_id: &str,
    requester_uid: Option<nix::unistd::Uid>,
) -> Result<StopResult> {
    stop_namespace_with_wait_hook(namespace_id, requester_uid, || {})
}

pub(crate) fn stop_namespace_with_wait_hook(
    namespace_id: &str,
    requester_uid: Option<nix::unistd::Uid>,
    before_wait: impl FnOnce(),
) -> Result<StopResult> {
    let status = read_lock_namespaces()?;
    // Lockfiles can be missing (for example after a manual cleanup) while the
    // owned namespace still exists, so consult both sources.
    if !status.namespaces.contains_key(namespace_id)
        && !get_existing_namespaces()?
            .iter()
            .any(|name| name == namespace_id)
    {
        return Err(CliError::NamespaceNotFound {
            id: namespace_id.to_string(),
        }
        .into());
    }

    if let Some(uid) = requester_uid {
        crate::namespace_ownership::authorize(namespace_id, uid)?;
        // Make an explicit stop authoritative over a previous keep-alive or
        // create-only request. A live handler will observe this after its child
        // exits and perform normal teardown; an idle namespace is handled below.
        allow_completed_teardown(mark_namespace_stopping(namespace_id, uid), || {
            namespace_exists(namespace_id)
        })?;
        allow_completed_teardown(
            terminate_namespace_user_processes(namespace_id, uid),
            || namespace_exists(namespace_id),
        )?;
        let lock_dir = vopono_core::util::vopono_dir()?
            .join("locks")
            .join(namespace_id);
        // The applications terminated above leave client lockfiles whose PIDs
        // are now dead. Prune them before deciding whether a live daemon
        // session still owns the namespace: a lock leaked by an earlier
        // session must not block an explicit stop forever.
        vopono_core::status::prune_stale_client_lockfiles(&lock_dir)?;
        if !vopono_core::status::has_client_lockfiles(&lock_dir) {
            // No live application lock remains. A handler may already have
            // finished teardown; persistent namespaces need explicit cleanup.
            if let Some(namespace) = allow_completed_teardown(
                crate::namespace_ownership::load(namespace_id, uid),
                || namespace_exists(namespace_id),
            )? {
                allow_completed_teardown(namespace.teardown(), || namespace_exists(namespace_id))?;
            }
        }
        // Release any caller-held namespace transition lock before polling so a
        // live session controller (`Session::run_until_unused`) can acquire the
        // lock and complete teardown without deadlocking.
        if namespace_exists(namespace_id)? {
            before_wait();
        }
        let namespace_removed = wait_for_namespace_removal(namespace_id)?;
        if !namespace_removed {
            return Err(CliError::NamespaceTeardownFailed {
                namespace_id: namespace_id.to_string(),
            }
            .into());
        }
        crate::namespace_ownership::remove(namespace_id);
        return Ok(StopResult {
            version: SCHEMA_VERSION,
            target: StopTargetKind::Namespace,
            application_id: None,
            namespace_id: namespace_id.to_string(),
            namespace_removed,
        });
    }

    let namespace = NetworkNamespace::from_existing(namespace_id.to_string())?;
    // A namespace is shared by every application selected for the same
    // provider/server. Stopping it is therefore deliberately a group
    // operation: terminate every process still attached to the namespace,
    // including the VPN helper itself, before tearing the namespace down.
    terminate_namespace_processes(namespace_id)?;

    remove_lock_files(namespace_id)?;
    // Explicit (rather than implicit drop): removes firewall rules, veth pair,
    // runs predown, and deletes the network namespace.
    namespace.teardown()?;
    let namespace_removed = wait_for_namespace_removal(namespace_id)?;
    if !namespace_removed {
        return Err(CliError::NamespaceTeardownFailed {
            namespace_id: namespace_id.to_string(),
        }
        .into());
    }
    Ok(StopResult {
        version: SCHEMA_VERSION,
        target: StopTargetKind::Namespace,
        application_id: None,
        namespace_id: namespace_id.to_string(),
        namespace_removed,
    })
}

pub fn print_result(result: &StopResult, json: bool) -> anyhow::Result<()> {
    if json {
        crate::api::print_json(result)?;
    } else {
        println!("{}", human_summary(result));
    }
    Ok(())
}

fn human_summary(result: &StopResult) -> String {
    let removal_note = if result.namespace_removed {
        " (namespace removed)".to_string()
    } else {
        " (teardown still in progress)".to_string()
    };
    match result.target {
        StopTargetKind::Application => format!(
            "Stopped application {} in namespace {}{}",
            result.application_id.as_deref().unwrap_or(""),
            result.namespace_id,
            removal_note
        ),
        StopTargetKind::Namespace => {
            format!("Stopped namespace {}{}", result.namespace_id, removal_note)
        }
    }
}

// Control operations keep signal handling local so the CLI can map failures to
// its typed control errors.
fn send_signal(pid: u32, signal: Signal) -> Result<(), CliError> {
    match kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(CliError::ProcessSignal {
            pid,
            source: anyhow::Error::new(error),
        }),
    }
}

/// Real UID of `pid` from /proc, if the process exists and is inspectable.
fn process_real_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|real_uid| real_uid.parse::<u32>().ok())
}

fn open_pidfd(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd =
        unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid as nix::libc::pid_t, 0u32) };
    if fd >= 0 {
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as nix::libc::c_int) })
    } else {
        None
    }
}

fn send_signal_verified(
    pid: u32,
    pidfd: Option<&std::os::fd::OwnedFd>,
    signal: Signal,
) -> Result<(), CliError> {
    use std::os::fd::AsRawFd;
    if let Some(fd) = pidfd {
        let rc = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal as nix::libc::c_int,
                std::ptr::null::<nix::libc::siginfo_t>(),
                0u32,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(nix::libc::ESRCH) {
            return Ok(());
        }
        return Err(CliError::ProcessSignal {
            pid,
            source: err.into(),
        });
    }
    send_signal(pid, signal)
}

fn process_is_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().next())
        .is_some_and(|state| state == "Z")
}

fn process_is_live(pid: u32, pidfd: Option<&std::os::fd::OwnedFd>) -> bool {
    use std::os::fd::AsRawFd;
    if let Some(fd) = pidfd {
        let mut pfd = nix::libc::pollfd {
            fd: fd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { nix::libc::poll(&mut pfd, 1, 0) };
        if rc > 0 && (pfd.revents & nix::libc::POLLIN) != 0 {
            return false;
        }
    }
    check_process_running(pid) && !process_is_zombie(pid)
}

fn wait_for_process_verified(
    pid: u32,
    pidfd: Option<&std::os::fd::OwnedFd>,
) -> Result<(), CliError> {
    if wait_until(|| !process_is_live(pid, pidfd)) {
        return Ok(());
    }
    if process_is_live(pid, pidfd) {
        send_signal_verified(pid, pidfd, Signal::SIGKILL)?;
        if wait_until(|| !process_is_live(pid, pidfd)) {
            return Ok(());
        }
        return Err(CliError::ProcessStillRunning { pid });
    }
    Ok(())
}

fn namespace_processes(namespace_id: &str) -> anyhow::Result<Vec<i32>> {
    Ok(get_pids_in_namespace(namespace_id)?
        .into_iter()
        .filter(|pid| *pid > 1)
        .collect())
}

fn terminate_namespace_processes(namespace_id: &str) -> anyhow::Result<()> {
    for pid in namespace_processes(namespace_id)? {
        send_signal(pid as u32, Signal::SIGTERM)?;
    }

    if wait_until(|| {
        namespace_processes(namespace_id)
            .map(|processes| processes.is_empty())
            .unwrap_or(false)
    }) {
        return Ok(());
    }

    for pid in namespace_processes(namespace_id)? {
        send_signal(pid as u32, Signal::SIGKILL)?;
    }
    if wait_until(|| {
        namespace_processes(namespace_id)
            .map(|processes| processes.is_empty())
            .unwrap_or(false)
    }) {
        return Ok(());
    }

    Err(CliError::NamespaceProcessesStillRunning {
        namespace_id: namespace_id.to_string(),
        pids: namespace_processes(namespace_id)?,
    }
    .into())
}

fn namespace_processes_for_uid(
    namespace_id: &str,
    uid: nix::unistd::Uid,
) -> anyhow::Result<Vec<i32>> {
    Ok(namespace_processes(namespace_id)?
        .into_iter()
        .filter(|pid| process_real_uid(*pid as u32) == Some(uid.as_raw()))
        .collect())
}

fn terminate_namespace_user_processes(
    namespace_id: &str,
    uid: nix::unistd::Uid,
) -> anyhow::Result<()> {
    for pid in namespace_processes_for_uid(namespace_id, uid)? {
        send_signal(pid as u32, Signal::SIGTERM)?;
    }
    if wait_until(|| {
        namespace_processes_for_uid(namespace_id, uid)
            .map(|processes| processes.is_empty())
            .unwrap_or(false)
    }) {
        return Ok(());
    }
    for pid in namespace_processes_for_uid(namespace_id, uid)? {
        send_signal(pid as u32, Signal::SIGKILL)?;
    }
    anyhow::ensure!(
        wait_until(|| {
            namespace_processes_for_uid(namespace_id, uid)
                .map(|processes| processes.is_empty())
                .unwrap_or(false)
        }),
        "Processes owned by uid {} remain in namespace {namespace_id}",
        uid.as_raw()
    );
    Ok(())
}

fn wait_for_namespace_removal(namespace_id: &str) -> anyhow::Result<bool> {
    if wait_until_for(100, || {
        get_existing_namespaces()
            .map(|namespaces| !namespaces.iter().any(|name| name == namespace_id))
            .unwrap_or(false)
    }) {
        return Ok(true);
    }
    Ok(!get_existing_namespaces()?
        .iter()
        .any(|name| name == namespace_id))
}

fn namespace_exists(namespace_id: &str) -> anyhow::Result<bool> {
    Ok(get_existing_namespaces()?
        .iter()
        .any(|name| name == namespace_id))
}

// Once stop has been authorized, the application's handler may finish
// teardown at any point. Suppress a later error only when absence is verified;
// ownership failures for an existing namespace and inspection errors still fail.
fn allow_completed_teardown<T>(
    result: anyhow::Result<T>,
    exists: impl FnOnce() -> anyhow::Result<bool>,
) -> anyhow::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(_) if !exists()? => Ok(None),
        Err(error) => Err(error),
    }
}

fn wait_until(condition: impl FnMut() -> bool) -> bool {
    wait_until_for(20, condition)
}

fn wait_until_for(attempts: usize, mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..attempts {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    condition()
}

#[cfg(test)]
mod tests {
    use super::allow_completed_teardown;

    #[test]
    fn stop_accepts_teardown_completed_by_the_application_handler() {
        let result = allow_completed_teardown::<()>(
            Err(anyhow::anyhow!(
                "namespace disappeared during snapshot load"
            )),
            || Ok(false),
        );
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn stop_keeps_ownership_errors_when_the_namespace_still_exists() {
        let error =
            allow_completed_teardown::<()>(Err(anyhow::anyhow!("ownership tag is stale")), || {
                Ok(true)
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "ownership tag is stale");
    }

    #[test]
    fn stop_requires_verified_namespace_removal() {
        assert!(
            allow_completed_teardown::<()>(Err(anyhow::anyhow!("snapshot unavailable")), || Err(
                anyhow::anyhow!("could not inspect namespaces")
            ),)
            .is_err()
        );
        assert_eq!(
            allow_completed_teardown(Ok(42), || panic!("no error to recheck")).unwrap(),
            Some(42)
        );
    }
}
