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

    send_signal(pid, Signal::SIGTERM)?;
    wait_for_process(pid)?;
    let namespace_removed = wait_for_namespace_removal(&namespace_id)?;

    Ok(StopResult {
        version: SCHEMA_VERSION,
        target: StopTargetKind::Application,
        application_id: Some(application_id.to_string()),
        namespace_id,
        namespace_removed,
    })
}

pub fn stop_namespace(
    namespace_id: &str,
    requester_uid: Option<nix::unistd::Uid>,
) -> Result<StopResult> {
    let status = read_lock_namespaces()?;
    if !status.namespaces.contains_key(namespace_id) {
        return Err(CliError::NamespaceNotFound {
            id: namespace_id.to_string(),
        }
        .into());
    }

    if let Some(uid) = requester_uid {
        authorize_namespace_owner(namespace_id, uid)?;
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
    namespace.teardown();
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

/// Require every non-root process in a namespace to belong to the caller.
///
/// VPN helpers legitimately run as root, so they cannot establish ownership.
/// At least one caller-owned process must still be present; otherwise a local
/// user could forge a lockfile naming a root-only namespace and tear it down.
fn authorize_namespace_owner(
    namespace_id: &str,
    requester_uid: nix::unistd::Uid,
) -> anyhow::Result<()> {
    let processes = namespace_processes(namespace_id)?
        .into_iter()
        .map(|pid| {
            let owner = process_real_uid(pid as u32).ok_or_else(|| {
                anyhow::anyhow!(
                    "Refusing to stop namespace {namespace_id}: could not verify owner of PID {pid}"
                )
            })?;
            Ok((pid, owner))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    validate_namespace_owners(namespace_id, requester_uid.as_raw(), &processes)
}

fn validate_namespace_owners(
    namespace_id: &str,
    requester_uid: u32,
    processes: &[(i32, u32)],
) -> anyhow::Result<()> {
    let mut found_requester = false;
    for &(pid, owner) in processes {
        if owner == 0 {
            continue;
        }
        if owner != requester_uid {
            anyhow::bail!(
                "Refusing to stop namespace {namespace_id}: PID {pid} is owned by uid {owner}, not requesting uid {requester_uid}"
            );
        }
        found_requester = true;
    }
    anyhow::ensure!(
        found_requester,
        "Refusing to stop namespace {namespace_id}: no process owned by requesting uid {requester_uid} was found"
    );
    Ok(())
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

fn wait_for_process(pid: u32) -> Result<(), CliError> {
    if wait_until(|| !check_process_running(pid)) {
        return Ok(());
    }
    if check_process_running(pid) {
        send_signal(pid, Signal::SIGKILL)?;
        if wait_until(|| !check_process_running(pid)) {
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

fn wait_for_namespace_removal(namespace_id: &str) -> anyhow::Result<bool> {
    if wait_until(|| {
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

fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..20 {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    condition()
}

#[cfg(test)]
mod tests {
    use super::validate_namespace_owners;

    #[test]
    fn namespace_stop_allows_root_helpers_and_requester_processes() {
        assert!(validate_namespace_owners("vo_test", 1000, &[(10, 0), (11, 1000)]).is_ok());
    }

    #[test]
    fn namespace_stop_rejects_foreign_processes() {
        let error = validate_namespace_owners("vo_test", 1000, &[(10, 0), (11, 1001)])
            .unwrap_err()
            .to_string();
        assert!(error.contains("owned by uid 1001"));
    }

    #[test]
    fn namespace_stop_rejects_root_only_namespaces() {
        let error = validate_namespace_owners("vo_test", 1000, &[(10, 0)])
            .unwrap_err()
            .to_string();
        assert!(error.contains("no process owned by requesting uid 1000"));
    }
}
