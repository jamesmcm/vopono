use anyhow::Result;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::Serialize;
use std::fs;
use std::time::Duration;
use vopono_core::network::netns::NetworkNamespace;
use vopono_core::status::read_lock_namespaces;
use vopono_core::util::{
    check_process_running, config_dir, get_existing_namespaces, get_pids_in_namespace,
};

use crate::errors::CliError;
use crate::providers::SCHEMA_VERSION;

#[derive(Debug, Serialize)]
pub struct StopResult {
    pub version: u8,
    pub success: bool,
    pub target: String,
    pub application_id: Option<String>,
    pub namespace_id: String,
    pub namespace_removed: bool,
}

pub fn stop_application(application_id: &str) -> Result<StopResult> {
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

    let _ = send_signal(pid, Signal::SIGTERM)?;
    wait_for_process(pid)?;
    let namespace_removed = wait_for_namespace_removal(&namespace_id)?;

    Ok(StopResult {
        version: SCHEMA_VERSION,
        success: true,
        target: "application".to_string(),
        application_id: Some(application_id.to_string()),
        namespace_id,
        namespace_removed,
    })
}

pub fn stop_namespace(namespace_id: &str) -> Result<StopResult> {
    let status = read_lock_namespaces()?;
    if !status.namespaces.contains_key(namespace_id) {
        return Err(CliError::NamespaceNotFound {
            id: namespace_id.to_string(),
        }
        .into());
    }

    let namespace = NetworkNamespace::from_existing(namespace_id.to_string())?;
    // A namespace is shared by every application selected for the same
    // provider/server. Stopping it is therefore deliberately a group
    // operation: terminate every process still attached to the namespace,
    // including the VPN helper itself, before tearing the namespace down.
    terminate_namespace_processes(namespace_id)?;

    remove_namespace_locks(namespace_id)?;
    // Dropping the reconstructed namespace performs the normal vopono teardown, including
    // firewall, veth, predown, and network-namespace cleanup.
    drop(namespace);
    let namespace_removed = wait_for_namespace_removal(namespace_id)?;
    if !namespace_removed {
        return Err(CliError::NamespaceTeardownFailed {
            namespace_id: namespace_id.to_string(),
        }
        .into());
    }

    Ok(StopResult {
        version: SCHEMA_VERSION,
        success: namespace_removed,
        target: "namespace".to_string(),
        application_id: None,
        namespace_id: namespace_id.to_string(),
        namespace_removed,
    })
}

pub fn print_result(result: &StopResult, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else if result.target == "application" {
        println!(
            "Stopped application {} in namespace {}{}",
            result.application_id.as_deref().unwrap_or(""),
            result.namespace_id,
            if result.namespace_removed {
                " (namespace removed)"
            } else {
                ""
            }
        );
    } else {
        println!(
            "Stopped namespace {}{}",
            result.namespace_id,
            if result.namespace_removed {
                ""
            } else {
                " (teardown still in progress)"
            }
        );
    }
    Ok(())
}

// Control operations keep signal handling local so the CLI can map failures to
// its typed control errors.
fn send_signal(pid: u32, signal: Signal) -> Result<bool, CliError> {
    match kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(error) => Err(CliError::ProcessSignal {
            pid,
            source: anyhow::Error::new(error),
        }),
    }
}

fn wait_for_process(pid: u32) -> Result<(), CliError> {
    if wait_until(|| !check_process_running(pid)) {
        return Ok(());
    }
    if check_process_running(pid) {
        let _ = send_signal(pid, Signal::SIGKILL)?;
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
        let _ = send_signal(pid as u32, Signal::SIGTERM)?;
    }

    if wait_until(|| {
        namespace_processes(namespace_id)
            .map(|processes| processes.is_empty())
            .unwrap_or(false)
    }) {
        return Ok(());
    }

    for pid in namespace_processes(namespace_id)? {
        let _ = send_signal(pid as u32, Signal::SIGKILL)?;
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

fn remove_namespace_locks(namespace_id: &str) -> anyhow::Result<()> {
    let lock_dir = config_dir()?.join("vopono/locks").join(namespace_id);
    if !lock_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&lock_dir)? {
        let entry = entry?;
        if entry.path().is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
