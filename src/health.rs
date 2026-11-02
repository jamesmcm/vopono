//! Opt-in tunnel monitoring and repair using a frozen root-owned snapshot.
//! The `health.json` sidecar is user-owned advisory telemetry, not security state.
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vopono_core::network::netns::NetworkNamespace;

pub use vopono_core::network::health::{HEALTH_FILE, Health, State, read_health};

/// Persist a heartbeat at this interval; state transitions are written immediately.
const HEALTH_WRITE_INTERVAL: Duration = Duration::from_secs(30);
const MONITOR_STOP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct MonitorStop {
    sender: mpsc::Sender<()>,
    finished: Arc<AtomicBool>,
}
impl MonitorStop {
    pub fn stop_and_wait(&self) -> anyhow::Result<()> {
        let _ = self.sender.send(());
        let deadline = Instant::now() + MONITOR_STOP_TIMEOUT;
        while !self.finished.load(Ordering::Acquire) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "Tunnel monitor has not stopped; namespace is preserved"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
struct Completion(Arc<AtomicBool>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub struct Monitor {
    stop: mpsc::Sender<()>,
    finished: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Monitor {
    pub fn stop_handle(&self) -> MonitorStop {
        MonitorStop {
            sender: self.stop.clone(),
            finished: self.finished.clone(),
        }
    }
    pub fn start(ns: &NetworkNamespace, recover: bool) -> Self {
        let name = ns.name.clone();
        let wg = ns
            .wireguard
            .as_ref()
            .map(|wg| (wg.executable_wg.clone(), wg.if_name.clone()));
        let owner = vopono_core::util::config_owner_override();
        let mut recovery_state = ns.snapshot().ok();
        let base = vopono_core::util::config_dir().ok();
        let (stop, receiver) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let completed = finished.clone();
        let worker = std::thread::spawn(move || {
            let _completion = Completion(completed);
            vopono_core::util::set_config_owner_override(owner);
            vopono_core::util::set_config_dir_override(base.clone());
            vopono_core::util::set_helper_exe_override(std::env::current_exe().ok());
            let Some(base) = base else {
                return;
            };
            let path = base.join("vopono/locks").join(&name).join(HEALTH_FILE);
            let mut health = Health {
                state: State::Degraded,
                checked_at: 0,
                last_successful_probe: None,
                handshake_age_seconds: None,
                reconnect_attempts: 0,
                last_error: None,
            };
            let mut last_write: Option<Instant> = None;
            let mut last_written_state = None;
            let mut failures = 0u32;
            let mut route_signature = recovery_state
                .as_ref()
                .and_then(vopono_core::network::recovery::signature);
            loop {
                if receiver.try_recv().is_ok() || !Path::new("/run/netns").join(&name).exists() {
                    break;
                }
                if recover {
                    let next = recovery_state
                        .as_ref()
                        .and_then(vopono_core::network::recovery::signature);
                    if next != route_signature {
                        failures = 0;
                        route_signature = next;
                    }
                }
                let status = crate::check::probe_namespace(
                    &name,
                    crate::check::DEFAULT_V4_HOST,
                    crate::check::DEFAULT_V6_HOST,
                    443,
                    1500,
                    crate::check::DEFAULT_DNS_HOST,
                    false,
                    false,
                    false,
                );
                health.checked_at = now();
                health.handshake_age_seconds = wg
                    .as_ref()
                    .and_then(|(exe, interface)| handshake_age(&name, exe, interface));
                let healthy = status.connected
                    && status
                        .dns
                        .as_ref()
                        .is_some_and(|dns| !dns.resolved_ips.is_empty());
                if healthy {
                    health.state = State::Connected;
                    health.last_successful_probe = Some(health.checked_at);
                    health.last_error = None;
                    failures = 0;
                } else {
                    failures = failures.saturating_add(1);
                    health.state = State::Degraded;
                    health.last_error = Some(if status.connected { "Namespace DNS probe failed" } else { "Namespace TCP probes failed; endpoint reachability and key authorization remain uncertain" }.into());
                    if recover
                        && !status.connected
                        && should_recover(failures)
                        && recovery_state.is_some()
                    {
                        health.reconnect_attempts = health.reconnect_attempts.saturating_add(1);
                        health.state = State::Reconnecting;
                        let repair = (|| -> anyhow::Result<()> {
                            let _transition = crate::namespace_sessions::try_lock_namespace(&name)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Namespace transition in progress")
                                })?;
                            let state = recovery_state.as_mut().unwrap();
                            let mut candidate = state.inert_copy()?;
                            vopono_core::network::recovery::repair(&mut candidate)?;
                            if let Some((uid, _)) = owner {
                                let replacement = candidate.inert_copy()?;
                                crate::namespace_ownership::update_snapshot(
                                    &name,
                                    uid,
                                    replacement,
                                )?;
                            }
                            *state = candidate;
                            Ok(())
                        })();
                        if repair.is_err() {
                            health.last_error = Some("Automatic underlay/tunnel repair failed; kill switch and namespace were preserved".into());
                        }
                    }
                }
                // Persist state transitions immediately, but keep the heartbeat
                // inexpensive: replaying `checked_at` every probe is not needed.
                let state_key = (
                    health.state,
                    health.reconnect_attempts,
                    health.last_error.clone(),
                );
                let write_due = last_write
                    .is_none_or(|written| written.elapsed() >= HEALTH_WRITE_INTERVAL)
                    || last_written_state.as_ref() != Some(&state_key);
                if write_due {
                    match write_health(&path, &health) {
                        Ok(()) => {
                            last_write = Some(Instant::now());
                            last_written_state = Some(state_key);
                        }
                        Err(error) => log::debug!("Could not write tunnel health: {error}"),
                    }
                }
                // Exponential spacing between recovery attempts; monitoring continues every 15 seconds.
                if receiver.recv_timeout(Duration::from_secs(15)).is_ok() {
                    break;
                }
            }
        });
        Self {
            stop,
            finished,
            worker: Some(worker),
        }
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        let deadline = Instant::now() + MONITOR_STOP_TIMEOUT;
        while !self.finished.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(worker) = self.worker.take() {
            if self.finished.load(Ordering::Acquire) {
                let _ = worker.join();
            } else {
                // A wedged probe must not hang namespace teardown forever. The
                // namespace is preserved by the caller if it cannot be cleaned.
                log::warn!(
                    "Tunnel monitor did not stop within {MONITOR_STOP_TIMEOUT:?}; detaching"
                );
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn should_recover(failures: u32) -> bool {
    (2..=32).contains(&failures) && failures.is_power_of_two()
}

fn handshake_age(name: &str, exe: &str, interface: &str) -> Option<u64> {
    let output =
        NetworkNamespace::exec_with_output(name, &[exe, "show", interface, "latest-handshakes"])
            .ok()?;
    if !output.status.success() {
        return None;
    }
    let last = std::str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .filter(|time| *time > 0)
        .max()?;
    now().checked_sub(last)
}
fn write_health(path: &Path, health: &Health) -> anyhow::Result<()> {
    let body = serde_json::to_string(health)?;
    anyhow::ensure!(
        vopono_core::util::write_file_as_config_owner(path, &body, Some(0o600))?,
        "Health writer requires a config owner"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_has_grace_period_and_bounded_exponential_backoff() {
        let attempts: Vec<_> = (0..1000).filter(|n| should_recover(*n)).collect();
        assert_eq!(attempts, vec![2, 4, 8, 16, 32]);
    }
}
