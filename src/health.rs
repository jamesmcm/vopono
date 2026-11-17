//! Opt-in tunnel monitoring and repair using a frozen root-owned snapshot.
//! The `health.json` sidecar is user-owned advisory telemetry, not security state.
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vopono_core::diagnostics::runtime;
use vopono_core::network::netns::NetworkNamespace;

pub use vopono_core::network::health::{HEALTH_FILE, Health, State, read_health};

/// Persist a heartbeat at this interval; state transitions are written immediately.
const HEALTH_WRITE_INTERVAL: Duration = Duration::from_secs(30);
const MONITOR_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(60);
const DIAGNOSTIC_BUDGET: Duration = Duration::from_secs(4);

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
    recover: Arc<AtomicBool>,
}
impl Monitor {
    pub fn stop_handle(&self) -> MonitorStop {
        MonitorStop {
            sender: self.stop.clone(),
            finished: self.finished.clone(),
        }
    }
    pub fn recovery_enabled(&self) -> bool {
        self.recover.load(Ordering::Acquire)
    }

    pub fn enable_recovery(&self) {
        self.recover.store(true, Ordering::Release);
    }

    pub fn start(ns: &NetworkNamespace, recover: bool) -> Self {
        let recover = Arc::new(AtomicBool::new(recover));
        let worker_recover = recover.clone();
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
            let skip_ipv4 = recovery_state.as_ref().is_some_and(runtime::skip_ipv4);
            let skip_ipv6 = recovery_state.as_ref().is_none_or(runtime::skip_ipv6);
            let mut health = Health {
                state: State::Degraded,
                checked_at: 0,
                last_successful_probe: None,
                handshake_age_seconds: None,
                reconnect_attempts: 0,
                last_error: None,
                diagnostics: Vec::new(),
                diagnostics_checked_at: None,
                daemon_version: Some(env!("CARGO_PKG_VERSION").into()),
                daemon_pid: Some(std::process::id()),
            };
            let mut last_write: Option<Instant> = None;
            let mut last_written_state = None;
            let mut failures = 0u32;
            let mut recovery_was_enabled = worker_recover.load(Ordering::Acquire);
            let mut last_diagnostics: Option<Instant> = None;
            let mut observations = Vec::new();
            let mut previous_failure = false;
            let mut route_signature = recovery_state
                .as_ref()
                .and_then(vopono_core::network::recovery::signature);
            loop {
                if receiver.try_recv().is_ok() || !Path::new("/run/netns").join(&name).exists() {
                    break;
                }
                let recover = worker_recover.load(Ordering::Acquire);
                if recover {
                    if !recovery_was_enabled {
                        failures = 0;
                    }
                    let next = recovery_state
                        .as_ref()
                        .and_then(vopono_core::network::recovery::signature);
                    if next != route_signature {
                        failures = 0;
                        route_signature = next;
                    }
                }
                recovery_was_enabled = recover;
                let status = crate::check::probe_namespace(
                    &name,
                    crate::check::DEFAULT_V4_HOST,
                    crate::check::DEFAULT_V6_HOST,
                    443,
                    1500,
                    crate::check::DEFAULT_DNS_HOST,
                    skip_ipv4,
                    skip_ipv6,
                    false,
                );
                health.checked_at = now();
                health.handshake_age_seconds = wg
                    .as_ref()
                    .and_then(|(exe, interface)| runtime::handshake_age(&name, exe, interface));
                let error = connectivity_error(&status, skip_ipv4, skip_ipv6);
                let healthy = error.is_none();
                failures = repair_failure_count(failures, &status);
                // Capture doctor evidence periodically even while connected,
                // and immediately when a previously healthy probe fails.
                if last_diagnostics.is_none_or(|scan| scan.elapsed() >= DIAGNOSTIC_INTERVAL)
                    || !healthy && !previous_failure
                {
                    if receiver.try_recv().is_ok() {
                        break;
                    }
                    observations =
                        runtime::collect(recovery_state.as_ref(), skip_ipv6, DIAGNOSTIC_BUDGET);
                    health.diagnostics_checked_at = Some(now());
                    last_diagnostics = Some(Instant::now());
                }
                previous_failure = !healthy;
                health.diagnostics = crate::doctor::connectivity_diagnostics_for_families(
                    &status, skip_ipv4, skip_ipv6,
                );
                health.diagnostics.extend(observations.iter().cloned());
                health.diagnostics = runtime::bounded(health.diagnostics);
                if healthy {
                    health.state = State::Connected;
                    health.last_successful_probe = Some(health.checked_at);
                    health.last_error = None;
                    failures = 0;
                } else {
                    health.state = State::Degraded;
                    health.last_error = error;
                    if recover
                        && !status.connected
                        && probe_ran(&status)
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
                        if let Err(error) = repair {
                            let message =
                                format!("Automatic underlay/tunnel repair failed: {error:#}");
                            log::warn!("{name}: {message}");
                            health.last_error = Some(message);
                        }
                    }
                }
                // Persist state transitions immediately, but keep the heartbeat
                // inexpensive: replaying `checked_at` every probe is not needed.
                let state_key = (
                    health.state,
                    health.reconnect_attempts,
                    health.last_error.clone(),
                    health.diagnostics_checked_at,
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
            recover,
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

fn probe_ran(status: &crate::check::ConnectivityStatus) -> bool {
    status.dns.as_ref().is_some_and(|dns| {
        dns.code != Some(vopono_core::diagnostics::DiagnosticCode::ProbeUnavailable)
    })
}

fn repair_failure_count(previous: u32, status: &crate::check::ConnectivityStatus) -> u32 {
    if !status.connected && probe_ran(status) {
        previous.saturating_add(1)
    } else {
        // DNS-only failures and partial connectivity must not consume the
        // recovery budget before a subsequent transport outage.
        0
    }
}

fn connectivity_error(
    status: &crate::check::ConnectivityStatus,
    skip_ipv4: bool,
    skip_ipv6: bool,
) -> Option<String> {
    if !probe_ran(status) {
        return Some("Namespace connectivity probe unavailable; no tunnel repair attempted".into());
    }
    let mut failed = Vec::new();
    if !skip_ipv4 && status.ipv4.as_ref().is_none_or(|p| p.latency_ms.is_none()) {
        failed.push("IPv4");
    }
    if !skip_ipv6 && status.ipv6.as_ref().is_none_or(|p| p.latency_ms.is_none()) {
        failed.push("IPv6");
    }
    if !failed.is_empty() {
        return Some(format!(
            "Namespace {} TCP probe(s) failed; endpoint reachability and key authorization remain uncertain",
            failed.join("/")
        ));
    }
    if status
        .dns
        .as_ref()
        .is_none_or(|dns| dns.resolved_ips.is_empty())
    {
        return Some("Namespace DNS probe failed".into());
    }
    None
}
fn write_health(path: &Path, health: &Health) -> anyhow::Result<()> {
    let body = serde_json::to_string(health)?;
    anyhow::ensure!(
        body.len() <= 64 * 1024,
        "Health telemetry exceeds the reader's size limit"
    );
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

    fn sample() -> crate::check::ConnectivityStatus {
        serde_json::from_value(serde_json::json!({
            "id": "test", "connected": true,
            "ipv4": {"target":"1.1.1.1:443", "latency_ms":1},
            "ipv6": {"target":"[2606:4700:4700::1111]:443", "latency_ms":1},
            "dns": {"host":"one.one.one.one", "resolved_ips":["1.1.1.1"]}
        }))
        .unwrap()
    }

    #[test]
    fn partial_family_and_dns_failures_degrade_without_consuming_repair_budget() {
        let mut status = sample();
        assert!(connectivity_error(&status, false, false).is_none());
        status.ipv6.as_mut().unwrap().latency_ms = None;
        assert!(
            connectivity_error(&status, false, false)
                .unwrap()
                .contains("IPv6")
        );
        assert!(connectivity_error(&status, false, true).is_none());
        assert_eq!(repair_failure_count(32, &status), 0);
        status = sample();
        status.dns.as_mut().unwrap().resolved_ips.clear();
        assert_eq!(
            connectivity_error(&status, false, false).unwrap(),
            "Namespace DNS probe failed"
        );
        assert_eq!(repair_failure_count(32, &status), 0);
        status.connected = false;
        assert_eq!(repair_failure_count(0, &status), 1);
        assert_eq!(repair_failure_count(1, &status), 2);
    }

    #[test]
    fn unavailable_probe_never_triggers_repair() {
        let mut status = sample();
        status.connected = false;
        status.dns.as_mut().unwrap().code =
            Some(vopono_core::diagnostics::DiagnosticCode::ProbeUnavailable);
        assert!(!probe_ran(&status));
        assert_eq!(repair_failure_count(32, &status), 0);
        assert!(
            connectivity_error(&status, false, false)
                .unwrap()
                .contains("unavailable")
        );
        status.dns = None;
        assert!(!probe_ran(&status));
    }

    #[test]
    fn ipv6_only_tunnel_does_not_require_ipv4_or_report_an_absent_probe() {
        let mut status = sample();
        status.ipv4 = None;
        assert!(connectivity_error(&status, true, false).is_none());
        let diagnostics =
            crate::doctor::connectivity_diagnostics_for_families(&status, true, false);
        assert!(
            diagnostics
                .iter()
                .all(|d| d.state == vopono_core::diagnostics::DiagnosticState::Pass)
        );
        assert!(
            connectivity_error(&status, false, false)
                .unwrap()
                .contains("IPv4")
        );
    }
}
