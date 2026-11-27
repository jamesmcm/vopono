//! Serialize daemon lifecycle transitions and keep resources with the namespace.
//! The controller remains on the creating request's thread: provider forwarders
//! need not become Send, and client config ownership stays thread-local.
use nix::unistd::Uid;
use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc, Condvar, LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use vopono_core::network::netns::NetworkNamespace;
use vopono_core::network::port_forwarding::Forwarder;

static TRANSITIONS: LazyLock<(Mutex<HashSet<String>>, Condvar)> =
    LazyLock::new(|| (Mutex::new(HashSet::new()), Condvar::new()));
thread_local! { static SETUP_TRANSITION: std::cell::RefCell<Option<Transition>> = const { std::cell::RefCell::new(None) }; }
// Count pending setup as well as live controllers so concurrent requests cannot
// race past the quotas. Control operations do not acquire these permits.
static RESOURCES: LazyLock<Mutex<HashMap<String, (Uid, bool)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const MAX_NAMESPACES_PER_UID: usize = 16;
const MAX_NAMESPACES: usize = 64;
const MAX_MONITORS_PER_UID: usize = 8;
const MAX_MONITORS: usize = 32;

fn release_resources(name: &str) {
    RESOURCES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(name);
}

pub struct Transition(String);
impl Drop for Transition {
    fn drop(&mut self) {
        TRANSITIONS
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
        TRANSITIONS.1.notify_all();
    }
}
/// Each namespace has its own transition permit. A slow handshake never blocks
/// unrelated namespaces or another user's stop request.
pub fn lock_namespace(name: &str) -> Transition {
    let mut busy = TRANSITIONS.0.lock().unwrap_or_else(|p| p.into_inner());
    while busy.contains(name) {
        busy = TRANSITIONS.1.wait(busy).unwrap_or_else(|p| p.into_inner());
    }
    busy.insert(name.to_owned());
    Transition(name.to_owned())
}

pub fn try_lock_namespace(name: &str) -> Option<Transition> {
    let mut busy = TRANSITIONS.0.lock().unwrap_or_else(|p| p.into_inner());
    busy.insert(name.to_owned())
        .then(|| Transition(name.to_owned()))
}

/// Wait briefly during daemon shutdown for in-flight setup/teardown transitions to finish.
pub fn wait_for_idle_transitions(timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    let mut busy = TRANSITIONS.0.lock().unwrap_or_else(|p| p.into_inner());
    while !busy.is_empty() {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        let (guard, result) = TRANSITIONS
            .1
            .wait_timeout(busy, remaining)
            .unwrap_or_else(|p| p.into_inner());
        busy = guard;
        if result.timed_out() {
            break;
        }
    }
}

pub struct SetupGuard;
impl Drop for SetupGuard {
    fn drop(&mut self) {
        if let Some(transition) = SETUP_TRANSITION.with(|slot| slot.borrow_mut().take()) {
            let sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = sessions.get(&transition.0) {
                if let Some((_, reserved_monitor)) = RESOURCES
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get_mut(&transition.0)
                {
                    *reserved_monitor = entry.monitor.is_some();
                }
            } else {
                release_resources(&transition.0);
            }
        }
    }
}
pub fn begin_setup() -> SetupGuard {
    SetupGuard
}

/// Called once the resolved namespace name is known, before inspecting or creating it.
pub fn reserve(name: &str, uid: Uid, monitor: bool) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let permit = lock_namespace(name);
        let retiring = SESSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .is_some_and(|entry| !entry.valid.load(Ordering::Acquire));
        if !retiring {
            anyhow::ensure!(
                !SESSIONS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(name)
                    .is_some_and(|entry| entry.stop_forwarder_for_teardown.load(Ordering::Acquire)),
                "Namespace {name} is being stopped"
            );
            reserve_resources(name, uid, monitor)?;
            SETUP_TRANSITION.with(|slot| *slot.borrow_mut() = Some(permit));
            return Ok(());
        }
        drop(permit);
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "A stopped namespace controller is still releasing resources; retry shortly"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn reserve_resources(name: &str, uid: Uid, monitor: bool) -> anyhow::Result<()> {
    let mut resources = RESOURCES.lock().unwrap_or_else(|p| p.into_inner());
    if !resources.contains_key(name) {
        anyhow::ensure!(
            resources.len() < MAX_NAMESPACES
                && resources
                    .values()
                    .filter(|(owner, _)| *owner == uid)
                    .count()
                    < MAX_NAMESPACES_PER_UID,
            vopono_core::diagnostics::Diagnostic::new(
                vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                vopono_core::diagnostics::DiagnosticState::Fail,
                "Namespace controller limit reached (16 per user, 64 total)",
                Some("Stop an unused namespace before creating another")
            )
        );
    }
    let reserved_monitor = resources.get(name).is_some_and(|(_, enabled)| *enabled);
    if monitor && !reserved_monitor {
        anyhow::ensure!(
            resources.values().filter(|(_, enabled)| *enabled).count() < MAX_MONITORS
                && resources
                    .values()
                    .filter(|(owner, enabled)| *owner == uid && *enabled)
                    .count()
                    < MAX_MONITORS_PER_UID,
            vopono_core::diagnostics::Diagnostic::new(
                vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                vopono_core::diagnostics::DiagnosticState::Fail,
                "Namespace monitor limit reached (8 per user, 32 total)",
                Some("Stop an unused monitored namespace")
            )
        );
    }
    resources
        .entry(name.to_owned())
        .and_modify(|(_, enabled)| *enabled |= monitor)
        .or_insert((uid, monitor));
    Ok(())
}

struct Entry {
    applications: usize,
    valid: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    stop_forwarder_for_teardown: Arc<AtomicBool>,
    forwarder_released: Arc<AtomicBool>,
    monitor: Option<crate::health::Monitor>,
    forwarder_stop: Option<std::sync::mpsc::Sender<bool>>,
    proxies: HashMap<u16, crate::tcp_proxy::TcpProxy>,
    desired_host_ports: std::collections::BTreeSet<u16>,
}
static SESSIONS: LazyLock<Mutex<HashMap<String, Entry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Called after an authorized explicit stop, while holding this namespace's transition permit.
pub fn invalidate(name: &str) -> Option<Arc<AtomicBool>> {
    let sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let entry = sessions.get(name)?;
    entry.valid.store(false, Ordering::Release);
    Some(entry.released.clone())
}

pub fn wait_released(released: &AtomicBool) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !released.load(Ordering::Acquire) {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "Namespace workers are still releasing resources"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Stop active probes and port-renewal threads before an authorized namespace
/// teardown inspects remaining PIDs.
pub fn stop_monitor(name: &str) -> anyhow::Result<()> {
    let stop_handle = SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(name)
        .and_then(|entry| {
            entry
                .monitor
                .as_ref()
                .map(crate::health::Monitor::stop_handle)
        });
    if let Some(handle) = stop_handle {
        // Wait for the monitor to stop before removing tracking or stopping
        // port renewal; on timeout the session retains ownership and Monitor::drop
        // is not invoked for a second wait.
        handle.stop_and_wait()?;
    }
    let (monitor, forwarder_stop) = SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_mut(name)
        .map(|entry| (entry.monitor.take(), entry.forwarder_stop.take()))
        .unwrap_or_default();
    if monitor.is_some()
        && let Some((_, reserved_monitor)) = RESOURCES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(name)
    {
        *reserved_monitor = false;
    }
    drop(monitor);
    if let Some(stop) = forwarder_stop {
        let _ = stop.send(true);
    }
    Ok(())
}

/// Signal the controller to drop its port forwarder (joining renewal threads
/// and allowing remote DELETE calls like AzireVPN while the netns still exists)
/// and wait for completion without holding the namespace transition lock.
pub fn request_forwarder_release(name: &str) -> Option<Arc<AtomicBool>> {
    let (stop, released) = {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        let entry = sessions.get_mut(name)?;
        entry
            .stop_forwarder_for_teardown
            .store(true, Ordering::Release);
        (
            entry.forwarder_stop.take(),
            Arc::clone(&entry.forwarder_released),
        )
    };
    if let Some(stop) = stop {
        let _ = stop.send(true);
    }
    Some(released)
}

pub fn wait_forwarder_released(released: &AtomicBool, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while !released.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Caller holds the namespace's transition permit so relays cannot disappear during an attach.
pub fn contains(name: &str) -> bool {
    SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(name)
}

/// Existing relays belong to the namespace and can be reused by later launches.
pub fn relay_ports(name: &str) -> Vec<u16> {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(entry) = sessions.get_mut(name) else {
        return Vec::new();
    };
    entry.proxies.retain(|_, proxy| proxy.is_alive());
    entry.proxies.keys().copied().collect()
}

pub fn desired_relay_ports(name: &str) -> Vec<u16> {
    SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(name)
        .map(|entry| entry.desired_host_ports.iter().copied().collect())
        .unwrap_or_default()
}

fn remove_session(name: &str, valid: &Arc<AtomicBool>) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    if sessions
        .get(name)
        .is_some_and(|entry| Arc::ptr_eq(&entry.valid, valid))
    {
        let entry = sessions.remove(name).expect("matched session entry");
        let released = entry.released.clone();
        release_resources(name);
        drop(sessions);
        drop(entry);
        released.store(true, Ordering::Release);
    }
}

/// Every application holds a registration; only the first owns cleanup and leases.
pub struct Session {
    pub ns: NetworkNamespace,
    uid: Uid,
    controller: bool,
    registered: bool,
    valid: Arc<AtomicBool>,
    stop_forwarder_for_teardown: Arc<AtomicBool>,
    forwarder_released: Arc<AtomicBool>,
    forwarder: Option<Box<dyn Forwarder>>,
    pending_forwarder: Option<vopono_core::network::port_forwarding::ForwarderSnapshot>,
}
impl Session {
    /// Caller must retain the namespace's transition permit across setup, spawn, and registration.
    pub fn register(
        mut ns: NetworkNamespace,
        uid: Uid,
        forwarder: Option<Box<dyn Forwarder>>,
        monitor: bool,
        recover: bool,
    ) -> Self {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        let controller = !sessions.contains_key(&ns.name);
        let has_forwarder = forwarder.is_some();
        let entry = sessions.entry(ns.name.clone()).or_insert_with(|| Entry {
            applications: 0,
            valid: Arc::new(AtomicBool::new(true)),
            released: Arc::new(AtomicBool::new(false)),
            stop_forwarder_for_teardown: Arc::new(AtomicBool::new(false)),
            forwarder_released: Arc::new(AtomicBool::new(!has_forwarder)),
            monitor: None,
            forwarder_stop: None,
            proxies: HashMap::new(),
            desired_host_ports: std::collections::BTreeSet::new(),
        });
        entry.applications += 1;
        if let Some(stop) = forwarder.as_ref().and_then(|f| f.stop_handle()) {
            entry.forwarder_stop = Some(stop);
        }
        let valid = entry.valid.clone();
        let stop_forwarder_for_teardown = entry.stop_forwarder_for_teardown.clone();
        let forwarder_released = entry.forwarder_released.clone();
        if !controller {
            ns.detach();
        }
        if monitor {
            let active = entry
                .monitor
                .get_or_insert_with(|| crate::health::Monitor::start(&ns, recover));
            if recover {
                active.enable_recovery();
            }
        }
        Self {
            ns,
            uid,
            controller,
            registered: true,
            valid,
            stop_forwarder_for_teardown,
            forwarder_released,
            forwarder,
            pending_forwarder: None,
        }
    }
    pub fn retain_proxies(&self, proxies: crate::exec::HostProxies) {
        if let Some(entry) = SESSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&self.ns.name)
        {
            entry
                .desired_host_ports
                .extend(proxies.iter().map(|(port, _)| *port));
            entry.proxies.extend(proxies);
        }
    }

    fn retain_desired_host_ports(&self, ports: &[u16]) {
        if let Some(entry) = SESSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&self.ns.name)
        {
            entry.desired_host_ports.extend(ports.iter().copied());
        }
    }

    fn restore_missing_relays(&self) {
        let active = relay_ports(&self.ns.name);
        for port in desired_relay_ports(&self.ns.name) {
            if active.contains(&port) {
                continue;
            }
            match crate::exec::restore_host_proxies(&self.ns, &[port]) {
                Ok(proxies) => self.retain_proxies(proxies),
                Err(error) => log::warn!("{error:#}; will retry host relay"),
            }
        }
    }

    pub fn persist_options(&self) -> anyhow::Result<()> {
        let (monitor, recover, host_ports) = {
            let sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
            let entry = &sessions[&self.ns.name];
            let mut ports: std::collections::BTreeSet<u16> = entry.desired_host_ports.clone();
            ports.extend(entry.proxies.keys().copied());
            (
                entry.monitor.is_some(),
                entry
                    .monitor
                    .as_ref()
                    .is_some_and(|monitor| monitor.recovery_enabled()),
                ports.into_iter().collect::<Vec<_>>(),
            )
        };
        let config_base = if self.controller {
            let (_, gid) = vopono_core::util::config_owner_override()
                .ok_or_else(|| anyhow::anyhow!("Missing authenticated config owner"))?;
            let config_base = vopono_core::util::config_dir()?;
            crate::namespace_ownership::save_runtime(
                &self.ns.name,
                self.uid,
                crate::namespace_ownership::RuntimeSettings {
                    config_base: config_base.clone(),
                    gid: gid.as_raw(),
                    monitor,
                    recover,
                    host_ports: host_ports.clone(),
                    forwarder: self
                        .forwarder
                        .as_ref()
                        .and_then(|forwarder| forwarder.snapshot())
                        .or_else(|| self.pending_forwarder.clone()),
                    daemon_pid: std::process::id(),
                },
            )?;
            config_base
        } else {
            crate::namespace_ownership::update_runtime_options(
                &self.ns.name,
                self.uid,
                monitor,
                recover,
                host_ports.clone(),
            )?
        };
        if !host_ports.is_empty()
            && let Err(error) = vopono_core::status::record_host_relays(
                &config_base.join("vopono/locks").join(&self.ns.name),
                &host_ports,
            )
        {
            log::warn!(
                "Could not publish host relays for {}: {error:#}",
                self.ns.name
            );
        }
        Ok(())
    }

    pub fn forwarded_port(&self) -> Option<u16> {
        self.forwarder
            .as_ref()
            .map(|f| f.forwarded_port())
            .or_else(|| self.ns.state.port_forwarding.as_ref().map(|f| f.port))
    }

    fn disarm(&mut self) {
        if let Some(forwarder) = self.forwarder.as_mut() {
            forwarder.disarm();
        }
        self.forwarder.take();
        self.ns.detach();
    }
}

impl Session {
    fn unregister_application(&mut self) {
        if !self.registered {
            return;
        }
        self.registered = false;
        let holds_setup = SETUP_TRANSITION.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|transition| transition.0 == self.ns.name)
        });
        let _transition = (!holds_setup).then(|| lock_namespace(&self.ns.name));
        let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = sessions.get_mut(&self.ns.name)
            && Arc::ptr_eq(&entry.valid, &self.valid)
        {
            entry.applications = entry.applications.saturating_sub(1);
        }
    }

    /// Tear down or detach a session whose post-registration bookkeeping failed
    /// before entering `run_until_unused()`.
    pub fn abort_failed_launch(mut self) {
        self.unregister_application();
        if self.controller {
            self.forwarder_released.store(true, Ordering::Release);
            remove_session(&self.ns.name, &self.valid);
        }
        // `self` drops here: if controller, `ns` and `forwarder` clean up;
        // if attached non-controller, `ns` is already detached.
    }

    /// Run only after the request has replied and released its client resources.
    /// The creating thread retains provider leases and its authenticated config context.
    pub fn run_until_unused(mut self) {
        self.unregister_application();
        if !self.controller {
            return;
        }
        // Respond to the client before entering this loop. The namespace and
        // provider renewal task outlive any individual client/application.
        let mut lease_retry_at = std::time::Instant::now();
        let mut relay_retry_at = std::time::Instant::now();
        let mut cleanup_retry_at = std::time::Instant::now();
        let mut primary_removed = false;
        loop {
            let mut transition = lock_namespace(&self.ns.name);
            if !self.valid.load(Ordering::Acquire) {
                self.disarm();
                self.forwarder_released.store(true, Ordering::Release);
                remove_session(&self.ns.name, &self.valid);
                break;
            }
            // Explicit teardown requests forwarder shutdown BEFORE deleting the
            // netns so renewal threads join cleanly and AzireVPN DELETE runs.
            if self.stop_forwarder_for_teardown.load(Ordering::Acquire) {
                self.pending_forwarder = None;
                if !self.forwarder_released.load(Ordering::Acquire) {
                    let forwarder = self.forwarder.take();
                    drop(transition);
                    drop(forwarder);
                    self.forwarder_released.store(true, Ordering::Release);
                    continue;
                }
            }
            // An explicit stop may already have removed the namespace. Disarm
            // our copy so a subsequent namespace with the same name stays safe.
            if !std::path::Path::new("/run/netns")
                .join(&self.ns.name)
                .exists()
            {
                self.disarm();
                self.forwarder_released.store(true, Ordering::Release);
                remove_session(&self.ns.name, &self.valid);
                break;
            }
            let stopping =
                crate::namespace_ownership::is_stopping(&self.ns.name, self.uid).unwrap_or(false);
            if !stopping
                && !self.stop_forwarder_for_teardown.load(Ordering::Acquire)
                && std::time::Instant::now() >= relay_retry_at
            {
                self.restore_missing_relays();
                relay_retry_at = std::time::Instant::now() + Duration::from_secs(5);
            }
            if !stopping
                && !self.stop_forwarder_for_teardown.load(Ordering::Acquire)
                && let Some(snapshot) = self.pending_forwarder.clone()
                && std::time::Instant::now() >= lease_retry_at
            {
                // Keep `forwarder_released = false` while restoration is in
                // flight so `stop_daemon_namespace` waits before deleting the
                // namespace.
                self.forwarder_released.store(false, Ordering::Release);
                // Release the transition lock while performing network I/O and
                // user callback execution so stop/launch requests cannot deadlock.
                drop(transition);
                let restored = snapshot.restore(&self.ns);
                transition = lock_namespace(&self.ns.name);
                if !self.valid.load(Ordering::Acquire)
                    || self.stop_forwarder_for_teardown.load(Ordering::Acquire)
                    || crate::namespace_ownership::is_stopping(&self.ns.name, self.uid)
                        .unwrap_or(true)
                    || !std::path::Path::new("/run/netns")
                        .join(&self.ns.name)
                        .exists()
                {
                    if let Ok(mut forwarder) = restored {
                        forwarder.disarm();
                    }
                    self.pending_forwarder = None;
                    self.forwarder_released.store(true, Ordering::Release);
                    continue;
                }
                match restored {
                    Ok(forwarder) => {
                        let port = forwarder.forwarded_port();
                        if let Some(stop) = forwarder.stop_handle()
                            && let Some(entry) = SESSIONS
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .get_mut(&self.ns.name)
                        {
                            entry.forwarder_stop = Some(stop);
                        }
                        self.forwarder_released.store(false, Ordering::Release);
                        let previous_port = self.ns.state.port_forwarding.as_ref().map(|s| s.port);
                        if previous_port != Some(port)
                            && let Err(error) =
                                vopono_core::util::open_ports(&self.ns, &[port], self.ns.firewall)
                        {
                            log::warn!(
                                "Could not open restored forwarded port {port} in {}: {error:#}",
                                self.ns.name
                            );
                        }
                        self.forwarder = Some(forwarder);
                        self.pending_forwarder = None;
                        if let Some(state) = &mut self.ns.state.port_forwarding {
                            state.port = port;
                        }
                        let _ = self.persist_options();
                        if let Ok(base) = vopono_core::util::vopono_dir() {
                            let _ = vopono_core::status::record_forwarded_port(
                                &base.join("locks"),
                                &self.ns.name,
                                port,
                            );
                        }
                    }
                    Err(_) => {
                        self.forwarder_released.store(true, Ordering::Release);
                        log::warn!(
                            "Could not resume provider port lease for {}; will retry",
                            self.ns.name
                        );
                        lease_retry_at = std::time::Instant::now() + Duration::from_secs(5);
                    }
                }
            }
            let active = SESSIONS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&self.ns.name)
                .map(|e| e.applications)
                .unwrap_or(0);
            let persistent =
                crate::namespace_ownership::is_persistent(&self.ns.name, self.uid).unwrap_or(true);
            if primary_removed
                && (active > 0 || persistent || stopping)
                && std::time::Instant::now() >= cleanup_retry_at
            {
                // Re-publish status in the controller's configuration tree after reattachment.
                match self.ns.write_lockfile_in_place("") {
                    Ok(()) => primary_removed = false,
                    Err(error) => log::warn!(
                        "Could not restore primary lock for {}: {error:#}",
                        self.ns.name
                    ),
                }
                cleanup_retry_at = std::time::Instant::now() + Duration::from_secs(2);
            }
            if active == 0
                && !persistent
                && std::time::Instant::now() >= cleanup_retry_at
                && !self.ns.has_application_processes().unwrap_or(true)
            {
                let mut can_teardown = true;
                if let Ok(base) = vopono_core::util::vopono_dir() {
                    let lock_dir = base.join("locks").join(&self.ns.name);
                    let _ = vopono_core::status::prune_stale_client_lockfiles(&lock_dir);
                    let own_lock = std::process::id().to_string();
                    if !vopono_core::status::lock_dir_has_no_other_session_state(
                        &lock_dir, &own_lock,
                    )
                    .unwrap_or(false)
                    {
                        can_teardown = false;
                        // Release our application status while keeping the controller,
                        // ownership record and resources available for a later retry.
                        let primary = lock_dir.join(own_lock);
                        if !stopping
                            && primary.exists()
                            && !vopono_core::status::has_client_lockfiles(&lock_dir)
                        {
                            match vopono_core::util::owner_write::remove_file_as_config_owner(
                                &primary,
                            ) {
                                Ok(()) => primary_removed = true,
                                Err(error) => log::warn!(
                                    "Could not remove idle namespace lock {primary:?}: {error:#}"
                                ),
                            }
                        }
                    }
                }
                if can_teardown {
                    match crate::namespace_ownership::load(&self.ns.name, self.uid) {
                        Ok(owned) => match stop_monitor(&self.ns.name) {
                            Ok(()) => {
                                // Drop live forwarder before teardown so renewal threads stop
                                // and external mappings (e.g. AzireVPN) are deleted while netns exists.
                                self.forwarder.take();
                                // Teardown can preserve the namespace (for example when an
                                // unknown lockfile remains), or fail partway through cleanup.
                                // Retain the owning guard, runtime files and ownership record
                                // until removal is verified, so an explicit stop can retry.
                                if let Err(error) = owned.teardown() {
                                    log::warn!(
                                        "Could not tear down namespace {}: {error:#}",
                                        self.ns.name
                                    );
                                }
                                if std::path::Path::new("/run/netns")
                                    .join(&self.ns.name)
                                    .try_exists()
                                    .is_ok_and(|exists| !exists)
                                {
                                    self.disarm();
                                    remove_session(&self.ns.name, &self.valid);
                                    crate::namespace_ownership::remove(&self.ns.name);
                                    break;
                                }
                            }
                            Err(error) => {
                                log::warn!(
                                    "Could not stop monitor for namespace {}: {error:#}",
                                    self.ns.name
                                );
                            }
                        },
                        Err(error) => {
                            log::warn!(
                                "Could not load ownership record for namespace {}: {error:#}",
                                self.ns.name
                            );
                        }
                    }
                }
                cleanup_retry_at = std::time::Instant::now() + Duration::from_secs(2);
            }
            drop(transition);
            std::thread::sleep(Duration::from_millis(250));
        }
        self.disarm();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.unregister_application();
        if self.controller {
            remove_session(&self.ns.name, &self.valid);
        }
        // An unwind/early return must preserve the namespace. The explicit
        // controller loop performs teardown after verifying its last user.
        self.disarm();
    }
}

/// Rebuild workers from root-owned intent, without rereading client commands or
/// provisioning VPN keys. Kernel tunnels and applications survive daemon exit.
pub fn restore_all() -> anyhow::Result<()> {
    for (name, uid, runtime) in crate::namespace_ownership::restart_records()? {
        let transition = lock_namespace(&name);
        if let Err(error) = reserve_resources(&name, uid, runtime.monitor) {
            log::warn!("Could not reserve restored namespace {name}: {error}");
            continue;
        }
        std::thread::spawn(move || {
            let result = (|| -> anyhow::Result<Option<Session>> {
                let _setup = begin_setup();
                SETUP_TRANSITION.with(|slot| *slot.borrow_mut() = Some(transition));
                let base = vopono_core::util::validated_user_owned_dir(&runtime.config_base, uid)?;
                vopono_core::util::set_config_dir_override(Some(base));
                vopono_core::util::set_config_owner_override(Some((
                    uid,
                    nix::unistd::Gid::from_raw(runtime.gid),
                )));
                vopono_core::util::set_helper_exe_override(
                    vopono_core::util::current_vopono_exe().ok(),
                );
                let lock_dir = vopono_core::util::vopono_dir()?.join("locks").join(&name);
                if crate::namespace_ownership::is_stopping(&name, uid)? {
                    if runtime.daemon_pid != std::process::id() {
                        let _ = vopono_core::util::owner_write::remove_file_as_config_owner(
                            &lock_dir.join(runtime.daemon_pid.to_string()),
                        );
                    }
                    match crate::control::stop_namespace(&name, Some(uid)) {
                        Ok(_) => return Ok(None),
                        Err(error) => {
                            log::warn!("Will retry interrupted stop for {name}: {error:#}")
                        }
                    }
                }
                let mut ns = crate::namespace_ownership::load(&name, uid)?;
                // Write the new primary lockfile BEFORE removing the previous daemon PID's
                // lockfile so status visibility is continuous across daemon restarts.
                // Detach on error so dropping `ns` cannot tear down a live persistent namespace.
                if let Err(error) = ns.write_lockfile_in_place("") {
                    ns.detach();
                    return Err(error);
                }
                if runtime.daemon_pid != std::process::id() {
                    let _ = vopono_core::util::owner_write::remove_file_as_config_owner(
                        &lock_dir.join(runtime.daemon_pid.to_string()),
                    );
                }
                let stopping = crate::namespace_ownership::is_stopping(&name, uid)?;
                let mut session =
                    Session::register(ns, uid, None, runtime.monitor && !stopping, runtime.recover);
                if !stopping {
                    session.retain_desired_host_ports(&runtime.host_ports);
                    session.pending_forwarder = runtime.forwarder;
                }
                // A failure to refresh restart bookkeeping must not drop a
                // persistent controller while the startup transition is held.
                if let Err(error) = session.persist_options() {
                    log::warn!("Could not update restored runtime bookkeeping for {name}: {error}");
                }
                Ok(Some(session))
            })();
            match result {
                Ok(Some(session)) => session.run_until_unused(),
                Ok(None) => {}
                Err(error) => {
                    log::warn!("Could not restore namespace {name}: {error}");
                }
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    #[test]
    fn transitions_serialize_same_namespace_without_blocking_other_namespaces() {
        let held = lock_namespace("same_namespace_test");
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _permit = lock_namespace("same_namespace_test");
            sender.send(()).unwrap();
        });
        let independent = lock_namespace("other_namespace_test");
        assert!(receiver.try_recv().is_err());
        drop(independent);
        drop(held);
        receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        waiter.join().unwrap();
    }
    struct Lease(Rc<Cell<bool>>);
    impl Forwarder for Lease {
        fn forwarded_port(&self) -> u16 {
            1234
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    #[test]
    fn first_app_retains_provider_lease_and_stop_invalidates_old_generation() {
        let dropped = Rc::new(Cell::new(false));
        let ns = || NetworkNamespace::attach_unmanaged("test_session_lifetime".into()).unwrap();
        let first = Session::register(
            ns(),
            Uid::current(),
            Some(Box::new(Lease(dropped.clone()))),
            false,
            false,
        );
        let second = Session::register(ns(), Uid::current(), None, false, false);
        assert!(first.controller);
        assert!(!second.controller);
        assert_eq!(first.forwarded_port(), Some(1234));
        drop(second);
        assert!(!dropped.get());
        let released = invalidate(&first.ns.name).unwrap();
        assert!(!released.load(Ordering::Acquire));
        first.run_until_unused();
        let replacement = Session::register(ns(), Uid::current(), None, false, false);
        assert!(released.load(Ordering::Acquire));
        wait_released(&released).unwrap();
        assert!(replacement.controller);
        assert!(dropped.get());
        assert!(replacement.valid.load(Ordering::Acquire));
        let released = invalidate(&replacement.ns.name).unwrap();
        replacement.run_until_unused();
        wait_released(&released).unwrap();
    }
}
