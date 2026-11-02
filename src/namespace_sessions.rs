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

pub struct SetupGuard;
impl Drop for SetupGuard {
    fn drop(&mut self) {
        if let Some(transition) = SETUP_TRANSITION.with(|slot| slot.borrow_mut().take())
            && !contains(&transition.0)
        {
            release_resources(&transition.0);
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
        if monitor {
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
        resources.insert(name.to_owned(), (uid, monitor));
    }
    Ok(())
}

struct Entry {
    applications: usize,
    valid: Arc<AtomicBool>,
    monitor_stop: Option<crate::health::MonitorStop>,
}
static SESSIONS: LazyLock<Mutex<HashMap<String, Entry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Called after an authorized explicit stop, while holding this namespace's transition permit.
pub fn invalidate(name: &str) {
    if let Some(entry) = SESSIONS.lock().unwrap_or_else(|p| p.into_inner()).get(name) {
        entry.valid.store(false, Ordering::Release);
    }
}

pub fn wait_released(name: &str) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while contains(name) {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "Namespace workers are still releasing resources"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Stop active probes before an authorized namespace teardown inspects remaining PIDs.
pub fn stop_monitor(name: &str) -> anyhow::Result<()> {
    let stop = SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(name)
        .and_then(|entry| entry.monitor_stop.clone());
    if let Some(stop) = stop {
        stop.stop_and_wait()?;
    }
    Ok(())
}

/// Caller holds the namespace's transition permit so relays cannot disappear during an attach.
pub fn contains(name: &str) -> bool {
    SESSIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(name)
}

/// Every application holds a registration; only the first owns cleanup and leases.
pub struct Session {
    pub ns: NetworkNamespace,
    uid: Uid,
    controller: bool,
    registered: bool,
    valid: Arc<AtomicBool>,
    forwarder: Option<Box<dyn Forwarder>>,
    monitor: Option<crate::health::Monitor>,
    proxies: Vec<crate::tcp_proxy::TcpProxy>,
    pending_forwarder: Option<vopono_core::network::port_forwarding::ForwarderSnapshot>,
    monitor_enabled: bool,
    recover_enabled: bool,
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
        let entry = sessions.entry(ns.name.clone()).or_insert_with(|| Entry {
            applications: 0,
            valid: Arc::new(AtomicBool::new(true)),
            monitor_stop: None,
        });
        entry.applications += 1;
        let valid = entry.valid.clone();
        if !controller {
            ns.detach();
        }
        let monitor = (controller && monitor).then(|| crate::health::Monitor::start(&ns, recover));
        if let Some(monitor) = &monitor {
            entry.monitor_stop = Some(monitor.stop_handle());
        }
        Self {
            ns,
            uid,
            controller,
            registered: true,
            valid,
            forwarder,
            monitor_enabled: monitor.is_some(),
            monitor,
            proxies: Vec::new(),
            pending_forwarder: None,
            recover_enabled: recover,
        }
    }
    pub fn retain_proxies(&mut self, proxies: Vec<crate::tcp_proxy::TcpProxy>) {
        self.proxies.extend(proxies);
    }

    pub fn persist_options(&self) -> anyhow::Result<()> {
        if !self.controller {
            return Ok(());
        }
        let (_, gid) = vopono_core::util::config_owner_override()
            .ok_or_else(|| anyhow::anyhow!("Missing authenticated config owner"))?;
        crate::namespace_ownership::save_runtime(
            &self.ns.name,
            self.uid,
            crate::namespace_ownership::RuntimeSettings {
                config_base: vopono_core::util::config_dir()?,
                gid: gid.as_raw(),
                monitor: self.monitor_enabled,
                recover: self.recover_enabled,
                host_ports: if self.proxies.is_empty() {
                    Vec::new()
                } else {
                    self.ns.state.host_forwarded_ports.clone()
                },
                forwarder: self
                    .forwarder
                    .as_ref()
                    .and_then(|forwarder| forwarder.snapshot())
                    .or_else(|| self.pending_forwarder.clone()),
                daemon_pid: std::process::id(),
            },
        )
    }

    pub fn forwarded_port(&self) -> Option<u16> {
        self.forwarder
            .as_ref()
            .map(|f| f.forwarded_port())
            .or_else(|| self.ns.state.port_forwarding.as_ref().map(|f| f.port))
    }

    fn disarm(&mut self) {
        self.monitor.take();
        self.forwarder.take();
        self.proxies.clear();
        self.ns.detach();
    }
}

impl Session {
    fn unregister_application(&mut self) {
        if !self.registered {
            return;
        }
        self.registered = false;
        {
            let _transition = lock_namespace(&self.ns.name);
            let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = sessions.get_mut(&self.ns.name)
                && Arc::ptr_eq(&entry.valid, &self.valid)
            {
                entry.applications = entry.applications.saturating_sub(1);
            }
        }
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
        loop {
            let transition = lock_namespace(&self.ns.name);
            if !self.valid.load(Ordering::Acquire) {
                self.disarm();
                let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
                if sessions
                    .get(&self.ns.name)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.valid, &self.valid))
                {
                    sessions.remove(&self.ns.name);
                    release_resources(&self.ns.name);
                }
                break;
            }
            // An explicit stop may already have removed the namespace. Disarm
            // our copy so a subsequent namespace with the same name stays safe.
            if !std::path::Path::new("/run/netns")
                .join(&self.ns.name)
                .exists()
            {
                self.disarm();
                SESSIONS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&self.ns.name);
                release_resources(&self.ns.name);
                break;
            }
            if let Some(snapshot) = self.pending_forwarder.as_ref()
                && std::time::Instant::now() >= lease_retry_at
            {
                match snapshot.restore(&self.ns) {
                    Ok(forwarder) => {
                        let port = forwarder.forwarded_port();
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
            if active == 0 && !persistent && !self.ns.has_application_processes().unwrap_or(true) {
                // Stop probes before inspecting processes during teardown,
                // while no concurrent attach can enter setup.
                self.monitor.take();
                // Teardown can preserve the namespace (for example when an
                // unknown lockfile remains), or fail partway through cleanup.
                // Retain the owning guard, runtime files and ownership record
                // until removal is verified, so an explicit stop can retry.
                let teardown = crate::namespace_ownership::load(&self.ns.name, self.uid)
                    .and_then(NetworkNamespace::teardown);
                if let Err(error) = teardown {
                    log::warn!("Could not tear down namespace {}: {error:#}", self.ns.name);
                }
                if std::path::Path::new("/run/netns")
                    .join(&self.ns.name)
                    .try_exists()
                    .is_ok_and(|exists| !exists)
                {
                    self.disarm();
                    SESSIONS
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&self.ns.name);
                    release_resources(&self.ns.name);
                    crate::namespace_ownership::remove(&self.ns.name);
                    break;
                }
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
            let mut sessions = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
            if sessions
                .get(&self.ns.name)
                .is_some_and(|entry| Arc::ptr_eq(&entry.valid, &self.valid))
            {
                sessions.remove(&self.ns.name);
                release_resources(&self.ns.name);
            }
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
                vopono_core::util::set_helper_exe_override(std::env::current_exe().ok());
                let lock_dir = vopono_core::util::vopono_dir()?.join("locks").join(&name);
                vopono_core::util::owner_write::remove_file_as_config_owner(
                    &lock_dir.join(runtime.daemon_pid.to_string()),
                )?;
                if crate::namespace_ownership::is_stopping(&name, uid)? {
                    crate::control::stop_namespace(&name, Some(uid))?;
                    return Ok(None);
                }
                let mut ns = crate::namespace_ownership::load(&name, uid)?;
                // Errors during restoration must preserve existing protection.
                let restored = (|| -> anyhow::Result<_> {
                    let proxies = crate::exec::restore_host_proxies(&ns, &runtime.host_ports)?;
                    Ok(proxies)
                })();
                let proxies = match restored {
                    Ok(proxies) => proxies,
                    Err(error) => {
                        ns.detach();
                        return Err(error);
                    }
                };
                ns = ns.write_lockfile("")?;
                let mut session =
                    Session::register(ns, uid, None, runtime.monitor, runtime.recover);
                session.retain_proxies(proxies);
                session.pending_forwarder = runtime.forwarder;
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
        invalidate(&first.ns.name);
        first.run_until_unused();
        let replacement = Session::register(ns(), Uid::current(), None, false, false);
        assert!(replacement.controller);
        assert!(dropped.get());
        assert!(replacement.valid.load(Ordering::Acquire));
        invalidate(&replacement.ns.name);
        replacement.run_until_unused();
    }
}
