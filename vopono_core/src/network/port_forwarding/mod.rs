use std::sync::mpsc::Receiver;

use super::netns::NetworkNamespace;

pub mod azirevpn;
pub mod natpmpc;
pub mod piapf;

pub trait Forwarder {
    fn forwarded_port(&self) -> u16;
    /// Root-owned daemon restart state; never written to user-visible status.
    fn snapshot(&self) -> Option<ForwarderSnapshot> {
        None
    }
    /// Disarm external side effects (e.g., remote port-mapping deletion) when
    /// the daemon exits while leaving the namespace alive.
    fn disarm(&mut self) {}
    /// Stop handle for background renewal threads so teardown can terminate
    /// them before checking namespace processes.
    fn stop_handle(&self) -> Option<std::sync::mpsc::Sender<bool>> {
        None
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum ForwarderSnapshot {
    Pia(piapf::ThreadParamsImpl),
    Natpmp(natpmpc::ThreadParamsImpl),
    Azire {
        local_ip: std::net::IpAddr,
        access_token: String,
        netns_name: String,
    },
}
impl ForwarderSnapshot {
    pub fn restore(&self, ns: &NetworkNamespace) -> anyhow::Result<Box<dyn Forwarder>> {
        match self {
            Self::Pia(params) => {
                anyhow::ensure!(params.netns_name == ns.name, "Forwarder namespace mismatch");
                Ok(Box::new(piapf::Piapf::resume(params.clone())?))
            }
            Self::Natpmp(params) => {
                anyhow::ensure!(params.netns_name == ns.name, "Forwarder namespace mismatch");
                Ok(Box::new(natpmpc::Natpmpc::resume(params.clone())?))
            }
            Self::Azire {
                local_ip,
                access_token,
                netns_name,
            } => {
                anyhow::ensure!(*netns_name == ns.name, "Forwarder namespace mismatch");
                Ok(Box::new(azirevpn::AzireVpnPortForwarding::restore(
                    ns,
                    access_token,
                    *local_ip,
                )?))
            }
        }
    }
}

/// A port-forwarding callback and the identity it must run as.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CallbackCommand {
    command: String,
    user: Option<String>,
    group: Option<String>,
}

impl CallbackCommand {
    pub fn for_session(
        command: Option<&String>,
        user: Option<String>,
        group: Option<String>,
    ) -> Option<Self> {
        command.cloned().map(|command| Self {
            command,
            user,
            group,
        })
    }

    fn build_command(&self, netns_name: &str, port: u16) -> std::process::Command {
        let port_str = port.to_string();
        let argv = [self.command.as_str(), port_str.as_str()];
        NetworkNamespace::build_exec_command(
            netns_name,
            &argv,
            self.user.as_deref(),
            self.group.as_deref(),
            false,
            true,
            false,
            None,
        )
    }
}

/// ThreadParams must implement these methods
pub trait ThreadParameters {
    fn get_callback(&self) -> Option<&CallbackCommand>;
    fn get_loop_delay(&self) -> u64;
    fn get_netns_name(&self) -> String;
    /// Resolved vopono locks directory. Captured on the creating thread
    /// because the config-dir override is thread-local and background
    /// refresh threads would otherwise resolve the wrong root.
    fn get_locks_dir(&self) -> std::path::PathBuf;
    /// Firewall configuration so renewed ports can be opened dynamically.
    fn get_firewall(&self) -> Option<(crate::network::firewall::Firewall, bool)> {
        None
    }
    /// Initial port already opened by namespace setup so the first unchanged
    /// renewal does not append duplicate firewall rules.
    fn initial_opened_port(&self) -> Option<u16> {
        None
    }
    /// Optional hook to update the forwarder's live port cache on renewal.
    fn on_port_refreshed(&self, _port: u16) {}
}

fn renewal_retry_delay(normal: u64, failures: u32) -> u64 {
    (30u64 << failures.saturating_sub(1).min(4))
        .min(300)
        .min(normal.max(1))
}

pub trait ThreadLoopForwarder: Forwarder {
    /// Implementation defines parameter struct passed to loop on thread
    type ThreadParams: ThreadParameters;

    /// Implementation defines how to refresh port
    fn refresh_port(params: &Self::ThreadParams) -> anyhow::Result<u16>;

    /// Provided common implementation for thread loop
    fn thread_loop(params: Self::ThreadParams, recv: Receiver<bool>) {
        let mut failures = 0u32;
        let mut delay = params.get_loop_delay().max(1);
        let mut opened_port: Option<u16> = params.initial_opened_port();
        loop {
            let resp = recv.recv_timeout(std::time::Duration::from_secs(delay));
            if resp.is_ok() || matches!(resp, Err(std::sync::mpsc::RecvTimeoutError::Disconnected))
            {
                log::debug!("Thread exiting...");
                return;
            } else {
                let port = Self::refresh_port(&params);
                match port {
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        delay = renewal_retry_delay(params.get_loop_delay(), failures);
                        log::warn!("Port renewal failed; retrying in {delay}s: {e}");
                    }
                    Ok(p) => {
                        failures = 0;
                        delay = params.get_loop_delay().max(1);
                        log::debug!("Thread refreshed port: {p}");
                        params.on_port_refreshed(p);
                        if opened_port != Some(p) {
                            match params.get_firewall() {
                                Some((firewall, ipv6_enabled)) => {
                                    match crate::util::open_ports::open_port_in_namespace(
                                        &params.get_netns_name(),
                                        firewall,
                                        ipv6_enabled,
                                        None,
                                        None,
                                        p,
                                    ) {
                                        Ok(()) => {
                                            if let Some(previous) = opened_port
                                                && previous != p
                                            {
                                                crate::util::open_ports::close_port_in_namespace(
                                                    &params.get_netns_name(),
                                                    firewall,
                                                    ipv6_enabled,
                                                    previous,
                                                );
                                            }
                                            opened_port = Some(p);
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "Failed to open renewed port {p} in firewall: {e:#}"
                                            );
                                        }
                                    }
                                }
                                None => opened_port = Some(p),
                            }
                        }
                        // Keep the lockfile-visible status in sync so status
                        // readers see the renewed port, not the initial one.
                        if let Err(e) = crate::status::record_forwarded_port(
                            &params.get_locks_dir(),
                            &params.get_netns_name(),
                            p,
                        ) {
                            log::warn!("Failed to update forwarded port status: {e:?}");
                        }
                        Self::callback_command(&params, p);
                    }
                }
            }
        }
    }

    fn callback_command(params: &Self::ThreadParams, port: u16) -> Option<anyhow::Result<String>> {
        params.get_callback().map(|callback| {
            use std::io::Read;
            use std::os::unix::process::CommandExt;
            use std::time::{Duration, Instant};

            // The callback is attacker-controllable input relative to this
            // process: de-elevate it to the session user via build_exec_command so
            // both `--` separation and PR_SET_NO_NEW_PRIVS are enforced, and bound
            // its runtime so a hanging script cannot stall teardown or recovery.
            let mut cmd = callback.build_command(&params.get_netns_name(), port);
            cmd.process_group(0);
            let mut child = cmd.spawn()?;
            let stdout_pipe = child.stdout.take();
            let stderr_pipe = child.stderr.take();
            let stdout_reader = std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(pipe) = stdout_pipe {
                    let _ = pipe.take(64 * 1024).read_to_end(&mut buf);
                }
                buf
            });
            let stderr_reader = std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(pipe) = stderr_pipe {
                    let _ = pipe.take(64 * 1024).read_to_end(&mut buf);
                }
                buf
            });
            let deadline = Instant::now() + Duration::from_secs(15);
            let status = loop {
                match child.try_wait()? {
                    Some(status) => break status,
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    None => {
                        let pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
                        let _ = nix::sys::signal::kill(pgid, nix::sys::signal::Signal::SIGKILL);
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = stdout_reader.join();
                        let _ = stderr_reader.join();
                        anyhow::bail!("Port forwarding callback script timed out after 15s");
                    }
                }
            };
            let stdout = stdout_reader.join().unwrap_or_default();
            let stderr = stderr_reader.join().unwrap_or_default();
            if !status.success() {
                log::error!(
                    "Port forwarding callback script was unsuccessful!: stdout: {:?}, stderr: {:?}, exit code: {}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr),
                    status
                );
                Err(anyhow::anyhow!("Port forwarding callback script failed"))
            } else if let Ok(out) = String::from_utf8(stdout) {
                println!("{out}");
                Ok(out)
            } else {
                Ok("Callback script succeeded but stdout was not valid UTF8".to_string())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Params;
    impl ThreadParameters for Params {
        fn get_callback(&self) -> Option<&CallbackCommand> {
            None
        }
        fn get_loop_delay(&self) -> u64 {
            3600
        }
        fn get_netns_name(&self) -> String {
            "not-a-real-namespace".into()
        }
        fn get_locks_dir(&self) -> std::path::PathBuf {
            unreachable!()
        }
    }
    struct TestForwarder;
    impl Forwarder for TestForwarder {
        fn forwarded_port(&self) -> u16 {
            1
        }
    }
    impl ThreadLoopForwarder for TestForwarder {
        type ThreadParams = Params;
        fn refresh_port(_: &Params) -> anyhow::Result<u16> {
            panic!("Disconnected forwarders must never renew a port");
        }
    }
    #[test]
    fn disconnected_owner_stops_renewal_without_network_requests() {
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(sender);
        TestForwarder::thread_loop(Params, receiver);
    }
    #[test]
    fn transient_renewal_errors_use_bounded_backoff() {
        assert_eq!(
            (1..=7)
                .map(|n| renewal_retry_delay(3600, n))
                .collect::<Vec<_>>(),
            vec![30, 60, 120, 240, 300, 300, 300]
        );
        assert_eq!(renewal_retry_delay(10, 5), 10);
    }

    #[test]
    fn callback_command_argv_separates_sudo_options_from_command() {
        let cb = CallbackCommand::for_session(
            Some(&"-u".to_string()),
            Some("alice".to_string()),
            Some("staff".to_string()),
        )
        .unwrap();
        let cmd = cb.build_command("vo_test", 51820);
        assert_eq!(cmd.get_program(), "ip");
        let args: Vec<&str> = cmd
            .get_args()
            .map(|arg| arg.to_str().expect("UTF-8 argv"))
            .collect();
        assert_eq!(
            args,
            vec![
                "netns",
                "exec",
                "vo_test",
                "sudo",
                "--preserve-env",
                "--user",
                "alice",
                "--group",
                "staff",
                "--",
                "-u",
                "51820"
            ]
        );
    }
}
