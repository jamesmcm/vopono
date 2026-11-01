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
                Ok(Box::new(azirevpn::AzireVpnPortForwarding::new(
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

    fn argv(&self, port: u16) -> Vec<String> {
        let mut argv = Vec::new();
        if let Some(user) = &self.user {
            argv.extend(["sudo".to_string(), "--preserve-env".to_string()]);
            if let Some(group) = &self.group {
                argv.extend(["--group".to_string(), group.clone()]);
            }
            argv.extend(["--user".to_string(), user.clone()]);
        }
        argv.extend([self.command.clone(), port.to_string()]);
        argv
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
            // The callback is attacker-controllable input relative to this
            // process: de-elevate it to the session user (network namespaces
            // are not a privilege boundary).
            let command_vec = callback.argv(port);
            let argv: Vec<&str> = command_vec.iter().map(|s| s.as_str()).collect();
            let refresh_response =
                NetworkNamespace::exec_with_output(&params.get_netns_name(), &argv)?;
            if !refresh_response.status.success() {
                log::error!(
                    "Port forwarding callback script was unsuccessful!: stdout: {:?}, stderr: {:?}, exit code: {}",
                    String::from_utf8(refresh_response.stdout),
                    String::from_utf8(refresh_response.stderr),
                    refresh_response.status
                );
                Err(anyhow::anyhow!("Port forwarding callback script failed"))
            } else if let Ok(out) = String::from_utf8(refresh_response.stdout) {
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
}
