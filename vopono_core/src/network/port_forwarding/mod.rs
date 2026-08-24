use std::sync::mpsc::Receiver;

use super::netns::NetworkNamespace;

pub mod azirevpn;
pub mod natpmpc;
pub mod piapf;

pub trait Forwarder {
    fn forwarded_port(&self) -> u16;
}

/// ThreadParams must implement these methods
pub trait ThreadParameters {
    fn get_callback_command(&self) -> Option<String>;
    /// Session user for callback execution (de-elevation). `None` keeps the
    /// historical behaviour of running as the current user in CLI sessions.
    fn get_callback_user(&self) -> Option<String> {
        None
    }
    /// Session group for callback execution.
    fn get_callback_group(&self) -> Option<String> {
        None
    }
    fn get_loop_delay(&self) -> u64;
    fn get_netns_name(&self) -> String;
    /// Resolved vopono locks directory. Captured on the creating thread
    /// because the config-dir override is thread-local and background
    /// refresh threads would otherwise resolve the wrong root.
    fn get_locks_dir(&self) -> std::path::PathBuf;
}

pub trait ThreadLoopForwarder: Forwarder {
    /// Implementation defines parameter struct passed to loop on thread
    type ThreadParams: ThreadParameters;

    /// Implementation defines how to refresh port
    fn refresh_port(params: &Self::ThreadParams) -> anyhow::Result<u16>;

    /// Provided common implementation for thread loop
    fn thread_loop(params: Self::ThreadParams, recv: Receiver<bool>) {
        loop {
            let resp = recv.recv_timeout(std::time::Duration::from_secs(params.get_loop_delay()));
            if resp.is_ok() {
                log::debug!("Thread exiting...");
                return;
            } else {
                let port = Self::refresh_port(&params);
                match port {
                    Err(e) => {
                        log::error!("Thread failed to refresh port: {e:?}");
                        return;
                    }
                    Ok(p) => {
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
        params.get_callback_command().map(|callback_command| {
            // The callback is attacker-controllable input relative to this
            // process: de-elevate it to the session user (network namespaces
            // are not a privilege boundary).
            let mut command_vec: Vec<String> = Vec::new();
            if let Some(user) = params.get_callback_user() {
                command_vec.push("sudo".to_string());
                command_vec.push("--preserve-env".to_string());
                if let Some(group) = params.get_callback_group() {
                    command_vec.push("--group".to_string());
                    command_vec.push(group);
                }
                command_vec.push("--user".to_string());
                command_vec.push(user);
            }
            command_vec.push(callback_command);
            command_vec.push(port.to_string());
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
