use std::sync::mpsc::Receiver;

use super::netns::NetworkNamespace;

pub mod natpmpc;
pub mod piapf;

pub trait Forwarder {
    fn forwarded_port(&self) -> u16;
}

/// ThreadParams must implement these methods
pub trait ThreadParameters {
    fn get_callback_command(&self) -> Option<String>;
    fn get_loop_delay(&self) -> u64;
    fn get_netns_name(&self) -> String;
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
                        Self::callback_command(&params, p);
                    }
                }
            }
        }
    }

    fn callback_command(params: &Self::ThreadParams, port: u16) -> Option<anyhow::Result<String>> {
        params.get_callback_command().map(|callback_command|
             {
        let refresh_response = NetworkNamespace::exec_with_output(
            &params.get_netns_name(),
            &[&callback_command, &port.to_string()],
        )?;
        if !refresh_response.status.success() {
            log::error!(
                    "Port forwarding callback script was unsuccessful!: stdout: {:?}, stderr: {:?}, exit code: {}",
                    String::from_utf8(refresh_response.stdout),
                    String::from_utf8(refresh_response.stderr),
                    refresh_response.status
                );
            Err(anyhow::anyhow!("Port forwarding callback script failed"))
        } else if let Ok(out) = String::from_utf8(refresh_response.stdout) {
            println!("{}", out);
            Ok(out)
        } else {
            Ok("Callback script succeeded but stdout was not valid UTF8".to_string())
        }
    }
    )
    }
}
