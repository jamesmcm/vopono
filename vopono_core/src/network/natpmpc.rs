use anyhow::Context;
use regex::Regex;
use std::sync::mpsc::{self, Receiver};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::mpsc::Sender,
    thread::JoinHandle,
};

use super::netns::NetworkNamespace;

// TODO: Move this to ProtonVPN provider
pub const PROTONVPN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));

/// Used to provide port forwarding for ProtonVPN
pub struct Natpmpc {
    pub local_port: u16,
    loop_thread_handle: Option<JoinHandle<()>>,
    send_channel: Sender<bool>,
}

impl Natpmpc {
    pub fn new(ns: &NetworkNamespace) -> anyhow::Result<Self> {
        let gateway_str = PROTONVPN_GATEWAY.to_string();

        // Check output for readnatpmpresponseorretry returned 0 (OK)
        // If receive readnatpmpresponseorretry returned -7
        // Then prompt user to choose different gateway
        let output =
            NetworkNamespace::exec_with_output(&ns.name, &["natpmpc", "-g", &gateway_str])?;
        if !output.status.success() {
            log::error!("natpmpc failed - likely that this server does not support port forwarding, please choose another server");
            anyhow::bail!("natpmpc failed - likely that this server does not support port forwarding, please choose another server")
        }

        let port = Self::refresh_port(&ns.name)?;

        let (send, recv) = mpsc::channel::<bool>();

        let ns_name = ns.name.clone();
        let handle = std::thread::spawn(move || Self::thread_loop(ns_name, recv));

        log::info!("ProtonVPN forwarded local port: {port}");
        Ok(Self {
            local_port: port,
            loop_thread_handle: Some(handle),
            send_channel: send,
        })
    }

    fn refresh_port(ns_name: &str) -> anyhow::Result<u16> {
        let gateway_str = PROTONVPN_GATEWAY.to_string();
        // TODO: Cache regex
        let re = Regex::new(r"Mapped public port (?P<port>\d{1,5}) protocol").unwrap();
        // Read Mapped public port 61057 protocol UDP
        let udp_output = NetworkNamespace::exec_with_output(
            ns_name,
            &["natpmpc", "-a", "1", "0", "udp", "60", "-g", &gateway_str],
        )?;
        let udp_port: u16 = re
            .captures(String::from_utf8_lossy(&udp_output.stdout).as_ref())
            .context("Failed to read port from natpmpc output - no captures")?
            .get(1)
            .context("Failed to read port from natpmpc output - no port")?
            .as_str()
            .parse()?;
        // Mapped public port 61057 protocol TCP
        let tcp_output = NetworkNamespace::exec_with_output(
            ns_name,
            &["natpmpc", "-a", "1", "0", "tcp", "60", "-g", &gateway_str],
        )?;
        let tcp_port: u16 = re
            .captures(String::from_utf8_lossy(&tcp_output.stdout).as_ref())
            .context("Failed to read port from natpmpc output - no captures")?
            .get(1)
            .context("Failed to read port from natpmpc output - no port")?
            .as_str()
            .parse()?;
        if udp_port != tcp_port {
            log::error!("natpmpc assigned UDP port: {udp_port} did not equal TCP port: {tcp_port}");
            anyhow::bail!(
                "natpmpc assigned UDP port: {udp_port} did not equal TCP port: {tcp_port}"
            )
        }

        Ok(udp_port)
    }

    // Spawn thread to repeat above every 45 seconds
    fn thread_loop(netns_name: String, recv: Receiver<bool>) {
        loop {
            let resp = recv.recv_timeout(std::time::Duration::from_secs(45));
            if resp.is_ok() {
                log::debug!("Thread exiting...");
                return;
            } else {
                let port = Self::refresh_port(&netns_name);
                match port {
                    Err(e) => {
                        log::error!("Thread failed to refresh port: {e:?}");
                        return;
                    }
                    Ok(p) => log::debug!("Thread refreshed port: {p}"),
                }

                // TODO: Communicate port change via channel?
            }
        }
    }
}

impl Drop for Natpmpc {
    fn drop(&mut self) {
        let handle = self.loop_thread_handle.take();
        if let Some(h) = handle {
            self.send_channel.send(true).ok();
            h.join().ok();
        }
    }
}
