use anyhow::Context;
use regex::Regex;
use std::sync::LazyLock;
use std::sync::mpsc;
use std::{sync::mpsc::Sender, thread::JoinHandle};

use super::{CallbackCommand, Forwarder, ThreadLoopForwarder, ThreadParameters};
use crate::config::providers::protonvpn::PROTONVPN_GATEWAY;
use crate::network::netns::NetworkNamespace;

static MAPPED_PORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Mapped public port (?P<port>\d{1,5}) protocol")
        .expect("Invalid natpmpc mapped port regex")
});

/// Used to provide port forwarding for ProtonVPN
pub struct Natpmpc {
    pub local_port: u16,
    loop_thread_handle: Option<JoinHandle<()>>,
    send_channel: Sender<bool>,
}

pub struct ThreadParamsImpl {
    pub netns_name: String,
    pub locks_dir: std::path::PathBuf,
    pub callback: Option<CallbackCommand>,
}

impl ThreadParameters for ThreadParamsImpl {
    fn get_callback(&self) -> Option<&CallbackCommand> {
        self.callback.as_ref()
    }
    fn get_loop_delay(&self) -> u64 {
        45
    }
    fn get_netns_name(&self) -> String {
        self.netns_name.clone()
    }
    fn get_locks_dir(&self) -> std::path::PathBuf {
        self.locks_dir.clone()
    }
}

impl Natpmpc {
    pub fn new(ns: &NetworkNamespace, callback: Option<&String>) -> anyhow::Result<Self> {
        let gateway_str = PROTONVPN_GATEWAY.to_string();

        if let Err(x) = which::which("natpmpc") {
            log::error!(
                "natpmpc not found. Is natpmpc installed and on PATH? (e.g. libnatpmp package)"
            );
            return Err(anyhow::anyhow!(
                "natpmpc not found. Is natpmpc installed and on PATH?: {:?}",
                x
            ));
        }

        log::debug!("Opening firewall for NAT-PMP gateway: {gateway_str}");
        match ns.firewall {
            crate::network::firewall::Firewall::IpTables => {
                NetworkNamespace::exec(
                    &ns.name,
                    &[
                        "iptables",
                        "-A",
                        "OUTPUT",
                        "-p",
                        "udp",
                        "-d",
                        &gateway_str,
                        "--dport",
                        "5351",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            crate::network::firewall::Firewall::NfTables => {
                NetworkNamespace::exec(
                    &ns.name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        &ns.name,
                        "output",
                        "ip",
                        "daddr",
                        &gateway_str,
                        "udp",
                        "dport",
                        "5351",
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }

        // Check output for readnatpmpresponseorretry returned 0 (OK)
        // If receive readnatpmpresponseorretry returned -7
        // Then prompt user to choose different gateway
        let output =
            NetworkNamespace::exec_with_output(&ns.name, &["natpmpc", "-g", &gateway_str])?;
        if !output.status.success() {
            log::error!(
                "natpmpc failed - likely that this server does not support port forwarding, please choose another server"
            );
            anyhow::bail!(
                "natpmpc failed - likely that this server does not support port forwarding, please choose another server"
            )
        }

        let params = ThreadParamsImpl {
            netns_name: ns.name.clone(),
            locks_dir: crate::util::config_dir()?.join("vopono").join("locks"),
            callback: CallbackCommand::for_session(
                callback,
                ns.predown_user.clone(),
                ns.predown_group.clone(),
            ),
        };

        let port = Self::refresh_port(&params)?;
        Self::callback_command(&params, port);

        let (send, recv) = mpsc::channel::<bool>();

        let handle = std::thread::spawn(move || Self::thread_loop(params, recv));

        log::info!("ProtonVPN forwarded local port: {port}");
        Ok(Self {
            local_port: port,
            loop_thread_handle: Some(handle),
            send_channel: send,
        })
    }
}

impl ThreadLoopForwarder for Natpmpc {
    type ThreadParams = ThreadParamsImpl;

    fn refresh_port(params: &Self::ThreadParams) -> anyhow::Result<u16> {
        let gateway_str = PROTONVPN_GATEWAY.to_string();
        let re = &MAPPED_PORT_RE;
        // Read Mapped public port 61057 protocol UDP
        let udp_output = NetworkNamespace::exec_with_output(
            &params.netns_name,
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
            &params.netns_name,
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

impl Forwarder for Natpmpc {
    fn forwarded_port(&self) -> u16 {
        self.local_port
    }
}
