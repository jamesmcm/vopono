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
    current_port: std::sync::Arc<std::sync::atomic::AtomicU16>,
    loop_thread_handle: Option<JoinHandle<()>>,
    send_channel: Sender<bool>,
    params: ThreadParamsImpl,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreadParamsImpl {
    pub netns_name: String,
    pub locks_dir: std::path::PathBuf,
    pub callback: Option<CallbackCommand>,
    #[serde(default)]
    pub firewall: Option<crate::network::firewall::Firewall>,
    #[serde(default)]
    pub ipv6_enabled: bool,
    #[serde(skip)]
    pub current_port: Option<std::sync::Arc<std::sync::atomic::AtomicU16>>,
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
    fn get_firewall(&self) -> Option<(crate::network::firewall::Firewall, bool)> {
        self.firewall.map(|fw| (fw, self.ipv6_enabled))
    }
    fn initial_opened_port(&self) -> Option<u16> {
        self.current_port
            .as_ref()
            .map(|current| current.load(std::sync::atomic::Ordering::Acquire))
    }
    fn on_port_refreshed(&self, port: u16) {
        if let Some(current) = &self.current_port {
            current.store(port, std::sync::atomic::Ordering::Release);
        }
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
        let tunnel_iface = ns
            .wireguard
            .as_ref()
            .map(|wg| wg.if_name.clone())
            .or_else(|| {
                crate::network::firewall::wait_for_tunnel_interface(&ns.name, &["tun"], 1)
                    .ok()
                    .flatten()
            })
            .context("Could not determine tunnel interface for NAT-PMP gateway rule")?;
        match ns.firewall {
            crate::network::firewall::Firewall::IpTables => {
                NetworkNamespace::exec(
                    &ns.name,
                    &[
                        "iptables",
                        "-I",
                        "OUTPUT",
                        "1",
                        "-o",
                        &tunnel_iface,
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
                let quoted_iface = format!("\"{tunnel_iface}\"");
                NetworkNamespace::exec(
                    &ns.name,
                    &[
                        "nft",
                        "insert",
                        "rule",
                        "inet",
                        &ns.name,
                        "output",
                        "oifname",
                        &quoted_iface,
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
            log::debug!(
                "NAT-PMP gateway probe failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            log::error!(
                "natpmpc failed - likely that this server does not support port forwarding, please choose another server"
            );
            anyhow::bail!(
                "natpmpc failed - likely that this server does not support port forwarding, please choose another server"
            )
        }

        let ipv6_enabled = ns
            .veth_pair_ips
            .as_ref()
            .and_then(|ips| ips.ipv6.as_ref())
            .is_some();
        let params = ThreadParamsImpl {
            netns_name: ns.name.clone(),
            locks_dir: crate::util::config_dir()?.join("vopono").join("locks"),
            callback: CallbackCommand::for_session(
                callback,
                ns.predown_user.clone(),
                ns.predown_group.clone(),
            ),
            firewall: Some(ns.firewall),
            ipv6_enabled,
            current_port: None,
        };

        Self::resume(params)
    }

    pub fn resume(mut params: ThreadParamsImpl) -> anyhow::Result<Self> {
        let port = Self::refresh_port(&params)?;
        let current_port = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(port));
        params.current_port = Some(current_port.clone());
        Self::callback_command(&params, port);

        let (send, recv) = mpsc::channel::<bool>();

        let owner_write_context = crate::util::capture_owner_write_context()?;
        let retained = params.clone();
        let handle = std::thread::spawn(move || {
            crate::util::install_owner_write_context(&owner_write_context);
            Self::thread_loop(params, recv);
        });

        log::info!("ProtonVPN forwarded local port: {port}");
        Ok(Self {
            local_port: port,
            current_port,
            loop_thread_handle: Some(handle),
            send_channel: send,
            params: retained,
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
        anyhow::ensure!(
            udp_output.status.success(),
            "natpmpc UDP port renewal failed ({})",
            udp_output.status
        );
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
        anyhow::ensure!(
            tcp_output.status.success(),
            "natpmpc TCP port renewal failed ({})",
            tcp_output.status
        );
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
        self.current_port.load(std::sync::atomic::Ordering::Acquire)
    }
    fn snapshot(&self) -> Option<super::ForwarderSnapshot> {
        Some(super::ForwarderSnapshot::Natpmp(self.params.clone()))
    }
    fn stop_handle(&self) -> Option<std::sync::mpsc::Sender<bool>> {
        Some(self.send_channel.clone())
    }
}
