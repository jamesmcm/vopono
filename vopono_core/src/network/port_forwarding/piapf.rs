use anyhow::Context;
use base64::prelude::*;
use regex::Regex;
use serde::Deserialize;
use std::sync::mpsc::{self};
use std::{sync::mpsc::Sender, thread::JoinHandle};
use which::which;

use super::{CallbackCommand, Forwarder, ThreadLoopForwarder, ThreadParameters};
use crate::network::netns::NetworkNamespace;

use crate::config::providers::OpenVpnProvider;
use crate::config::providers::pia::PrivateInternetAccess;
use crate::config::vpn::Protocol;

/// Used to provide port forwarding for PrivateInternetAccess
pub struct Piapf {
    pub port: u16,
    loop_thread_handle: Option<JoinHandle<()>>,
    send_channel: Sender<bool>,
    params: ThreadParamsImpl,
    cleanup_enabled: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreadParamsImpl {
    pub port: u16,
    pub netns_name: String,
    pub locks_dir: std::path::PathBuf,
    pub signature: String,
    pub payload: String,
    pub hostname: String,
    pub gateway: String,
    pub pia_cert_path: String,
    #[serde(default)]
    pub runtime_dir: Option<std::path::PathBuf>,
    pub callback: Option<CallbackCommand>,
    #[serde(default)]
    pub firewall: Option<crate::network::firewall::Firewall>,
    #[serde(default)]
    pub ipv6_enabled: bool,
}

#[derive(Deserialize)]
struct SignatureResponse {
    status: String,
    signature: Option<String>,
    payload: Option<String>,
}

#[derive(Deserialize)]
struct SignaturePayload {
    port: u16,
}

#[derive(Deserialize)]
struct BindResponse {
    status: String,
}

impl ThreadParameters for ThreadParamsImpl {
    fn get_callback(&self) -> Option<&CallbackCommand> {
        self.callback.as_ref()
    }

    fn get_loop_delay(&self) -> u64 {
        60 * 15
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
        Some(self.port)
    }
}

impl Piapf {
    pub fn new(
        ns: &NetworkNamespace,
        config_file: &String,
        protocol: &Protocol,
        callback: Option<&String>,
    ) -> anyhow::Result<Self> {
        let pia = PrivateInternetAccess {};

        if which("traceroute").is_err() {
            log::error!(
                "The traceroute utility is necessary for PIA port forwarding. Please install traceroute."
            );
            anyhow::bail!(
                "The traceroute utility is necessary for PIA port forwarding. Please install traceroute."
            )
        }

        let traceroute_response = NetworkNamespace::exec_with_output(
            &ns.name,
            &[
                "traceroute",
                "-4",
                "-n",
                "-m",
                "1",
                "privateinternetaccess.com",
            ],
        )?;
        if !traceroute_response.status.success() {
            log::error!("Could not locate gateway with traceroute");
            anyhow::bail!("Could not locate gateway with traceroute")
        }
        let re = Regex::new(r" *1 *(?P<gateway>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")
            .expect("Unable to compile regex");
        let result = String::from_utf8_lossy(&traceroute_response.stdout);
        let second_line = result
            .lines()
            .nth(1)
            .context("Missing first-hop line in PIA traceroute output")?;
        let vpn_gateway = re
            .captures(second_line)
            .and_then(|caps| caps.name("gateway"))
            .context("Could not extract PIA gateway IP from traceroute output")?
            .as_str()
            .to_string();

        log::info!("PIA gateway: {vpn_gateway}");

        let vpn_hostname = match protocol {
            Protocol::OpenVpn => pia.hostname_for_openvpn_conf(config_file)?,
            Protocol::Wireguard => pia.hostname_for_wireguard_conf(config_file)?,
            _ => {
                log::error!("PIA port forwarding only supported for OpenVPN and Wireguard");
                anyhow::bail!("PIA port forwarding only supported for OpenVPN and Wireguard")
            }
        };

        log::info!("PIA hostname: {vpn_hostname}");

        let (pia_user, pia_pass) = match protocol {
            Protocol::OpenVpn => pia.load_openvpn_auth()?,
            Protocol::Wireguard => pia.load_wireguard_auth()?,
            _ => {
                log::error!("PIA port forwarding only supported for OpenVPN and Wireguard");
                anyhow::bail!("PIA port forwarding only supported for OpenVPN and Wireguard")
            }
        };

        //log::info!("PIA u/p: {} / {}", pia_user, pia_pass);

        let pia_token = PrivateInternetAccess::get_pia_token(&pia_user, &pia_pass)?;
        let raw_cert_path = pia.pia_cert_path()?;
        let (pia_cert_path, runtime_dir_guard) = if crate::util::is_daemon_mode() {
            // Freeze the PIA CA certificate into a root-owned runtime directory
            // so root `curl --cacert` never opens a user-writable path directly.
            let cert_bytes = crate::util::owner_write::read_file_as_config_owner(&raw_cert_path)
                .with_context(|| {
                    format!(
                        "Failed to read PIA CA certificate {}",
                        raw_cert_path.display()
                    )
                })?;
            let runtime_dir = crate::network::etc_overlay::trusted_runtime_dir("piapf-")?;
            let frozen_cert = runtime_dir.path().join("ca.rsa.4096.crt");
            let mut file = crate::util::create_private_file(&frozen_cert)?;
            std::io::Write::write_all(&mut file, &cert_bytes)?;
            (frozen_cert.display().to_string(), Some(runtime_dir))
        } else {
            (raw_cert_path.display().to_string(), None)
        };

        log::info!("PIA pia_cert_path: {pia_cert_path}");

        if which("curl").is_err() {
            log::error!(
                "The curl utility is necessary for PIA port forwarding. Please install curl."
            );
            anyhow::bail!(
                "The curl utility is necessary for PIA port forwarding. Please install curl."
            )
        }

        let get_response = exec_curl_with_stdin(
            &ns.name,
            &[
                "curl",
                "-s",
                "-m",
                "5",
                "--connect-to",
                &format!("{vpn_hostname}::{vpn_gateway}:"),
                "--cacert",
                &pia_cert_path,
                "-G",
                "-K",
                "-",
                &format!("https://{vpn_hostname}:19999/getSignature"),
            ],
            &format!(
                "data-urlencode = {}\n",
                curl_quote(&format!("token={pia_token}"))
            ),
        )?;
        if !get_response.status.success() {
            log::error!("Could not obtain signature for port forward from PIA API");
            anyhow::bail!("Could not obtain signature for port forward from PIA API")
        }

        let parsed: SignatureResponse = serde_json::from_slice(&get_response.stdout)
            .context("Invalid PIA getSignature response")?;
        if parsed.status != "OK" {
            log::error!("Signature for port forward from PIA API not OK");
            anyhow::bail!("Signature for port forward from PIA API not OK");
        }

        let signature = parsed
            .signature
            .context("getSignature response missing signature")?;
        let payload = parsed
            .payload
            .context("getSignature response missing payload")?;
        let decoded = BASE64_STANDARD.decode(&payload)?;
        let parsed: SignaturePayload =
            serde_json::from_slice(&decoded).context("Invalid PIA signature payload")?;
        let port = parsed.port;

        let ipv6_enabled = ns
            .veth_pair_ips
            .as_ref()
            .and_then(|ips| ips.ipv6.as_ref())
            .is_some();
        let params = ThreadParamsImpl {
            netns_name: ns.name.clone(),
            locks_dir: crate::util::config_dir()?.join("vopono").join("locks"),
            hostname: vpn_hostname,
            gateway: vpn_gateway,
            pia_cert_path,
            runtime_dir: runtime_dir_guard.as_ref().map(|d| d.path().to_path_buf()),
            signature,
            payload,
            port,
            callback: CallbackCommand::for_session(
                callback,
                ns.predown_user.clone(),
                ns.predown_group.clone(),
            ),
            firewall: Some(ns.firewall),
            ipv6_enabled,
        };
        let forwarder = Self::resume(params)?;
        if let Some(dir) = runtime_dir_guard {
            let _ = dir.keep();
        }
        Ok(forwarder)
    }

    pub fn resume(params: ThreadParamsImpl) -> anyhow::Result<Self> {
        let port = Self::refresh_port(&params)?;
        Self::callback_command(&params, port);
        let (send, recv) = mpsc::channel::<bool>();
        let owner_write_context = crate::util::capture_owner_write_context()?;
        let retained = params.clone();
        let handle = std::thread::spawn(move || {
            crate::util::install_owner_write_context(&owner_write_context);
            Self::thread_loop(params, recv);
        });

        log::info!("PIA forwarded local port: {port}");
        Ok(Self {
            port,
            loop_thread_handle: Some(handle),
            send_channel: send,
            params: retained,
            cleanup_enabled: true,
        })
    }
}

fn curl_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

fn exec_curl_with_stdin(
    netns_name: &str,
    argv: &[&str],
    stdin_config: &str,
) -> anyhow::Result<std::process::Output> {
    use std::io::Write;
    let mut child =
        NetworkNamespace::exec_no_block(netns_name, argv, None, None, false, true, true, None)?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_config.as_bytes());
    }
    child.wait_with_output().map_err(Into::into)
}

impl ThreadLoopForwarder for Piapf {
    type ThreadParams = ThreadParamsImpl;

    fn refresh_port(params: &Self::ThreadParams) -> anyhow::Result<u16> {
        let bind_response = exec_curl_with_stdin(
            &params.netns_name,
            &[
                "curl",
                "-Gs",
                "-m",
                "5",
                "--connect-to",
                &format!("{}::{}:", params.hostname, params.gateway),
                "--cacert",
                &params.pia_cert_path,
                "-K",
                "-",
                &format!("https://{}:19999/bindPort", params.hostname),
            ],
            &format!(
                "data-urlencode = {}\ndata-urlencode = {}\n",
                curl_quote(&format!("payload={}", params.payload)),
                curl_quote(&format!("signature={}", params.signature))
            ),
        )?;
        if !bind_response.status.success() {
            log::error!("Could not bind port forward from PIA API");
            anyhow::bail!("Could not bind port forward from PIA API")
        }

        let parsed: BindResponse = serde_json::from_slice(&bind_response.stdout)
            .context("Invalid PIA bindPort response")?;

        if parsed.status != "OK" {
            log::error!("Bind for port forward from PIA API not OK");
            anyhow::bail!("Bind for port forward from PIA API not OK");
        }

        log::info!("Successfully updated claim to port {}", params.port);

        Ok(params.port)
    }
}

impl Drop for Piapf {
    fn drop(&mut self) {
        let handle = self.loop_thread_handle.take();
        if let Some(h) = handle {
            self.send_channel.send(true).ok();
            h.join().ok();
        }
        if self.cleanup_enabled
            && let Some(runtime_dir) = &self.params.runtime_dir
        {
            let _ = std::fs::remove_dir_all(runtime_dir);
        }
    }
}

impl Forwarder for Piapf {
    fn forwarded_port(&self) -> u16 {
        self.port
    }
    fn snapshot(&self) -> Option<super::ForwarderSnapshot> {
        Some(super::ForwarderSnapshot::Pia(self.params.clone()))
    }
    fn stop_handle(&self) -> Option<std::sync::mpsc::Sender<bool>> {
        Some(self.send_channel.clone())
    }
    fn disarm(&mut self) {
        self.cleanup_enabled = false;
    }
}
