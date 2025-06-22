use std::process::Command;

use log::{debug, warn};
use std::collections::HashMap;

use crate::network::{netns::NetworkNamespace, port_forwarding::Forwarder};

pub fn get_host_env_vars() -> HashMap<String, String> {
    let mut env_vars = HashMap::new();

    if which::which("pactl").is_ok() {
        match crate::util::pulseaudio::get_pulseaudio_server() {
            Ok(pa) => {
                debug!("Found PULSE_SERVER on host: {}", &pa);
                env_vars.insert("PULSE_SERVER".to_string(), pa);
            }
            Err(e) => {
                warn!("Could not get PULSE_SERVER from host: {:?}", e);
            }
        }
    } else {
        debug!("pactl not found on host, will not set PULSE_SERVER");
    }

    // Add any other host-specific environment variable lookups here in the future.

    env_vars
}

pub fn set_env_vars(
    ns: &NetworkNamespace,
    forwarder: Option<&dyn Forwarder>,
    cmd: &mut Command,
    host_vars: &HashMap<String, String>,
) {
    // Temporarily set env var referring to this network namespace IP
    // for the PostUp script and the application:
    for (key, value) in host_vars.iter() {
        cmd.env(key, value);
    }

    if let Some(ref veth_pair_ips) = ns.veth_pair_ips {
        if let Some(ipv4pair) = veth_pair_ips.ipv4.clone() {
            cmd.env("VOPONO_NS_IP", ipv4pair.namespace_ip.to_string());
            cmd.env("VOPONO_HOST_IP", ipv4pair.host_ip.to_string());
        } else {
            log::error!("No IPv4 veth pair!")
        };

        if let Some(ipv6pair) = veth_pair_ips.ipv6.clone() {
            cmd.env("VOPONO_NS_IPV6", ipv6pair.namespace_ip.to_string());
            cmd.env("VOPONO_HOST_IPV6", ipv6pair.host_ip.to_string());
        }
    }

    cmd.env("VOPONO_NS", &ns.name);

    // TODO: Do we want to provide -o open ports too?
    if let Some(f) = forwarder.as_ref() {
        cmd.env("VOPONO_FORWARDED_PORT", f.forwarded_port().to_string());
    }
}
