use std::process::Command;

use log::{debug, warn};

use crate::network::{netns::NetworkNamespace, port_forwarding::Forwarder};

pub fn set_env_vars(ns: &NetworkNamespace, forwarder: Option<&dyn Forwarder>, cmd: &mut Command) {
    // Temporarily set env var referring to this network namespace IP
    // for the PostUp script and the application:

    if which::which("pactl").is_ok() {
        let pa = crate::util::pulseaudio::get_pulseaudio_server();
        if let Ok(pa) = pa {
            cmd.env("PULSE_SERVER", &pa);
            debug!("Setting PULSE_SERVER to {}", &pa);
        } else if let Err(e) = pa {
            warn!("Could not get PULSE_SERVER: {e:?}");
        } else {
            warn!("Could not parse PULSE_SERVER from pactl info output: {pa:?}",);
        }
    } else {
        debug!("pactl not found, will not set PULSE_SERVER");
    }

    if let Some(ref ns_ip) = ns.veth_pair_ips {
        cmd.env("VOPONO_NS_IP", ns_ip.namespace_ip.to_string());
        cmd.env("VOPONO_HOST_IP", ns_ip.host_ip.to_string());
    }

    cmd.env("VOPONO_NS", &ns.name);

    // TODO: Do we want to provide -o open ports too?
    if let Some(f) = forwarder.as_ref() {
        cmd.env("VOPONO_FORWARDED_PORT", f.forwarded_port().to_string());
    }
}
