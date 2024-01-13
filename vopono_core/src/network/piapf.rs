extern crate json;

use std::sync::mpsc::{self, Receiver};
use std::{
    sync::mpsc::Sender,
    thread::JoinHandle
};
use base64::prelude::*;
use regex::Regex;

use super::netns::NetworkNamespace;
use super::Forwarder;

use crate::config::vpn::Protocol;
use crate::config::providers::OpenVpnProvider; // Added load_openvpn_auth to this trait 
use crate::config::providers::pia::PrivateInternetAccess;  // Added load_wireguard_auth to this struct 

/// Used to provide port forwarding for ProtonVPN
pub struct Piapf {
    pub port: u16,
    loop_thread_handle: Option<JoinHandle<()>>,
    send_channel: Sender<bool>,
}

struct ThreadParams {
    pub port: u16,
    pub netns_name: String,
    pub signature: String, 
    pub payload: String,
    pub hostname: String,
    pub gateway: String,
}

impl Piapf {
    pub fn new(ns: &NetworkNamespace, protocol: &Protocol) -> anyhow::Result<Self> {
        let pia = PrivateInternetAccess {}; //This is a bit weird, no? There's no state, so effectively all the methods are static...
        
        let traceroute_response = NetworkNamespace::exec_with_output(
            &ns.name, 
            &["traceroute", "-n", "-m", "1", "privateinternetaccess.com" ], )?;
        if !traceroute_response.status.success() {
            log::error!("Could not locate gateway with traceroute");
            anyhow::bail!("Could not locate gateway with traceroute")
        }
        let re = Regex::new(r" *1 *(?P<gateway>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*").unwrap();
        let result = String::from_utf8_lossy(&traceroute_response.stdout);
        let second_line = result.lines().skip(1).next().unwrap();
        let vpn_gateway = re.captures(&second_line).unwrap().get(1).unwrap().as_str().to_string();
        
        log::info!("PIA gateway: {}", vpn_gateway);
        
        let vpn_hostname = match protocol {
            Protocol::OpenVpn => "nl-amsterdam.privacy.network".to_string(), // FIXME: Parse this from the OpenVPN conf?
            Protocol::Wireguard => "nl-amsterdam.privacy.network".to_string(), // FIXME: [Insert clever idea to get wireguard endpoint hostname here] 
            _ => {
                log::error!("PIA port forwarding only supported for OpenVPN and Wireguard");
                anyhow::bail!("PIA port forwarding only supported for OpenVPN and Wireguard")
            }
        };
        
        log::info!("PIA hostname: {}", vpn_hostname);
        
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
        
        log::info!("PIA pia_token: {}", pia_token);

        let get_response = NetworkNamespace::exec_with_output(&ns.name, &["curl", 
            "-s", "-m", "5",
            "--connect-to", &format!("{}::{}:", vpn_hostname, vpn_gateway).to_string(),
            "--cacert", "/home/benland100/vopono/vopono_core/src/config/providers/pia/ca.rsa.4096.crt", //FIXME: how to get this path?
            "-G", "--data-urlencode", &format!("token={}",pia_token).to_string(),
            &format!("https://{}:19999/getSignature",vpn_hostname).to_string() ] )?;
        if !get_response.status.success() {
            log::error!("Could not obtain signature for port forward from PIA API");
            anyhow::bail!("Could not obtain signature for port forward from PIA API")
        }
        
        let parsed = json::parse(String::from_utf8_lossy(&get_response.stdout).as_ref())?;
        if parsed["status"] != "OK" {
            log::error!("Signature for port forward from PIA API not OK");
            anyhow::bail!("Signature for port forward from PIA API not OK");
        }
        
        let signature = parsed["signature"].as_str().unwrap().to_string();
        let payload = parsed["payload"].as_str().unwrap().to_string();
        let decoded = BASE64_STANDARD.decode(&payload)?;
        let parsed = json::parse(String::from_utf8_lossy(&decoded).as_ref())?;
        let port = parsed["port"].as_u16().unwrap();

        let params = ThreadParams {
            netns_name: ns.name.clone(),
            hostname: vpn_hostname,
            gateway: vpn_gateway,
            signature: signature,
            payload: payload,
            port: port,
        };
        Self::refresh_port(&params)?;
        let (send, recv) = mpsc::channel::<bool>();
        let handle = std::thread::spawn(move || Self::thread_loop(params, recv));

        log::info!("PIA forwarded local port: {port}");
        Ok(Self {
            port: port,
            loop_thread_handle: Some(handle),
            send_channel: send,
        })
    }

    fn refresh_port(params: &ThreadParams) -> anyhow::Result<u16> {
    
        let bind_response = NetworkNamespace::exec_with_output(&params.netns_name, &["curl", 
            "-Gs", "-m", "5",
            "--connect-to", &format!("{}::{}:", params.hostname, params.gateway).to_string(),
            "--cacert", "/home/benland100/vopono/vopono_core/src/config/providers/pia/ca.rsa.4096.crt", //FIXME: how to get this path?
            "--data-urlencode", &format!("payload={}", params.payload).to_string(),
            "--data-urlencode", &format!("signature={}", params.signature).to_string(),
            &format!("https://{}:19999/bindPort", params.hostname).to_string() ], )?;
        if !bind_response.status.success() {
            log::error!("Could not bind port forward from PIA API");
            anyhow::bail!("Could not bind port forward from PIA API")
        }
        
        let parsed = json::parse(String::from_utf8_lossy(&bind_response.stdout).as_ref())?;
        
        if parsed["status"] != "OK" {
            log::error!("Bind for port forward from PIA API not OK");
            anyhow::bail!("Bind for port forward from PIA API not OK");
        }
        
        //FIXME: its very useful to have a configurable callback script to receive the port number
        let refresh_response = NetworkNamespace::exec_with_output(&params.netns_name, &["/home/benland100/vopono/test_callback.sh", &params.port.to_string()], )?;
        if !refresh_response.status.success() {
            log::info!("Callback script was unsuccessful!");
        }
        
        log::info!("Successfully updated claim to port {}", params.port);

        Ok(params.port)
    }

    // Spawn thread to repeat above every 15 minutes
    fn thread_loop(params: ThreadParams, recv: Receiver<bool>) {
        loop {
            let resp = recv.recv_timeout(std::time::Duration::from_secs(60*15));
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
                    Ok(p) => log::debug!("Thread refreshed port: {p}"),
                }

                // TODO: Communicate port change via channel?
            }
        }
    }
}

impl Drop for Piapf {
    fn drop(&mut self) {
        let handle = self.loop_thread_handle.take();
        if let Some(h) = handle {
            self.send_channel.send(true).ok();
            h.join().ok();
        }
    }
}


impl Forwarder for Piapf {

    fn forwarded_port(&self) -> u16 {
        self.port
    }
    
}
