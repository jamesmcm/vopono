// TODO:
// Check if OpenVPN config uses shadowsocks:
// socks-proxy 127.0.0.1 1080
// return port to listen on
// In namespace run:
// ss-local -s 69.4.234.146 -p 443 -l 1080 -k 23#dfsbbb -m chacha20
// -l port should come from config
// -p port should come from remote config
// -s should be random route IP from config
// -k and -m can be fixed for now (Mullvad)
use crate::netns::NetworkNamespace;
use crate::openvpn::get_remotes_from_config;
use anyhow::anyhow;
use anyhow::Context;
use log::{debug, error};
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs::read_to_string;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct Shadowsocks {
    pid: u32,
}

impl Shadowsocks {
    pub fn run(
        netns: &NetworkNamespace,
        config_file: &Path,
        _ss_host: IpAddr,
        listen_port: u16,
        password: &str,
        encrypt_method: &str,
    ) -> anyhow::Result<Self> {
        // TODO: Check that host is local, and that Shadowsocks is not already running before running
        debug!("Launching Shadowsocks server");
        if let Err(x) = which::which("ss-local") {
            return Err(anyhow!(
                "Cannot find ss-local, is shadowsocks-libev installed?: {:?}",
                x
            ));
        }
        let route = get_routes_from_config(config_file)?;
        let route = route.choose(&mut rand::thread_rng()).unwrap();
        let port = get_remotes_from_config(config_file)?[0].port;

        let route_str = route.to_string();
        let port_str = port.to_string();
        let listen_port_str = listen_port.to_string();

        let command_vec = vec![
            "ss-local",
            "-s",
            &route_str,
            "-p",
            &port_str,
            "-l",
            &listen_port_str,
            "-k",
            password,
            "-m",
            encrypt_method,
        ];

        let handle = netns
            .exec_no_block(&command_vec, None, true, false, None)
            .context("Failed to launch Shadowsocks - is shadowsocks-libev installed?")?;

        Ok(Self { pid: handle.id() })
    }
}

pub fn uses_shadowsocks(openvpn_config: &Path) -> anyhow::Result<Option<(IpAddr, u16)>> {
    // TODO: We assume all socks-proxy are Shadowsocks
    let config_str = read_to_string(openvpn_config)?;

    let re = Regex::new(r"socks-proxy ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ([0-9]+)")?;
    let cap = re.captures(&config_str);

    if cap.is_none() {
        return Ok(None);
    }
    debug!("socks-proxy detected, will launch Shadowsocks server");
    Ok(Some((
        IpAddr::try_from(Ipv4Addr::from_str(
            cap.as_ref().unwrap().get(1).unwrap().as_str(),
        )?)?,
        cap.unwrap().get(2).unwrap().as_str().parse::<u16>()?,
    )))
}

pub fn get_routes_from_config(path: &Path) -> anyhow::Result<Vec<IpAddr>> {
    let file_string = std::fs::read_to_string(path)?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(
        r"route ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) net_gateway",
    )?;
    let caps = re.captures_iter(&file_string);

    for cap in caps {
        output_vec.push(IpAddr::try_from(Ipv4Addr::from_str(
            cap.get(1).unwrap().as_str(),
        )?)?);
    }

    if output_vec.is_empty() {
        return Err(anyhow!(
            "Failed to extract routes from config file: {}",
            &path.display()
        ));
    }
    Ok(output_vec)
}

impl Drop for Shadowsocks {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed Shadowsocks (pid: {})", self.pid),
            Err(e) => error!("Failed to kill Shadowsocks (pid: {}): {:?}", self.pid, e),
        }
    }
}
