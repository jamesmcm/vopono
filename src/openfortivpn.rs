use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct OpenFortiVpn {
    pid: u32,
}

impl OpenFortiVpn {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("openfortivpn") {
            error!("OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?");
            return Err(anyhow!(
                "OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?: {:?}",
                x
            ));
        }

        let mut handle;

        info!("Launching OpenFortiVPN...");
        // TODO: DNS + default route
        // Must run as root - https://github.com/adrienverge/openfortivpn/issues/650
        let command_vec = (&[
            "openfortivpn",
            "-c",
            config_file.to_str().expect("Invalid config path"),
        ])
            .to_vec();

        // TODO - better handle blocking for input and waiting until connection established
        handle = netns
            .exec_no_block(&command_vec, None, false, true, None)
            .context("Failed to launch OpenFortiVPN - is openfortivpn installed?")?;
        let mut stdout = handle.stdout.take().unwrap();
        let mut stderr = handle.stderr.take().unwrap();
        let id = handle.id();

        info!("Waiting for OpenFortiVPN to establish connection - you may be prompted on your 2FA device");
        let mut buffer: [u8; 8192] = [0; 8192];
        stdout.read(&mut buffer)?;
        // let mut errbuffer: [u8; 8192] = [0; 8192];
        // stderr.read(&mut buffer)?;

        let mut remote_peer = None;
        while !std::str::from_utf8(&buffer)?.contains("Tunnel is up and running") {
            // debug!("{}", std::str::from_utf8(&buffer)?);

            // TODO: remote peer is returned by pppd directly and this is NOT captured in the
            // stdout pipe
            remote_peer = remote_peer.or_else(|| {
                get_remote_peer(std::str::from_utf8(&errbuffer).expect("Non UTF8 stderr"))
            });
            std::thread::sleep(std::time::Duration::new(1, 0));
            stdout.read(&mut buffer)?;
            // stderr.read(&mut buffer)?;
        }

        remote_peer = remote_peer
            .or_else(|| get_remote_peer(std::str::from_utf8(&buffer).expect("Non UTF8 stdout")));

        debug!("Found OpenFortiVPN route: {:?}", remote_peer);
        netns.exec(&["ip", "route", "del", "default"])?;
        netns.exec(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &remote_peer.expect("No remote peer found").to_string(),
        ])?;
        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            super::util::open_ports(&netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            super::util::open_ports(&netns, forwards.as_slice(), firewall)?;
        }

        Ok(Self { pid: id })
    }
}

impl Drop for OpenFortiVpn {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenFortiVPN (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenFortiVPN (pid: {}): {:?}", self.pid, e),
        }
    }
}

// Cannot use in network namespace - at least if pppd is running outside?
pub fn get_peer_route() -> anyhow::Result<Ipv4Addr> {
    let output = Command::new("ip").args(&["route"]).output()?.stdout;
    let output = std::str::from_utf8(&output)?;
    debug!("OpenFortiVPN ip routes: {}", output);

    // sudo ip route | grep "ppp0 proto kernel"
    let re =
        Regex::new(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) dev ppp0 proto kernel").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(output) {
        ips.push(Ipv4Addr::from_str(&caps["ip"])?);
    }
    debug!("Found OpenFortiVPN routes: {:?}", &ips);
    debug!("Using last route as default gateway");
    ips.pop()
        .ok_or_else(|| anyhow!("No route found for gateway"))
}

pub fn get_remote_peer(stdout: &str) -> Option<Ipv4Addr> {
    let re = Regex::new(r"remote IP address (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(stdout) {
        ips.push(Ipv4Addr::from_str(&caps["ip"]).expect("Failed to parse IP address in stdout"));
    }
    ips.pop()
}

// DNS pppd:
// INFO:   Got addresses: [x.x.x.x], ns [y.y.y.y, y.y.y.y], ns_suffix [host.net;host2.com;host.com]
