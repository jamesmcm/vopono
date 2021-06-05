use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{anyhow, Context};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenFortiVpn {
    pid: u32,
}

impl OpenFortiVpn {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &mut NetworkNamespace,
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
        // Must run as root - https://github.com/adrienverge/openfortivpn/issues/650
        let command_vec = (&[
            "openfortivpn",
            "-c",
            config_file.to_str().expect("Invalid config path"),
        ])
            .to_vec();

        // TODO: Remove need for log file (and hardcoded path!)
        // Delete log file if exists
        let pppd_log = std::path::PathBuf::from_str("/tmp/pppd.log")?;
        std::fs::remove_file(&pppd_log).ok();

        // TODO - better handle forwarding output when blocking on password entry (no newline!)
        handle = netns
            .exec_no_block(&command_vec, None, false, true, None)
            .context("Failed to launch OpenFortiVPN - is openfortivpn installed?")?;
        let stdout = handle.stdout.take().unwrap();
        let id = handle.id();

        info!("Waiting for OpenFortiVPN to establish connection - you may be prompted on your 2FA device");
        info!("If your VPN password is not in the OpenFortiVPN config file then enter it here now");
        let mut bufreader = BufReader::with_capacity(16000, stdout);
        let mut buffer = String::with_capacity(16000);
        let mut bufcount: usize = 0;

        let newbytes = bufreader.read_line(&mut buffer)?;
        if newbytes > 0 {
            print!("{}", &buffer[bufcount..(bufcount + newbytes)]);
            std::io::stdout().flush()?;
            bufcount += newbytes;
        }

        while !buffer.contains("Tunnel is up and running") {
            let newbytes = bufreader.read_line(&mut buffer)?;
            if newbytes > 0 {
                print!("{}", &buffer[bufcount..(bufcount + newbytes)]);
                std::io::stdout().flush()?;
                bufcount += newbytes;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        debug!("Full OpenFortiVPN stdout: {:?}", &buffer);

        let remote_peer = get_remote_peer(&pppd_log)?;

        debug!("Found OpenFortiVPN route: {:?}", remote_peer);
        netns.exec(&["ip", "route", "del", "default"])?;
        netns.exec(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &remote_peer.to_string(),
        ])?;

        let dns = get_dns(&buffer)?;
        let dns_ip: Vec<IpAddr> = (dns.0).into_iter().map(IpAddr::from).collect();
        // TODO: Avoid this meaningless collect
        let suffixes: Vec<&str> = (dns.1).iter().map(|x| x.as_str()).collect();
        netns.dns_config(dns_ip.as_slice(), suffixes.as_slice())?;
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
// pub fn get_peer_route() -> anyhow::Result<Ipv4Addr> {
//     let output = Command::new("ip").args(&["route"]).output()?.stdout;
//     let output = std::str::from_utf8(&output)?;
//     debug!("OpenFortiVPN ip routes: {}", output);

//     // sudo ip route | grep "ppp0 proto kernel"
//     let re =
//         Regex::new(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) dev ppp0 proto kernel").unwrap();
//     let mut ips = Vec::new();
//     for caps in re.captures_iter(output) {
//         ips.push(Ipv4Addr::from_str(&caps["ip"])?);
//     }
//     debug!("Found OpenFortiVPN routes: {:?}", &ips);
//     debug!("Using last route as default gateway");
//     ips.pop()
//         .ok_or_else(|| anyhow!("No route found for gateway"))
// }

pub fn get_remote_peer(pppd_log: &Path) -> anyhow::Result<Ipv4Addr> {
    let stdout = std::fs::read_to_string(pppd_log)
        .context(format!("Opening pppd log file: {:?}", pppd_log))?;
    let re = Regex::new(r"remote IP address (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(&stdout) {
        ips.push(Ipv4Addr::from_str(&caps["ip"]).expect("Failed to parse IP address in stdout"));
    }
    ips.pop()
        .ok_or_else(|| anyhow!("Could not find remote IP address in pppd log"))
}

// DNS pppd:
// INFO:   Got addresses: [x.x.x.x], ns [y.y.y.y, y.y.y.y], ns_suffix [host.net;host2.com;host.com]
pub fn get_dns(stdout: &str) -> anyhow::Result<(Vec<IpAddr>, Vec<String>)> {
    // sudo ip route | grep "ppp0 proto kernel"
    let re = Regex::new(r"ns \[(?P<ip>[^\]]+)\]").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(stdout) {
        for ip_raw in caps["ip"].split(", ").into_iter() {
            let ip = IpAddr::from_str(ip_raw)?;
            if !ips.contains(&ip) && ip != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                ips.push(ip);
            }
        }
    }

    let re = Regex::new(r"ns_suffix \[(?P<suffix>[^\]]+)\]").unwrap();
    let mut suffixes = Vec::new();
    for caps in re.captures_iter(stdout) {
        for suffix_raw in caps["suffix"].split(';').into_iter() {
            let suffix = suffix_raw.to_string();
            if !suffixes.contains(&suffix) {
                suffixes.push(suffix);
            }
        }
    }

    debug!(
        "Found OpenFortiVPN DNS ips: {:?}, ns suffixes: {:?}",
        &ips, &suffixes
    );
    Ok((ips, suffixes))
}
