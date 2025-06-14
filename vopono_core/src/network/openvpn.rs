use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::{check_process_running, set_config_permissions, vopono_dir};
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenVpn {
    pid: u32,
    pub openvpn_dns: Option<IpAddr>,
    pub logfile: PathBuf,
    // pub distinct_remotes: Vec<String>, // Unique IP Addresses or hostnames
}

impl OpenVpn {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        auth_file: Option<PathBuf>,
        dns: &[IpAddr],
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
        verbose: bool,
    ) -> anyhow::Result<Self> {
        // TODO: Refactor this to separate functions
        // TODO: --status flag

        if let Err(x) = which::which("openvpn") {
            error!("OpenVPN not found. Is OpenVPN installed and on PATH?");
            return Err(anyhow!(
                "OpenVPN not found. Is OpenVPN installed and on PATH?: {:?}",
                x
            ));
        }

        std::fs::create_dir_all(vopono_dir()?.join("logs"))?;
        let log_file_path = vopono_dir()?.join(format!("logs/{}_openvpn.log", &netns.name));
        let log_file_str: String = log_file_path.as_os_str().to_string_lossy().to_string();
        {
            File::create(&log_file_str)?;
        }

        let config_file_path = config_file.canonicalize().context("Invalid path given")?;
        set_config_permissions()?;

        // Check config file for up and down script entries and warn on their presence
        warn_on_scripts_config(&config_file_path)?;

        info!("Launching OpenVPN...");
        let mut command_vec = ([
            "openvpn",
            "--config",
            config_file_path.to_str().unwrap(),
            "--machine-readable-output",
            "--log",
            log_file_str.as_str(),
        ])
        .to_vec();

        if let Some(af_ref) = auth_file.as_ref() {
            command_vec.push("--auth-user-pass");
            command_vec.push(af_ref.as_os_str().to_str().unwrap());
        }

        let ipv6_disabled = std::fs::read_to_string("/sys/module/ipv6/parameters/disable")
            .map(|x| x.trim().to_string())
            .unwrap_or_else(|_| "0".to_string())
            == "1";
        if ipv6_disabled {
            debug!("Detected IPv6 disabled in /sys/module/ipv6/parameters/disable");
        } else {
            debug!("Detected IPv6 enabled in /sys/module/ipv6/parameters/disable");
        }

        // Only try once for DNS resolution / remote host connection
        command_vec.push("--connect-retry-max");
        command_vec.push("1");
        // Ignore Windows-specific command
        command_vec.push("--pull-filter");
        command_vec.push("ignore");
        command_vec.push("block-outside-dns");

        if disable_ipv6 || ipv6_disabled {
            debug!("IPv6 disabled, will pass pull-filter ignore to OpenVPN");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("ifconfig-ipv6");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("route-ipv6");
        }

        let remotes = get_remotes_from_config(&config_file)?;
        debug!("Found remotes: {:?}", &remotes);
        let working_dir = PathBuf::from(config_file_path.parent().unwrap());

        let handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &command_vec,
            None,
            None,
            !verbose,
            false,
            false,
            Some(working_dir),
        )
        .context("Failed to launch OpenVPN - is openvpn installed?")?;
        let id = handle.id();
        let mut buffer = String::with_capacity(16384);

        let mut logfile = BufReader::with_capacity(64, File::open(log_file_str)?);
        let mut pos: usize = 0;

        // Parse DNS header from OpenVPN response
        let dns_regex = Regex::new(r"dhcp-option DNS ([0-9.]+)").unwrap();
        let mut openvpn_dns: Option<IpAddr> = None;
        // Tail OpenVPN log file
        loop {
            let x = logfile.read_line(&mut buffer)?;

            if x > 0 {
                debug!("{}", &buffer[pos..].trim_end());
            }

            pos += x;

            if let Some(cap) = dns_regex.captures(&buffer) {
                if openvpn_dns.is_none() {
                    if let Some(ipstr) = cap.get(1) {
                        debug!("Found OpenVPN DNS response: {}", ipstr.as_str());
                        let ipaddr = IpAddr::from_str(ipstr.as_str());
                        if let Ok(ip) = ipaddr {
                            openvpn_dns = Some(ip);
                            debug!("Set OpenVPN DNS to: {ip:?}");
                        }
                    }
                }
            }

            if buffer.contains("Initialization Sequence Completed")
                || buffer.contains("AUTH_FAILED")
                || buffer.contains("Options error")
            {
                break;
            }

            logfile.seek(SeekFrom::Start(pos as u64)).unwrap();
        }

        if buffer.contains("AUTH_FAILED") {
            if auth_file.is_some() {
                error!(
                    "OpenVPN authentication failed, modify your username and/or password in {}",
                    auth_file.as_ref().unwrap().display()
                );
                // std::fs::remove_file(auth_file.unwrap())?;
            }
            return Err(anyhow!(
                "OpenVPN authentication failed, use -v for full log output. Modify your username and/or password in {}",
                auth_file.as_ref().unwrap().display()
            ));
        }
        if buffer.contains("Options error") {
            error!("OpenVPN options error: {buffer}");
            return Err(anyhow!("OpenVPN options error, use -v for full log output"));
        }

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            crate::util::open_ports(netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports (will be proxied to host)
        if let Some(forwards) = forward_ports {
            crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
        }

        if use_killswitch {
            killswitch(netns, dns, remotes.as_slice(), firewall, disable_ipv6)?;
        }

        Ok(Self {
            pid: id,
            openvpn_dns,
            logfile: log_file_path,
        })
    }

    pub fn check_if_running(&self) -> bool {
        check_process_running(self.pid)
    }
}

impl Drop for OpenVpn {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenVPN (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenVPN (pid: {}): {:?}", self.pid, e),
        }

        match std::fs::remove_file(&self.logfile) {
            Ok(_) => debug!(
                "Deleted OpenVPN logfile: {}",
                self.logfile.as_os_str().to_string_lossy()
            ),
            Err(e) => error!(
                "Failed to delete OpenVPN logfile: {}: {:?}",
                self.logfile.as_os_str().to_string_lossy(),
                e
            ),
        }
    }
}

pub fn killswitch(
    netns: &NetworkNamespace,
    _dns: &[IpAddr],
    remotes: &[Remote],
    firewall: Firewall,
    disable_ipv6: bool,
) -> anyhow::Result<()> {
    debug!("Setting OpenVPN killswitch....");

    match firewall {
        Firewall::IpTables => {
            let ipcmds = if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
                vec!["iptables"]
            } else {
                vec!["iptables", "ip6tables"]
            };

            for ipcmd in ipcmds {
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "INPUT", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "FORWARD", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "OUTPUT", "DROP"])?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "INPUT",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                )?;

                // TODO: Tidy this up - remote can be IPv4 or IPv6 address or hostname
                for remote in remotes {
                    let port_str = format!("{}", remote.port);
                    match &remote.host {
                        // TODO: Fix this to specify destination address - but need hostname
                        // resolution working
                        Host::IPv4(ip) => {
                            if ipcmd == "iptables" {
                                NetworkNamespace::exec(
                                    &netns.name,
                                    &[
                                        ipcmd,
                                        "-A",
                                        "OUTPUT",
                                        "-p",
                                        &remote.protocol.to_string(),
                                        "-m",
                                        &remote.protocol.to_string(),
                                        "-d",
                                        &ip.to_string(),
                                        "--dport",
                                        port_str.as_str(),
                                        "-j",
                                        "ACCEPT",
                                    ],
                                )?;
                            }
                        }
                        Host::IPv6(ip) => {
                            if ipcmd == "ip6tables" {
                                NetworkNamespace::exec(
                                    &netns.name,
                                    &[
                                        ipcmd,
                                        "-A",
                                        "OUTPUT",
                                        "-p",
                                        &remote.protocol.to_string(),
                                        "-m",
                                        &remote.protocol.to_string(),
                                        "-d",
                                        &ip.to_string(),
                                        "--dport",
                                        port_str.as_str(),
                                        "-j",
                                        "ACCEPT",
                                    ],
                                )?;
                            }
                        }
                        Host::Hostname(_name) => {
                            NetworkNamespace::exec(
                                &netns.name,
                                &[
                                    ipcmd,
                                    "-A",
                                    "OUTPUT",
                                    "-p",
                                    &remote.protocol.to_string(),
                                    // "-d",
                                    // &name.to_string(),
                                    "-m",
                                    &remote.protocol.to_string(),
                                    "--dport",
                                    port_str.as_str(),
                                    "-j",
                                    "ACCEPT",
                                ],
                            )?;
                        }
                    }
                }

                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "OUTPUT",
                        "-j",
                        "REJECT",
                        "--reject-with",
                        "icmp-net-unreachable",
                    ],
                )?;
            }
        }
        Firewall::NfTables => {
            if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
            }
            // TODO: Test this with port forwarding
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "ct",
                    "state",
                    "related,established",
                    "counter",
                    "accept",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "iifname",
                    "\"tun*\"",
                    "counter",
                    "accept",
                ],
            )?;

            for remote in remotes {
                let port_str = format!("{}", remote.port);
                match &remote.host {
                    // TODO: Fix this to specify destination address - but need hostname
                    // resolution working
                    Host::IPv4(ip) => {
                        NetworkNamespace::exec(
                            &netns.name,
                            &[
                                "nft",
                                "add",
                                "rule",
                                "inet",
                                &netns.name,
                                "output",
                                "ip",
                                "daddr",
                                &ip.to_string(),
                                &remote.protocol.to_string(),
                                "dport",
                                port_str.as_str(),
                                "counter",
                                "accept",
                            ],
                        )?;
                    }
                    Host::IPv6(ip) => {
                        NetworkNamespace::exec(
                            &netns.name,
                            &[
                                "nft",
                                "add",
                                "rule",
                                "inet",
                                &netns.name,
                                "output",
                                "ip6",
                                "daddr",
                                &ip.to_string(),
                                &remote.protocol.to_string(),
                                "dport",
                                port_str.as_str(),
                                "counter",
                                "accept",
                            ],
                        )?;
                    }
                    Host::Hostname(_name) => {
                        // This rule allows traffic to the correct port/protocol regardless of destination IP.
                        // This is necessary because the hostname is resolved to an IP by OpenVPN,
                        // and we allow that IP via the DNS rules.
                        NetworkNamespace::exec(
                            &netns.name,
                            &[
                                "nft",
                                "add",
                                "rule",
                                "inet",
                                &netns.name,
                                "output",
                                &remote.protocol.to_string(),
                                "dport",
                                port_str.as_str(),
                                "counter",
                                "accept",
                            ],
                        )?;
                    }
                }
            }

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "oifname",
                    "\"tun*\"",
                    "counter",
                    "accept",
                ],
            )?;

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "counter",
                    "reject",
                    "with",
                    "icmp",
                    "type",
                    "net-unreachable",
                ],
            )?;
        }
    }
    Ok(())
}

pub fn warn_on_scripts_config(path: &Path) -> anyhow::Result<bool> {
    let mut out = false;
    let file_string =
        std::fs::read_to_string(path).context(format!("Reading OpenVPN config file: {path:?}"))?;
    for line in file_string.lines() {
        if line.trim().starts_with("up ") || line.trim().starts_with("down ") {
            log::error!(
                "up / down scripts detected in OpenVPN config file - remove these or OpenVPN will likely hang in the network namespace. Line: {line}"
            );
            out = true;
        }
    }
    Ok(out)
}

pub fn get_remotes_from_config(path: &Path) -> anyhow::Result<Vec<Remote>> {
    let file_string =
        std::fs::read_to_string(path).context(format!("Reading OpenVPN config file: {path:?}"))?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(r"(?m)^\s*remote ([^\s]+) ([0-9]+)\s?(tcp|udp|tcp-client)?")?;
    let caps = re.captures_iter(&file_string);

    let re2 = Regex::new(r"(?m)^\s*proto ([a-z\-]+)")?;
    let mut caps2 = re2.captures_iter(&file_string);
    let default_proto = caps2.next().and_then(|x| x.get(1));

    for cap in caps {
        let proto = match (cap.get(3), default_proto) {
            (None, None) => {
                return Err(anyhow!(
                    "No protocol given in OpenVPN config: {}",
                    path.display()
                ));
            }
            (Some(x), _) => OpenVpnProtocol::from_str(x.as_str()),
            (None, Some(x)) => OpenVpnProtocol::from_str(x.as_str()),
        }?;

        output_vec.push(Remote {
            host: Host::from_str(cap.get(1).unwrap().as_str()).expect("Could not convert hostname"),
            port: cap.get(2).unwrap().as_str().parse::<u16>()?,
            protocol: proto,
        });
    }

    if output_vec.is_empty() {
        return Err(anyhow!(
            "Failed to extract remotes from config file: {}",
            &path.display()
        ));
    }
    Ok(output_vec)
}

#[derive(Debug)]
pub struct Remote {
    host: Host,
    pub port: u16,
    protocol: OpenVpnProtocol,
}

#[derive(Debug)]
pub enum Host {
    IPv4(std::net::Ipv4Addr),
    IPv6(std::net::Ipv6Addr),
    Hostname(String),
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(x) = s.parse() {
            Ok(Host::IPv4(x))
        } else if let Ok(x) = s.parse() {
            Ok(Host::IPv6(x))
        } else {
            Ok(Host::Hostname(s.to_string()))
        }
    }
}
