use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use super::util::check_process_running;
use super::vpn::OpenVpnProtocol;
use anyhow::{anyhow, Context};
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

        let log_file_str = format!("/etc/netns/{}/openvpn.log", &netns.name);
        {
            File::create(&log_file_str)?;
        }

        let config_file_path = config_file.canonicalize().context("Invalid path given")?;

        info!("Launching OpenVPN...");
        let mut command_vec = (&[
            "openvpn",
            "--config",
            config_file_path.to_str().unwrap(),
            "--machine-readable-output",
            "--log",
            log_file_str.as_str(),
        ])
            .to_vec();

        if auth_file.is_some() {
            command_vec.push("--auth-user-pass");
            command_vec.push(auth_file.as_ref().unwrap().as_os_str().to_str().unwrap());
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

        let handle = netns
            .exec_no_block(&command_vec, None, true, false, Some(working_dir))
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

            if openvpn_dns.is_none() {
                if let Some(cap) = dns_regex.captures(&buffer) {
                    if let Some(ipstr) = cap.get(1) {
                        debug!("Found OpenVPN DNS response: {}", ipstr.as_str());
                        let ipaddr = IpAddr::from_str(ipstr.as_str());
                        if let Ok(ip) = ipaddr {
                            openvpn_dns = Some(ip);
                            debug!("Set OpenVPN DNS to: {:?}", ip);
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
                    "OpenVPN authentication failed, deleting {}",
                    auth_file.as_ref().unwrap().display()
                );
                std::fs::remove_file(auth_file.unwrap())?;
            }
            return Err(anyhow!(
                "OpenVPN authentication failed, use -v for full log output"
            ));
        }
        if buffer.contains("Options error") {
            error!("OpenVPN options error: {}", buffer);
            return Err(anyhow!("OpenVPN options error, use -v for full log output"));
        }

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            super::util::open_ports(netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports (will be proxied to host)
        if let Some(forwards) = forward_ports {
            super::util::open_ports(netns, forwards.as_slice(), firewall)?;
        }

        if use_killswitch {
            killswitch(netns, dns, remotes.as_slice(), firewall, disable_ipv6)?;
        }

        Ok(Self {
            pid: id,
            openvpn_dns,
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
                crate::firewall::disable_ipv6(netns, firewall)?;
                vec!["iptables"]
            } else {
                vec!["iptables", "ip6tables"]
            };

            for ipcmd in ipcmds {
                netns.exec(&[ipcmd, "-P", "INPUT", "DROP"])?;
                netns.exec(&[ipcmd, "-P", "FORWARD", "DROP"])?;
                netns.exec(&[ipcmd, "-P", "OUTPUT", "DROP"])?;
                netns.exec(&[
                    ipcmd,
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])?;
                netns.exec(&[ipcmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
                netns.exec(&[ipcmd, "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"])?;
                netns.exec(&[ipcmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;

                // TODO: Tidy this up - remote can be IPv4 or IPv6 address or hostname
                for remote in remotes {
                    let port_str = format!("{}", remote.port);
                    match &remote.host {
                        // TODO: Fix this to specify destination address - but need hostname
                        // resolution working
                        Host::IPv4(_ip) => {
                            if ipcmd == "iptables" {
                                netns.exec(&[
                                    ipcmd,
                                    "-A",
                                    "OUTPUT",
                                    "-p",
                                    &remote.protocol.to_string(),
                                    "-m",
                                    &remote.protocol.to_string(),
                                    // "-d",
                                    // &ip.to_string(),
                                    "--dport",
                                    port_str.as_str(),
                                    "-j",
                                    "ACCEPT",
                                ])?;
                            }
                        }
                        Host::IPv6(_ip) => {
                            if ipcmd == "ip6tables" {
                                netns.exec(&[
                                    ipcmd,
                                    "-A",
                                    "OUTPUT",
                                    "-p",
                                    &remote.protocol.to_string(),
                                    "-m",
                                    &remote.protocol.to_string(),
                                    // "-d",
                                    // &ip.to_string(),
                                    "--dport",
                                    port_str.as_str(),
                                    "-j",
                                    "ACCEPT",
                                ])?;
                            }
                        }
                        Host::Hostname(_name) => {
                            netns.exec(&[
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
                            ])?;
                        }
                    }
                }

                netns.exec(&[ipcmd, "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"])?;
                netns.exec(&[
                    ipcmd,
                    "-A",
                    "OUTPUT",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-net-unreachable",
                ])?;
            }
        }
        Firewall::NfTables => {
            if disable_ipv6 {
                crate::firewall::disable_ipv6(netns, firewall)?;
            }
            // TODO:
            netns.exec(&["nft", "add", "table", "inet", &netns.name])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "inet",
                &netns.name,
                "input",
                "{ type filter hook input priority 100 ; policy drop; }",
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "inet",
                &netns.name,
                "forward",
                "{ type filter hook forward priority 100 ; policy drop; }",
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "inet",
                &netns.name,
                "output",
                "{ type filter hook output priority 100 ; policy drop; }",
            ])?;
            netns.exec(&[
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
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "input",
                "iifname",
                "\"lo\"",
                "counter",
                "accept",
            ])?;
            netns.exec(&[
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
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "output",
                "oifname",
                "\"lo\"",
                "counter",
                "accept",
            ])?;

            for remote in remotes {
                let port_str = format!("{}", remote.port);
                match &remote.host {
                    // TODO: Fix this to specify destination address - but need hostname
                    // resolution working
                    Host::IPv4(_ip) => {
                        netns.exec(&[
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            &netns.name,
                            "output",
                            // "ip",
                            // "daddr",
                            // &ip.to_string(),
                            &remote.protocol.to_string(),
                            "dport",
                            port_str.as_str(),
                            "counter",
                            "accept",
                        ])?;
                    }
                    Host::IPv6(_ip) => {
                        netns.exec(&[
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            &netns.name,
                            "output",
                            // "ip6",
                            // "daddr",
                            // &ip.to_string(),
                            &remote.protocol.to_string(),
                            "dport",
                            port_str.as_str(),
                            "counter",
                            "accept",
                        ])?;
                    }
                    Host::Hostname(_name) => {
                        // TODO: Does this work with nftables?
                        netns.exec(&[
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            &netns.name,
                            "output",
                            // "ip",
                            // "daddr",
                            // &name.to_string(),
                            &remote.protocol.to_string(),
                            "dport",
                            port_str.as_str(),
                            "counter",
                            "accept",
                        ])?;
                    }
                }
            }

            netns.exec(&[
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
            ])?;

            netns.exec(&[
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
            ])?;
        }
    }
    Ok(())
}

pub fn get_remotes_from_config(path: &Path) -> anyhow::Result<Vec<Remote>> {
    let file_string = std::fs::read_to_string(path)
        .context(format!("Reading OpenVPN config file: {:?}", path))?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(r"remote ([^\s]+) ([0-9]+)\s?(tcp|udp|tcp-client)?")?;
    let caps = re.captures_iter(&file_string);

    let re2 = Regex::new(r"proto ([a-z\-]+)")?;
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
