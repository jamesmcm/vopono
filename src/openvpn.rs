use super::netns::NetworkNamespace;
use super::util::check_process_running;
use super::util::config_dir;
use super::vpn::OpenVpnProtocol;
use super::vpn::{find_host_from_alias, get_serverlist, VpnProvider};
use anyhow::anyhow;
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct OpenVpn {
    pid: u32,
}

impl OpenVpn {
    pub fn run(
        netns: &NetworkNamespace,
        provider: &VpnProvider,
        server_name: &str,
        custom_config: Option<PathBuf>,
        dns: &[IpAddr],
        mut use_killswitch: bool,
    ) -> anyhow::Result<Self> {
        // TODO: Refactor this to separate functions
        // TODO: --status flag
        let handle;
        let port;
        let log_file_str = format!("/etc/netns/{}/openvpn.log", &netns.name);
        {
            File::create(&log_file_str)?;
        }
        if let Some(config) = custom_config {
            info!("Launching OpenVPN...");
            let command_vec = (&[
                "openvpn",
                "--config",
                config.as_os_str().to_str().unwrap(),
                "--machine-readable-output",
                "--log",
                log_file_str.as_str(),
            ])
                .to_vec();

            let remotes = get_remotes_from_config(&config)?;

            // TODO: TCP support for killswitch
            port = match remotes.into_iter().find(|x| x.2 == OpenVpnProtocol::UDP) {
                None => {
                    warn!("No UDP remote found in OpenVPN config, disabling OpenVPN killswitch!");
                    use_killswitch = false;
                    0
                }
                Some(x) => x.1,
            };

            handle = netns.exec_no_block(&command_vec, None, true)?;
        } else {
            let serverlist = get_serverlist(&provider)?;
            let x = find_host_from_alias(server_name, &serverlist)?;
            let server = x.0;
            port = x.1;
            let protocol = x.3;
            let protocol_str = match protocol {
                OpenVpnProtocol::UDP => "udp",
                OpenVpnProtocol::TCP => "tcp-client",
            };

            let mut openvpn_config_dir = config_dir()?;
            openvpn_config_dir.push(format!("vopono/{}/openvpn", provider.alias()));

            let mut openvpn_auth = openvpn_config_dir.clone();
            openvpn_auth.push("auth.txt");

            // TODO: Make crl-verify and ca depend on VpnProvider - put inside openvpn config file?

            let openvpn_config = OpenVpn::find_config_file(&openvpn_config_dir)?;
            let openvpn_ca = OpenVpn::find_ca_file(&openvpn_config_dir)?;
            let openvpn_crl = OpenVpn::find_crl_file(&openvpn_config_dir)?;
            debug!("OpenVPN config: {:?}", &openvpn_config);
            info!("Launching OpenVPN...");
            let port_string = port.to_string();
            let mut command_vec = (&[
                "openvpn",
                "--config",
                openvpn_config.as_os_str().to_str().unwrap(),
                "--remote",
                &server,
                port_string.as_str(),
                "--auth-user-pass",
                openvpn_auth.as_os_str().to_str().unwrap(),
                "--machine-readable-output",
                "--log",
                log_file_str.as_str(),
                "--proto",
                &protocol_str,
            ])
                .to_vec();

            if let Some(ca) = openvpn_ca.as_ref() {
                command_vec.push("--ca");
                command_vec.push(ca.as_os_str().to_str().unwrap());
            }
            if let Some(crl) = openvpn_crl.as_ref() {
                command_vec.push("--crl-verify");
                command_vec.push(crl.as_os_str().to_str().unwrap());
            }
            handle = netns.exec_no_block(&command_vec, None, true)?;
        }

        let id = handle.id();
        let mut buffer = String::with_capacity(1024);

        let mut logfile = BufReader::new(File::open(log_file_str)?);
        let mut pos: usize = 0;

        // Tail OpenVPN log file
        loop {
            let x = logfile.read_line(&mut buffer)?;
            pos += x;

            if x > 0 {
                debug!("{:?}", buffer);
            }

            if buffer.contains("Initialization Sequence Completed")
                || buffer.contains("AUTH_FAILED")
            {
                break;
            }

            logfile.seek(SeekFrom::Start(pos as u64)).unwrap();
            buffer.clear();
        }

        if buffer.contains("AUTH_FAILED") {
            // TODO: DRY
            let mut openvpn_config_dir = config_dir()?;
            openvpn_config_dir.push(format!("vopono/{}/openvpn", provider.alias()));
            let mut openvpn_auth = openvpn_config_dir;
            openvpn_auth.push("auth.txt");

            debug!(
                "OpenVPN authentication failed, deleting {}",
                openvpn_auth.display()
            );
            std::fs::remove_file(openvpn_auth)?;
            return Err(anyhow!(
                "OpenVPN authentication failed, use -v for full log output"
            ));
        }

        if use_killswitch {
            killswitch(netns, dns, port)?;
        }

        Ok(Self { pid: id })
    }

    pub fn check_if_running(&mut self) -> anyhow::Result<bool> {
        check_process_running(self.pid)
    }

    fn find_ca_file(openvpn_dir: &PathBuf) -> anyhow::Result<Option<PathBuf>> {
        let path = WalkDir::new(openvpn_dir)
            .into_iter()
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .find(|x| {
                x.path().is_file() && x.path().extension() == Some(std::ffi::OsStr::new("crt"))
            });
        if path.is_none() {
            return Ok(None);
        }
        Ok(Some(PathBuf::from(path.unwrap().path())))
    }

    // TODO: DRY
    fn find_crl_file(openvpn_dir: &PathBuf) -> anyhow::Result<Option<PathBuf>> {
        let path = WalkDir::new(openvpn_dir)
            .into_iter()
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .find(|x| {
                x.path().is_file() && x.path().extension() == Some(std::ffi::OsStr::new("pem"))
            });
        if path.is_none() {
            return Ok(None);
        }
        Ok(Some(PathBuf::from(path.unwrap().path())))
    }

    fn find_config_file(openvpn_dir: &PathBuf) -> anyhow::Result<PathBuf> {
        let path = WalkDir::new(openvpn_dir)
            .into_iter()
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .find(|x| {
                x.path().is_file()
                    && (x.path().extension() == Some(std::ffi::OsStr::new("ovpn"))
                        || x.path().extension() == Some(std::ffi::OsStr::new("conf")))
            });
        if path.is_none() {
            return Err(anyhow!(
                "No OpenVPN config found in {}. Looking for .ovpn or .conf file",
                openvpn_dir.display()
            ));
        }
        Ok(PathBuf::from(path.unwrap().path()))
    }
}

impl Drop for OpenVpn {
    fn drop(&mut self) {
        // Do we need to handle child processes?
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenVPN (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenVPN (pid: {}): {:?}", self.pid, e),
        }
    }
}

pub fn killswitch(netns: &NetworkNamespace, dns: &[IpAddr], port: u16) -> anyhow::Result<()> {
    debug!("Setting OpenVPN killswitch....");
    netns.exec(&["iptables", "-P", "INPUT", "DROP"])?;
    netns.exec(&["iptables", "-P", "FORWARD", "DROP"])?;
    netns.exec(&["iptables", "-P", "OUTPUT", "DROP"])?;
    netns.exec(&[
        "iptables",
        "-A",
        "INPUT",
        "-m",
        "conntrack",
        "--ctstate",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ])?;
    netns.exec(&["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;
    netns.exec(&["iptables", "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"])?;
    netns.exec(&["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    for dnsa in dns.iter() {
        //TODO IPv6 DNS?
        let dns_mask = format!("{}/32", dnsa.to_string());
        netns.exec(&["iptables", "-A", "OUTPUT", "-d", &dns_mask, "-j", "ACCEPT"])?;
    }

    // TODO: Allow OpenVPN tcp connections
    // server port here
    let port_str = format!("{}", port);
    netns.exec(&[
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "-m",
        "udp",
        "--dport",
        port_str.as_str(),
        "-j",
        "ACCEPT",
    ])?;
    netns.exec(&["iptables", "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"])?;
    netns.exec(&[
        "iptables",
        "-A",
        "OUTPUT",
        "-j",
        "REJECT",
        "--reject-with",
        "icmp-net-unreachable",
    ])?;
    Ok(())
}

pub fn get_remotes_from_config(
    path: &PathBuf,
) -> anyhow::Result<Vec<(String, u16, OpenVpnProtocol)>> {
    let file_string = std::fs::read_to_string(path)?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(r"remote ([^\s]+) ([0-9]+) ([a-z\-]+)")?;
    let caps = re.captures_iter(&file_string);

    for cap in caps {
        let cap = cap;
        output_vec.push((
            cap.get(1).unwrap().as_str().to_string(),
            cap.get(2).unwrap().as_str().parse::<u16>()?,
            OpenVpnProtocol::from_str(cap.get(3).unwrap().as_str())?,
        ));
    }

    Ok(output_vec)
}
