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
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct OpenVpn {
    pid: u32,
}

impl OpenVpn {
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        auth_file: Option<PathBuf>,
        dns: &[IpAddr],
        use_killswitch: bool,
    ) -> anyhow::Result<Self> {
        // TODO: Refactor this to separate functions
        // TODO: --status flag
        let handle;
        let log_file_str = format!("/etc/netns/{}/openvpn.log", &netns.name);
        {
            File::create(&log_file_str)?;
        }

        info!("Launching OpenVPN...");
        let mut command_vec = (&[
            "openvpn",
            "--config",
            config_file.as_os_str().to_str().unwrap(),
            "--machine-readable-output",
            "--log",
            log_file_str.as_str(),
        ])
            .to_vec();

        if auth_file.is_some() {
            command_vec.push("--auth-user-pass");
            command_vec.push(auth_file.as_ref().unwrap().as_os_str().to_str().unwrap());
        }

        let remotes = get_remotes_from_config(&config_file)?;
        debug!("Found remotes: {:?}", &remotes);
        let working_dir = PathBuf::from(config_file.as_path().parent().unwrap());

        handle = netns
            .exec_no_block(&command_vec, None, true, Some(working_dir))
            .context("Failed to launch OpenVPN - is openvpn installed?")?;
        let id = handle.id();
        let mut buffer = String::with_capacity(1024);

        let mut logfile = BufReader::with_capacity(64, File::open(log_file_str)?);
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
                || buffer.contains("Options error")
            {
                break;
            }

            logfile.seek(SeekFrom::Start(pos as u64)).unwrap();
            buffer.clear();
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

        if use_killswitch {
            killswitch(netns, dns, remotes.as_slice())?;
        }

        Ok(Self { pid: id })
    }

    pub fn check_if_running(&self) -> bool {
        check_process_running(self.pid)
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

pub fn killswitch(
    netns: &NetworkNamespace,
    dns: &[IpAddr],
    remotes: &[Remote],
) -> anyhow::Result<()> {
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

    for remote in remotes {
        let port_str = format!("{}", remote.port);
        netns.exec(&[
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            &remote.protocol.to_string(),
            "-m",
            &remote.protocol.to_string(),
            "--dport",
            port_str.as_str(),
            "-j",
            "ACCEPT",
        ])?;
    }

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

pub fn get_remotes_from_config(path: &PathBuf) -> anyhow::Result<Vec<Remote>> {
    let file_string = std::fs::read_to_string(path)?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(r"remote ([^\s]+) ([0-9]+)\s?(tcp|udp|tcp-client)?")?;
    let caps = re.captures_iter(&file_string);

    let re2 = Regex::new(r"proto ([a-z\-]+)")?;
    let mut caps2 = re2.captures_iter(&file_string);
    let default_proto = caps2.next().map(|x| x.get(1)).flatten();

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
            _host: cap.get(1).unwrap().as_str().to_string(),
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
    _host: String,
    port: u16,
    protocol: OpenVpnProtocol,
}
