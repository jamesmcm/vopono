use super::netns::NetworkNamespace;
use super::util::check_process_running;
use super::util::config_dir;
use super::vpn::{find_host_from_alias, get_serverlist, VpnProvider};
use anyhow::anyhow;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
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
    ) -> anyhow::Result<Self> {
        // TODO: Refactor this - move all path handling earlier
        // TODO: --status flag
        let handle;
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

            handle = netns.exec_no_block(&command_vec, None, true)?;
        } else {
            let serverlist = get_serverlist(&provider)?;
            let x = find_host_from_alias(server_name, &serverlist)?;
            let server = x.0;
            let port = x.1;

            let mut openvpn_config_dir = config_dir()?;
            openvpn_config_dir.push(format!("vopono/{}/openvpn", provider.alias()));

            let mut openvpn_auth = openvpn_config_dir.clone();
            openvpn_auth.push("auth.txt");

            // TODO: Make crl-verify and ca depend on VpnProvider - put inside openvpn config file?

            let openvpn_ca = OpenVpn::find_ca_file(&openvpn_config_dir)?;
            let openvpn_crl = OpenVpn::find_crl_file(&openvpn_config_dir)?;
            let openvpn_config = OpenVpn::find_config_file(&openvpn_config_dir)?;
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
            return Err(anyhow!(
                "OpenVPN authentication failed, use -v for full log output"
            ));
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
            .filter(|x| {
                x.path().is_file() && x.path().extension() == Some(std::ffi::OsStr::new("crt"))
            })
            .nth(0);
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
            .filter(|x| {
                x.path().is_file() && x.path().extension() == Some(std::ffi::OsStr::new("pem"))
            })
            .nth(0);
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
            .filter(|x| {
                x.path().is_file()
                    && (x.path().extension() == Some(std::ffi::OsStr::new("ovpn"))
                        || x.path().extension() == Some(std::ffi::OsStr::new("conf")))
            })
            .nth(0);
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
