use super::netns::NetworkNamespace;
use super::util::check_process_running;
use super::util::{config_dir, sudo_command};
use super::vpn::VpnProvider;
use anyhow::anyhow;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct OpenVpn {
    pid: u32,
}

impl OpenVpn {
    pub fn run(
        netns: &NetworkNamespace,
        provider: &VpnProvider,
        server: &str,
        port: u32,
    ) -> anyhow::Result<Self> {
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
            server,
            port_string.as_str(),
            "--auth-user-pass",
            openvpn_auth.as_os_str().to_str().unwrap(),
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

        let handle = netns.exec_no_block(&command_vec, None)?;
        // TODO: How to check for VPN connection or auth error?? OpenVPN silently continues
        let id = handle.id();
        // let mut buffer: Vec<u8> = Vec::with_capacity(20000);
        // let mut stdout = handle.stdout.unwrap(); // TODO: Need to pass in stdout to use
        // while buffer.is_empty()
        //     || !std::str::from_utf8(buffer.as_slice())?
        //         .contains("Initialization Sequence Completed")
        // {
        //     stdout.read(&mut buffer)?;
        // }
        sleep(Duration::from_secs(10)); //TODO: Can we do this by parsing stdout
                                        // Initialization Sequence Completed
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
