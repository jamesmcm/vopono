use super::dns_config::DnsConfig;
use super::openvpn::OpenVpn;
use super::util::{config_dir, sudo_command};
use super::veth_pair::VethPair;
use super::vpn::VpnProvider;
use super::wireguard::Wireguard;
use anyhow::Context;
use log::{debug, warn};
use nix::unistd;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize)]
pub struct NetworkNamespace {
    pub name: String,
    veth_pair: Option<VethPair>,
    dns_config: Option<DnsConfig>,
    pub openvpn: Option<OpenVpn>,
    pub wireguard: Option<Wireguard>,
}

impl NetworkNamespace {
    pub fn from_existing(name: String) -> anyhow::Result<Self> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{}", name));

        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Trying to read lockfile: {}", lockfile_path.display());
        let lockfile = std::fs::read_dir(lockfile_path)?
            .next()
            .expect("No lockfile")?;

        let lockfile = File::open(lockfile.path())?;
        let ns: Self = ron::de::from_reader(lockfile)?;
        Ok(ns)
    }

    pub fn new(name: String) -> anyhow::Result<Self> {
        sudo_command(&["ip", "netns", "add", name.as_str()])
            .with_context(|| format!("Failed to create network namespace: {}", &name))?;

        Ok(Self {
            name,
            veth_pair: None,
            dns_config: None,
            openvpn: None,
            wireguard: None,
        })
    }
    pub fn exec_no_block(&self, command: &[&str]) -> anyhow::Result<std::process::Child> {
        debug!("sudo ip netns exec {} {}", &self.name, command.join(" "));
        let handle = Command::new("sudo")
            .args(&["ip", "netns", "exec", &self.name])
            .args(command)
            .spawn()?;
        Ok(handle)
    }

    //TODO: DRY
    pub fn exec_no_block_silent(&self, command: &[&str]) -> anyhow::Result<std::process::Child> {
        debug!("sudo ip netns exec {} {}", &self.name, command.join(" "));
        let handle = Command::new("sudo")
            .args(&["ip", "netns", "exec", &self.name])
            .args(command)
            .stdout(Stdio::null())
            .spawn()?;
        Ok(handle)
    }

    pub fn exec(&self, command: &[&str]) -> anyhow::Result<()> {
        self.exec_no_block(command)?.wait()?;
        Ok(())
    }

    pub fn add_loopback(&self) -> anyhow::Result<()> {
        self.exec(&["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
            .with_context(|| format!("Failed to add loopback adapter in netns: {}", &self.name))?;
        self.exec(&["ip", "link", "set", "lo", "up"])
            .with_context(|| format!("Failed to start networking in netns: {}", &self.name))?;
        Ok(())
    }

    pub fn add_veth_pair(&mut self) -> anyhow::Result<()> {
        // TODO: Handle if name taken?
        // TODO: Can we share veth dest between namespaces?
        // TODO: Better handle name length limits
        let source = format!("{}_s", &self.name);
        let dest = format!("{}_d", &self.name);
        self.veth_pair = Some(VethPair::new(source, dest, &self)?);
        Ok(())
    }

    pub fn add_routing(&self, target_subnet: u8) -> anyhow::Result<()> {
        // TODO: Handle case where IP address taken
        let veth_dest = &self
            .veth_pair
            .as_ref()
            .expect("Destination veth undefined")
            .dest;

        let veth_source = &self
            .veth_pair
            .as_ref()
            .expect("Source veth undefined")
            .source;

        let ip = format!("10.200.{}.1/24", target_subnet);
        let ip_nosub = format!("10.200.{}.1", target_subnet);
        let veth_source_ip = format!("10.200.{}.2/24", target_subnet);

        sudo_command(&["ip", "addr", "add", &ip, "dev", veth_dest]).with_context(|| {
            format!(
                "Failed to assign static IP to veth destination: {}",
                veth_dest
            )
        })?;

        self.exec(&["ip", "addr", "add", &veth_source_ip, "dev", veth_source])
            .with_context(|| {
                format!("Failed to assign static IP to veth source: {}", veth_source)
            })?;
        self.exec(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &ip_nosub,
            "dev",
            veth_source,
        ])
        .with_context(|| format!("Failed to assign static IP to veth source: {}", veth_source))?;

        Ok(())
    }

    pub fn dns_config(&mut self, server: Option<String>) -> anyhow::Result<()> {
        self.dns_config = Some(DnsConfig::new(self.name.clone(), server)?);
        Ok(())
    }

    pub fn run_openvpn(
        &mut self,
        provider: &VpnProvider,
        server: &str,
        port: u32,
    ) -> anyhow::Result<()> {
        self.openvpn = Some(OpenVpn::run(&self, provider, server, port)?);
        Ok(())
    }

    pub fn run_wireguard(&mut self, config_file: PathBuf) -> anyhow::Result<()> {
        self.wireguard = Some(Wireguard::run(self, config_file)?);
        Ok(())
    }

    pub fn check_openvpn_running(&mut self) -> anyhow::Result<bool> {
        self.openvpn.as_mut().unwrap().check_if_running()
    }

    pub fn write_lockfile(&self) -> anyhow::Result<()> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{}", self.name));
        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Writing lockfile: {}", lockfile_path.display());
        lockfile_path.push(format!("{}", unistd::getpid()));
        let lock_string = ron::ser::to_string(self)?;
        let mut f = File::create(&lockfile_path)?;
        write!(f, "{}", lock_string)?;
        debug!("Lockfile written: {}", lockfile_path.display());
        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        let mut lockfile_path = config_dir().expect("Failed to get config dir");
        lockfile_path.push(format!("vopono/locks/{}/{}", self.name, unistd::getpid()));
        match std::fs::remove_file(lockfile_path) {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to remove lockfile: {:?}", e);
            }
        };

        let mut lockfile_path = config_dir().expect("Failed to get config dir");
        lockfile_path.push(format!("vopono/locks/{}", self.name));
        let try_delete = std::fs::remove_dir(lockfile_path);

        // TODO: Clean this up
        if try_delete.is_ok() {
            self.openvpn = None;
            self.veth_pair = None;
            self.dns_config = None;
            self.wireguard = None;
            sudo_command(&["ip", "netns", "delete", &self.name]).expect(&format!(
                "Failed to delete network namespace: {}",
                &self.name
            ));
        } else {
            // Avoid triggering destructors?
            let openvpn = self.openvpn.take();
            let openvpn = Box::new(openvpn);
            Box::leak(openvpn);

            let veth_pair = self.veth_pair.take();
            let veth_pair = Box::new(veth_pair);
            Box::leak(veth_pair);

            let dns_config = self.dns_config.take();
            let dns_config = Box::new(dns_config);
            Box::leak(dns_config);
        }
    }
}
