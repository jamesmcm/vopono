use super::dns_config::DnsConfig;
use super::iptables::IpTables;
use super::network_interface::NetworkInterface;
use super::openvpn::OpenVpn;
use super::util::{config_dir, sudo_command};
use super::veth_pair::VethPair;
use super::vpn::{Protocol, VpnProvider};
use super::wireguard::Wireguard;
use anyhow::Context;
use log::{debug, warn};
use nix::unistd;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct NetworkNamespace {
    pub name: String,
    pub veth_pair: Option<VethPair>,
    dns_config: Option<DnsConfig>,
    pub openvpn: Option<OpenVpn>,
    pub wireguard: Option<Wireguard>,
    pub iptables: Option<IpTables>,
    pub provider: VpnProvider,
    pub protocol: Protocol,
}

impl NetworkNamespace {
    pub fn from_existing(name: String) -> anyhow::Result<Self> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{}", name));

        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Trying to read lockfile: {}", lockfile_path.display());
        // TODO: Make this more robust - delete existing namespace if no lockfile
        let lockfile = std::fs::read_dir(lockfile_path)?
            .next()
            .expect("No lockfile")?;

        let lockfile = File::open(lockfile.path())?;
        let lock: Lockfile = ron::de::from_reader(lockfile)?;
        let ns = lock.ns;
        Ok(ns)
    }

    pub fn new(name: String, provider: VpnProvider, protocol: Protocol) -> anyhow::Result<Self> {
        sudo_command(&["ip", "netns", "add", name.as_str()])
            .with_context(|| format!("Failed to create network namespace: {}", &name))?;

        Ok(Self {
            name,
            veth_pair: None,
            dns_config: None,
            openvpn: None,
            wireguard: None,
            iptables: None,
            provider,
            protocol,
        })
    }

    pub fn exec_no_block(
        &self,
        command: &[&str],
        user: Option<String>,
        silent: bool,
    ) -> anyhow::Result<std::process::Child> {
        let mut handle = Command::new("ip");
        handle.args(&["netns", "exec", &self.name]);

        let sudo_string = if user.is_some() {
            handle.args(&["sudo", "-u", user.as_ref().unwrap()]);
            Some(format!(" sudo -u {}", user.as_ref().unwrap()))
        } else {
            None
        };
        if silent {
            handle.stdout(Stdio::null());
            handle.stderr(Stdio::null());
        }

        debug!(
            "ip netns exec {}{} {}",
            &self.name,
            sudo_string.unwrap_or_else(|| String::from("")),
            command.join(" ")
        );
        let handle = handle.args(command).spawn()?;
        Ok(handle)
    }

    pub fn exec(&self, command: &[&str]) -> anyhow::Result<()> {
        self.exec_no_block(command, None, false)?.wait()?;
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
        let source = format!("{}_s", &self.name[7..self.name.len().min(20)]);
        let dest = format!("{}_d", &self.name[7..self.name.len().min(20)]);
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

    pub fn dns_config(&mut self, server: &[IpAddr]) -> anyhow::Result<()> {
        self.dns_config = Some(DnsConfig::new(self.name.clone(), &server)?);
        Ok(())
    }

    pub fn run_openvpn(
        &mut self,
        provider: &VpnProvider,
        server_name: &str,
        custom_config: Option<PathBuf>,
        dns: &[IpAddr],
        use_killswitch: bool,
    ) -> anyhow::Result<()> {
        self.openvpn = Some(OpenVpn::run(
            &self,
            provider,
            server_name,
            custom_config,
            dns,
            use_killswitch,
        )?);
        Ok(())
    }

    pub fn run_wireguard(
        &mut self,
        config_file: PathBuf,
        use_killswitch: bool,
    ) -> anyhow::Result<()> {
        self.wireguard = Some(Wireguard::run(self, config_file, use_killswitch)?);
        Ok(())
    }

    pub fn add_iptables_rule(
        &mut self,
        target_subnet: u8,
        interface: NetworkInterface,
    ) -> anyhow::Result<()> {
        self.iptables = Some(IpTables::add_masquerade_rule(
            format!("10.200.{}.0/24", target_subnet),
            interface,
        )?);

        Ok(())
    }

    pub fn check_openvpn_running(&self) -> bool {
        self.openvpn.as_ref().unwrap().check_if_running()
    }

    pub fn write_lockfile(
        self,
        command: &str,
        username: &str,
        group: &str,
    ) -> anyhow::Result<Self> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{}", self.name));
        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Writing lockfile: {}", lockfile_path.display());
        lockfile_path.push(format!("{}", unistd::getpid()));
        let since_the_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let lock: Lockfile = Lockfile {
            ns: self,
            command: command.to_string(),
            start: since_the_epoch.as_secs(),
        };
        let lock_string = ron::ser::to_string(&lock)?;
        let mut f = File::create(&lockfile_path)?;
        write!(f, "{}", lock_string)?;
        debug!("Lockfile written: {}", lockfile_path.display());

        // TODO: DRY
        let mut lockfile_path = config_dir()?;
        lockfile_path.push("vopono/locks/");
        sudo_command(&[
            "chown",
            "-R",
            username,
            lockfile_path.to_str().expect("No valid config dir"),
        ])?;
        sudo_command(&[
            "chgrp",
            "-R",
            group,
            lockfile_path.to_str().expect("No valid config dir"),
        ])?;

        Ok(lock.ns)
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        let mut lockfile_path = config_dir().expect("Failed to get config dir");
        // Each instance responsible for deleting their own lockfile
        lockfile_path.push(format!("vopono/locks/{}/{}", self.name, unistd::getpid()));
        if lockfile_path.exists() {
            match std::fs::remove_file(&lockfile_path) {
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "Failed to remove lockfile: {}, {:?}",
                        &lockfile_path.display(),
                        e
                    );
                }
            };
        }

        let mut lockfile_path = config_dir().expect("Failed to get config dir");
        lockfile_path.push(format!("vopono/locks/{}", self.name));

        // Drop if lock directory doesn't exist, or it exists but is empty
        if !lockfile_path.exists()
            || (lockfile_path.read_dir().is_ok()
                && lockfile_path.read_dir().unwrap().next().is_none())
        {
            // Only try to delete if exists
            if lockfile_path.exists() {
                match std::fs::remove_dir(&lockfile_path) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Could not remove locks directory: {}, {:?}",
                            lockfile_path.display(),
                            e
                        );
                    }
                }
            }
            self.openvpn = None;
            self.veth_pair = None;
            self.dns_config = None;
            self.wireguard = None;
            self.iptables = None;
            sudo_command(&["ip", "netns", "delete", &self.name])
                .unwrap_or_else(|_| panic!("Failed to delete network namespace: {}", &self.name));
        } else {
            debug!("Skipping destructors since other vopono instance using this namespace!");
            let openvpn = self.openvpn.take();
            let openvpn = Box::new(openvpn);
            Box::leak(openvpn);

            let veth_pair = self.veth_pair.take();
            let veth_pair = Box::new(veth_pair);
            Box::leak(veth_pair);

            let dns_config = self.dns_config.take();
            let dns_config = Box::new(dns_config);
            Box::leak(dns_config);

            let wireguard = self.wireguard.take();
            let wireguard = Box::new(wireguard);
            Box::leak(wireguard);

            let iptables = self.iptables.take();
            let iptables = Box::new(iptables);
            Box::leak(iptables);
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Lockfile {
    pub ns: NetworkNamespace,
    pub start: u64,
    pub command: String,
}
