use super::dns_config::DnsConfig;
use super::firewall::Firewall;
use super::host_masquerade::HostMasquerade;
use super::network_interface::NetworkInterface;
use super::openconnect::OpenConnect;
use super::openfortivpn::OpenFortiVpn;
use super::openvpn::OpenVpn;
use super::shadowsocks::Shadowsocks;
use super::veth_pair::VethPair;
use super::warp::Warp;
use super::wireguard::Wireguard;
use crate::config::providers::{UiClient, VpnProvider};
use crate::config::vpn::Protocol;
use crate::network::host_masquerade::FirewallException;
use crate::util::{config_dir, set_config_permissions, sudo_command};
use anyhow::{anyhow, Context};
use log::{debug, info, warn};
use nix::unistd;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkNamespace {
    pub name: String,
    pub veth_pair: Option<VethPair>,
    pub dns_config: Option<DnsConfig>,
    pub openvpn: Option<OpenVpn>,
    pub wireguard: Option<Wireguard>,
    pub host_masquerade: Option<HostMasquerade>,
    pub firewall_exception: Option<FirewallException>,
    pub shadowsocks: Option<Shadowsocks>,
    pub veth_pair_ips: Option<VethPairIPs>,
    pub openconnect: Option<OpenConnect>,
    pub openfortivpn: Option<OpenFortiVpn>,
    pub warp: Option<Warp>,
    pub provider: VpnProvider,
    pub protocol: Protocol,
    pub firewall: Firewall,
    pub predown: Option<String>,
    pub predown_user: Option<String>,
    pub predown_group: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VethPairIPs {
    pub host_ip: IpAddr,
    pub namespace_ip: IpAddr,
}

impl NetworkNamespace {
    pub fn from_existing(name: String) -> anyhow::Result<Self> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{name}"));

        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Trying to read lockfile: {}", lockfile_path.display());
        let lockfile = std::fs::read_dir(lockfile_path)?
            .next()
            .expect("No lockfile")?;

        let lockfile = File::open(lockfile.path())?;
        let lock: Lockfile = ron::de::from_reader(lockfile)?;
        let ns = lock.ns;
        info!("Using existing network namespace: {}", &name);
        Ok(ns)
    }

    pub fn new(
        name: String,
        provider: VpnProvider,
        protocol: Protocol,
        firewall: Firewall,
        predown: Option<String>,
        predown_user: Option<String>,
        predown_group: Option<String>,
    ) -> anyhow::Result<Self> {
        sudo_command(&["ip", "netns", "add", name.as_str()])
            .with_context(|| format!("Failed to create network namespace: {}", &name))?;
        info!("Created new network namespace: {}", &name);

        Ok(Self {
            name,
            veth_pair: None,
            dns_config: None,
            openvpn: None,
            wireguard: None,
            host_masquerade: None,
            firewall_exception: None,
            shadowsocks: None,
            veth_pair_ips: None,
            openconnect: None,
            openfortivpn: None,
            warp: None,
            provider,
            protocol,
            firewall,
            predown,
            predown_user,
            predown_group,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn exec_no_block(
        netns_name: &str,
        command: &[&str],
        user: Option<String>,
        group: Option<String>,
        silent: bool,
        capture_output: bool,
        capture_input: bool,
        set_dir: Option<PathBuf>,
    ) -> anyhow::Result<std::process::Child> {
        let mut handle = Command::new("ip");
        handle.args(["netns", "exec", netns_name]);
        if let Some(cdir) = set_dir {
            handle.current_dir(cdir);
        }

        let mut sudo_args = Vec::new();
        if let Some(ref user) = user {
            sudo_args.push("--user");
            sudo_args.push(user);
        }
        if let Some(ref group) = group {
            sudo_args.push("--group");
            sudo_args.push(group);
        }

        let sudo_string = if !sudo_args.is_empty() {
            let mut args = vec!["sudo", "--preserve-env"];
            args.append(&mut sudo_args);
            handle.args(args.clone());
            Some(format!(" {}", args.join(" ")))
        } else {
            None
        };

        if silent {
            handle.stdout(Stdio::null());
            handle.stderr(Stdio::null());
        }
        if capture_output {
            handle.stdout(Stdio::piped());
            handle.stderr(Stdio::piped());
        }
        if capture_input {
            handle.stdin(Stdio::piped());
        }

        debug!(
            "ip netns exec {}{} {}",
            netns_name,
            sudo_string.unwrap_or_else(|| String::from("")),
            command.join(" ")
        );
        let handle = handle.args(command).spawn()?;
        Ok(handle)
    }

    pub fn exec(netns_name: &str, command: &[&str]) -> anyhow::Result<()> {
        Self::exec_no_block(netns_name, command, None, None, false, false, false, None)?.wait()?;
        Ok(())
    }

    pub fn exec_with_output(netns_name: &str, command: &[&str]) -> anyhow::Result<Output> {
        Self::exec_no_block(netns_name, command, None, None, false, true, false, None)?
            .wait_with_output()
            .map_err(|e| anyhow!("Process Output error: {e:?}"))
    }

    pub fn add_loopback(&self) -> anyhow::Result<()> {
        Self::exec(
            &self.name,
            &["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"],
        )
        .with_context(|| format!("Failed to add loopback adapter in netns: {}", &self.name))?;
        Self::exec(&self.name, &["ip", "link", "set", "lo", "up"])
            .with_context(|| format!("Failed to start networking in netns: {}", &self.name))?;
        Ok(())
    }

    pub fn add_veth_pair(&mut self) -> anyhow::Result<()> {
        // TODO: Handle if name taken?
        let source = format!("{}_s", self.name);
        let dest = format!("{}_d", self.name);
        self.veth_pair = Some(VethPair::new(source, dest, self)?);
        Ok(())
    }

    pub fn add_routing(
        &mut self,
        target_subnet: u8,
        hosts: Option<&Vec<IpAddr>>,
        allow_host_access: bool,
    ) -> anyhow::Result<()> {
        // TODO: Handle case where IP address taken in better way i.e. don't just change subnet
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

        let ip = format!("10.200.{target_subnet}.1/24");
        let ip_nosub = format!("10.200.{target_subnet}.1");
        let veth_source_ip = format!("10.200.{target_subnet}.2/24");
        let veth_source_ip_nosub = format!("10.200.{target_subnet}.2");

        sudo_command(&["ip", "addr", "add", &ip, "dev", veth_dest]).with_context(|| {
            format!("Failed to assign static IP to veth destination: {veth_dest}")
        })?;

        Self::exec(
            &self.name,
            &["ip", "addr", "add", &veth_source_ip, "dev", veth_source],
        )
        .with_context(|| format!("Failed to assign static IP to veth source: {veth_source}"))?;
        Self::exec(
            &self.name,
            &[
                "ip",
                "route",
                "add",
                "default",
                "via",
                &ip_nosub,
                "dev",
                veth_source,
            ],
        )
        .with_context(|| format!("Failed to assign static IP to veth source: {veth_source}"))?;

        if let Some(my_hosts) = hosts {
            for host in my_hosts {
                Self::exec(
                    &self.name,
                    &[
                        "ip",
                        "route",
                        "add",
                        &host.to_string(),
                        "via",
                        &ip_nosub,
                        "dev",
                        veth_source,
                    ],
                )
                .with_context(|| {
                    format!("Failed to assign hosts route {host} to veth source: {veth_source}")
                })?;
            }
        }

        if allow_host_access {
            Self::exec(&self.name, &[
                "ip",
                "route",
                "add",
                &ip_nosub,
                "via",
                &ip_nosub,
                "dev",
                veth_source,
            ])
            .with_context(|| {
                format!(
                    "Failed to assign hosts route for local host {ip_nosub} to veth source: {veth_source}"
                )
            })?;
        }

        info!(
            "IP address of namespace as seen from host: {}",
            veth_source_ip_nosub
        );
        info!("IP address of host as seen from namespace: {}", ip_nosub);
        self.veth_pair_ips = Some(VethPairIPs {
            host_ip: ip_nosub.parse()?,
            namespace_ip: veth_source_ip_nosub.parse()?,
        });
        Ok(())
    }

    pub fn dns_config(
        &mut self,
        server: &[IpAddr],
        suffixes: &[&str],
        hosts_entries: Option<&Vec<String>>,
    ) -> anyhow::Result<()> {
        self.dns_config = Some(DnsConfig::new(
            self.name.clone(),
            server,
            suffixes,
            hosts_entries,
        )?);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_openvpn(
        &mut self,
        config_file: PathBuf,
        auth_file: Option<PathBuf>,
        dns: &[IpAddr],
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
    ) -> anyhow::Result<()> {
        self.openvpn = Some(OpenVpn::run(
            self,
            config_file,
            auth_file,
            dns,
            use_killswitch,
            open_ports,
            forward_ports,
            firewall,
            disable_ipv6,
        )?);
        Ok(())
    }

    pub fn run_openconnect(
        &mut self,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        server: &str,
        uiclient: &dyn UiClient,
    ) -> anyhow::Result<()> {
        self.openconnect = Some(OpenConnect::run(
            self,
            config_file,
            open_ports,
            forward_ports,
            firewall,
            server,
            uiclient,
        )?);
        Ok(())
    }

    pub fn run_openfortivpn(
        &mut self,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        hosts_entries: Option<&Vec<String>>,
        firewall: Firewall,
    ) -> anyhow::Result<()> {
        self.openfortivpn = Some(OpenFortiVpn::run(
            self,
            config_file,
            open_ports,
            forward_ports,
            hosts_entries,
            firewall,
        )?);
        Ok(())
    }

    pub fn run_warp(
        &mut self,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
    ) -> anyhow::Result<()> {
        self.warp = Some(Warp::run(self, open_ports, forward_ports, firewall)?);
        Ok(())
    }

    pub fn run_shadowsocks(
        &mut self,
        config_file: &Path,
        ss_host: IpAddr,
        listen_port: u16,
        password: &str,
        encrypt_method: &str,
    ) -> anyhow::Result<()> {
        self.shadowsocks = Some(Shadowsocks::run(
            self,
            config_file,
            ss_host,
            listen_port,
            password,
            encrypt_method,
        )?);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_wireguard(
        &mut self,
        config_file: PathBuf,
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
        dns: Option<&Vec<IpAddr>>,
        hosts_entries: Option<&Vec<String>>,
    ) -> anyhow::Result<()> {
        if let Ok(wgprov) = self.provider.get_dyn_wireguard_provider() {
            wgprov.wireguard_preup(config_file.as_path())?;
        }

        self.wireguard = Some(Wireguard::run(
            self,
            config_file,
            use_killswitch,
            open_ports,
            forward_ports,
            firewall,
            disable_ipv6,
            dns,
            hosts_entries,
        )?);
        Ok(())
    }

    pub fn add_host_masquerade(
        &mut self,
        target_subnet: u8,
        interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<()> {
        self.host_masquerade = Some(HostMasquerade::add_masquerade_rule(
            format!("10.200.{target_subnet}.0/24"),
            interface,
            firewall,
        )?);

        Ok(())
    }

    pub fn add_firewall_exception(
        &mut self,
        host_interface: NetworkInterface,
        ns_interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<()> {
        self.firewall_exception = Some(FirewallException::add_firewall_exception(
            host_interface,
            ns_interface,
            firewall,
        )?);

        Ok(())
    }

    pub fn check_openvpn_running(&self) -> bool {
        self.openvpn.as_ref().unwrap().check_if_running()
    }

    pub fn write_lockfile(self, command: &str) -> anyhow::Result<Self> {
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
        write!(f, "{lock_string}")?;
        debug!("Lockfile written: {}", lockfile_path.display());

        set_config_permissions()?;
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
        // TODO: How can we make this check that no _other_ PIDs exist (aside from ones we have spawned)
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
            info!("Shutting down vopono namespace - as there are no processes left running inside");
            // Run PreDown script (if any)
            if let Some(pdcmd) = self.predown.as_ref() {
                std::env::set_var("VOPONO_NS", &self.name);
                std::env::set_var(
                    "VOPONO_NS_IP",
                    self.veth_pair_ips
                        .as_ref()
                        .unwrap()
                        .namespace_ip
                        .to_string(),
                );

                let mut sudo_args = Vec::new();
                if let Some(ref predown_user) = self.predown_user {
                    sudo_args.push("--user");
                    sudo_args.push(predown_user);
                }
                if let Some(ref predown_group) = self.predown_group {
                    sudo_args.push("--group");
                    sudo_args.push(predown_group);
                }

                if !sudo_args.is_empty() {
                    let mut args = vec!["--preserve-env"];
                    args.append(&mut sudo_args);
                    args.push(pdcmd);

                    std::process::Command::new("sudo").args(args).spawn().ok();
                } else {
                    std::process::Command::new(pdcmd).spawn().ok();
                }

                std::env::remove_var("VOPONO_NS");
                std::env::remove_var("VOPONO_NS_IP");
            }

            self.openvpn = None;
            self.veth_pair = None;
            self.dns_config = None;
            self.wireguard = None;
            self.host_masquerade = None;
            self.firewall_exception = None;
            sudo_command(&["ip", "netns", "delete", &self.name])
                .unwrap_or_else(|_| panic!("Failed to delete network namespace: {}", &self.name));
        } else {
            debug!("Skipping destructors since other vopono instance using this namespace!");
            debug!(
                "Existing lockfiles using this namespace: {:?}",
                lockfile_path.read_dir().unwrap().collect::<Vec<_>>()
            );
            std::mem::forget(self.openvpn.take());
            std::mem::forget(self.veth_pair.take());
            std::mem::forget(self.dns_config.take());
            std::mem::forget(self.wireguard.take());
            std::mem::forget(self.firewall_exception.take());
            std::mem::forget(self.host_masquerade.take());
            std::mem::forget(self.openconnect.take());
            std::mem::forget(self.openfortivpn.take());
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Lockfile {
    pub ns: NetworkNamespace,
    pub start: u64,
    pub command: String,
}
