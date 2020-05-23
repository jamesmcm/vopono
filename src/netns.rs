use super::sudo_command;
use super::vpn::VpnProvider;
use anyhow::anyhow;
use anyhow::Context;
use directories_next::BaseDirs;
use log::{debug, info};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use users::{get_current_uid, get_user_by_uid};

pub struct NetworkNamespace {
    name: String,
    veth_pair: Option<VethPair>,
    dns_config: Option<DnsConfig>,
    openvpn: Option<OpenVpn>,
}

impl NetworkNamespace {
    pub fn new(name: String) -> anyhow::Result<Self> {
        // TODO: Lockfile to allow shared namespaces
        sudo_command(&["ip", "netns", "add", name.as_str()])
            .with_context(|| format!("Failed to create network namespace: {}", &name))?;

        Ok(Self {
            name,
            veth_pair: None,
            dns_config: None,
            openvpn: None,
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
            .stderr(Stdio::null())
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
        let source = format!("{}_src0", &self.name);
        let dest = format!("{}_dest0", &self.name);
        self.veth_pair = Some(VethPair::new(source, dest, &self)?);
        Ok(())
    }

    pub fn add_routing(&self) -> anyhow::Result<()> {
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

        sudo_command(&["ip", "addr", "add", "10.200.200.1/24", "dev", veth_dest]).with_context(
            || {
                format!(
                    "Failed to assign static IP to veth destination: {}",
                    veth_dest
                )
            },
        )?;

        self.exec(&["ip", "addr", "add", "10.200.200.2/24", "dev", veth_source])
            .with_context(|| {
                format!("Failed to assign static IP to veth source: {}", veth_source)
            })?;
        self.exec(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            "10.200.200.1",
            "dev",
            veth_source,
        ])
        .with_context(|| format!("Failed to assign static IP to veth source: {}", veth_source))?;

        Ok(())
    }

    pub fn dns_config(&mut self) -> anyhow::Result<()> {
        self.dns_config = Some(DnsConfig::new(self.name.clone())?);
        Ok(())
    }

    pub fn run_openvpn(&mut self, provider: &VpnProvider) -> anyhow::Result<()> {
        self.openvpn = Some(OpenVpn::run(&self, provider)?);
        Ok(())
    }
}

impl Drop for NetworkNamespace {
    fn drop(&mut self) {
        sudo_command(&["ip", "netns", "delete", &self.name]).expect(&format!(
            "Failed to delete network namespace: {}",
            &self.name
        ));
    }
}

struct VethPair {
    source: String,
    dest: String,
}

impl VethPair {
    fn new(source: String, dest: String, netns: &NetworkNamespace) -> anyhow::Result<Self> {
        sudo_command(&[
            "ip",
            "link",
            "add",
            dest.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            source.as_str(),
        ])
        .with_context(|| format!("Failed to create veth pair {}, {}", &source, &dest))?;

        sudo_command(&["ip", "link", "set", dest.as_str(), "up"])
            .with_context(|| format!("Failed to bring up destination veth: {}", &dest))?;

        sudo_command(&[
            "ip",
            "link",
            "set",
            source.as_str(),
            "netns",
            &netns.name,
            "up",
        ])
        .with_context(|| format!("Failed to bring up source veth: {}", &dest))?;

        Ok(Self { source, dest })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        sudo_command(&["ip", "link", "delete", &self.dest])
            .expect(&format!("Failed to delete veth pair: {}", &self.dest));
    }
}

struct DnsConfig {
    ns_name: String,
}

impl DnsConfig {
    pub fn new(ns_name: String) -> anyhow::Result<Self> {
        // TODO: Do this by requesting escalated privileges to current binary and use std::fs
        sudo_command(&["mkdir", "-p", &format!("/etc/netns/{}", ns_name)])
            .with_context(|| format!("Failed to create directory: /etc/netns/{}", ns_name))?;

        sudo_command(&[
            "sh",
            "-c",
            &format!(
                "echo 'nameserver 8.8.8.8' > /etc/netns/{}/resolv.conf",
                ns_name
            ),
        ])
        .with_context(|| {
            format!(
                "Failed to overwrite resolv.conf: /etc/netns/{}/resolv.conf",
                ns_name
            )
        })?;

        Ok(Self { ns_name })
    }
}

impl Drop for DnsConfig {
    fn drop(&mut self) {
        //TODO: Do this a much safer way!!
        sudo_command(&["rm", "-rf", &format!("/etc/netns/{}", self.ns_name)]).expect(&format!(
            "Failed to delete resolv.conf for {}",
            self.ns_name
        ));
    }
}

pub struct OpenVpn {
    handle: std::process::Child,
}
impl OpenVpn {
    pub fn run(netns: &NetworkNamespace, provider: &VpnProvider) -> anyhow::Result<Self> {
        let mut openvpn_config = config_dir()?;
        openvpn_config.push(format!("vopono/{}/openvpn/client.conf", provider.alias()));
        debug!("OpenVPN config: {:?}", &openvpn_config);
        info!("Launching OpenVPN...");
        let handle = netns.exec_no_block_silent(&[
            "openvpn",
            "--config",
            openvpn_config.as_os_str().to_str().unwrap(),
        ])?;
        sleep(Duration::from_secs(10)); //TODO: Can we do this by parsing stdout
        Ok(Self { handle })
    }
}

pub fn config_dir() -> anyhow::Result<PathBuf> {
    let mut pathbuf = PathBuf::new();
    let _res: () = if let Some(base_dirs) = BaseDirs::new() {
        pathbuf.push(base_dirs.config_dir());
        Ok(())
    // Ok((*base_dirs.config_dir()))
    } else if let Some(user) = get_user_by_uid(get_current_uid()) {
        let confpath = format!("/home/{}/.config", user.name().to_str().unwrap());
        let path = Path::new(&confpath);
        if path.exists() {
            pathbuf.push(path);
            Ok(())
        } else {
            Err(anyhow!("Could not find valid config directory!"))
        }
    } else {
        Err(anyhow!("Could not find valid config directory!"))
    }?;
    Ok(pathbuf)
}

impl Drop for OpenVpn {
    fn drop(&mut self) {
        // TODO: Do this with elevated privileges
        // nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).expect("Failed to elevate privileges");
        // self.handle.kill().expect("Failed to kill OpenVPN");
        // sudo_command(&["sh", "-c", &format!("kill -9 {}", &self.handle.id())])
        //     .expect("Failed to kill OpenVPN");
        // TODO: Fix this!
        sudo_command(&["killall", "-s", "SIGKILL", "openvpn"]).expect("Failed to kill OpenVPN");
        sleep(Duration::from_secs(2));
    }
}
