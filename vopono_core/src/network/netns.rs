use super::dns_config::DnsConfig;
use super::firewall::Firewall;
use super::host_masquerade::HostMasquerade;
use super::network_interface::NetworkInterface;
use super::openconnect::OpenConnect;
use super::openfortivpn::OpenFortiVpn;
use super::openvpn::OpenVpn;
use super::shadowsocks::Shadowsocks;
use super::trojan::TrojanHost;
use super::trojan::trojan_exec::Trojan;
use super::veth_pair::VethPair;
use super::warp::Warp;
use super::wireguard::Wireguard;
use crate::config::providers::{UiClient, VpnProvider};
use crate::config::vpn::Protocol;
use crate::network::host_masquerade::FirewallException;
use crate::network::wireguard_config::WireguardPeer;
use crate::util::{config_dir, parse_command_str, set_config_permissions, sudo_command};
use anyhow::{Context, anyhow};
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
    pub config_file: Option<PathBuf>, // Used to save config file path in lockfile
    pub trojan: Option<Trojan>,
}

/// Pair of IP addresses for veth tunnel
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpPair {
    pub host_ip: IpAddr,
    pub namespace_ip: IpAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VethPairIPs {
    pub ipv4: Option<IpPair>,
    pub ipv6: Option<IpPair>, // None if IPv6 disabled
}

impl NetworkNamespace {
    pub fn from_existing(name: String) -> anyhow::Result<Self> {
        let mut lockfile_path = config_dir()?;
        lockfile_path.push(format!("vopono/locks/{name}"));

        std::fs::create_dir_all(&lockfile_path)?;
        debug!("Trying to read lockfile: {}", lockfile_path.display());
        let lockfile = std::fs::read_dir(lockfile_path)?.next();

        if let Some(lf) = lockfile {
            let lockfile = File::open(lf?.path())?;
            let lock: Lockfile = ron::de::from_reader(lockfile)?;
            let ns = lock.ns;
            info!("Using existing network namespace: {}", &name);
            Ok(ns)
        } else {
            log::error!(
                "No lockfile found for namespace: {} - deleting namespace",
                &name
            );
            sudo_command(&["ip", "netns", "delete", &name])
                .with_context(|| format!("Failed to delete network namespace: {}", &name))?;
            Err(anyhow!(
                "No lockfile found for namespace: {} - deleting namespace",
                &name
            ))
        }
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
            config_file: None,
            trojan: None,
        })
    }

    pub fn set_config_file(&mut self, config_file: Option<PathBuf>) {
        self.config_file = config_file;
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
        disable_ipv6: bool,
    ) -> anyhow::Result<()> {
        let veth_dest = &self.veth_pair.as_ref().expect("veth_pair is None").dest;
        let veth_source = &self.veth_pair.as_ref().expect("veth_pair is None").source;
        let mut veth_ips = VethPairIPs::default();

        let ipv4_host_ip_str = format!("10.200.{target_subnet}.1");
        let ipv4_ns_ip_str = format!("10.200.{target_subnet}.2");
        let ipv4_host_ip_cidr = format!("{ipv4_host_ip_str}/24");
        let ipv4_ns_ip_cidr = format!("{ipv4_ns_ip_str}/24");

        sudo_command(&["ip", "addr", "add", &ipv4_host_ip_cidr, "dev", veth_dest])
            .with_context(|| format!("Failed to assign IPv4 to veth destination: {veth_dest}"))?;

        Self::exec(
            &self.name,
            &["ip", "addr", "add", &ipv4_ns_ip_cidr, "dev", veth_source],
        )
        .with_context(|| format!("Failed to assign IPv4 to veth source: {veth_source}"))?;

        Self::exec(
            &self.name,
            &[
                "ip",
                "route",
                "add",
                "default",
                "via",
                &ipv4_host_ip_str,
                "dev",
                veth_source,
            ],
        )
        .with_context(|| "Failed to add IPv4 default route in netns")?;

        info!("IPv4 address of namespace as seen from host: {ipv4_ns_ip_str}");
        info!("IPv4 address of host as seen from namespace: {ipv4_host_ip_str}");

        veth_ips.ipv4 = Some(IpPair {
            host_ip: ipv4_host_ip_str.parse()?,
            namespace_ip: ipv4_ns_ip_str.parse()?,
        });

        if !disable_ipv6 {
            // Using Unique Local Addresses (ULA) fd42:4242:{subnet}::/64
            let ipv6_host_ip_str = format!("fd42:4242:{target_subnet:x}::1");
            let ipv6_ns_ip_str = format!("fd42:4242:{target_subnet:x}::2");
            let ipv6_host_ip_cidr = format!("{ipv6_host_ip_str}/64");
            let ipv6_ns_ip_cidr = format!("{ipv6_ns_ip_str}/64");

            let ipv6_sysctl_path = format!("net.ipv6.conf.{veth_dest}.disable_ipv6");
            let sysctl_output = std::process::Command::new("sysctl")
                .args(["-n", &ipv6_sysctl_path])
                .output();
            match sysctl_output {
                Ok(output) if output.status.success() => {
                    let value = String::from_utf8_lossy(&output.stdout);
                    if value.trim() == "1" {
                        log::warn!(
                            "IPv6 is currently disabled for interface {veth_dest}, enabling it now"
                        );
                    }
                }
                Ok(output) => {
                    let value = String::from_utf8_lossy(&output.stdout);
                    log::warn!(
                        "Failed to check IPv6 status for {veth_dest}: sysctl returned non-zero exit code, output: {value}"
                    );
                }
                Err(e) => {
                    log::warn!("Failed to check IPv6 status for {veth_dest}: {e}");
                }
            }
            log::debug!("Enabling IPv6 for {veth_dest}");
            sudo_command(&[
                "sysctl",
                "-w",
                &format!("net.ipv6.conf.{veth_dest}.disable_ipv6=0"),
            ])?;

            sudo_command(&["ip", "addr", "add", &ipv6_host_ip_cidr, "dev", veth_dest])
                .with_context(|| {
                    format!("Failed to assign IPv6 to veth destination: {veth_dest}")
                })?;

            Self::exec(
                &self.name,
                &["ip", "addr", "add", &ipv6_ns_ip_cidr, "dev", veth_source],
            )
            .with_context(|| format!("Failed to assign IPv6 to veth source: {veth_source}"))?;

            Self::exec(
                &self.name,
                &[
                    "ip",
                    "-6",
                    "route",
                    "add",
                    "default",
                    "via",
                    &ipv6_host_ip_str,
                    "dev",
                    veth_source,
                ],
            )
            .with_context(|| "Failed to add IPv6 default route in netns")?;

            info!("IPv6 address of namespace as seen from host: {ipv6_ns_ip_str}");
            info!("IPv6 address of host as seen from namespace: {ipv6_host_ip_str}");

            veth_ips.ipv6 = Some(IpPair {
                host_ip: ipv6_host_ip_str.parse()?,
                namespace_ip: ipv6_ns_ip_str.parse()?,
            });
        }

        if let Some(my_hosts) = hosts {
            for host in my_hosts {
                let via_ip = match host {
                    IpAddr::V4(_) => &ipv4_host_ip_str,
                    IpAddr::V6(_) => {
                        if disable_ipv6 {
                            continue; // Skip IPv6 hosts if IPv6 disabled
                        } else {
                            &veth_ips
                                .ipv6
                                .as_ref()
                                .context("IPv6 not configured")?
                                .host_ip
                                .to_string()
                        }
                    }
                };
                Self::exec(
                    &self.name,
                    &[
                        "ip",
                        "route",
                        "add",
                        &host.to_string(),
                        "via",
                        via_ip,
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
            Self::exec(
                &self.name,
                &[
                    "ip",
                    "route",
                    "add",
                    &ipv4_host_ip_str,
                    "via",
                    &ipv4_host_ip_str,
                    "dev",
                    veth_source,
                ],
            )
            .context("Failed to add IPv4 host access route")?;
            if let Some(ipv6_pair) = &veth_ips.ipv6 {
                let ipv6_host_ip_str = ipv6_pair.host_ip.to_string();
                Self::exec(
                    &self.name,
                    &[
                        "ip",
                        "route",
                        "add",
                        &ipv6_host_ip_str,
                        "via",
                        &ipv6_host_ip_str,
                        "dev",
                        veth_source,
                    ],
                )
                .context("Failed to add IPv6 host access route")?;
            }
        }

        // Store the IPs
        self.veth_pair_ips = Some(veth_ips);
        Ok(())
    }

    pub fn dns_config(
        &mut self,
        server: &[IpAddr],
        suffixes: &[&str],
        hosts_entries: Option<&Vec<String>>,
        allow_host_access: bool,
    ) -> anyhow::Result<()> {
        self.dns_config = Some(DnsConfig::new(
            self.name.clone(),
            server,
            suffixes,
            hosts_entries,
            self.veth_pair_ips
                .as_ref()
                .expect("Failed to get veth pair IPs for DNS config"),
            allow_host_access,
            self.firewall,
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
        verbose: bool,
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
            verbose,
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
        allow_host_access: bool,
    ) -> anyhow::Result<()> {
        self.openfortivpn = Some(OpenFortiVpn::run(
            self,
            config_file,
            open_ports,
            forward_ports,
            hosts_entries,
            firewall,
            allow_host_access,
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
        allow_host_access: bool,
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
            allow_host_access,
            self.trojan.as_ref().map(|t| t.config.clone()),
        )?);
        Ok(())
    }

    pub fn run_trojan(
        &mut self,
        trojan_host: Option<TrojanHost>,
        trojan_password: Option<&str>,
        trojan_no_verify: bool,
        trojan_config: Option<&Path>,
        wg_peer: Option<WireguardPeer>,
    ) -> anyhow::Result<()> {
        self.trojan = Some(Trojan::run_in_netns(
            self,
            trojan_host,
            trojan_password,
            trojan_config,
            trojan_no_verify,
            wg_peer,
        )?);
        Ok(())
    }

    pub fn add_host_masquerade(
        &mut self,
        target_subnet: u8,
        interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<()> {
        let veth_ips = self.veth_pair_ips.as_ref().context("Veth IPs not set")?;

        let ipv4_mask = veth_ips
            .ipv4
            .as_ref()
            .map(|_| format!("10.200.{target_subnet}.0/24"));

        let ipv6_mask = veth_ips
            .ipv6
            .as_ref()
            .map(|_| format!("fd42:4242:{target_subnet:x}::/64")); // Will be None if IPv6 disabled

        self.host_masquerade = Some(HostMasquerade::add_masquerade_rule(
            ipv4_mask, ipv6_mask, interface, firewall,
        )?);

        Ok(())
    }
    pub fn add_firewall_exception(
        &mut self,
        host_interface: NetworkInterface,
        ns_interface: NetworkInterface,
        firewall: Firewall,
        disable_ipv6: bool,
    ) -> anyhow::Result<()> {
        self.firewall_exception = Some(FirewallException::add_firewall_exception(
            host_interface,
            ns_interface,
            firewall,
            disable_ipv6,
        )?);

        Ok(())
    }

    pub fn check_openvpn_running(&self) -> bool {
        self.openvpn.as_ref().unwrap().check_if_running()
    }

    pub fn add_env_vars_to_cmd(&self, cmd: &mut Command) {
        cmd.env("VOPONO_NS", &self.name);
        if let Some(ref veth_pair_ips) = self.veth_pair_ips {
            if let Some(ipv4pair) = veth_pair_ips.ipv4.clone() {
                cmd.env("VOPONO_NS_IP", ipv4pair.namespace_ip.to_string());
                cmd.env("VOPONO_HOST_IP", ipv4pair.host_ip.to_string());
            } else {
                log::error!("No IPv4 veth pair!")
            };

            if let Some(ipv6pair) = veth_pair_ips.ipv6.clone() {
                cmd.env("VOPONO_NS_IPV6", ipv6pair.namespace_ip.to_string());
                cmd.env("VOPONO_HOST_IPV6", ipv6pair.host_ip.to_string());
            }
        }
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

    pub fn setup_nftables_firewall(&self) -> anyhow::Result<()> {
        debug!("Setting up base nftables firewall for {}", &self.name);

        // Use `nft -f` to apply a full, idempotent ruleset in one go.
        // This is more robust than running many individual commands.
        let ruleset = format!(
            "
        add table inet {ns_name}
        flush table inet {ns_name}

        add chain inet {ns_name} input {{ type filter hook input priority 0; policy accept; }}
        add chain inet {ns_name} forward {{ type filter hook forward priority 0; policy accept; }}
        add chain inet {ns_name} output {{ type filter hook output priority 0; policy accept; }}

        # Allow loopback traffic
        add rule inet {ns_name} input iifname \"lo\" accept
        add rule inet {ns_name} output oifname \"lo\" accept

        # Allow return traffic for established connections
        add rule inet {ns_name} input ct state related,established accept
        add rule inet {ns_name} output ct state related,established accept
        ",
            ns_name = self.name
        );

        // Write the ruleset to a temporary file
        let temp_filename = format!("vopono-nft-base-{}.conf", self.name);
        let temp_path = std::env::temp_dir().join(temp_filename);

        std::fs::write(&temp_path, ruleset.as_bytes())
            .with_context(|| format!("Failed to write nft ruleset to {:?}", &temp_path))?;

        // Execute the ruleset file
        let temp_path_str = temp_path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to convert temporary file path to string: {:?}",
                temp_path
            )
        })?;
        let exec_result = Self::exec(&self.name, &["nft", "-f", temp_path_str]);

        // Clean up the temporary file, logging any error
        if let Err(e) = std::fs::remove_file(&temp_path) {
            debug!("Failed to remove temporary file {:?}: {}", &temp_path, e);
        }

        exec_result.context("Failed to apply base nftables ruleset")?;

        Ok(())
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
                // Extra check so we don't panic on bad predown command
                match parse_command_str(pdcmd) {
                    Ok(parsed_pdcmd) => {
                        let parsed_pdcmd_ptrs: Vec<&str> =
                            parsed_pdcmd.iter().map(|s| s.as_str()).collect();

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
                            args.extend(parsed_pdcmd_ptrs);

                            let mut cmd = std::process::Command::new("sudo");
                            cmd.args(args);
                            self.add_env_vars_to_cmd(&mut cmd);
                            cmd.spawn().ok();
                        } else {
                            let mut cmd = std::process::Command::new(parsed_pdcmd_ptrs[0]);
                            cmd.args(parsed_pdcmd_ptrs[1..].iter());
                            self.add_env_vars_to_cmd(&mut cmd);
                            cmd.spawn().ok();
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to parse postdown command: {} in shutdown state - skipped postdown execution, error: {:?}",
                            &pdcmd,
                            e
                        )
                    }
                }
            }

            self.trojan = None;
            self.shadowsocks = None;
            self.openvpn = None;
            self.veth_pair = None;
            self.dns_config = None;
            self.warp = None;
            self.wireguard = None;
            self.host_masquerade = None;
            self.firewall_exception = None;
            let delete_result = sudo_command(&["ip", "netns", "delete", &self.name]);
            if delete_result.is_err() {
                warn!(
                    "Failed to delete network namespace: {} - will retry once",
                    &self.name
                );
                std::thread::sleep(std::time::Duration::from_secs(4));

                sudo_command(&["ip", "netns", "delete", &self.name]).unwrap_or_else(|e| {
                    log::error!(
                        "Failed to delete network namespace: {}: {:?}",
                        &self.name,
                        e
                    )
                });
            }
        } else {
            debug!("Skipping destructors since other vopono instance using this namespace!");
            debug!(
                "Existing lockfiles using this namespace: {:?}",
                lockfile_path.read_dir().unwrap().collect::<Vec<_>>()
            );
            std::mem::forget(self.openvpn.take());
            std::mem::forget(self.warp.take());
            std::mem::forget(self.shadowsocks.take());
            std::mem::forget(self.veth_pair.take());
            std::mem::forget(self.dns_config.take());
            std::mem::forget(self.wireguard.take());
            std::mem::forget(self.firewall_exception.take());
            std::mem::forget(self.host_masquerade.take());
            std::mem::forget(self.openconnect.take());
            std::mem::forget(self.openfortivpn.take());
            std::mem::forget(self.trojan.take());
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Lockfile {
    pub ns: NetworkNamespace,
    pub start: u64,
    pub command: String,
}
