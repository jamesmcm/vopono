use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::{check_process_running, set_config_permissions};
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

const OPENVPN_STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenVpn {
    pub(crate) pid: u32,
    #[serde(default)]
    pub openvpn_dns_servers: Vec<IpAddr>,
    pub logfile: PathBuf,
    #[serde(default)]
    runtime_dir: Option<PathBuf>,
    #[serde(default)]
    supervised: bool,
    #[serde(default)]
    pub(crate) recovery_host: Option<String>,
    #[serde(skip)]
    cleanup_enabled: bool,
    // pub distinct_remotes: Vec<String>, // Unique IP Addresses or hostnames
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
        verbose: bool,
    ) -> anyhow::Result<Self> {
        // TODO: Refactor this to separate functions

        if which::which("openvpn").is_err() {
            return Err(crate::diagnostics::SetupError::DependencyMissing("openvpn").into());
        }

        // OpenVPN runs as root and opens its log path itself. Keep that path
        // inside an unpredictable, root-owned runtime directory rather than
        // the client's writable config tree, where a symlink swap could turn
        // it into a privileged file write.
        let runtime_dir = tempfile::Builder::new()
            .prefix("vopono-openvpn-")
            // Do not use the inherited TMPDIR after privilege escalation: its
            // parent may be controlled by the invoking user.
            .tempdir_in("/run")
            .context("Failed to create private OpenVPN runtime directory")?;
        let log_file_path = runtime_dir.path().join("openvpn.log");
        let log_file_str: String = log_file_path.as_os_str().to_string_lossy().to_string();
        File::create(&log_file_path)?;

        let (config_file_path, effective_auth_file) = if crate::util::is_daemon_mode() {
            super::openvpn_config::snapshot(&config_file, runtime_dir.path(), auth_file.as_deref())?
        } else {
            (
                config_file.canonicalize().context("Invalid path given")?,
                auth_file.clone(),
            )
        };
        // Daemon model creates each config object with the correct owner/mode
        // up front; the recursive walk runs dropped-privilege and cannot
        // repair root-owned trees, so it must not run here (EPERM, #382).
        if !crate::util::is_daemon_mode() {
            set_config_permissions()?;
        }

        // Check config file for up and down script entries and warn on their presence
        warn_on_scripts_config(&config_file_path)?;

        info!("Launching OpenVPN...");
        let mut command_vec = ([
            "openvpn",
            "--config",
            config_file_path.to_str().unwrap(),
            "--machine-readable-output",
            "--log",
            log_file_str.as_str(),
            "--ignore-unknown-option",
            "dns-updown",
            "--dns-updown",
            "disable",
        ])
        .to_vec();

        if let Some(af_ref) = effective_auth_file.as_ref() {
            command_vec.push("--auth-user-pass");
            command_vec.push(af_ref.as_os_str().to_str().unwrap());
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

        // Only try once for DNS resolution / remote host connection
        command_vec.push("--connect-retry-max");
        command_vec.push("1");
        // Ignore Windows-specific command
        command_vec.push("--pull-filter");
        command_vec.push("ignore");
        command_vec.push("block-outside-dns");

        // In daemon mode the config file is client-controlled input, so
        // script hooks (up/down/iproute/...) must never run as root: cap
        // script-security after --config so a config-file directive cannot
        // raise it again (later options win).
        if crate::util::is_daemon_mode() {
            command_vec.push("--script-security");
            command_vec.push("1");
        }

        if disable_ipv6 || ipv6_disabled {
            debug!("IPv6 disabled, will pass pull-filter ignore to OpenVPN");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("ifconfig-ipv6");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("route-ipv6");
        }

        let remotes = get_remotes_from_config(&config_file_path)?;
        let recovery_host = remotes.first().map(|remote| match &remote.host {
            Host::IPv4(ip) => ip.to_string(),
            Host::IPv6(ip) => ip.to_string(),
            Host::Hostname(host) => host.clone(),
        });
        debug!("Found remotes: {:?}", remotes);
        let working_dir = PathBuf::from(config_file_path.parent().unwrap());

        let supervised = crate::util::is_daemon_mode();
        let supervisor = if supervised {
            Some(super::openvpn_supervisor::prepare(
                &command_vec,
                runtime_dir.path(),
            )?)
        } else {
            None
        };
        let supervisor_refs = supervisor
            .as_ref()
            .map(|args| args.iter().map(String::as_str).collect::<Vec<_>>());
        let mut handle = NetworkNamespace::exec_no_block(
            &netns.name,
            supervisor_refs.as_deref().unwrap_or(&command_vec),
            None,
            None,
            !verbose,
            false,
            false,
            Some(working_dir),
        )
        .context("Failed to launch OpenVPN - is openvpn installed?")?;
        let id = handle.id();
        let mut buffer = String::with_capacity(16384);

        let mut logfile = BufReader::with_capacity(64, File::open(log_file_str)?);
        let mut pos: usize = 0;

        // Parse DNS headers from OpenVPN response
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let mut openvpn_dns_servers = Vec::new();
        // `--machine-readable-output` adds timestamps and flags to ordinary
        // log messages. `>STATE:` records belong to the management interface,
        // so readiness must be detected from the log messages themselves.
        let mut connect_state: Option<OpenVpnStartupState> = None;
        let startup_deadline = Instant::now() + OPENVPN_STARTUP_TIMEOUT;
        loop {
            let start = pos;
            let x = logfile.read_line(&mut buffer)?;

            if x > 0 {
                debug!("{}", buffer[pos..].trim_end());
            }

            pos += x;

            for ip in parse_openvpn_dns_servers(&buffer[start..pos], &dns_regex) {
                if (ip.is_ipv4() || !(disable_ipv6 || ipv6_disabled))
                    && !openvpn_dns_servers.contains(&ip)
                {
                    debug!("Found OpenVPN DNS response: {ip}");
                    openvpn_dns_servers.push(ip);
                }
            }

            if let Some(state) = parse_openvpn_startup_state(&buffer[start..pos]) {
                debug!("OpenVPN startup state: {state:?}");
                connect_state = Some(state);
            }

            if connect_state.is_some() {
                break;
            }

            // A fast failure can exit while its AUTH_FAILED/TLS diagnosis is
            // still buffered in the logfile. Drain those lines before using
            // process exit as a generic startup failure.
            if x == 0 && supervised && runtime_dir.path().join("child-exited").exists() {
                terminate_startup(&mut handle);
                return Err(anyhow!("OpenVPN exited before the tunnel was established"));
            }
            if x == 0
                && let Some(status) = handle.try_wait()?
            {
                return Err(anyhow!(
                    "OpenVPN exited with {status} before the tunnel was established, use -v for full log output"
                ));
            }

            if Instant::now() >= startup_deadline {
                terminate_startup(&mut handle);
                return Err(anyhow!(
                    "OpenVPN did not establish the tunnel within {} seconds, use -v for full log output",
                    OPENVPN_STARTUP_TIMEOUT.as_secs()
                ));
            }

            if x == 0 {
                std::thread::sleep(Duration::from_millis(50));
            }

            logfile.seek(SeekFrom::Start(pos as u64)).unwrap();
        }

        match connect_state {
            Some(OpenVpnStartupState::AuthFailed) => {
                terminate_startup(&mut handle);
                let auth_path_display = auth_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "the auth file".to_string());
                let provider_hint = auth_file
                    .as_ref()
                    .filter(|path| path.components().any(|part| part.as_os_str() == "pia"))
                    .map(|_| {
                        " For PIA, use the VPN service username in the form p1234567 (not an email address), then rerun `vopono sync --protocol openvpn privateinternetaccess` to replace cached credentials."
                    })
                    .unwrap_or_default();
                error!(
                    "OpenVPN server rejected the username/password in {}.{}",
                    auth_path_display, provider_hint
                );
                return Err(crate::diagnostics::Diagnostic::new(
                    crate::diagnostics::DiagnosticCode::TunnelAuthentication,
                    crate::diagnostics::DiagnosticState::Fail,
                    "OpenVPN authentication rejected by the server",
                    Some("Verify provider-specific VPN credentials; ProtonVPN uses separate OpenVPN credentials")).into());
            }
            Some(OpenVpnStartupState::TlsFailed) => {
                terminate_startup(&mut handle);
                return Err(crate::diagnostics::Diagnostic::new(
                    crate::diagnostics::DiagnosticCode::TunnelTls,
                    crate::diagnostics::DiagnosticState::Fail,
                    "OpenVPN TLS negotiation or certificate verification failed",
                    Some("Check system time, certificates and provider configuration"),
                )
                .into());
            }
            Some(OpenVpnStartupState::OptionsError) => {
                terminate_startup(&mut handle);
                error!(
                    "OpenVPN rejected configuration options; raw input is excluded from diagnostic output"
                );
                return Err(anyhow!("OpenVPN options error, use -v for full log output"));
            }
            Some(OpenVpnStartupState::Connected) => {}
            None => unreachable!("startup loop only exits with a terminal state"),
        }

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            crate::util::open_ports(netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports (will be proxied to host)
        if let Some(forwards) = forward_ports {
            crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
        }

        if use_killswitch {
            killswitch(netns, dns, remotes.as_slice(), firewall, disable_ipv6)?;
        }

        Ok(Self {
            pid: id,
            openvpn_dns_servers,
            logfile: log_file_path,
            runtime_dir: Some(runtime_dir.keep()),
            supervised,
            recovery_host,
            cleanup_enabled: true,
        })
    }

    pub fn check_if_running(&self) -> bool {
        check_process_running(self.pid)
    }

    /// Reuse the frozen launch plan; neither configuration nor credentials are
    /// read from user-writable files during automatic recovery.
    pub fn request_restart(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.supervised
                && self
                    .runtime_dir
                    .as_ref()
                    .is_some_and(|path| super::openvpn_supervisor::matches(self.pid, path)),
            "OpenVPN has no live namespace supervisor"
        );
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGUSR1,
        )?;
        Ok(())
    }
}

fn terminate_startup(child: &mut std::process::Child) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
    for _ in 0..40 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for OpenVpn {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        if self.supervised {
            if let Some(runtime) = &self.runtime_dir
                && super::openvpn_supervisor::matches(self.pid, runtime)
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(self.pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
                for _ in 0..40 {
                    if !super::openvpn_supervisor::matches(self.pid, runtime) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        } else {
            match nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(self.pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(_) => debug!("Killed OpenVPN (pid: {})", self.pid),
                Err(e) => error!("Failed to kill OpenVPN (pid: {}): {:?}", self.pid, e),
            }
        }

        match std::fs::remove_file(&self.logfile) {
            Ok(_) => debug!(
                "Deleted OpenVPN logfile: {}",
                self.logfile.as_os_str().to_string_lossy()
            ),
            Err(e) => error!(
                "Failed to delete OpenVPN logfile: {}: {:?}",
                self.logfile.as_os_str().to_string_lossy(),
                e
            ),
        }
        if let Some(runtime) = &self.runtime_dir {
            let _ = std::fs::remove_dir_all(runtime);
        }
    }
}

impl OpenVpn {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
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
    let endpoints = resolve_remote_endpoints(remotes, disable_ipv6)?;

    match firewall {
        Firewall::IpTables => {
            let ipcmds: &[&str] = if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
                &["iptables"]
            } else {
                &["iptables", "ip6tables"]
            };

            for ipcmd in ipcmds {
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "INPUT", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "FORWARD", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "OUTPUT", "DROP"])?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "INPUT",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                )?;

                for endpoint in &endpoints {
                    let endpoint_ipcmd = if endpoint.address.is_ipv4() {
                        "iptables"
                    } else {
                        "ip6tables"
                    };
                    if endpoint_ipcmd != *ipcmd {
                        continue;
                    }

                    let protocol = endpoint.protocol.to_string();
                    let address = endpoint.address.to_string();
                    let port = endpoint.port.to_string();
                    NetworkNamespace::exec(
                        &netns.name,
                        &[
                            ipcmd,
                            "-A",
                            "OUTPUT",
                            "-p",
                            protocol.as_str(),
                            "-m",
                            protocol.as_str(),
                            "-d",
                            address.as_str(),
                            "--dport",
                            port.as_str(),
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                }

                if *ipcmd == "ip6tables" {
                    add_iptables_neighbor_discovery_rules(netns)?;
                }

                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"],
                )?;
                let reject_type = if *ipcmd == "ip6tables" {
                    "icmp6-no-route"
                } else {
                    "icmp-net-unreachable"
                };
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "OUTPUT",
                        "-j",
                        "REJECT",
                        "--reject-with",
                        reject_type,
                    ],
                )?;
            }
        }
        Firewall::NfTables => {
            if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
            }
            NetworkNamespace::exec(
                &netns.name,
                &[
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
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
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
                ],
            )?;

            if !disable_ipv6 {
                add_nft_neighbor_discovery_rules(netns)?;
            }

            for endpoint in &endpoints {
                let address_family = if endpoint.address.is_ipv4() {
                    "ip"
                } else {
                    "ip6"
                };
                let address = endpoint.address.to_string();
                let protocol = endpoint.protocol.to_string();
                let port = endpoint.port.to_string();
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        &netns.name,
                        "output",
                        address_family,
                        "daddr",
                        address.as_str(),
                        protocol.as_str(),
                        "dport",
                        port.as_str(),
                        "counter",
                        "accept",
                    ],
                )?;
            }

            NetworkNamespace::exec(
                &netns.name,
                &[
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
                ],
            )?;

            // Port-opening rules are inserted before this rule, so --open-ports,
            // --forward, and provider-assigned forwarded ports continue to work
            // while all other traffic remains blocked.
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "counter",
                    "drop",
                ],
            )?;

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "counter",
                    "reject",
                    "with",
                    "icmpx",
                    "type",
                    "admin-prohibited",
                ],
            )?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RemoteEndpoint {
    address: IpAddr,
    port: u16,
    protocol: OpenVpnProtocol,
}

fn resolve_remote_endpoints(
    remotes: &[Remote],
    disable_ipv6: bool,
) -> anyhow::Result<Vec<RemoteEndpoint>> {
    let mut endpoints = Vec::new();
    for remote in remotes {
        let addresses: Vec<IpAddr> = match &remote.host {
            Host::IPv4(address) => vec![IpAddr::V4(*address)],
            Host::IPv6(address) => vec![IpAddr::V6(*address)],
            Host::Hostname(hostname) => (hostname.as_str(), remote.port)
                .to_socket_addrs()
                .with_context(|| format!("Failed to resolve OpenVPN remote hostname {hostname}"))?
                .map(|address| address.ip())
                .collect(),
        };

        for address in addresses {
            if disable_ipv6 && address.is_ipv6() {
                continue;
            }
            if !endpoints.iter().any(|endpoint: &RemoteEndpoint| {
                endpoint.address == address
                    && endpoint.port == remote.port
                    && endpoint.protocol == remote.protocol
            }) {
                endpoints.push(RemoteEndpoint {
                    address,
                    port: remote.port,
                    protocol: remote.protocol.clone(),
                });
            }
        }
    }

    if endpoints.is_empty() {
        anyhow::bail!("OpenVPN has no usable remote endpoints after applying IPv6 settings");
    }
    Ok(endpoints)
}

fn add_iptables_neighbor_discovery_rules(netns: &NetworkNamespace) -> anyhow::Result<()> {
    let veth_ifname = netns
        .veth_pair
        .as_ref()
        .context("Veth pair not set while configuring OpenVPN IPv6 killswitch")?
        .source
        .as_str();

    for (chain, interface_flag) in [("INPUT", "-i"), ("OUTPUT", "-o")] {
        for icmpv6_type in ["135", "136"] {
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "ip6tables",
                    "-A",
                    chain,
                    interface_flag,
                    veth_ifname,
                    "-p",
                    "icmpv6",
                    "-m",
                    "icmp6",
                    "--icmpv6-type",
                    icmpv6_type,
                    "-j",
                    "ACCEPT",
                ],
            )
            .with_context(|| {
                format!("Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname}")
            })?;
        }
    }
    Ok(())
}

fn add_nft_neighbor_discovery_rules(netns: &NetworkNamespace) -> anyhow::Result<()> {
    let veth_ifname = netns
        .veth_pair
        .as_ref()
        .context("Veth pair not set while configuring OpenVPN IPv6 killswitch")?
        .source
        .as_str();

    for (chain, interface_keyword) in [("input", "iifname"), ("output", "oifname")] {
        for icmpv6_type in ["nd-neighbor-solicit", "nd-neighbor-advert"] {
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    chain,
                    interface_keyword,
                    veth_ifname,
                    "icmpv6",
                    "type",
                    icmpv6_type,
                    "counter",
                    "accept",
                ],
            )
            .with_context(|| {
                format!(
                    "Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname} in nftables"
                )
            })?;
        }
    }
    Ok(())
}

fn parse_openvpn_dns_servers(log: &str, dns_regex: &Regex) -> Vec<IpAddr> {
    dns_regex
        .captures_iter(log)
        .filter_map(|cap| cap.get(1))
        .filter_map(|ipstr| IpAddr::from_str(ipstr.as_str()).ok())
        .fold(Vec::new(), |mut servers, server| {
            if !servers.contains(&server) {
                servers.push(server);
            }
            servers
        })
}

/// Terminal startup outcomes detected from OpenVPN's ordinary log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenVpnStartupState {
    Connected,
    AuthFailed,
    OptionsError,
    TlsFailed,
}

/// Match stable OpenVPN messages anywhere in a line because
/// `--machine-readable-output` prefixes them with a timestamp and flags.
fn parse_openvpn_startup_state(log: &str) -> Option<OpenVpnStartupState> {
    if log.contains("AUTH_FAILED") {
        Some(OpenVpnStartupState::AuthFailed)
    } else if log.contains("TLS Error") || log.contains("VERIFY ERROR") {
        Some(OpenVpnStartupState::TlsFailed)
    } else if log.contains("Options error") {
        Some(OpenVpnStartupState::OptionsError)
    } else if log.contains("Initialization Sequence Completed") {
        Some(OpenVpnStartupState::Connected)
    } else {
        None
    }
}

pub fn warn_on_scripts_config(path: &Path) -> anyhow::Result<bool> {
    let mut out = false;
    let file_string =
        std::fs::read_to_string(path).context(format!("Reading OpenVPN config file: {path:?}"))?;
    for line in file_string.lines() {
        if line.trim().starts_with("up ") || line.trim().starts_with("down ") {
            log::error!(
                "up / down scripts detected in OpenVPN config file - remove these or OpenVPN will likely hang in the network namespace. Line: {line}"
            );
            out = true;
        }
    }
    Ok(out)
}

pub fn get_remotes_from_config(path: &Path) -> anyhow::Result<Vec<Remote>> {
    let content =
        std::fs::read_to_string(path).context("Reading OpenVPN endpoint configuration")?;
    let endpoints = super::openvpn_config::endpoints(&content)
        .map_err(|_| anyhow!("Invalid or unsupported OpenVPN remote configuration"))?;
    endpoints
        .into_iter()
        .map(|endpoint| {
            Ok(Remote {
                host: Host::from_str(&endpoint.host)?,
                port: endpoint.port,
                protocol: if endpoint.tcp {
                    OpenVpnProtocol::TCP
                } else {
                    OpenVpnProtocol::UDP
                },
            })
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_pushed_ipv4_and_ipv6_dns_servers() {
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let log =
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00::53,route-gateway 10.8.0.1";

        assert_eq!(
            parse_openvpn_dns_servers(log, &dns_regex),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
                IpAddr::V6("fd00::53".parse::<Ipv6Addr>().unwrap()),
            ]
        );
    }

    #[test]
    fn deduplicates_pushed_dns_servers() {
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let log = "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.1";

        assert_eq!(
            parse_openvpn_dns_servers(log, &dns_regex),
            vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]
        );
    }

    #[test]
    fn remote_endpoints_keep_only_enabled_address_families() {
        let remotes = vec![
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
            Remote {
                host: Host::IPv6("2001:db8::10".parse().unwrap()),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
        ];

        let endpoints = resolve_remote_endpoints(&remotes, true).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].address,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );

        let endpoints = resolve_remote_endpoints(&remotes, false).unwrap();
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn remote_endpoints_are_deduplicated() {
        let remotes = vec![
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
        ];

        assert_eq!(resolve_remote_endpoints(&remotes, false).unwrap().len(), 1);
    }

    #[test]
    fn parses_prefixed_connected_log_message() {
        let log = "1787685612.853245 0012 Initialization Sequence Completed";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::Connected)
        );
    }

    #[test]
    fn parses_prefixed_auth_failed_log_message() {
        let log = "1787685612.853245 0012 AUTH_FAILED";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::AuthFailed)
        );
    }

    #[test]
    fn classifies_tls_failures_without_exposing_server_reply() {
        assert_eq!(
            parse_openvpn_startup_state("timestamp TLS Error: TLS key negotiation failed"),
            Some(OpenVpnStartupState::TlsFailed)
        );
        assert_eq!(
            parse_openvpn_startup_state("timestamp VERIFY ERROR: certificate expired"),
            Some(OpenVpnStartupState::TlsFailed)
        );
    }

    #[test]
    fn parses_prefixed_options_error_log_message() {
        let log = "1787685612.853245 b000 Options error: Unrecognized option";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::OptionsError)
        );
    }

    #[test]
    fn ignores_non_terminal_log_lines() {
        assert_eq!(
            parse_openvpn_startup_state("TCP connection established"),
            None
        );
    }
}
