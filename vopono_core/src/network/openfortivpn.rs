use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_STARTUP_OUTPUT: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenFortiVpn {
    pub(crate) pid: u32,
    #[serde(default)]
    runtime_dir: Option<PathBuf>,
    #[serde(default)]
    ns_name: Option<String>,
    #[serde(skip)]
    cleanup_enabled: bool,
}

fn read_config_as_owner(config_file: &Path) -> anyhow::Result<String> {
    let bytes = crate::util::owner_write::read_file_as_config_owner(config_file)
        .with_context(|| format!("Failed to read {}", config_file.display()))?;
    String::from_utf8(bytes).with_context(|| {
        format!(
            "OpenFortiVPN config {} is not valid UTF-8",
            config_file.display()
        )
    })
}

fn validate_unprivileged_config_str(contents: &str) -> anyhow::Result<()> {
    const EXECUTION_DIRECTIVES: &[&str] = &[
        "pinentry",
        "pppd-plugin",
        "pppd-call",
        "ppp-system",
        "ca-file",
        "user-cert",
        "user-key",
        "pppd-use-peerdns",
        "pppd-ipparam",
        "pppd-log",
    ];
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line.split_once('=').map_or(line, |(key, _)| key).trim();
        anyhow::ensure!(
            !EXECUTION_DIRECTIVES.contains(&key),
            "OpenFortiVPN directive '{key}' is not allowed in daemon mode (line {})",
            line_number + 1
        );
    }
    Ok(())
}

#[cfg(test)]
fn validate_unprivileged_config(config_file: &Path) -> anyhow::Result<()> {
    validate_unprivileged_config_str(&read_config_as_owner(config_file)?)
}

pub fn server_from_config(config_file: &Path) -> anyhow::Result<String> {
    let contents = read_config_as_owner(config_file)?;
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "host")
                .then(|| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow!("OpenFortiVPN config has no host option"))
}

/// Apply the fail-closed tunnel-only killswitch for OpenFortiVPN.
///
/// openfortivpn does not implement a killswitch itself, so once the tunnel is
/// up all input/output in the namespace is dropped except loopback, the
/// tunnel interface, return traffic and the resolved VPN server endpoints
/// (the client needs those to keep its session alive). Without this policy
/// the namespace keeps a working default route through the host veth/NAT
/// path, so any tunnel failure silently bypasses the VPN.
pub fn apply_killswitch(
    netns: &NetworkNamespace,
    firewall: Firewall,
    disable_ipv6: bool,
    config_file: &Path,
) -> anyhow::Result<()> {
    let server = server_from_config(config_file)?;
    super::firewall::apply_tunnel_only_killswitch_for_server(
        netns,
        firewall,
        disable_ipv6,
        &server,
        &["ppp"],
    )
}

impl OpenFortiVpn {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &mut NetworkNamespace,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        hosts_entries: Option<&Vec<String>>,
        firewall: Firewall,
        allow_host_access: bool,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("openfortivpn") {
            error!("OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?");
            return Err(anyhow!(
                "OpenFortiVPN not found. Is OpenFortiVPN installed and on PATH?: {:?}",
                x
            ));
        }

        let contents = read_config_as_owner(&config_file)?;
        if crate::util::is_daemon_mode() {
            validate_unprivileged_config_str(&contents)?;
        }

        info!("Launching OpenFortiVPN...");
        let runtime_dir = super::etc_overlay::trusted_runtime_dir("openfortivpn-")?;
        // Freeze the validated config into a root-owned 0600 file inside runtime_dir
        // to eliminate TOCTOU races against a user-writable config path.
        let frozen_config = runtime_dir.path().join("config");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&frozen_config)?;
            file.write_all(contents.as_bytes())?;
        }
        let pppd_log = runtime_dir.path().join("pppd.log");
        // Must run as root - https://github.com/adrienverge/openfortivpn/issues/650
        let command_vec = ([
            "openfortivpn",
            "-c",
            frozen_config
                .to_str()
                .context("Invalid frozen OpenFortiVPN config path")?,
            "--no-dns",
            "--pppd-log",
            pppd_log.to_str().context("Invalid PPP log path")?,
        ])
        .to_vec();

        let log_path = runtime_dir.path().join("openfortivpn.log");
        let stdout_file = crate::util::create_private_file(&log_path)?;
        let stderr_file = stdout_file.try_clone()?;

        // Spawn in its own process group and log to a 0600 runtime file rather
        // than pipes so stderr can never deadlock startup and openfortivpn does
        // not receive SIGPIPE after OpenFortiVpn::run returns.
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &netns.name])
            .args(&command_vec)
            .process_group(0)
            .stdin(if crate::util::is_daemon_mode() {
                Stdio::null()
            } else {
                Stdio::inherit()
            })
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        let mut handle = cmd
            .spawn()
            .context("Failed to launch OpenFortiVPN - is openfortivpn installed?")?;
        let id = handle.id();

        info!(
            "Waiting for OpenFortiVPN to establish connection - you may be prompted on your 2FA device"
        );
        info!("If your VPN password is not in the OpenFortiVPN config file then enter it here now");
        let setup_result = (|| -> anyhow::Result<()> {
            let mut log_reader = std::fs::File::open(&log_path)?;
            let deadline = Instant::now() + STARTUP_TIMEOUT;
            let mut bytes = Vec::with_capacity(16_000);
            let mut chunk = [0_u8; 4096];
            let mut pos: u64 = 0;
            loop {
                log_reader.seek(SeekFrom::Start(pos))?;
                let count = log_reader.read(&mut chunk)?;
                if count > 0 {
                    pos = pos.saturating_add(count as u64);
                    anyhow::ensure!(
                        bytes.len() + count <= MAX_STARTUP_OUTPUT,
                        "OpenFortiVPN startup output exceeded {} bytes",
                        MAX_STARTUP_OUTPUT
                    );
                    if !crate::util::is_daemon_mode() {
                        let _ = std::io::stdout().write_all(&chunk[..count]);
                        let _ = std::io::stdout().flush();
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes
                        .windows(b"Tunnel is up and running".len())
                        .any(|window| window == b"Tunnel is up and running")
                    {
                        break;
                    }
                    continue;
                }

                if let Some(status) = handle.try_wait()? {
                    anyhow::bail!("OpenFortiVPN exited before the tunnel became ready: {status}");
                }
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "Timed out after {} seconds waiting for OpenFortiVPN",
                    STARTUP_TIMEOUT.as_secs()
                );
                std::thread::sleep(Duration::from_millis(100));
            }

            let buffer = String::from_utf8(bytes).context("OpenFortiVPN emitted invalid UTF-8")?;
            debug!("Full OpenFortiVPN stdout: {:?}", buffer);
            let remote_peer = get_remote_peer(&pppd_log)?;

            // Preserve an explicit host route to the FortiVPN gateway over veth
            // before replacing the IPv4 default route, so outer TLS traffic
            // cannot loop back into ppp0 when set-routes=0 is configured.
            if let Some(host_ip) = netns
                .veth_pair_ips
                .as_ref()
                .and_then(|ips| ips.ipv4.as_ref())
                .map(|pair| pair.host_ip)
                && let Ok(server) = server_from_config(&frozen_config)
                && let Ok(ips) = crate::util::hostname_to_ip(&server)
            {
                let via = host_ip.to_string();
                for ip in ips.into_iter().filter(IpAddr::is_ipv4) {
                    let route = format!("{ip}/32");
                    let _ = NetworkNamespace::exec(
                        &netns.name,
                        &["ip", "route", "replace", &route, "via", &via],
                    );
                }
            }

            debug!("Found OpenFortiVPN route: {remote_peer:?}");
            let _ = NetworkNamespace::exec(&netns.name, &["ip", "route", "del", "default"]);
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "ip",
                    "route",
                    "add",
                    "default",
                    "via",
                    &remote_peer.to_string(),
                ],
            )?;
            // Remove any IPv6 default route over veth since OpenFortiVPN tunnels IPv4.
            let _ = NetworkNamespace::exec(&netns.name, &["ip", "-6", "route", "del", "default"]);

            let dns = get_dns(&buffer)?;
            let suffixes: Vec<&str> = dns.1.iter().map(|x| x.as_str()).collect();
            let interface = super::firewall::wait_for_tunnel_interface(&netns.name, &["ppp"], 1)?
                .context("Could not identify the OpenFortiVPN DNS egress interface")?;
            netns.dns_config_with_interface(
                &dns.0,
                &suffixes,
                hosts_entries,
                allow_host_access,
                Some(&interface),
            )?;
            if let Some(opens) = open_ports {
                crate::util::open_ports(netns, opens.as_slice(), firewall)?;
            }
            if let Some(forwards) = forward_ports {
                crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
            }
            Ok(())
        })();

        if let Err(error) = setup_result {
            let group = nix::unistd::Pid::from_raw(-(handle.id() as i32));
            let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
            let _ = handle.kill();
            let _ = handle.wait();
            return Err(error);
        }

        Ok(Self {
            pid: id,
            runtime_dir: Some(runtime_dir.keep()),
            ns_name: Some(netns.name.clone()),
            cleanup_enabled: true,
        })
    }
}

impl Drop for OpenFortiVpn {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let pid_matches = self.ns_name.as_deref().is_none_or(|ns| {
            crate::util::process_is_in_network_namespace(self.pid, ns).unwrap_or(false)
        });
        let pid = nix::unistd::Pid::from_raw(self.pid as i32);
        let group = nix::unistd::Pid::from_raw(-(self.pid as i32));
        if pid_matches {
            let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGTERM);
            for _ in 0..10 {
                if matches!(
                    nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
                    Ok(nix::sys::wait::WaitStatus::Exited(_, _))
                        | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _))
                        | Err(nix::errno::Errno::ECHILD)
                ) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            match nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL) {
                Ok(_) => debug!("Killed OpenFortiVPN process group (pgid: {})", self.pid),
                Err(nix::errno::Errno::ESRCH) => {}
                Err(e) => error!("Failed to kill OpenFortiVPN (pid: {}): {:?}", self.pid, e),
            }
        } else {
            debug!(
                "Skipping OpenFortiVPN kill for pid {}: no longer in target namespace",
                self.pid
            );
        }
        while matches!(
            nix::sys::wait::waitpid(pid, None),
            Err(nix::errno::Errno::EINTR)
        ) {}
        if let Some(runtime) = &self.runtime_dir {
            let _ = std::fs::remove_dir_all(runtime);
        }
    }
}

impl OpenFortiVpn {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

// Cannot use in network namespace - at least if pppd is running outside?
// pub fn get_peer_route() -> anyhow::Result<Ipv4Addr> {
//     let output = Command::new("ip").args(&["route"]).output()?.stdout;
//     let output = std::str::from_utf8(&output)?;
//     debug!("OpenFortiVPN ip routes: {}", output);

//     // sudo ip route | grep "ppp0 proto kernel"
//     let re =
//         Regex::new(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) dev ppp0 proto kernel").unwrap();
//     let mut ips = Vec::new();
//     for caps in re.captures_iter(output) {
//         ips.push(Ipv4Addr::from_str(&caps["ip"])?);
//     }
//     debug!("Found OpenFortiVPN routes: {:?}", &ips);
//     debug!("Using last route as default gateway");
//     ips.pop()
//         .ok_or_else(|| anyhow!("No route found for gateway"))
// }

pub fn get_remote_peer(pppd_log: &Path) -> anyhow::Result<Ipv4Addr> {
    let stdout = std::fs::read_to_string(pppd_log)
        .context(format!("Opening pppd log file: {pppd_log:?}"))?;
    let re = Regex::new(r"remote IP address (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(&stdout) {
        if let Ok(ip) = Ipv4Addr::from_str(&caps["ip"]) {
            ips.push(ip);
        }
    }
    ips.pop()
        .ok_or_else(|| anyhow!("Could not find remote IP address in pppd log"))
}

// DNS pppd:
// INFO:   Got addresses: [x.x.x.x], ns [y.y.y.y, y.y.y.y], ns_suffix [host.net;host2.com;host.com]
pub fn get_dns(stdout: &str) -> anyhow::Result<(Vec<IpAddr>, Vec<String>)> {
    // sudo ip route | grep "ppp0 proto kernel"
    let re = Regex::new(r"ns \[(?P<ip>[^\]]+)\]").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(stdout) {
        for ip_raw in caps["ip"].split(", ") {
            let ip = IpAddr::from_str(ip_raw)?;
            if !ips.contains(&ip) && ip != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                ips.push(ip);
            }
        }
    }

    let re = Regex::new(r"ns_suffix \[(?P<suffix>[^\]]+)\]").unwrap();
    let mut suffixes = Vec::new();
    for caps in re.captures_iter(stdout) {
        for suffix_raw in caps["suffix"].split(';') {
            let suffix = suffix_raw.to_string();
            if !suffixes.contains(&suffix) {
                suffixes.push(suffix);
            }
        }
    }

    debug!(
        "Found OpenFortiVPN DNS ips: {:?}, ns suffixes: {:?}",
        ips, suffixes
    );
    Ok((ips, suffixes))
}

#[cfg(test)]
mod tests {
    use super::{server_from_config, validate_unprivileged_config};
    use std::io::Write;

    #[test]
    fn reads_host_from_config() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "# comment\nhost = vpn.company.example\nport = 443").unwrap();
        assert_eq!(
            server_from_config(config.path()).unwrap(),
            "vpn.company.example"
        );
    }

    #[test]
    fn daemon_config_rejects_execution_directives() {
        for directive in [
            "pinentry",
            "pppd-plugin",
            "pppd-call",
            "ppp-system",
            "ca-file",
            "user-cert",
            "user-key",
            "pppd-use-peerdns",
            "pppd-ipparam",
            "pppd-log",
        ] {
            let mut config = tempfile::NamedTempFile::new().unwrap();
            writeln!(config, "host = vpn.example.com\n{directive} = /tmp/evil").unwrap();
            let error = validate_unprivileged_config(config.path())
                .unwrap_err()
                .to_string();
            assert!(error.contains(directive));
        }
    }

    #[test]
    fn daemon_config_accepts_non_execution_directives() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "host = vpn.example.com\nusername = alice\n# pinentry = ignored"
        )
        .unwrap();
        validate_unprivileged_config(config.path()).unwrap();
    }
}
