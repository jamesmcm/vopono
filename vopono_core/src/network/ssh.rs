use super::firewall::{Firewall, disable_ipv6};
use super::netns::NetworkNamespace;
use crate::util::hostname_to_ip;
use anyhow::{Context, anyhow, bail};
use log::{debug, error, info, warn};
use nix::unistd::User;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REDSOCKS_PORT: u16 = 12345;
const DNSTC_PORT: u16 = 12346;

struct SshEndpoint {
    address: Ipv4Addr,
    port: u16,
    host_key_alias: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SshProxy {
    pub(crate) ssh_pid: u32,
    pub(crate) redsocks_pid: u32,
    pub listen_port: u16,
    #[serde(default)]
    ns_name: Option<String>,
    #[serde(default)]
    runtime_dir: Option<PathBuf>,
    #[serde(skip)]
    cleanup_enabled: bool,
}

impl SshProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        server: &str,
        config_file: Option<&Path>,
        listen_port: u16,
        ssh_user: Option<&str>,
        ssh_port: Option<u16>,
        user: Option<String>,
        group: Option<String>,
        firewall: Firewall,
        use_killswitch: bool,
    ) -> anyhow::Result<Self> {
        which::which("ssh").map_err(|e| anyhow!("Cannot find ssh on PATH: {e}"))?;
        which::which("redsocks").map_err(|e| {
            anyhow!("Cannot find redsocks on PATH; SSH transparent proxying requires redsocks: {e}")
        })?;

        let endpoint = ssh_endpoint(server, config_file, ssh_user, ssh_port, user.as_deref())?;
        let identity_file = user
            .as_deref()
            .map(default_identity_file)
            .transpose()?
            .flatten();
        if let Some(path) = identity_file.as_deref() {
            debug!(
                "Using initiating user's SSH identity: {}",
                path.to_string_lossy()
            );
        }
        let ssh_command = ssh_command(
            server,
            config_file,
            identity_file.as_deref(),
            listen_port,
            Some(&endpoint),
            ssh_user,
            ssh_port,
        )?;
        info!("Launching SSH dynamic proxy on socks5h://127.0.0.1:{listen_port}");
        let mut ssh = command_in_namespace(netns, &ssh_command, user, group)?;
        if crate::util::is_daemon_mode() {
            ssh.stdin(Stdio::null());
            ssh.stdout(Stdio::null());
        }
        ssh.stderr(Stdio::piped());
        let mut ssh = ssh.spawn().context("Failed to launch SSH dynamic proxy")?;
        let ssh_pid = ssh.id();

        if let Err(e) = wait_for_listener(netns, listen_port, &mut ssh, "SSH proxy") {
            kill_process_group(ssh_pid, "SSH proxy");
            return Err(e);
        }

        let runtime_dir = super::etc_overlay::trusted_runtime_dir("redsocks-")
            .context("Failed to create runtime directory for redsocks configuration")?;
        let config_path = runtime_dir.path().join("redsocks.conf");
        {
            let mut config = crate::util::create_private_file(&config_path)
                .context("Failed to create temporary redsocks configuration")?;
            write!(
                config,
                "{}",
                redsocks_config(listen_port, REDSOCKS_PORT, DNSTC_PORT)
            )?;
            config.flush()?;
        }

        let redsocks_command = vec![
            "redsocks".to_owned(),
            "-c".to_owned(),
            config_path.to_string_lossy().into_owned(),
        ];
        info!("Launching redsocks transparent TCP proxy");
        let mut redsocks = command_in_namespace(netns, &redsocks_command, None, None)?;
        if crate::util::is_daemon_mode() {
            redsocks.stdin(Stdio::null());
        }
        redsocks.stdout(Stdio::null());
        let mut redsocks = match redsocks.spawn() {
            Ok(child) => child,
            Err(e) => {
                kill_process_group(ssh_pid, "SSH proxy");
                return Err(e).context("Failed to launch redsocks");
            }
        };
        let redsocks_pid = redsocks.id();

        if let Err(e) =
            wait_for_listener(netns, REDSOCKS_PORT, &mut redsocks, "redsocks").and_then(|_| {
                setup_transparent_firewall(
                    netns,
                    firewall,
                    (endpoint.address, endpoint.port),
                    use_killswitch,
                )
            })
        {
            kill_process_group(redsocks_pid, "redsocks");
            kill_process_group(ssh_pid, "SSH proxy");
            return Err(e);
        }

        if use_killswitch {
            info!("SSH killswitch enabled; non-proxied traffic and non-DNS UDP are blocked");
        } else {
            warn!("SSH killswitch disabled; UDP other than DNS may bypass the SSH proxy");
        }

        Ok(Self {
            ssh_pid,
            redsocks_pid,
            listen_port,
            ns_name: Some(netns.name.clone()),
            runtime_dir: Some(runtime_dir.keep()),
            cleanup_enabled: true,
        })
    }
}

fn command_in_namespace(
    netns: &NetworkNamespace,
    command: &[String],
    user: Option<String>,
    group: Option<String>,
) -> anyhow::Result<Command> {
    let is_root = nix::unistd::geteuid().is_root();
    if is_root && (user.is_some() || group.is_some()) {
        let (program, args) = command
            .split_first()
            .context("SSH namespace command cannot be empty")?;
        let target_user = if let Some(user_name) = user.as_deref() {
            Some(
                User::from_name(user_name)?
                    .with_context(|| format!("Unknown SSH user '{user_name}'"))?,
            )
        } else {
            None
        };
        let target_gid = match (group.as_deref(), target_user.as_ref()) {
            (Some(group_name), _) => Some(
                nix::unistd::Group::from_name(group_name)?
                    .with_context(|| format!("Unknown SSH group '{group_name}'"))?
                    .gid,
            ),
            (None, Some(u)) => Some(u.gid),
            (None, None) => None,
        };
        let user_details = match (target_user.as_ref(), target_gid) {
            (Some(u), Some(gid)) => {
                let groups = crate::util::owner_write::supplementary_groups(&u.name, gid)?;
                Some((u.uid, gid, groups, u.dir.clone(), u.name.clone()))
            }
            _ => None,
        };
        let netns_path = std::ffi::CString::new(format!("/var/run/netns/{}", netns.name))?;
        let mut handle = Command::new(program);
        handle.args(args);
        if crate::util::is_daemon_mode() {
            handle.env_clear();
            handle.env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        }
        if let Some((_, _, _, ref dir, ref name)) = user_details {
            handle.env("HOME", dir);
            handle.env("USER", name);
            handle.env("LOGNAME", name);
        }
        handle.process_group(0);
        unsafe {
            use std::os::unix::process::CommandExt;
            handle.pre_exec(move || {
                let ns_fd = nix::fcntl::open(
                    netns_path.as_c_str(),
                    nix::fcntl::OFlag::O_RDONLY,
                    nix::sys::stat::Mode::empty(),
                )?;
                nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)?;
                let _ = nix::unistd::close(ns_fd);
                if let Some((uid, gid, ref groups, _, _)) = user_details {
                    nix::unistd::setgroups(groups)?;
                    nix::unistd::setgid(gid)?;
                    nix::unistd::setuid(uid)?;
                }
                nix::sys::prctl::set_no_new_privs()?;
                Ok(())
            });
        }
        return Ok(handle);
    }

    let mut handle = Command::new("ip");
    handle.args(["netns", "exec", &netns.name]);
    handle.args(command);
    handle.process_group(0);
    Ok(handle)
}

fn ssh_command(
    server: &str,
    config_file: Option<&Path>,
    identity_file: Option<&Path>,
    listen_port: u16,
    endpoint: Option<&SshEndpoint>,
    ssh_user: Option<&str>,
    ssh_port: Option<u16>,
) -> anyhow::Result<Vec<String>> {
    let mut command = vec![
        "ssh".to_owned(),
        "-4".to_owned(),
        "-N".to_owned(),
        "-o".to_owned(),
        "ExitOnForwardFailure=yes".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-D".to_owned(),
        format!("127.0.0.1:{listen_port}"),
    ];
    if let Some(endpoint) = endpoint {
        command.push("-o".to_owned());
        command.push(format!("HostName={}", endpoint.address));
        command.push("-o".to_owned());
        command.push(format!("HostKeyAlias={}", endpoint.host_key_alias));
    }
    if let Some(path) = identity_file {
        command.push("-i".to_owned());
        command.push(
            path.to_str()
                .ok_or_else(|| anyhow!("SSH identity path is not valid UTF-8"))?
                .to_owned(),
        );
    }
    add_remote_options(&mut command, ssh_user, ssh_port);
    add_config_file(&mut command, config_file)?;
    command.push("--".to_owned());
    command.push(server.to_owned());
    Ok(command)
}

fn default_identity_file(user: &str) -> anyhow::Result<Option<PathBuf>> {
    let user = User::from_name(user)?
        .ok_or_else(|| anyhow!("Cannot find local user {user} for SSH authentication"))?;
    let identity = user.dir.join(".ssh/id_ed25519");
    Ok(identity.is_file().then_some(identity))
}

fn ssh_endpoint(
    server: &str,
    config_file: Option<&Path>,
    ssh_user: Option<&str>,
    ssh_port: Option<u16>,
    user: Option<&str>,
) -> anyhow::Result<SshEndpoint> {
    let mut args = vec!["ssh".to_owned(), "-G".to_owned(), "-4".to_owned()];
    add_remote_options(&mut args, ssh_user, ssh_port);
    add_config_file(&mut args, config_file)?;
    args.push("--".to_owned());
    args.push(server.to_owned());

    let mut command = if nix::unistd::geteuid().is_root()
        && let Some(user_name) = user
    {
        let target_user = User::from_name(user_name)?
            .with_context(|| format!("Unknown SSH user '{user_name}'"))?;
        let groups =
            crate::util::owner_write::supplementary_groups(&target_user.name, target_user.gid)?;
        let uid = target_user.uid;
        let gid = target_user.gid;
        let mut command = Command::new(&args[0]);
        command.args(&args[1..]);
        if crate::util::is_daemon_mode() {
            command.env_clear();
            command.env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        }
        command.env("HOME", &target_user.dir);
        command.env("USER", &target_user.name);
        command.env("LOGNAME", &target_user.name);
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(move || {
                nix::unistd::setgroups(&groups)?;
                nix::unistd::setgid(gid)?;
                nix::unistd::setuid(uid)?;
                nix::sys::prctl::set_no_new_privs()?;
                Ok(())
            });
        }
        command
    } else if let Some(user) = user {
        let mut command = Command::new("sudo");
        command.args(["--set-home", "--user", user, "--"]);
        command.args(&args);
        command
    } else {
        let mut command = Command::new(&args[0]);
        command.args(&args[1..]);
        command
    };
    let output = command
        .output()
        .context("Failed to read the effective OpenSSH configuration with `ssh -G`")?;
    if !output.status.success() {
        bail!(
            "`ssh -G` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let config = String::from_utf8(output.stdout)?;
    let hostname = effective_ssh_value(&config, "hostname")
        .ok_or_else(|| anyhow!("OpenSSH did not report an effective hostname for {server}"))?;
    let port = effective_ssh_value(&config, "port")
        .unwrap_or("22")
        .parse::<u16>()
        .context("Invalid SSH port in effective OpenSSH configuration")?;
    if effective_ssh_value(&config, "proxyjump").is_some_and(|value| value != "none") {
        bail!("ProxyJump is not supported with the SSH transparent killswitch");
    }
    if effective_ssh_value(&config, "proxycommand").is_some_and(|value| value != "none") {
        bail!("ProxyCommand is not supported with the SSH transparent killswitch");
    }

    let address = hostname_to_ip(hostname)?
        .into_iter()
        .find_map(|ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| anyhow!("SSH server {hostname} has no IPv4 address"))?;
    Ok(SshEndpoint {
        address,
        port,
        host_key_alias: hostname.to_owned(),
    })
}

fn add_remote_options(command: &mut Vec<String>, user: Option<&str>, port: Option<u16>) {
    if let Some(user) = user {
        command.extend(["-l".to_owned(), user.to_owned()]);
    }
    if let Some(port) = port {
        command.extend(["-p".to_owned(), port.to_string()]);
    }
}

fn effective_ssh_value<'a>(config: &'a str, key: &str) -> Option<&'a str> {
    config.lines().find_map(|line| {
        let (candidate, value) = line.split_once(' ')?;
        candidate.eq_ignore_ascii_case(key).then_some(value.trim())
    })
}

fn add_config_file(command: &mut Vec<String>, config_file: Option<&Path>) -> anyhow::Result<()> {
    if let Some(path) = config_file {
        command.push("-F".to_owned());
        command.push(
            path.to_str()
                .ok_or_else(|| anyhow!("SSH config path is not valid UTF-8"))?
                .to_owned(),
        );
    }
    Ok(())
}

fn redsocks_config(socks_port: u16, redirect_port: u16, dnstc_port: u16) -> String {
    format!(
        r#"base {{
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}}
redsocks {{
    local_ip = 127.0.0.1;
    local_port = {redirect_port};
    ip = 127.0.0.1;
    port = {socks_port};
    type = socks5;
}}
dnstc {{
    local_ip = 127.0.0.1;
    local_port = {dnstc_port};
}}
"#
    )
}

fn wait_for_listener(
    netns: &NetworkNamespace,
    port: u16,
    child: &mut std::process::Child,
    name: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let needle = format!(":{port}");
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let stderr = child_stderr(child);
            if stderr.is_empty() {
                bail!("{name} exited before listening on port {port}: {status}");
            }
            bail!("{name} exited before listening on port {port}: {status}: {stderr}");
        }
        let output = NetworkNamespace::exec_with_output(&netns.name, &["ss", "-ltn"])?;
        if String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.contains(&needle))
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("Timed out waiting for {name} to listen on port {port}")
}

fn child_stderr(child: &mut std::process::Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take()
        && let Err(e) = pipe.read_to_string(&mut stderr)
    {
        debug!("Failed to read child process stderr: {e}");
    }
    stderr.trim().to_owned()
}

fn setup_transparent_firewall(
    netns: &NetworkNamespace,
    firewall: Firewall,
    endpoint: (Ipv4Addr, u16),
    use_killswitch: bool,
) -> anyhow::Result<()> {
    // IPv6 cannot be carried by this IPv4 redsocks listener. Always reject it
    // instead of permitting an unproxied fallback.
    disable_ipv6(netns, firewall)?;
    match firewall {
        Firewall::IpTables => setup_iptables(netns, endpoint, use_killswitch),
        Firewall::NfTables => setup_nftables(netns, endpoint, use_killswitch),
    }
}

fn setup_iptables(
    netns: &NetworkNamespace,
    (endpoint, port): (Ipv4Addr, u16),
    use_killswitch: bool,
) -> anyhow::Result<()> {
    let endpoint = endpoint.to_string();
    let port = port.to_string();
    let redirect_port = REDSOCKS_PORT.to_string();
    let dnstc_port = DNSTC_PORT.to_string();
    for command in [
        vec!["iptables", "-t", "nat", "-N", "VOPONO_SSH"],
        vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "-j",
            "VOPONO_SSH",
        ],
        vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "VOPONO_SSH",
            "-d",
            "127.0.0.0/8",
            "-j",
            "RETURN",
        ],
        vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "VOPONO_SSH",
            "-d",
            &endpoint,
            "-p",
            "tcp",
            "--dport",
            &port,
            "-j",
            "RETURN",
        ],
        vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "VOPONO_SSH",
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &redirect_port,
        ],
        vec![
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            &dnstc_port,
        ],
    ] {
        NetworkNamespace::exec(&netns.name, &command)?;
    }
    if use_killswitch {
        for command in [
            vec!["iptables", "-P", "INPUT", "DROP"],
            vec!["iptables", "-P", "FORWARD", "DROP"],
            vec!["iptables", "-P", "OUTPUT", "DROP"],
            vec![
                "iptables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
            vec!["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            vec!["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            vec![
                "iptables", "-A", "OUTPUT", "-d", &endpoint, "-p", "tcp", "--dport", &port, "-j",
                "ACCEPT",
            ],
            vec!["iptables", "-A", "OUTPUT", "-j", "REJECT"],
        ] {
            NetworkNamespace::exec(&netns.name, &command)?;
        }
    }
    Ok(())
}

fn setup_nftables(
    netns: &NetworkNamespace,
    (endpoint, port): (Ipv4Addr, u16),
    use_killswitch: bool,
) -> anyhow::Result<()> {
    let endpoint = endpoint.to_string();
    let port = port.to_string();
    let redirect_port = format!(":{REDSOCKS_PORT}");
    let dnstc_port = format!(":{DNSTC_PORT}");
    for command in [
        vec!["nft", "add", "table", "inet", "vopono_ssh"],
        vec![
            "nft",
            "add",
            "chain",
            "inet",
            "vopono_ssh",
            "output_nat",
            "{ type nat hook output priority dstnat; policy accept; }",
        ],
        vec![
            "nft",
            "add",
            "rule",
            "inet",
            "vopono_ssh",
            "output_nat",
            "ip",
            "daddr",
            "127.0.0.0/8",
            "return",
        ],
        vec![
            "nft",
            "add",
            "rule",
            "inet",
            "vopono_ssh",
            "output_nat",
            "ip",
            "daddr",
            &endpoint,
            "tcp",
            "dport",
            &port,
            "return",
        ],
        vec![
            "nft",
            "add",
            "rule",
            "inet",
            "vopono_ssh",
            "output_nat",
            "meta",
            "nfproto",
            "ipv4",
            "meta",
            "l4proto",
            "tcp",
            "redirect",
            "to",
            &redirect_port,
        ],
        vec![
            "nft",
            "add",
            "rule",
            "inet",
            "vopono_ssh",
            "output_nat",
            "meta",
            "nfproto",
            "ipv4",
            "udp",
            "dport",
            "53",
            "redirect",
            "to",
            &dnstc_port,
        ],
    ] {
        NetworkNamespace::exec(&netns.name, &command)?;
    }
    if use_killswitch {
        // Place filter rules in the namespace's standard `inet <netns>` table so
        // `--open-hosts`, `--allow-host-access`, and `--open-ports` rules inserted
        // into that table are honored rather than dropped by a separate base chain.
        for command in [
            vec![
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
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "input",
                "iifname",
                "lo",
                "counter",
                "accept",
            ],
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "input",
                "counter",
                "drop",
            ],
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "forward",
                "counter",
                "drop",
            ],
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "output",
                "oifname",
                "lo",
                "counter",
                "accept",
            ],
            vec![
                "nft",
                "add",
                "rule",
                "inet",
                &netns.name,
                "output",
                "ip",
                "daddr",
                &endpoint,
                "tcp",
                "dport",
                &port,
                "counter",
                "accept",
            ],
            vec![
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
        ] {
            NetworkNamespace::exec(&netns.name, &command)?;
        }
    }
    Ok(())
}

fn kill_process_group(pid: u32, name: &str) {
    let raw = nix::unistd::Pid::from_raw(pid as i32);
    match nix::sys::signal::killpg(raw, nix::sys::signal::Signal::SIGKILL) {
        Ok(_) => debug!("Killed {name} (process group: {pid})"),
        Err(nix::errno::Errno::ESRCH) => {}
        Err(e) => error!("Failed to kill {name} (process group: {pid}): {e:?}"),
    }
    while matches!(
        nix::sys::wait::waitpid(raw, None),
        Err(nix::errno::Errno::EINTR)
    ) {}
}

fn kill_process_group_in_ns(pid: u32, ns_name: Option<&str>, name: &str) {
    let pid_matches = ns_name
        .is_none_or(|ns| crate::util::process_is_in_network_namespace(pid, ns).unwrap_or(false));
    if pid_matches {
        kill_process_group(pid, name);
    } else {
        debug!("Skipping {name} kill for pid {pid}: no longer in target namespace");
        let raw = nix::unistd::Pid::from_raw(pid as i32);
        while matches!(
            nix::sys::wait::waitpid(raw, None),
            Err(nix::errno::Errno::EINTR)
        ) {}
    }
}

impl Drop for SshProxy {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        kill_process_group_in_ns(self.redsocks_pid, self.ns_name.as_deref(), "redsocks");
        kill_process_group_in_ns(self.ssh_pid, self.ns_name.as_deref(), "SSH proxy");
        if let Some(runtime) = &self.runtime_dir {
            let _ = std::fs::remove_dir_all(runtime);
        }
    }
}

impl SshProxy {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_ssh_value, redsocks_config, ssh_command};
    use std::path::Path;

    #[test]
    fn builds_dynamic_forward_command() {
        assert_eq!(
            ssh_command("proxy.example.com", None, None, 1080, None, None, None).unwrap(),
            [
                "ssh",
                "-4",
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "BatchMode=yes",
                "-D",
                "127.0.0.1:1080",
                "--",
                "proxy.example.com",
            ]
        );
    }

    #[test]
    fn supports_openssh_config_file() {
        let args = ssh_command(
            "work-proxy",
            Some(Path::new("/tmp/ssh_config")),
            None,
            9080,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(&args[9..], ["-F", "/tmp/ssh_config", "--", "work-proxy"]);
    }

    #[test]
    fn supports_explicit_identity_file() {
        let args = ssh_command(
            "proxy.example.com",
            None,
            Some(Path::new("/home/alice/.ssh/id_ed25519")),
            1080,
            None,
            Some("gopostal"),
            Some(2222),
        )
        .unwrap();
        assert_eq!(
            &args[9..],
            [
                "-i",
                "/home/alice/.ssh/id_ed25519",
                "-l",
                "gopostal",
                "-p",
                "2222",
                "--",
                "proxy.example.com"
            ]
        );
    }

    #[test]
    fn reads_effective_ssh_configuration() {
        let config = "hostname proxy.example.com\nuser alice\nport 2222\nproxyjump none\n";
        assert_eq!(
            effective_ssh_value(config, "hostname"),
            Some("proxy.example.com")
        );
        assert_eq!(effective_ssh_value(config, "port"), Some("2222"));
    }

    #[test]
    fn configures_socks_and_dns_tcp_fallback() {
        let config = redsocks_config(1080, 12345, 12346);
        assert!(config.contains("port = 1080;"));
        assert!(config.contains("local_port = 12345;"));
        assert!(config.contains("local_port = 12346;"));
    }
}
