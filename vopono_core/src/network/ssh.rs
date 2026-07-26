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
    ssh_pid: u32,
    redsocks_pid: u32,
    pub listen_port: u16,
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
        let mut ssh = command_in_namespace(netns, &ssh_command, user, group);
        ssh.stderr(Stdio::piped());
        let mut ssh = ssh.spawn().context("Failed to launch SSH dynamic proxy")?;
        let ssh_pid = ssh.id();

        if let Err(e) = wait_for_listener(netns, listen_port, &mut ssh, "SSH proxy") {
            kill_process_group(ssh_pid, "SSH proxy");
            return Err(e);
        }

        let mut config = tempfile::NamedTempFile::new()
            .context("Failed to create temporary redsocks configuration")?;
        write!(
            config,
            "{}",
            redsocks_config(listen_port, REDSOCKS_PORT, DNSTC_PORT)
        )?;
        config.flush()?;

        let redsocks_command = vec![
            "redsocks".to_owned(),
            "-c".to_owned(),
            config.path().to_string_lossy().into_owned(),
        ];
        info!("Launching redsocks transparent TCP proxy");
        let mut redsocks = command_in_namespace(netns, &redsocks_command, None, None);
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
        })
    }
}

fn command_in_namespace(
    netns: &NetworkNamespace,
    command: &[String],
    user: Option<String>,
    group: Option<String>,
) -> Command {
    let mut handle = Command::new("ip");
    handle.args(["netns", "exec", &netns.name]);
    if user.is_some() || group.is_some() {
        handle.args(["sudo", "--preserve-env"]);
        if let Some(user) = user {
            handle.args(["--set-home", "--user", &user]);
        }
        if let Some(group) = group {
            handle.args(["--group", &group]);
        }
    }
    handle.args(command);
    handle.process_group(0);
    handle
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
    args.push(server.to_owned());

    let mut command = if let Some(user) = user {
        let mut command = Command::new("sudo");
        command.args(["--preserve-env", "--set-home", "--user", user]);
        command
    } else {
        Command::new(&args[0])
    };
    if user.is_some() {
        command.args(&args);
    } else {
        command.args(&args[1..]);
    }
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
        NetworkNamespace::exec(
            &netns.name,
            &[
                "nft",
                "add",
                "chain",
                "inet",
                "vopono_ssh",
                "output_filter",
                "{ type filter hook output priority filter; policy drop; }",
            ],
        )?;
        NetworkNamespace::exec(
            &netns.name,
            &[
                "nft",
                "add",
                "rule",
                "inet",
                "vopono_ssh",
                "output_filter",
                "oifname",
                "lo",
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
                "vopono_ssh",
                "output_filter",
                "ip",
                "daddr",
                &endpoint,
                "tcp",
                "dport",
                &port,
                "accept",
            ],
        )?;
    }
    Ok(())
}

fn kill_process_group(pid: u32, name: &str) {
    match nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    ) {
        Ok(_) => debug!("Killed {name} (process group: {pid})"),
        Err(e) => error!("Failed to kill {name} (process group: {pid}): {e:?}"),
    }
}

impl Drop for SshProxy {
    fn drop(&mut self) {
        kill_process_group(self.redsocks_pid, "redsocks");
        kill_process_group(self.ssh_pid, "SSH proxy");
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
        assert_eq!(&args[9..], ["-F", "/tmp/ssh_config", "work-proxy"]);
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
