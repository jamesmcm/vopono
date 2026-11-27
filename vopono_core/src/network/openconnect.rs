use crate::config::providers::{Password, UiClient};

use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

fn read_config_as_owner(config_file: &std::path::Path) -> anyhow::Result<String> {
    let bytes = crate::util::owner_write::read_file_as_config_owner(config_file)
        .with_context(|| format!("Failed to read {}", config_file.display()))?;
    String::from_utf8(bytes).with_context(|| {
        format!(
            "OpenConnect config {} is not valid UTF-8",
            config_file.display()
        )
    })
}

fn validate_unprivileged_config_str(contents: &str) -> anyhow::Result<()> {
    const PRIVILEGED_DIRECTIVES: &[&str] = &[
        "script",
        "script-tun",
        "csd-wrapper",
        "csd-user",
        "setuid",
        "external-browser",
        "pid-file",
        "cafile",
        "certificate",
        "sslkey",
        "mca-certificate",
        "mca-key",
        "token-secret",
        "key-password-from-fsid",
        "config",
        "xmlconfig",
        "background",
    ];
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split_once(|c: char| c == '=' || c == ':' || c.is_whitespace())
            .map_or(line, |(key, _)| key)
            .trim();
        anyhow::ensure!(
            !PRIVILEGED_DIRECTIVES.contains(&key),
            "OpenConnect directive '{key}' is not allowed in daemon mode (line {})",
            line_number + 1
        );
    }
    Ok(())
}

#[cfg(test)]
fn validate_unprivileged_config(config_file: &std::path::Path) -> anyhow::Result<()> {
    validate_unprivileged_config_str(&read_config_as_owner(config_file)?)
}

fn append_csd_user<'a>(
    command: &mut Vec<&'a str>,
    daemon_mode: bool,
    session_user: Option<&'a str>,
) -> anyhow::Result<()> {
    if daemon_mode {
        let session_user =
            session_user.context("Daemon OpenConnect session has no authenticated user")?;
        command.extend(["--csd-user", session_user]);
    }
    Ok(())
}

pub fn server_from_config(config_file: &std::path::Path) -> anyhow::Result<String> {
    let contents = read_config_as_owner(config_file)?;
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let (option, value) =
                line.split_once(|c: char| c == '=' || c == ':' || c.is_whitespace())?;
            let trimmed = value.trim_start();
            let value = trimmed
                .strip_prefix('=')
                .or_else(|| trimmed.strip_prefix(':'))
                .unwrap_or(trimmed)
                .trim();
            (option.trim() == "server" && !value.is_empty()).then(|| value.to_string())
        })
        .ok_or_else(|| anyhow!("OpenConnect config has no server option"))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenConnect {
    pub(crate) pid: u32,
    #[serde(default)]
    runtime_dir: Option<PathBuf>,
    #[serde(default)]
    ns_name: Option<String>,
    #[serde(skip)]
    cleanup_enabled: bool,
}

impl OpenConnect {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        server: &str,
        uiclient: &dyn UiClient,
    ) -> anyhow::Result<Self> {
        if let Err(x) = which::which("openconnect") {
            error!("OpenConnect not found. Is OpenConnect installed and on PATH?");
            return Err(anyhow!(
                "OpenConnect not found. Is OpenConnect installed and on PATH?: {:?}",
                x
            ));
        }

        let contents = read_config_as_owner(&config_file)?;
        if crate::util::is_daemon_mode() {
            validate_unprivileged_config_str(&contents)?;
            anyhow::bail!(
                "Interactive OpenConnect password prompts are not supported in daemon mode"
            );
        }

        let password =
            request_creds(uiclient).context("Failed to read OpenConnect password from stdin")?;

        let runtime_dir = super::etc_overlay::trusted_runtime_dir("openconnect-")?;
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

        info!("Launching OpenConnect...");
        let mut command_vec = [
            "openconnect",
            "--config",
            frozen_config
                .to_str()
                .context("Invalid frozen OpenConnect config path")?,
            "--passwd-on-stdin",
        ]
        .to_vec();

        // A VPN server may provide a CSD/host-scan program. OpenConnect runs
        // it with its own privileges unless --csd-user is set, which would
        // turn a client-selected server into root code execution in daemon
        // mode. The session identity is authenticated by the daemon.
        append_csd_user(
            &mut command_vec,
            crate::util::is_daemon_mode(),
            netns.predown_user.as_deref(),
        )?;

        if !server.is_empty() {
            anyhow::ensure!(
                !server.starts_with('-'),
                "OpenConnect server must not start with '-'"
            );
            command_vec.push("--");
            command_vec.push(server);
        }

        let mut handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &command_vec,
            None,
            None,
            false,
            false,
            true,
            None,
        )
        .context("Failed to launch OpenConnect - is openconnect installed?")?;

        let id = handle.id();
        let setup_result = (|| -> anyhow::Result<()> {
            handle
                .stdin
                .as_ref()
                .context("OpenConnect stdin was not piped")?
                .write_all(password.as_bytes())
                .context("Failed to write OpenConnect password to stdin")?;

            // Allow input to and output from open ports (for port forwarding in tunnel)
            if let Some(opens) = open_ports {
                crate::util::open_ports(netns, opens.as_slice(), firewall)?;
            }

            // Allow input to and output from forwarded ports
            if let Some(forwards) = forward_ports {
                crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
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

fn request_creds(uiclient: &dyn UiClient) -> anyhow::Result<String> {
    let password = uiclient.get_password(Password {
        prompt: "OpenConnect password".to_string(),
        confirm: true,
    })?;
    let password = password.trim();
    Ok(password.to_string())
}

/// Apply the fail-closed tunnel-only killswitch for OpenConnect.
///
/// openconnect does not implement a killswitch itself, so once the tunnel is
/// up all input/output in the namespace is dropped except loopback, the
/// tunnel interface, return traffic and the resolved VPN server endpoints
/// (the client needs those to keep its session alive). Without this policy
/// the namespace keeps a working default route through the host veth/NAT
/// path, so any tunnel failure silently bypasses the VPN.
///
/// The server is taken from `server` when non-empty, otherwise derived from
/// the config file.
pub fn apply_killswitch(
    netns: &NetworkNamespace,
    firewall: Firewall,
    disable_ipv6: bool,
    server: &str,
    config_file: Option<&Path>,
) -> anyhow::Result<()> {
    let server = if server.is_empty() {
        server_from_config(config_file.context("No OpenConnect config file provided")?)?
    } else {
        server.to_string()
    };
    let uses_setuid = !crate::util::is_daemon_mode()
        && config_file
            .and_then(|path| read_config_as_owner(path).ok())
            .is_some_and(|contents| {
                contents.lines().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#')
                        && trimmed
                            .split(|c: char| c.is_whitespace() || c == '=')
                            .next()
                            .is_some_and(|key| key.trim_start_matches("--") == "setuid")
                })
            });
    super::firewall::apply_tunnel_only_killswitch_for_server_with_uid_filter(
        netns,
        firewall,
        disable_ipv6,
        &server,
        &["tun"],
        !uses_setuid,
    )
}

impl Drop for OpenConnect {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let pid = nix::unistd::Pid::from_raw(self.pid as i32);
        let pid_matches = self.ns_name.as_deref().is_none_or(|ns| {
            crate::util::process_is_in_network_namespace(self.pid, ns).unwrap_or(false)
        });
        if pid_matches {
            match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL) {
                Ok(_) => debug!("Killed OpenConnect (pid: {})", self.pid),
                Err(e) => error!("Failed to kill OpenConnect (pid: {}): {:?}", self.pid, e),
            }
        } else {
            debug!(
                "Skipping OpenConnect kill for pid {}: no longer in target namespace",
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

impl OpenConnect {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::{append_csd_user, server_from_config, validate_unprivileged_config};
    use std::io::Write;

    #[test]
    fn reads_server_from_config() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "# comment\nserver = https://vpn.example.com:443/path"
        )
        .unwrap();
        assert_eq!(
            server_from_config(config.path()).unwrap(),
            "https://vpn.example.com:443/path"
        );
    }

    #[test]
    fn reads_server_with_query_equals_and_colon_delimiter() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(config, "server https://vpn.example.com/path?a=b").unwrap();
        assert_eq!(
            server_from_config(config.path()).unwrap(),
            "https://vpn.example.com/path?a=b"
        );
        let mut colon = tempfile::NamedTempFile::new().unwrap();
        writeln!(colon, "server: https://vpn.example.com:443/path").unwrap();
        assert_eq!(
            server_from_config(colon.path()).unwrap(),
            "https://vpn.example.com:443/path"
        );
    }

    #[test]
    fn daemon_config_rejects_privileged_directives() {
        for directive in [
            "script",
            "script-tun",
            "csd-wrapper",
            "csd-user",
            "setuid",
            "external-browser",
            "pid-file",
            "cafile",
            "certificate",
            "sslkey",
            "mca-certificate",
            "mca-key",
            "token-secret",
            "key-password-from-fsid",
            "config",
            "xmlconfig",
            "background",
        ] {
            for line in [
                format!("{directive}=/tmp/evil"),
                format!("{directive}:/tmp/evil"),
                format!("{directive} /bin/sh -c \"x=1\""),
            ] {
                let mut config = tempfile::NamedTempFile::new().unwrap();
                writeln!(config, "server=vpn.example.com\n{line}").unwrap();
                let error = validate_unprivileged_config(config.path())
                    .unwrap_err()
                    .to_string();
                assert!(error.contains(directive), "expected {directive} in {error}");
            }
        }
    }

    #[test]
    fn daemon_config_accepts_connection_directives() {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config,
            "server vpn.example.com\nprotocol=anyconnect\n# script=/tmp/ignored"
        )
        .unwrap();
        validate_unprivileged_config(config.path()).unwrap();
    }

    #[test]
    fn daemon_forces_csd_to_authenticated_user() {
        let mut command = vec!["openconnect"];
        append_csd_user(&mut command, true, Some("alice")).unwrap();
        assert_eq!(command, ["openconnect", "--csd-user", "alice"]);
        assert!(append_csd_user(&mut command, true, None).is_err());
    }
}
