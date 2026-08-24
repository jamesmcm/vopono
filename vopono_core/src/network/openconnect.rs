use crate::config::providers::{Password, UiClient};

use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

fn validate_unprivileged_config(config_file: &std::path::Path) -> anyhow::Result<()> {
    const PRIVILEGED_DIRECTIVES: &[&str] = &[
        "script",
        "script-tun",
        "csd-wrapper",
        "external-browser",
        "pid-file",
    ];
    let contents = std::fs::read_to_string(config_file)
        .with_context(|| format!("Failed to read {}", config_file.display()))?;
    for (line_number, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split_once('=')
            .or_else(|| line.split_once(char::is_whitespace))
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
    let contents = std::fs::read_to_string(config_file)
        .with_context(|| format!("Failed to read {}", config_file.display()))?;
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let (option, value) = line
                .split_once('=')
                .or_else(|| line.split_once(char::is_whitespace))?;
            (option.trim() == "server")
                .then(|| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow!("OpenConnect config has no server option"))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenConnect {
    pid: u32,
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

        if crate::util::is_daemon_mode() {
            validate_unprivileged_config(&config_file)?;
        }

        let pass = request_creds(uiclient);

        let password = pass.expect("Provide password via Stdin!");

        info!("Launching OpenConnect...");
        let mut command_vec = [
            "openconnect",
            "--config",
            config_file.to_str().expect("Invalid config path"),
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
            command_vec.push(server.as_ref());
        }

        let handle = NetworkNamespace::exec_no_block(
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

        handle
            .stdin
            .as_ref()
            .unwrap()
            .write_all(password.as_bytes())
            .expect("Failed to write to stdin");

        let id = handle.id();

        // Allow input to and output from open ports (for port forwarding in tunnel)
        if let Some(opens) = open_ports {
            crate::util::open_ports(netns, opens.as_slice(), firewall)?;
        }

        // Allow input to and output from forwarded ports
        if let Some(forwards) = forward_ports {
            crate::util::open_ports(netns, forwards.as_slice(), firewall)?;
        }

        Ok(Self { pid: id })
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

impl Drop for OpenConnect {
    fn drop(&mut self) {
        match nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(_) => debug!("Killed OpenConnect (pid: {})", self.pid),
            Err(e) => error!("Failed to kill OpenConnect (pid: {}): {:?}", self.pid, e),
        }
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
    fn daemon_config_rejects_privileged_directives() {
        for directive in [
            "script",
            "script-tun",
            "csd-wrapper",
            "external-browser",
            "pid-file",
        ] {
            let mut config = tempfile::NamedTempFile::new().unwrap();
            writeln!(config, "server=vpn.example.com\n{directive}=/tmp/evil").unwrap();
            let error = validate_unprivileged_config(config.path())
                .unwrap_err()
                .to_string();
            assert!(error.contains(directive));
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
