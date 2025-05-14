use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use log::debug;

use super::{netns::NetworkNamespace, port_forwarding::Forwarder};
use crate::util::{env_vars::set_env_vars, get_all_running_process_names, parse_command_str};

pub struct ApplicationWrapper {
    pub handle: std::process::Child,
    pub port_forwarding: Option<Box<dyn Forwarder>>,
}

impl ApplicationWrapper {
    pub fn new(
        netns: &NetworkNamespace,
        application: &str,
        user: Option<String>,
        group: Option<String>,
        working_directory: Option<PathBuf>,
        port_forwarding: Option<Box<dyn Forwarder>>,
        silent: bool,
    ) -> anyhow::Result<Self> {
        let running_processes = get_all_running_process_names();
        let app_vec = parse_command_str(application)?;

        for shared_process_app in [
            "google-chrome-stable",
            "google-chrome-beta",
            "google-chrome",
            "chromium",
            "firefox",
            "firefox-developer-edition",
        ]
        .iter()
        {
            // TODO: Avoid String allocation here
            if app_vec.contains(&shared_process_app.to_string())
                && running_processes.contains(&shared_process_app.to_string())
            {
                log::error!(
                    "{shared_process_app} is already running. You must force it to use a separate profile in order to launch a new process!"
                );
            }
        }

        let app_vec_ptrs: Vec<&str> = app_vec.iter().map(|s| s.as_str()).collect();

        let handle = Self::run_with_env_in_netns(
            netns,
            app_vec_ptrs.as_slice(),
            user,
            group,
            silent,
            false,
            false,
            working_directory,
            port_forwarding.as_deref(),
        )?;
        Ok(Self {
            handle,
            port_forwarding,
        })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_with_env_in_netns(
        netns: &NetworkNamespace,
        command: &[&str],
        user: Option<String>,
        group: Option<String>,
        silent: bool,
        capture_output: bool,
        capture_input: bool,
        set_dir: Option<PathBuf>,
        forwarder: Option<&dyn Forwarder>,
    ) -> anyhow::Result<std::process::Child> {
        let mut handle = Command::new("ip");
        set_env_vars(netns, forwarder, &mut handle);
        handle.args(["netns", "exec", netns.name.as_str()]);
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
            netns.name,
            sudo_string.unwrap_or_else(|| String::from("")),
            command.join(" ")
        );
        let handle = handle.args(command).spawn()?;
        Ok(handle)
    }
}
