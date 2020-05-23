mod args;
mod iptables;
mod netns;
mod network_interface;
mod sysctl;
mod vpn;

use anyhow::{anyhow, Context};
use args::{ExecCommand, SetDefaultsCommand};
use iptables::IpTables;
use log::{debug, error, info, log_enabled, Level, LevelFilter};
use netns::NetworkNamespace;
use network_interface::NetworkInterface;
use std::io::{self, Write};
use std::process::Command;
use structopt::StructOpt;
use sysctl::SysCtl;

// TODO: Allow listing of open network namespaces, applications currently running in network
// namespaces
fn main() -> anyhow::Result<()> {
    // Get struct of args using structopt
    let app = args::App::from_args();

    // Set up logging
    let mut builder = pretty_env_logger::formatted_timed_builder();
    let log_level = if app.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter_level(log_level);
    builder.init();

    match app.cmd {
        args::Command::Create(cmd) => exec(cmd)?,
        args::Command::SetDefaults(cmd) => todo!(),
    }
    Ok(())
}

fn exec(command: ExecCommand) -> anyhow::Result<()> {
    // TODO: Handle when we must elevate privileges
    // TODO: Handle lock file
    // TODO: Handle running as current user vs. root
    // Get server and provider (handle default case)
    let provider = command.vpn_provider.unwrap();
    let server = command.server.unwrap();
    // if protocol == OpenVPN
    let ns_name = format!("{}_{}", provider.alias(), server.to_string());
    let mut ns = NetworkNamespace::new(ns_name)?;
    ns.add_loopback()?;
    ns.add_veth_pair()?;
    ns.add_routing()?;
    let interface = NetworkInterface::Ethernet; //TODO
    let iptables = IpTables::add_masquerade_rule(String::from("10.200.200.0/24"), interface);
    let sysctl = SysCtl::enable_ipv4_forwarding();
    ns.dns_config()?;
    ns.run_openvpn(&provider)?;
    let application = ApplicationWrapper::new(&ns, &command.application)?;
    let output = application.wait_with_output()?;
    io::stdout().write_all(output.stdout.as_slice())?;

    Ok(())
}

struct ApplicationWrapper {
    handle: std::process::Child,
}

impl ApplicationWrapper {
    pub fn new(netns: &NetworkNamespace, application: &str) -> anyhow::Result<Self> {
        let handle = netns.exec_no_block(
            application
                .split_whitespace()
                .collect::<Vec<_>>()
                .as_slice(),
        )?;
        Ok(Self { handle })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }
}

// impl Drop for ApplicationWrapper {
//     fn drop(&mut self) {
//         self.handle.kill().expect("Could not kill application");
//     }
// }

pub fn sudo_command(command: &[&str]) -> anyhow::Result<()> {
    debug!("sudo {}", command.join(" "));
    let exit_status = Command::new("sudo")
        .args(command)
        .status()
        .with_context(|| format!("Failed to run command: sudo {}", command.join(" ")))?;

    if exit_status.success() {
        Ok(())
    } else {
        Err(anyhow!("Command failed: sudo {}", command.join(" ")))
    }
}
