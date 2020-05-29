mod args;
mod iptables;
mod netns;
mod network_interface;
mod sysctl;
mod vpn;

use anyhow::{anyhow, Context};
use args::ExecCommand;
use iptables::IpTables;
use log::{debug, error, LevelFilter};
use netns::NetworkNamespace;
use network_interface::NetworkInterface;
use regex::Regex;
use std::io::{self, Write};
use std::process::Command;
use structopt::StructOpt;
use sysctl::SysCtl;
use vpn::{find_host_from_alias, get_auth, get_serverlist};

// TODO:
// - Ability to run multiple network namespace (handle IP address allocation)
// - Lockfile to share existing network namespaces (lookup on ID)
// - Handle running process as current user or root (make current user default)
// - Allow custom VPNs (provide .ovpn file?)

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
    get_auth(&provider)?;

    let serverlist = get_serverlist(&provider)?;
    let (server, port, server_alias) = find_host_from_alias(&server, &serverlist)?;
    // if protocol == OpenVPN
    let ns_name = format!("{}_{}", provider.alias(), server_alias);
    let mut ns;
    // Better to check for lockfile exists?
    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        ns = NetworkNamespace::from_existing(ns_name.clone())?;
    } else {
        ns = NetworkNamespace::new(ns_name.clone())?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;
        let target_subnet = get_target_subnet()?;
        ns.add_routing(target_subnet)?;
        let interface = NetworkInterface::Ethernet; //TODO
        let _iptables =
            IpTables::add_masquerade_rule(format!("10.200.{}.0/24", target_subnet), interface);
        let _sysctl = SysCtl::enable_ipv4_forwarding();
        ns.dns_config()?;
        ns.run_openvpn(&provider, &server, port)?;
    }
    ns.write_lockfile()?;

    debug!(
        "Checking that OpenVPN is running in namespace: {}",
        &ns_name
    );
    if !ns.check_openvpn_running()? {
        error!(
            "OpenVPN not running in network namespace {}, probable dead lock file or authentication error",
            &ns_name
        );
        return Err(anyhow!(
            "OpenVPN not running in network namespace, probable dead lock file authentication error"
        ));
    }
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

    pub fn check_if_running(&mut self) -> anyhow::Result<bool> {
        let output = self.handle.try_wait()?;

        Ok(output.is_none())
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

fn get_target_subnet() -> anyhow::Result<u8> {
    // TODO clean this up
    let assigned_ips = get_allocated_ip_addresses()?;
    let mut target_ip = 1;
    loop {
        let ip = format!("10.200.{}.1/24", target_ip);
        if assigned_ips.contains(&ip) {
            target_ip += 1;
        } else {
            return Ok(target_ip);
        }
    }
}

// TODO: Create struct for holding IPv4 addresses and use FromStr and Eq with that
fn get_allocated_ip_addresses() -> anyhow::Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(&["ip", "addr", "show", "type", "veth"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?;
    debug!("Existing interfaces: {}", output);

    let re = Regex::new(r"inet\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(output) {
        ips.push(String::from(&caps["ip"]));
    }
    debug!("Assigned IPs: {:?}", &ips);
    Ok(ips)
}

fn get_existing_namespaces() -> anyhow::Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(&["ip", "netns", "list"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?
        .split("\n")
        .into_iter()
        .map(|x| x.split_whitespace().nth(0))
        .filter(|x| x.is_some())
        .map(|x| String::from(x.unwrap()))
        .collect();
    debug!("Existing namespaces: {:?}", output);

    Ok(output)
}

fn check_process_running(pid: u32) -> anyhow::Result<bool> {
    let output = Command::new("ps")
        .args(&["-p", &pid.to_string(), "-o", "pid:1", "--no-headers"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?.split("\n").into_iter().next();
    debug!("pid: {}, output: {:?}", pid, &output);
    if let Some(x) = output {
        Ok(x.trim() == pid.to_string())
    } else {
        Ok(false)
    }
}
