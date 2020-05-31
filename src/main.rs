mod application_wrapper;
mod args;
mod dns_config;
mod iptables;
mod netns;
mod network_interface;
mod openvpn;
mod sysctl;
mod util;
mod veth_pair;
mod vpn;
mod wireguard;

use anyhow::anyhow;
use application_wrapper::ApplicationWrapper;
use args::ExecCommand;
use iptables::IpTables;
use log::{debug, error, LevelFilter};
use netns::NetworkNamespace;
use network_interface::NetworkInterface;
use std::io::{self, Write};
use structopt::StructOpt;
use sysctl::SysCtl;
use util::{clean_dead_locks, get_existing_namespaces, get_target_subnet};
use vpn::{find_host_from_alias, get_auth, get_protocol, get_serverlist, Protocol};
use wireguard::{get_config_from_alias, Wireguard};

// TODO:
// - Add configuration for wireless interface for OpenVPN
// - Parse OpenVPN stdout (can we buffer?)
// - Allow OpenVPN UDP (1194) and TCP (443) toggle
// - Add Mullvad Wireguard
// - Add DNS server support for OpenVPN (parse for Mullvad)
// - Always run as root (use sudo self on startup)
// - Allow custom VPNs (provide .ovpn file?)
// - Mullvad Shadowsocks

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

    clean_dead_locks()?;
    match app.cmd {
        args::Command::Create(cmd) => exec(cmd)?,
        args::Command::SetDefaults(cmd) => todo!(),
    }
    Ok(())
}

fn exec(command: ExecCommand) -> anyhow::Result<()> {
    // TODO: Handle when we must elevate privileges
    // TODO: Handle running as current user vs. root
    // Get server and provider (handle default case)
    let provider = command.vpn_provider.unwrap();
    let server = command.server.unwrap();
    get_auth(&provider)?;

    let serverlist = get_serverlist(&provider)?;
    let (server, port, server_alias) = find_host_from_alias(&server, &serverlist)?;
    let protocol = get_protocol(&provider, command.protocol)?;
    let ns_name = format!("{}_{}", provider.alias(), server_alias);
    let mut ns;
    // Better to check for lockfile exists?
    let _iptables;
    let _sysctl;
    let target_subnet;
    let interface;

    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        ns = NetworkNamespace::from_existing(ns_name.clone())?;
    } else {
        ns = NetworkNamespace::new(ns_name.clone())?;
        match protocol {
            Protocol::OpenVpn => {
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                target_subnet = get_target_subnet()?;
                ns.add_routing(target_subnet)?;
                interface = NetworkInterface::Ethernet; //TODO
                _iptables = IpTables::add_masquerade_rule(
                    format!("10.200.{}.0/24", target_subnet),
                    interface,
                );
                _sysctl = SysCtl::enable_ipv4_forwarding();
                ns.dns_config()?;
                ns.run_openvpn(&provider, &server, port)?;
            }
            Protocol::Wireguard => {
                let config = get_config_from_alias(&provider, &server)?;
                ns.
            }
        }
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
