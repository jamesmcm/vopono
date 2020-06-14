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
use network_interface::{get_active_interfaces, NetworkInterface};
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
    let server_name = command.server.unwrap();

    let protocol = get_protocol(&provider, command.protocol)?;

    let serverlist = get_serverlist(&provider)?;
    let server;
    let port;
    let ns_name;
    let server_alias;

    match protocol {
        Protocol::OpenVpn => {
            let x = find_host_from_alias(&server_name, &serverlist)?;
            server = x.0;
            port = x.1;
            server_alias = x.2;
            // (server, port, server_alias) = find_host_from_alias(&server, &serverlist)?;
            ns_name = format!("{}_{}", provider.alias(), server_alias);
        }
        Protocol::Wireguard => {
            server = String::new();
            port = 0;
            server_alias = String::new();
            ns_name = format!("{}_{}", provider.alias(), server_name);
        }
    }
    let mut ns;
    let _iptables;
    let _sysctl;
    let target_subnet;
    let interface: NetworkInterface = match command.interface {
        Some(x) => anyhow::Result::<NetworkInterface>::Ok(x),
        None => Ok(NetworkInterface::new(
            get_active_interfaces()?
                .into_iter()
                .nth(0)
                .ok_or_else(|| anyhow!("No active interface"))?,
        )?),
    }?;

    debug!("Interface: {}", &interface.name);
    // Better to check for lockfile exists?
    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        ns = NetworkNamespace::from_existing(ns_name.clone())?;
    } else {
        ns = NetworkNamespace::new(ns_name.clone())?;
        match protocol {
            Protocol::OpenVpn => {
                get_auth(&provider)?;
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                target_subnet = get_target_subnet()?;
                ns.add_routing(target_subnet)?;
                _iptables = IpTables::add_masquerade_rule(
                    format!("10.200.{}.0/24", target_subnet),
                    interface,
                );
                _sysctl = SysCtl::enable_ipv4_forwarding();
                // TODO: Handle custom DNS
                ns.dns_config(None)?;
                ns.run_openvpn(&provider, &server, port)?;
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
            }
            Protocol::Wireguard => {
                let config = get_config_from_alias(&provider, &server_name)?;
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                target_subnet = get_target_subnet()?;
                ns.add_routing(target_subnet)?;
                _iptables = IpTables::add_masquerade_rule(
                    format!("10.200.{}.0/24", target_subnet),
                    interface,
                );
                _sysctl = SysCtl::enable_ipv4_forwarding();
                ns.run_wireguard(config)?;
            }
        }
    }

    ns.write_lockfile()?;
    let application = ApplicationWrapper::new(&ns, &command.application)?;
    let output = application.wait_with_output()?;
    io::stdout().write_all(output.stdout.as_slice())?;

    Ok(())
}
