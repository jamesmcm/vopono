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

use anyhow::{anyhow, bail};
use application_wrapper::ApplicationWrapper;
use args::ExecCommand;
use log::{debug, error, info, warn, LevelFilter};
use netns::NetworkNamespace;
use network_interface::{get_active_interfaces, NetworkInterface};
use std::io::{self, Write};
use std::process::Command;
use structopt::StructOpt;
use sysctl::SysCtl;
use util::{clean_dead_locks, get_existing_namespaces, get_target_subnet, init_config};
use vpn::VpnProvider;
use vpn::{find_host_from_alias, get_auth, get_protocol, get_serverlist, Protocol};
use wireguard::get_config_from_alias;

// TODO:
// - Test configuration for wireless interface for OpenVPN
// - Parse OpenVPN stdout to check when ready
// - Allow OpenVPN UDP (1194) and TCP (443) toggle
// - Allow custom VPNs (provide .ovpn file?)
// - Allow for not saving OpenVPN creds to config
// - Allow for choice between iptables and nftables and avoid mixed dependency
// - Mullvad Shadowsocks
// - Handle setting and using default provider and server

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

    init_config()?;
    clean_dead_locks()?;

    match app.cmd {
        args::Command::Create(cmd) => {
            // Check if already running as root
            if nix::unistd::getuid().as_raw() != 0 {
                info!("Calling sudo for elevated privileges, current user will be used as default user");
                let args: Vec<String> = std::env::args().collect();

                debug!("Args: {:?}", &args);
                Command::new("sudo").arg("-E").args(args).status()?;
                // Do we want to block here to ensure stdout kept alive? Does it matter?
                std::process::exit(0);
            } else {
                warn!("Running vopono as root user directly!");
            }

            exec(cmd)?
        } // args::Command::SetDefaults(cmd) => todo!(),
    }
    Ok(())
}

fn exec(command: ExecCommand) -> anyhow::Result<()> {
    let provider: VpnProvider;
    let server_name: String;

    // TODO: Clean this up and merge with protocol logic below
    if let Some(path) = &command.custom_config {
        if command.protocol.is_none() {
            // TODO: Detect config type from file
            bail!("Must specify protocol when using custom config");
        }
        provider = VpnProvider::Custom;
        // Could hash filename with CRC and use base64 but chars are limited
        server_name = String::from(
            &path
                .as_path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .chars()
                .into_iter()
                .filter(|&x| x != ' ' && x != '-')
                .collect::<String>()[0..4],
        );
    } else {
        // Get server and provider
        // TODO: Handle default case and remove expect()
        provider = command.vpn_provider.expect("Enter a VPN provider");
        if provider == VpnProvider::Custom {
            bail!("Must provide config file if using custom VPN Provider");
        }
        server_name = command.server.expect("Enter a VPN server prefix");
    }
    // Check protocol is valid for provider
    let protocol = get_protocol(&provider, command.protocol)?;
    let serverlist;
    let server;
    let port;
    let ns_name;
    let server_alias;

    // TODO: Refactor and simplify
    match (&protocol, &provider) {
        (Protocol::OpenVpn, VpnProvider::Custom) => {
            // TODO: Make these unnecessary by moving this inside OpenVpn
            server = String::new();
            port = 0;
            ns_name = format!("{}_{}", provider.alias(), server_name);
        }
        (Protocol::OpenVpn, _) => {
            serverlist = get_serverlist(&provider)?;
            let x = find_host_from_alias(&server_name, &serverlist)?;
            server = x.0;
            port = x.1;
            server_alias = x.2;
            ns_name = format!("{}_{}", provider.alias(), server_alias);
        }
        (Protocol::Wireguard, _) => {
            server = String::new();
            port = 0;
            ns_name = format!("{}_{}", provider.alias(), server_name);
        }
    }
    let mut ns;
    let _sysctl;
    let target_subnet;
    let interface: NetworkInterface = match command.interface {
        Some(x) => anyhow::Result::<NetworkInterface>::Ok(x),
        None => Ok(NetworkInterface::new(
            get_active_interfaces()?
                .into_iter()
                .nth(0)
                .ok_or_else(|| anyhow!("No active network interface"))?,
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
                if command.custom_config.is_none() {
                    // TODO: Also handle case where custom config does not provide user-pass
                    get_auth(&provider)?;
                }
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                target_subnet = get_target_subnet()?;
                ns.add_routing(target_subnet)?;
                ns.add_iptables_rule(target_subnet, interface)?;
                _sysctl = SysCtl::enable_ipv4_forwarding();
                // TODO: Handle custom DNS
                ns.dns_config(None)?;
                ns.run_openvpn(&provider, &server, port, command.custom_config)?;
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
                let config = if command.custom_config.is_some() {
                    command.custom_config.unwrap()
                } else {
                    get_config_from_alias(&provider, &server_name)?
                };
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                target_subnet = get_target_subnet()?;
                ns.add_routing(target_subnet)?;
                ns.add_iptables_rule(target_subnet, interface)?;
                _sysctl = SysCtl::enable_ipv4_forwarding();
                ns.run_wireguard(config)?;
            }
        }
    }

    ns.write_lockfile()?;

    // User for application command, if None will use root
    let user = if command.user.is_none() {
        std::env::var("SUDO_USER").ok()
    } else {
        command.user
    };

    let application = ApplicationWrapper::new(&ns, &command.application, user)?;
    let output = application.wait_with_output()?;
    io::stdout().write_all(output.stdout.as_slice())?;

    Ok(())
}
