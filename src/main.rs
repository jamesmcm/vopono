mod application_wrapper;
mod args;
mod dns_config;
mod iptables;
mod list;
mod netns;
mod network_interface;
mod openvpn;
mod providers;
mod sync;
mod sysctl;
mod util;
mod veth_pair;
mod vpn;
mod wireguard;

use anyhow::{anyhow, bail};
use application_wrapper::ApplicationWrapper;
use args::ExecCommand;
use list::output_list;
use log::{debug, error, info, LevelFilter};
use netns::NetworkNamespace;
use network_interface::{get_active_interfaces, NetworkInterface};
use providers::VpnProvider;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use structopt::StructOpt;
use sync::{sync_menu, synch};
use sysctl::SysCtl;
use util::clean_dead_namespaces;
use util::elevate_privileges;
use util::{clean_dead_locks, get_existing_namespaces, get_target_subnet};
use vpn::{get_auth, Protocol};
use wireguard::get_config_from_alias;

// TODO:
// - OpenVPN authentication for custom config
// - Support update_resolv_conf with OpenVPN (i.e. get DNS server from OpenVPN headers)
// - Disable ipv6 traffic when not routed?
// - Test configuration for wireless interface for OpenVPN
// - Allow for not saving OpenVPN creds to config
// - Allow for choice between iptables and nftables and avoid mixed dependency
// - Make provider and server prefix mandatory (not optional args)

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
        args::Command::Exec(cmd) => {
            clean_dead_locks()?;

            elevate_privileges()?;
            clean_dead_namespaces()?;
            exec(cmd)?
        }
        args::Command::List(listcmd) => {
            clean_dead_locks()?;
            output_list(listcmd)?;
        }
        args::Command::Synch(synchcmd) => {
            elevate_privileges()?;
            // If provider given then sync that, else prompt with menu
            if synchcmd.vpn_provider.is_none() {
                sync_menu()?;
            } else {
                synch(synchcmd.vpn_provider.unwrap(), synchcmd.protocol)?;
            }
        }
    }
    Ok(())
}

// TODO: Move this to separate file
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
    let protocol = command
        .protocol
        .unwrap_or(provider.get_dyn_provider().default_protocol());

    if provider != VpnProvider::Custom {
        // Check config files exist for provider
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
        }?;
        if !cdir.exists() || cdir.read_dir()?.next().is_none() {
            info!(
                "Config files for {} {} do not exist, running vopono sync",
                provider, protocol
            );
            synch(provider.clone(), Some(protocol.clone()))?;
        }
    }

    let ns_name = format!(
        "vopono_{}_{}",
        provider.get_dyn_provider().alias(),
        server_name
    );

    let mut ns;
    let _sysctl;
    let interface: NetworkInterface = match command.interface {
        Some(x) => anyhow::Result::<NetworkInterface>::Ok(x),
        None => Ok(NetworkInterface::new(
            get_active_interfaces()?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No active network interface"))?,
        )?),
    }?;

    debug!("Interface: {}", &interface.name);
    // Better to check for lockfile exists?
    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        ns = NetworkNamespace::from_existing(ns_name)?;
    } else {
        ns = NetworkNamespace::new(ns_name.clone(), provider.clone(), protocol.clone())?;
        let target_subnet = get_target_subnet()?;
        match protocol {
            Protocol::OpenVpn => {
                if command.custom_config.is_none() {
                    // TODO: Also handle case where custom config does not provide user-pass
                    get_auth(&provider)?;
                }
                ns.add_loopback()?;
                ns.add_veth_pair()?;
                ns.add_routing(target_subnet)?;
                ns.add_iptables_rule(target_subnet, interface)?;
                _sysctl = SysCtl::enable_ipv4_forwarding();
                // TODO: Clean up nested unwrap
                let dns = command.dns.unwrap_or(
                    provider
                        .get_dyn_openvpn_provider()?
                        .provider_dns()
                        .unwrap_or(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]),
                );

                ns.dns_config(&dns)?;
                // TODO Change these calls to take config file path directly
                // Put call to get config file from prefix above
                // Then can use same call for custom and standard config? (deal with
                // authentication for OpenVPN)
                ns.run_openvpn(
                    &provider,
                    &server_name,
                    command.custom_config,
                    &dns,
                    !command.no_killswitch,
                )?;
                debug!(
                    "Checking that OpenVPN is running in namespace: {}",
                    &ns_name
                );
                if !ns.check_openvpn_running() {
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
                ns.add_routing(target_subnet)?;
                ns.add_iptables_rule(target_subnet, interface)?;
                _sysctl = SysCtl::enable_ipv4_forwarding();
                ns.run_wireguard(config, !command.no_killswitch)?;
            }
        }
    }

    let ns = ns.write_lockfile(&command.application)?;

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
