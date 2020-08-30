mod application_wrapper;
mod args;
mod dns_config;
mod iptables;
mod list;
mod list_configs;
mod netns;
mod network_interface;
mod openvpn;
mod providers;
mod shadowsocks;
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
use list_configs::print_configs;
use log::{debug, error, info, warn, LevelFilter};
use netns::NetworkNamespace;
use network_interface::{get_active_interfaces, NetworkInterface};
use providers::VpnProvider;
use shadowsocks::uses_shadowsocks;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use structopt::StructOpt;
use sync::{sync_menu, synch};
use sysctl::SysCtl;
use util::clean_dead_namespaces;
use util::elevate_privileges;
use util::get_config_from_alias;
use util::{clean_dead_locks, get_existing_namespaces, get_target_subnet};
use vpn::{verify_auth, Protocol};

// TODO:
// - Support update_resolv_conf with OpenVPN (i.e. get DNS server from OpenVPN headers)
// - Disable ipv6 traffic when not routed?
// - Allow for not saving OpenVPN creds to config

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
        args::Command::Servers(serverscmd) => {
            print_configs(serverscmd)?;
        }
    }
    Ok(())
}

// TODO: Move this to separate file
fn exec(command: ExecCommand) -> anyhow::Result<()> {
    let provider: VpnProvider;
    let server_name: String;

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
        .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());

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

    let alias = match provider {
        VpnProvider::Custom => "custom".to_string(),
        _ => provider.get_dyn_provider().alias(),
    };

    let ns_name = format!("vopono_{}_{}", alias, server_name);

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

    let config_file = if provider != VpnProvider::Custom {
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
        }?;
        get_config_from_alias(&cdir, &server_name)?
    } else {
        command.custom_config.expect("No custom config provided")
    };

    // Better to check for lockfile exists?
    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        ns = NetworkNamespace::from_existing(ns_name)?;
    } else {
        ns = NetworkNamespace::new(ns_name.clone(), provider.clone(), protocol.clone())?;
        let target_subnet = get_target_subnet()?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;
        ns.add_routing(target_subnet)?;
        ns.add_iptables_rule(target_subnet, interface)?;
        _sysctl = SysCtl::enable_ipv4_forwarding();
        match protocol {
            Protocol::OpenVpn => {
                // Handle authentication check
                let auth_file = if provider != VpnProvider::Custom {
                    Some(verify_auth(provider.get_dyn_openvpn_provider()?)?)
                } else {
                    None
                };

                let dns = command
                    .dns
                    .or_else(|| {
                        provider
                            .get_dyn_openvpn_provider()
                            .ok()
                            .map(|x| x.provider_dns())
                            .flatten()
                    })
                    .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);

                ns.dns_config(&dns)?;

                // Check if using Shadowsocks
                if let Some((ss_host, ss_lport)) = uses_shadowsocks(&config_file)? {
                    if provider == VpnProvider::Custom {
                        warn!("Custom provider specifies socks-proxy, if this is local you must run it yourself (e.g. shadowsocks)");
                    } else {
                        let dyn_ss_provider = provider.get_dyn_shadowsocks_provider()?;
                        let password = dyn_ss_provider.password();
                        let encrypt_method = dyn_ss_provider.encrypt_method();
                        ns.run_shadowsocks(
                            &config_file,
                            ss_host,
                            ss_lport,
                            &password,
                            &encrypt_method,
                        )?;
                    }
                }

                ns.run_openvpn(config_file, auth_file, &dns, !command.no_killswitch)?;
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
                ns.run_wireguard(config_file, !command.no_killswitch)?;
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
