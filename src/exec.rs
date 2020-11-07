use super::application_wrapper::ApplicationWrapper;
use super::args::ExecCommand;
use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use super::network_interface::{get_active_interfaces, NetworkInterface};
use super::providers::VpnProvider;
use super::shadowsocks::uses_shadowsocks;
use super::sync::synch;
use super::sysctl::SysCtl;
use super::util::{get_config_file_protocol, get_config_from_alias};
use super::util::{get_existing_namespaces, get_target_subnet};
use super::vpn::{verify_auth, Protocol};
use anyhow::{anyhow, bail};
use log::{debug, error, info, warn};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};

pub fn exec(command: ExecCommand) -> anyhow::Result<()> {
    let provider: VpnProvider;
    let server_name: String;
    let protocol: Protocol;

    let firewall: Firewall = command
        .firewall
        .ok_or_else(|| anyhow!(""))
        .or_else(|_x| crate::util::get_firewall())?;

    if let Some(path) = &command.custom_config {
        protocol = command
            .protocol
            .unwrap_or_else(|| get_config_file_protocol(path));
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

        // Check protocol is valid for provider
        protocol = command
            .protocol
            .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());
    }

    if provider != VpnProvider::Custom {
        // Check config files exist for provider
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
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
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
        }?;
        Some(get_config_from_alias(&cdir, &server_name)?)
    } else {
        // Config file required for non OpenConnect custom providers
        if protocol != Protocol::OpenConnect {
            Some(command.custom_config.expect("No custom config provided"))
        } else {
            None
        }
    };

    // Better to check for lockfile exists?
    if get_existing_namespaces()?.contains(&ns_name) {
        // If namespace exists, read its lock config
        info!(
            "Using existing namespace: {}, will not modify firewall rules",
            &ns_name
        );
        ns = NetworkNamespace::from_existing(ns_name)?;
    } else {
        ns = NetworkNamespace::new(
            ns_name.clone(),
            provider.clone(),
            protocol.clone(),
            firewall,
        )?;
        let target_subnet = get_target_subnet()?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;
        ns.add_routing(target_subnet)?;
        ns.add_host_masquerade(target_subnet, interface, firewall)?;
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
                    .clone()
                    .or_else(|| {
                        provider
                            .get_dyn_openvpn_provider()
                            .ok()
                            .map(|x| x.provider_dns())
                            .flatten()
                    })
                    .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);

                // TODO: Don't rely on Google DNS here - could copy local one?
                ns.dns_config(&dns)?;
                // Check if using Shadowsocks
                if let Some((ss_host, ss_lport)) =
                    uses_shadowsocks(config_file.as_ref().expect("No config file provided"))?
                {
                    if provider == VpnProvider::Custom {
                        warn!("Custom provider specifies socks-proxy, if this is local you must run it yourself (e.g. shadowsocks)");
                    } else {
                        let dyn_ss_provider = provider.get_dyn_shadowsocks_provider()?;
                        let password = dyn_ss_provider.password();
                        let encrypt_method = dyn_ss_provider.encrypt_method();
                        ns.run_shadowsocks(
                            config_file.as_ref().expect("No config file provided"),
                            ss_host,
                            ss_lport,
                            &password,
                            &encrypt_method,
                        )?;
                    }
                }

                ns.run_openvpn(
                    config_file.expect("No config file provided"),
                    auth_file,
                    &dns,
                    !command.no_killswitch,
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                    command.disable_ipv6,
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

                // Set DNS with OpenVPN server response if present
                if command.dns.is_none() {
                    if let Some(newdns) = ns.openvpn.as_ref().unwrap().openvpn_dns {
                        let old_dns = ns.dns_config.take();
                        std::mem::forget(old_dns);
                        ns.dns_config(&[newdns])?;
                    }
                }
            }
            Protocol::Wireguard => {
                ns.run_wireguard(
                    config_file.expect("No config file provided"),
                    !command.no_killswitch,
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                    command.disable_ipv6,
                )?;
            }
            Protocol::OpenConnect => {
                let dns = command
                    .dns
                    .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
                ns.dns_config(&dns)?;
                ns.run_openconnect(
                    config_file,
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                    &server_name,
                )?;
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

    // Launch TCP proxy server on other threads if forwarding ports
    let mut proxy = Vec::new();
    if let Some(f) = command.forward_ports {
        if !(command.no_proxy || f.is_empty()) {
            for p in f {
                debug!(
                    "Forwarding port: {}, {:?}",
                    p,
                    ns.veth_pair_ips.as_ref().unwrap().namespace_ip
                );
                proxy.push(basic_tcp_proxy::TcpProxy::new(
                    p,
                    std::net::SocketAddr::new(ns.veth_pair_ips.as_ref().unwrap().namespace_ip, p),
                ));
            }
        }
    }

    let pid = application.handle.id();
    info!(
        "Application {} launched in network namespace {} with pid {}",
        &command.application, &ns.name, pid
    );
    let output = application.wait_with_output()?;
    io::stdout().write_all(output.stdout.as_slice())?;

    // Allow daemons to leave namespace open
    if crate::util::check_process_running(pid) {
        info!(
            "Process {} still running, assumed to be daemon - will leave network namespace alive until ctrl+C received",
            pid
        );
        stay_alive(pid)?;
    } else if command.keep_alive {
        info!("Keep-alive flag active - will leave network namespace alive until ctrl+C received");
        stay_alive(pid)?;
    }

    Ok(())
}

// Block waiting for SIGINT
fn stay_alive(pid: u32) -> anyhow::Result<()> {
    let recv = ctrl_channel(pid);
    recv?.recv().unwrap();
    Ok(())
}

// Handle waiting for SIGINT
fn ctrl_channel(pid: u32) -> Result<std::sync::mpsc::Receiver<()>, ctrlc::Error> {
    let (sender, receiver) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = sender.send(());
        info!(
            "SIGINT received, killing process {} and terminating...",
            pid
        );
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        )
        .ok();
    })?;

    Ok(receiver)
}
