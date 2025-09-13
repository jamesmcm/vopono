use crate::args_config::ArgsConfig;
use crate::cli_client::CliClient;

use super::args::ExecCommand;
use super::sync::synch;
use anyhow::{anyhow, bail};
use log::{debug, error, info, warn};
use signal_hook::iterator::SignalsInfo;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::{
    fs::create_dir_all,
    io::{self, Write},
};
use vopono_core::config::providers::{UiClient, VpnProvider};
use vopono_core::config::vpn::{Protocol, verify_auth};
use vopono_core::network::application_wrapper::ApplicationWrapper;
use vopono_core::network::netns::NetworkNamespace;
use vopono_core::network::network_interface::NetworkInterface;
use vopono_core::network::port_forwarding::Forwarder;
use vopono_core::network::port_forwarding::azirevpn::AzireVpnPortForwarding;
use vopono_core::network::port_forwarding::natpmpc::Natpmpc;
use vopono_core::network::port_forwarding::piapf::Piapf;
use vopono_core::network::shadowsocks::uses_shadowsocks;
use vopono_core::network::sysctl::SysCtl;
use vopono_core::network::trojan::trojan_config::TrojanConfig;
use vopono_core::network::wireguard::Wireguard;
use vopono_core::util::env_vars::set_env_vars;
use vopono_core::util::{get_config_from_alias, get_existing_namespaces, get_target_subnet};
use vopono_core::util::{parse_command_str, vopono_dir};

/// Configuration struct for namespace setup results
pub struct NamespaceConfig {
    pub ns: NetworkNamespace,
    pub parsed_command: ArgsConfig,
    pub forwarder: Option<Box<dyn Forwarder>>,
    pub host_env_vars: std::collections::HashMap<String, String>,
}

/// Special entry point for the daemon. It sets up the namespace and returns the
/// child process handle and the namespace object itself to keep it alive.
pub fn execute_as_daemon(
    command: ExecCommand,
) -> anyhow::Result<(ApplicationWrapper, NetworkNamespace)> {
    let uiclient = CliClient {};
    let NamespaceConfig {
        ns,
        parsed_command,
        forwarder,
        host_env_vars,
    } = setup_namespace(command, &uiclient, true)?;

    let ns = ns.write_lockfile(&parsed_command.application)?;

    let application = ApplicationWrapper::new(
        &ns,
        &parsed_command.application,
        parsed_command.user.clone(),
        parsed_command.group.clone(),
        parsed_command.working_directory.clone().map(PathBuf::from),
        forwarder,
        true, // Always silent on daemon side
        &host_env_vars,
        true, // Pipe IO for legacy daemon path
        None,
        false,
    )?;
    Ok((application, ns))
}

/// Daemon entry that allows selecting pipe mode and passing explicit stdio FDs.
pub fn execute_as_daemon_with_stdio(
    command: ExecCommand,
    pipe_io: bool,
    stdio_fds: Option<(RawFd, RawFd, RawFd)>,
    take_controlling_tty: bool,
) -> anyhow::Result<(ApplicationWrapper, NetworkNamespace)> {
    let uiclient = CliClient {};
    let NamespaceConfig {
        ns,
        parsed_command,
        forwarder,
        host_env_vars,
    } = setup_namespace(command, &uiclient, true)?;

    // In daemon mode, ensure PULSE_SERVER points to the connecting user's runtime
    // so apps can talk to the host Pulse/pipewire server.
    let mut host_env_vars = host_env_vars;
    if let Some(ref user_name) = parsed_command.user
        && let Some(user) = nix::unistd::User::from_name(user_name)?
    {
        let pulse = format!("unix:/run/user/{}/pulse/native", user.uid.as_raw());
        host_env_vars.insert("PULSE_SERVER".to_string(), pulse);
    }

    let ns = ns.write_lockfile(&parsed_command.application)?;
    let application = ApplicationWrapper::new(
        &ns,
        &parsed_command.application,
        parsed_command.user.clone(),
        parsed_command.group.clone(),
        parsed_command.working_directory.clone().map(PathBuf::from),
        forwarder,
        true, // Always silent on daemon side
        &host_env_vars,
        pipe_io,
        stdio_fds,
        take_controlling_tty,
    )?;
    Ok((application, ns))
}

/// The main entry point for the non-daemon (sudo-based fallback) execution path.
pub fn exec(
    command: ExecCommand,
    uiclient: &dyn UiClient,
    verbose: bool,
    silent: bool,
) -> anyhow::Result<i32> {
    let signals = Signals::new([SIGINT])?;
    let NamespaceConfig {
        ns,
        parsed_command,
        forwarder,
        host_env_vars,
    } = setup_namespace(command, uiclient, verbose)?;
    let ns = ns.write_lockfile(&parsed_command.application)?;
    run_application_and_wait(
        &parsed_command,
        forwarder,
        &ns,
        signals,
        silent,
        &host_env_vars,
    )
}

/// Shared logic to set up a new or existing network namespace.
fn setup_namespace(
    command: ExecCommand,
    uiclient: &dyn UiClient,
    verbose: bool,
) -> anyhow::Result<NamespaceConfig> {
    create_dir_all(vopono_dir()?)?;
    let vopono_config_settings = ArgsConfig::get_config_file(&command)?;
    let host_env_vars = vopono_core::util::env_vars::get_host_env_vars();

    let mut parsed_command = ArgsConfig::get_cli_or_config_args(command, vopono_config_settings)?;

    if parsed_command.provider != VpnProvider::Custom
        && parsed_command.provider != VpnProvider::None
        && parsed_command.protocol != Protocol::Warp
    {
        let cdir = match parsed_command.protocol {
            Protocol::OpenVpn => parsed_command
                .provider
                .get_dyn_openvpn_provider()?
                .openvpn_dir(),
            Protocol::Wireguard => parsed_command
                .provider
                .get_dyn_wireguard_provider()?
                .wireguard_dir(),
            _ => unreachable!(),
        }?;
        if !cdir.exists() || cdir.read_dir()?.next().is_none() {
            info!(
                "Config files for {} {} do not exist, running vopono sync",
                parsed_command.provider, parsed_command.protocol
            );
            synch(
                parsed_command.provider.clone(),
                &Some(parsed_command.protocol.clone()),
                uiclient,
            )?;
        }
    }

    let alias = match parsed_command.provider {
        VpnProvider::Custom => "c".to_string(),
        VpnProvider::None => "none".to_string(),
        _ => parsed_command.provider.get_dyn_provider().alias_2char(),
    };

    let ns_name = if let Some(c_ns_name) = parsed_command.custom_netns_name.clone() {
        c_ns_name
    } else {
        let short_name = if parsed_command.server.len() > 7 {
            bs58::encode(&parsed_command.server).into_string()[0..7].to_string()
        } else {
            parsed_command.server.replace('-', "")
        };
        format!("vo_{alias}_{short_name}")
    };

    let mut ns;
    let _sysctl;
    let forwarder;

    if get_existing_namespaces()?.contains(&ns_name) {
        info!(
            "Using existing namespace: {}, will not modify firewall rules",
            &ns_name
        );
        ns = NetworkNamespace::from_existing(ns_name)?;
        if parsed_command.port_forwarding || parsed_command.custom_port_forwarding.is_some() {
            warn!(
                "Re-using existing network namespace {} - will not run port forwarder, should be run when netns first created",
                &ns.name
            );
        }
        forwarder = None;
    } else {
        ns = NetworkNamespace::new(
            ns_name.clone(),
            parsed_command.provider.clone(),
            parsed_command.protocol.clone(),
            parsed_command.firewall,
            parsed_command.predown.clone(),
            parsed_command.user.clone(),
            parsed_command.group.clone(),
        )?;
        let target_subnet = get_target_subnet()?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;

        if parsed_command.trojan_host.is_some() || parsed_command.trojan_config.is_some() {
            let mut c = TrojanConfig::new(parsed_command.trojan_config.as_deref())?;
            if let Some(trojan_host) = parsed_command.trojan_host.as_ref() {
                c.set_remote_fields(trojan_host);
            }
            let resolved_ip = c.get_remote_trojanhost()?.resolve_ip()?;
            log::debug!("Resolved trojan host IP: {resolved_ip} - setting as open host");
            if let Some(oh) = parsed_command.open_hosts.as_mut() {
                oh.push(resolved_ip);
            } else {
                parsed_command.open_hosts = Some(vec![resolved_ip]);
            }
        }

        ns.add_routing(
            target_subnet,
            parsed_command.open_hosts.as_ref(),
            parsed_command.allow_host_access,
            parsed_command.disable_ipv6,
        )?;
        ns.enable_unprivileged_ping()?;

        if parsed_command.firewall == vopono_core::network::firewall::Firewall::NfTables {
            ns.setup_nftables_firewall()?;
        }

        if parsed_command.allow_host_access {
            let host_ip = ns
                .veth_pair_ips
                .as_ref()
                .expect("No veth pair")
                .ipv4
                .as_ref()
                .expect("No IPv4 host address")
                .host_ip;
            warn!("Allowing host access from network namespace, host IP address is: {host_ip}");
            if let Some(oh) = parsed_command.open_hosts.as_mut() {
                oh.push(host_ip);
            } else {
                parsed_command.open_hosts = Some(vec![host_ip]);
            }

            if let Some(ref mut open_hosts) = parsed_command.open_hosts {
                warn!(
                    "Allowing host access from network namespace, host IPv6 address is: {host_ip}"
                );
                ns.veth_pair_ips
                    .as_ref()
                    .iter()
                    .flat_map(|p| p.ipv6.as_ref())
                    .for_each(|ipv6| open_hosts.push(ipv6.host_ip));
            }
        }

        ns.add_host_masquerade(
            target_subnet,
            parsed_command.interface.clone(),
            parsed_command.firewall,
        )?;
        ns.add_firewall_exception(
            parsed_command.interface.clone(),
            NetworkInterface::new(ns.veth_pair.as_ref().unwrap().dest.clone())?,
            parsed_command.firewall,
            parsed_command.disable_ipv6,
        )?;
        _sysctl = SysCtl::enable_ipv4_forwarding();

        let config_file = run_protocol_in_netns(&parsed_command, &mut ns, uiclient, verbose)?;
        ns.set_config_file(config_file);

        if let Some(ref hosts) = parsed_command.open_hosts {
            vopono_core::util::open_hosts(&ns.name, hosts, parsed_command.firewall)?;
        }

        forwarder = provider_port_forwarding(&parsed_command, &ns)?;

        if let Some(pucmd) = parsed_command.postup.clone() {
            let mut sudo_args = Vec::new();
            if let Some(ref user) = parsed_command.user {
                sudo_args.push("--user");
                sudo_args.push(user);
            }
            if let Some(ref group) = parsed_command.group {
                sudo_args.push("--group");
                sudo_args.push(group);
            }

            let parsed_pucmd = parse_command_str(&pucmd)?;
            let parsed_pucmd_ptrs: Vec<&str> = parsed_pucmd.iter().map(|s| s.as_str()).collect();

            let mut cmd = if !sudo_args.is_empty() {
                let mut args = vec!["sudo", "--preserve-env"];
                args.append(&mut sudo_args);
                args.extend(parsed_pucmd_ptrs);
                let mut cmd = std::process::Command::new(args[0]);
                cmd.args(&args[1..]);
                cmd
            } else {
                let mut cmd = std::process::Command::new(parsed_pucmd_ptrs[0]);
                cmd.args(&parsed_pucmd_ptrs[1..]);
                cmd
            };
            set_env_vars(&ns, forwarder.as_deref(), &mut cmd, &host_env_vars);
            cmd.spawn()?;
        }
    }

    Ok(NamespaceConfig {
        ns,
        parsed_command,
        forwarder,
        host_env_vars,
    })
}

fn run_application_and_wait(
    parsed_command: &ArgsConfig,
    forwarder: Option<Box<dyn Forwarder>>,
    ns: &NetworkNamespace,
    signals: SignalsInfo,
    silent: bool,
    host_env_vars: &std::collections::HashMap<String, String>,
) -> anyhow::Result<i32> {
    let mut proxy = Vec::new();
    if let Some(f) = &parsed_command.forward
        && !(parsed_command.no_proxy || f.is_empty())
    {
        for p in f {
            debug!(
                "Forwarding port: {}, {:?}",
                p,
                ns.veth_pair_ips
                    .as_ref()
                    .unwrap()
                    .ipv4
                    .as_ref()
                    .unwrap()
                    .namespace_ip
            );
            proxy.push(basic_tcp_proxy::TcpProxy::new(
                *p,
                std::net::SocketAddr::new(
                    ns.veth_pair_ips
                        .as_ref()
                        .unwrap()
                        .ipv4
                        .as_ref()
                        .unwrap()
                        .namespace_ip,
                    *p,
                ),
                false,
            ));
        }
    }

    if !parsed_command.create_netns_only {
        let application = ApplicationWrapper::new(
            ns,
            &parsed_command.application,
            parsed_command.user.clone(),
            parsed_command.group.clone(),
            parsed_command.working_directory.clone().map(PathBuf::from),
            forwarder,
            silent,
            host_env_vars,
            false, // Do not pipe IO for normal execution
            None,
            false,
        )?;

        let pid = application.handle.id();
        info!(
            "Application {} launched in network namespace {} with pid {}",
            &parsed_command.application, &ns.name, pid
        );

        if let Some(fwd) = application.port_forwarding.as_ref() {
            info!("Port Forwarding on port {}", fwd.forwarded_port())
        }
        let output = application.wait_with_output()?;
        io::stdout().write_all(output.stdout.as_slice())?;

        if vopono_core::util::check_process_running(pid) {
            info!(
                "Process {} still running, assumed to be daemon - will leave network namespace {} alive until ctrl+C received",
                pid, &ns.name
            );
            stay_alive(Some(pid), signals);
            Ok(0)
        } else if parsed_command.keep_alive {
            info!(
                "Keep-alive flag active - will leave network namespace {} alive until ctrl+C received",
                &ns.name
            );
            stay_alive(None, signals);
            Ok(0)
        } else {
            Ok(output.status.code().unwrap_or(1))
        }
    } else {
        info!(
            "Created netns {} - will leave network namespace alive until ctrl+C received",
            &ns.name
        );
        stay_alive(None, signals);
        Ok(0)
    }
}

// Block waiting for SIGINT
fn stay_alive(pid: Option<u32>, mut signals: Signals) {
    let (sender, receiver) = std::sync::mpsc::channel();
    for _old in signals.pending() {}

    let handle = signals.handle();
    let thread = std::thread::spawn(move || {
        for _sig in signals.forever() {
            if let Some(pid) = pid {
                info!("SIGINT received, killing process {pid} and terminating...");
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                )
                .ok();
            } else {
                info!("SIGINT received, terminating...",);
            }
            let _ = sender.send(());
        }
    });

    receiver.recv().unwrap();
    handle.close();
    thread.join().unwrap();
}

fn run_protocol_in_netns(
    parsed_command: &ArgsConfig,
    ns: &mut NetworkNamespace,
    uiclient: &dyn UiClient,
    verbose: bool,
) -> anyhow::Result<Option<PathBuf>> {
    if parsed_command.provider == VpnProvider::None {
        log::warn!(
            "Provider set to None, will not run any VPN protocol inside the network namespace"
        );
        if let Some(dns) = &parsed_command.dns {
            ns.dns_config(
                dns,
                &[],
                parsed_command.hosts.as_ref(),
                parsed_command.allow_host_access,
            )?;
        }
        return Ok(None);
    }

    let config_file = if parsed_command.protocol == Protocol::Warp {
        None
    } else if parsed_command.provider != VpnProvider::Custom {
        let cdir = match parsed_command.protocol {
            Protocol::OpenVpn => parsed_command
                .provider
                .get_dyn_openvpn_provider()?
                .openvpn_dir(),
            Protocol::Wireguard => parsed_command
                .provider
                .get_dyn_wireguard_provider()?
                .wireguard_dir(),
            _ => bail!("This protocol must use a custom provider"),
        }?;
        Some(get_config_from_alias(&cdir, &parsed_command.server)?)
    } else {
        Some(
            parsed_command
                .custom
                .clone()
                .expect("No custom config provided"),
        )
    };

    match parsed_command.protocol {
        Protocol::None => unreachable!(),
        Protocol::Warp => ns.run_warp(
            parsed_command.open_ports.as_ref(),
            parsed_command.forward.as_ref(),
            parsed_command.firewall,
        )?,
        Protocol::OpenVpn => {
            let auth_file = if parsed_command.provider != VpnProvider::Custom {
                verify_auth(
                    parsed_command.provider.get_dyn_openvpn_provider()?,
                    uiclient,
                )?
            } else {
                None
            };

            let dns = parsed_command
                .dns
                .clone()
                .or_else(|| {
                    parsed_command
                        .provider
                        .get_dyn_openvpn_provider()
                        .ok()
                        .and_then(|x| x.provider_dns())
                })
                .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);

            ns.dns_config(
                &dns,
                &[],
                parsed_command.hosts.as_ref(),
                parsed_command.allow_host_access,
            )?;
            let config_path = config_file
                .as_ref()
                .expect("No OpenVPN config file provided");
            if let Some((ss_host, ss_lport)) = uses_shadowsocks(config_path)? {
                if parsed_command.provider == VpnProvider::Custom {
                    warn!(
                        "Custom provider specifies socks-proxy, if this is local you must run it yourself (e.g. shadowsocks)"
                    );
                } else {
                    let dyn_ss_provider = parsed_command.provider.get_dyn_shadowsocks_provider()?;
                    let password = dyn_ss_provider.password();
                    let encrypt_method = dyn_ss_provider.encrypt_method();
                    ns.run_shadowsocks(config_path, ss_host, ss_lport, &password, &encrypt_method)?;
                }
            }

            ns.run_openvpn(
                config_path.clone(),
                auth_file,
                &dns,
                !parsed_command.no_killswitch,
                parsed_command.open_ports.as_ref(),
                parsed_command.forward.as_ref(),
                parsed_command.firewall,
                parsed_command.disable_ipv6,
                verbose,
            )?;
            debug!(
                "Checking that OpenVPN is running in namespace: {}",
                &ns.name
            );
            if !ns.check_openvpn_running() {
                return Err(anyhow!(
                    "OpenVPN not running in network namespace, probable dead lock file authentication error"
                ));
            }

            if let Some(newdns) = ns.openvpn.as_ref().unwrap().openvpn_dns
                && parsed_command.dns.is_none()
            {
                let old_dns = ns.dns_config.take();
                std::mem::forget(old_dns);
                ns.dns_config(
                    &[newdns],
                    &[],
                    parsed_command.hosts.as_ref(),
                    parsed_command.allow_host_access,
                )?;
            }
        }
        Protocol::Wireguard => {
            if parsed_command.trojan_host.is_some() || parsed_command.trojan_config.is_some() {
                let wg_conf = if parsed_command.trojan_config.is_none() {
                    Some(Wireguard::config_from_file(
                        config_file.as_ref().expect("No Wireguard config"),
                    )?)
                } else {
                    None
                };
                let peer = wg_conf.map(|c| c.peer);
                ns.run_trojan(
                    parsed_command.trojan_host.clone(),
                    parsed_command.trojan_password.as_deref(),
                    parsed_command.trojan_no_verify,
                    parsed_command.trojan_config.clone().as_deref(),
                    peer,
                )?;
            }

            ns.run_wireguard(
                config_file
                    .clone()
                    .expect("No Wireguard config file provided"),
                !parsed_command.no_killswitch,
                parsed_command.open_ports.as_ref(),
                parsed_command.forward.as_ref(),
                parsed_command.firewall,
                parsed_command.disable_ipv6,
                parsed_command.dns.as_ref(),
                parsed_command.hosts.as_ref(),
                parsed_command.allow_host_access,
            )?;
        }
        Protocol::OpenConnect => {
            let dns = parsed_command
                .dns
                .clone()
                .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
            ns.dns_config(
                &dns,
                &[],
                parsed_command.hosts.as_ref(),
                parsed_command.allow_host_access,
            )?;
            ns.run_openconnect(
                config_file
                    .clone()
                    .expect("No OpenConnect config file provided"),
                parsed_command.open_ports.as_ref(),
                parsed_command.forward.as_ref(),
                parsed_command.firewall,
                &parsed_command.server,
                uiclient,
            )?;
        }
        Protocol::OpenFortiVpn => {
            ns.run_openfortivpn(
                config_file
                    .clone()
                    .expect("No OpenFortiVPN config file provided"),
                parsed_command.open_ports.as_ref(),
                parsed_command.forward.as_ref(),
                parsed_command.hosts.as_ref(),
                parsed_command.firewall,
                parsed_command.allow_host_access,
            )?;
        }
    }
    Ok(config_file)
}

fn provider_port_forwarding(
    parsed_command: &ArgsConfig,
    ns: &NetworkNamespace,
) -> anyhow::Result<Option<Box<dyn Forwarder>>> {
    let forwarder: Option<Box<dyn Forwarder>> = if parsed_command.port_forwarding
        || parsed_command.custom_port_forwarding.is_some()
    {
        let provider_or_custom = if parsed_command.custom.is_some() {
            parsed_command.custom_port_forwarding.clone()
        } else {
            Some(parsed_command.provider.clone())
        };

        if let Some(provider) = &provider_or_custom {
            debug!("Will use {:?} as provider for port forwarding", provider);
        }

        match provider_or_custom {
            Some(VpnProvider::PrivateInternetAccess) => {
                let conf_path = ns.config_file.clone().expect("No PIA config file provided");
                let conf_name = conf_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .expect("No filename for PIA config file")
                    .to_string();
                Some(Box::new(Piapf::new(
                    ns,
                    &conf_name,
                    &parsed_command.protocol,
                    parsed_command.port_forwarding_callback.as_ref(),
                )?))
            }
            Some(VpnProvider::ProtonVPN) => {
                vopono_core::util::open_hosts(
                    &ns.name,
                    &[vopono_core::network::port_forwarding::natpmpc::PROTONVPN_GATEWAY],
                    parsed_command.firewall,
                )?;
                Some(Box::new(Natpmpc::new(
                    ns,
                    parsed_command.port_forwarding_callback.as_ref(),
                )?))
            }
            Some(VpnProvider::AzireVPN) => {
                let azirevpn = vopono_core::config::providers::azirevpn::AzireVPN {};
                let access_token = azirevpn.read_access_token()?;

                if parsed_command.port_forwarding_callback.is_some() {
                    warn!(
                        "Port forwarding callback not supported for AzireVPN - ignoring --port-forwarding-callback"
                    );
                }
                if ns.wireguard.is_none() {
                    log::error!(
                        "AzireVPN Port Forwarding in vopono is only supported for Wireguard"
                    )
                }
                let endpoint_ip = ns.wireguard.as_ref().map(|wg| wg.interface_addresses[0]);

                endpoint_ip
                    .map(|ip| AzireVpnPortForwarding::new(ns, &access_token, ip))
                    .transpose()?
                    .map(|fwd| Box::new(fwd) as Box<dyn Forwarder>)
            }
            Some(p) => {
                error!(
                    "Port forwarding not supported for the selected provider: {p} - ignoring --port-forwarding"
                );
                None
            }
            None => {
                error!(
                    "--port-forwarding set but --custom-port-forwarding provider not provided for --custom-config usage. Ignoring --port-forwarding"
                );
                None
            }
        }
    } else {
        None
    };

    if let Some(fwd) = forwarder.as_ref() {
        vopono_core::util::open_ports(ns, &[fwd.forwarded_port()], parsed_command.firewall)?;
    }
    Ok(forwarder)
}
