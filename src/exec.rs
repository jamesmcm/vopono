use super::application_wrapper::ApplicationWrapper;
use super::args::ExecCommand;
use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use super::network_interface::{get_active_interfaces, NetworkInterface};
use super::providers::VpnProvider;
use super::shadowsocks::uses_shadowsocks;
use super::sync::synch;
use super::sysctl::SysCtl;
use super::util::vopono_dir;
use super::util::{get_config_file_protocol, get_config_from_alias};
use super::util::{get_existing_namespaces, get_target_subnet};
use super::vpn::{verify_auth, Protocol};
use anyhow::{anyhow, bail};
use log::{debug, error, info, warn};
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::net::{IpAddr, Ipv4Addr};
use std::{
    fs::create_dir_all,
    io::{self, Write},
};

pub fn exec(command: ExecCommand) -> anyhow::Result<()> {
    // this captures all sigint signals
    // ignore for now, they are automatically passed on to the child
    let signals = Signals::new(&[SIGINT])?;

    let provider: VpnProvider;
    let server_name: String;
    let protocol: Protocol;

    // TODO: Refactor this part - DRY
    // Check if we have config file path passed on command line
    // Create empty config file if does not exist
    create_dir_all(vopono_dir()?)?;
    let config_path = command
        .vopono_config
        .ok_or_else(|| anyhow!("No config file passed"))
        .or_else::<anyhow::Error, _>(|_| Ok(vopono_dir()?.join("config.toml")))?;
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .open(&config_path)?;
    }
    let mut vopono_config_settings = config::Config::default();
    vopono_config_settings.merge(config::File::from(config_path))?;

    // Assign firewall from args or vopono config file
    let firewall: Firewall = command
        .firewall
        .ok_or_else(|| anyhow!(""))
        .or_else(|_| {
            vopono_config_settings.get("firewall").map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
        })
        .or_else(|_x| crate::util::get_firewall())?;

    // Assign custom_config from args or vopono config file
    let custom_config = command.custom_config.clone().or_else(|| {
        vopono_config_settings
            .get("custom_config")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .ok()
    });

    // Assign postup script from args or vopono config file
    let postup = command.postup.clone().or_else(|| {
        vopono_config_settings
            .get("postup")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .ok()
    });

    // Assign predown script from args or vopono config file
    let predown = command.predown.clone().or_else(|| {
        vopono_config_settings
            .get("predown")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .ok()
    });

    // User for application command, if None will use root
    let user = if command.user.is_none() {
        vopono_config_settings
            .get("user")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .ok()
            .or_else(|| std::env::var("SUDO_USER").ok())
    } else {
        command.user
    };

    // Assign DNS server from args or vopono config file
    let base_dns = command.dns.clone().or_else(|| {
        vopono_config_settings
            .get("dns")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .ok()
    });

    // Assign protocol and server from args or vopono config file or custom config if used
    if let Some(path) = &custom_config {
        protocol = command
            .protocol
            .unwrap_or_else(|| get_config_file_protocol(path));
        provider = VpnProvider::Custom;
        // Encode filename with base58 so we can fit it within 16 chars for the veth pair name
        let sname = bs58::encode(&path.to_str().unwrap()).into_string();

        server_name = sname[0..std::cmp::min(11, sname.len())].to_string();
    } else {
        // Get server and provider
        provider = command
            .vpn_provider
            .or_else(|| {
                vopono_config_settings
                    .get("provider")
                    .map_err(|e| {
                        debug!("vopono config.toml: {:?}", e);
                        anyhow!("Failed to read config file")
                    })
                    .ok()
            })
            .expect(
                "Enter a VPN provider as a command-line argument or in the vopono config.toml file",
            );
        if provider == VpnProvider::Custom {
            bail!("Must provide config file if using custom VPN Provider");
        }
        server_name = command
            .server
            .or_else(|| {
                vopono_config_settings
                    .get("server")
                    .map_err(|e| {
                        debug!("vopono config.toml: {:?}", e);
                        anyhow!("Failed to read config file")
                    })
                    .ok()
            })
            .expect(
                "Enter a VPN server prefix as a command-line argument or in the vopono config.toml file",
            );

        // Check protocol is valid for provider
        protocol = command
            .protocol
            .or_else(|| {
                vopono_config_settings
                    .get("protocol")
                    .map_err(|e| {
                        debug!("vopono config.toml: {:?}", e);
                        anyhow!("Failed to read config file")
                    })
                    .ok()
            })
            .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());
    }

    if provider != VpnProvider::Custom {
        // Check config files exist for provider
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
            Protocol::OpenFortiVpn => bail!("OpenFortiVpn must use Custom provider"),
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
        VpnProvider::Custom => "c".to_string(),
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
                .ok_or_else(|| anyhow!("No active network interface - consider overriding network interface selection with -i argument"))?,
        )?),
    }?;
    debug!("Interface: {}", &interface.name);

    let config_file = if provider != VpnProvider::Custom {
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
            Protocol::OpenFortiVpn => bail!("OpenFortiVpn must use Custom provider"),
        }?;
        Some(get_config_from_alias(&cdir, &server_name)?)
    } else {
        // Config file required for non OpenConnect custom providers
        if protocol != Protocol::OpenConnect {
            Some(custom_config.expect("No custom config provided"))
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
            predown,
            user.clone(),
        )?;
        let target_subnet = get_target_subnet()?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;
        ns.add_routing(target_subnet)?;
        ns.add_host_masquerade(target_subnet, interface.clone(), firewall)?;
        ns.add_firewall_exception(
            interface,
            NetworkInterface::new(ns.veth_pair.as_ref().unwrap().dest.clone())?,
            firewall,
        )?;
        _sysctl = SysCtl::enable_ipv4_forwarding();
        match protocol {
            Protocol::OpenVpn => {
                // Handle authentication check
                let auth_file = if provider != VpnProvider::Custom {
                    verify_auth(provider.get_dyn_openvpn_provider()?)?
                } else {
                    None
                };

                let dns = base_dns
                    .clone()
                    .or_else(|| {
                        provider
                            .get_dyn_openvpn_provider()
                            .ok()
                            .and_then(|x| x.provider_dns())
                    })
                    .unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);

                // TODO: DNS suffixes?
                ns.dns_config(&dns, &[])?;
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
                if base_dns.is_none() {
                    if let Some(newdns) = ns.openvpn.as_ref().unwrap().openvpn_dns {
                        let old_dns = ns.dns_config.take();
                        std::mem::forget(old_dns);
                        // TODO: DNS suffixes?
                        ns.dns_config(&[newdns], &[])?;
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
                    base_dns.as_ref(),
                )?;
            }
            Protocol::OpenConnect => {
                let dns = base_dns.unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
                // TODO: DNS suffixes?
                ns.dns_config(&dns, &[])?;
                ns.run_openconnect(
                    config_file,
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                    &server_name,
                )?;
            }
            Protocol::OpenFortiVpn => {
                // TODO: DNS handled by OpenFortiVpn directly?
                ns.run_openfortivpn(
                    config_file.expect("No OpenFortiVPN config file provided"),
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                )?;
            }
        }

        // Run PostUp script (if any)
        // Temporarily set env var referring to this network namespace name
        if let Some(pucmd) = postup {
            std::env::set_var("VOPONO_NS", &ns.name);
            if user.is_some() {
                std::process::Command::new("sudo")
                    .args(&["-Eu", user.as_ref().unwrap(), &pucmd])
                    .spawn()?;
            } else {
                std::process::Command::new(&pucmd).spawn()?;
            }
            std::env::remove_var("VOPONO_NS");
        }
    }

    let ns = ns.write_lockfile(&command.application)?;

    let application = ApplicationWrapper::new(&ns, &command.application, user)?;

    // Launch TCP proxy server on other threads if forwarding ports
    // TODO: Fix when running as root
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
                    false,
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
        stay_alive(Some(pid), signals);
    } else if command.keep_alive {
        info!("Keep-alive flag active - will leave network namespace alive until ctrl+C received");
        stay_alive(None, signals);
    }

    Ok(())
}

// Block waiting for SIGINT
fn stay_alive(pid: Option<u32>, mut signals: Signals) {
    let (sender, receiver) = std::sync::mpsc::channel();

    // discard old signals
    for _old in signals.pending() {
        // pass, just empty the iterator
    }

    let handle = signals.handle();

    let thread = std::thread::spawn(move || {
        for _sig in signals.forever() {
            if let Some(pid) = pid {
                info!(
                    "SIGINT received, killing process {} and terminating...",
                    pid
                );
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

    // this blocks until sender sends, so until sigint is received
    receiver.recv().unwrap();

    handle.close();
    thread.join().unwrap();
}
