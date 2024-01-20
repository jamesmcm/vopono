use super::args::ExecCommand;
use super::sync::synch;
use anyhow::{anyhow, bail};
use log::{debug, error, info, warn};
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::{
    fs::create_dir_all,
    io::{self, Write},
};
use vopono_core::config::providers::{UiClient, VpnProvider};
use vopono_core::config::vpn::{verify_auth, Protocol};
use vopono_core::network::application_wrapper::ApplicationWrapper;
use vopono_core::network::firewall::Firewall;
use vopono_core::network::natpmpc::Natpmpc;
use vopono_core::network::netns::NetworkNamespace;
use vopono_core::network::network_interface::{get_active_interfaces, NetworkInterface};
use vopono_core::network::shadowsocks::uses_shadowsocks;
use vopono_core::network::sysctl::SysCtl;
use vopono_core::util::vopono_dir;
use vopono_core::util::{get_config_file_protocol, get_config_from_alias};
use vopono_core::util::{get_existing_namespaces, get_target_subnet};

pub fn exec(command: ExecCommand, uiclient: &dyn UiClient) -> anyhow::Result<()> {
    // this captures all sigint signals
    // ignore for now, they are automatically passed on to the child
    let signals = Signals::new([SIGINT])?;

    let provider: VpnProvider;
    let server_name: String;
    let protocol: Protocol;

    // TODO: Refactor this part - DRY - macro_rules ?
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
    let vopono_config_settings_builder =
        config::Config::builder().add_source(config::File::from(config_path));
    let vopono_config_settings = vopono_config_settings_builder.build()?;

    // Assign firewall from args or vopono config file
    let firewall: Firewall = command
        .firewall
        .map(|x| x.to_variant())
        .ok_or_else(|| anyhow!(""))
        .or_else(|_| {
            vopono_config_settings
                .get("firewall")
                .map_err(|_e| anyhow!("Failed to read config file"))
        })
        .or_else(|_x| vopono_core::util::get_firewall())?;

    // Assign custom_config from args or vopono config file
    let custom_config = command.custom_config.clone().or_else(|| {
        vopono_config_settings
            .get("custom_config")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });

    // Assign custom_config from args or vopono config file
    let custom_netns_name = command.custom_netns_name.clone().or_else(|| {
        vopono_config_settings
            .get("custom_netns_name")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });

    // Assign open_hosts from args or vopono config file
    let mut open_hosts = command.open_hosts.clone().or_else(|| {
        vopono_config_settings
            .get("open_hosts")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });
    let allow_host_access = command.allow_host_access
        || vopono_config_settings
            .get("allow_host_access")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .unwrap_or(false);

    // Assign postup script from args or vopono config file
    let postup = command.postup.clone().or_else(|| {
        vopono_config_settings
            .get("postup")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });

    // Assign predown script from args or vopono config file
    let predown = command.predown.clone().or_else(|| {
        vopono_config_settings
            .get("predown")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });

    // User for application command, if None will use root
    let user = if command.user.is_none() {
        vopono_config_settings
            .get("user")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
            .or_else(|| std::env::var("SUDO_USER").ok())
    } else {
        command.user
    };

    // Group for application command
    let group = if command.group.is_none() {
        vopono_config_settings
            .get("group")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    } else {
        command.group
    };

    // Working directory for application command
    let working_directory = if command.working_directory.is_none() {
        vopono_config_settings
            .get("working-directory")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    } else {
        command.working_directory
    };

    // Port forwarding for ProtonVPN
    let protonvpn_port_forwarding = if !command.protonvpn_port_forwarding {
        vopono_config_settings
            .get("protonvpn-port-forwarding")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
            .unwrap_or(false)
    } else {
        command.protonvpn_port_forwarding
    };

    // Create netns only
    let create_netns_only = if !command.create_netns_only {
        vopono_config_settings
            .get("create-netns-only")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
            .unwrap_or(false)
    } else {
        command.create_netns_only
    };

    // Assign DNS server from args or vopono config file
    let base_dns = command.dns.clone().or_else(|| {
        vopono_config_settings
            .get("dns")
            .map_err(|_e| anyhow!("Failed to read config file"))
            .ok()
    });

    // TODO: Modify this to allow creating base netns only
    // Assign protocol and server from args or vopono config file or custom config if used
    if let Some(path) = &custom_config {
        protocol = command
            .protocol
            .map(|x| x.to_variant())
            .unwrap_or_else(|| get_config_file_protocol(path));
        provider = VpnProvider::Custom;

        if protocol != Protocol::OpenConnect {
            // Encode filename with base58 so we can fit it within 16 chars for the veth pair name
            let sname = bs58::encode(&path.to_str().unwrap()).into_string();

            server_name = sname[0..std::cmp::min(11, sname.len())].to_string();
        } else {
            // For OpenConnect the server-name can be provided via the usual config or
            // command-line-options. Since it also can be provided via the custom-config we will
            // set an empty-string if it isn't provided.
            server_name = command
                .server
                .or_else(|| {
                    vopono_config_settings
                        .get("server")
                        .map_err(|_e| anyhow!("Failed to read config file"))
                        .ok()
                })
                .or_else(|| Some(String::new()))
                .unwrap();
        }
    } else {
        // Get server and provider
        provider = command
            .vpn_provider
            .map(|x| x.to_variant())
            .or_else(|| {
                vopono_config_settings
                    .get("provider")
                    .map_err(|_e| anyhow!("Failed to read config file"))
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
            .or_else(|| if provider == VpnProvider::Warp {Some("warp".to_owned())} else {None})
            .or_else(|| {
                vopono_config_settings
                    .get("server")
                    .map_err(|_e| {
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
            .map(|x| x.to_variant())
            .or_else(|| {
                vopono_config_settings
                    .get("protocol")
                    .map_err(|_e| anyhow!("Failed to read config file"))
                    .ok()
            })
            .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());
    }

    if (provider == VpnProvider::Warp && protocol != Protocol::Warp)
        || (provider != VpnProvider::Warp && protocol == Protocol::Warp)
    {
        bail!("Cloudflare Warp protocol must use Warp provider");
    }

    if provider != VpnProvider::Custom && protocol != Protocol::Warp {
        // Check config files exist for provider
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
            Protocol::Warp => unreachable!("Unreachable, Warp must use Warp provider"),
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
            Protocol::OpenFortiVpn => bail!("OpenFortiVpn must use Custom provider"),
        }?;
        if !cdir.exists() || cdir.read_dir()?.next().is_none() {
            info!(
                "Config files for {} {} do not exist, running vopono sync",
                provider, protocol
            );
            synch(provider.clone(), Some(protocol.clone()), uiclient)?;
        }
    }

    let alias = match provider {
        VpnProvider::Custom => "c".to_string(),
        _ => provider.get_dyn_provider().alias_2char(),
    };

    let ns_name = if let Some(c_ns_name) = custom_netns_name {
        c_ns_name
    } else {
        let short_name = if server_name.len() > 7 {
            bs58::encode(&server_name).into_string()[0..7].to_string()
        } else {
            server_name.replace('-', "")
        };
        format!("vo_{alias}_{short_name}")
    };

    let mut ns;
    let _sysctl;

    // Assign network interface from args or vopono config file
    let interface = command.interface.clone().or_else(|| {
        vopono_config_settings
            .get_string("interface")
            .map_err(|e| {
                debug!("vopono config.toml: {:?}", e);
                anyhow!("Failed to read config file")
            })
            .map(|x| {
                NetworkInterface::from_str(&x)
                    .map_err(|e| {
                        debug!("vopono config.toml: {:?}", e);
                        anyhow!("Failed to parse network interface in config file")
                    })
                    .ok()
            })
            .ok()
            .flatten()
    });
    let interface: NetworkInterface = match interface {
        Some(x) => anyhow::Result::<NetworkInterface>::Ok(x),
        None => {
            let active_interfaces = get_active_interfaces()?;
            if active_interfaces.len() > 1 {
                warn!("Multiple network interfaces are active: {:#?}, consider specifying the interface with the -i argument. Using {}", &active_interfaces, &active_interfaces[0]);
            }
            Ok(
            NetworkInterface::new(
            active_interfaces
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No active network interface - consider overriding network interface selection with -i argument"))?,
        )?)
        }
    }?;
    debug!("Interface: {}", &interface.name);

    let config_file = if protocol == Protocol::Warp {
        None
    } else if provider != VpnProvider::Custom {
        let cdir = match protocol {
            Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
            Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
            Protocol::OpenConnect => bail!("OpenConnect must use Custom provider"),
            Protocol::OpenFortiVpn => bail!("OpenFortiVpn must use Custom provider"),
            Protocol::Warp => unreachable!(),
        }?;
        Some(get_config_from_alias(&cdir, &server_name)?)
    } else {
        Some(custom_config.expect("No custom config provided"))
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
            group.clone(),
        )?;
        let target_subnet = get_target_subnet()?;
        ns.add_loopback()?;
        ns.add_veth_pair()?;
        ns.add_routing(target_subnet, open_hosts.as_ref(), allow_host_access)?;

        // Add local host to open hosts if allow_host_access enabled
        if allow_host_access {
            let host_ip = ns.veth_pair_ips.as_ref().unwrap().host_ip;
            warn!(
                "Allowing host access from network namespace, host IP address is: {}",
                host_ip
            );
            if let Some(oh) = open_hosts.iter_mut().next() {
                oh.push(host_ip);
            } else {
                open_hosts = Some(vec![host_ip]);
            }
        }

        ns.add_host_masquerade(target_subnet, interface.clone(), firewall)?;
        ns.add_firewall_exception(
            interface,
            NetworkInterface::new(ns.veth_pair.as_ref().unwrap().dest.clone())?,
            firewall,
        )?;
        _sysctl = SysCtl::enable_ipv4_forwarding();

        // TODO: Skip this if netns config only
        match protocol {
            Protocol::Warp => ns.run_warp(
                command.open_ports.as_ref(),
                command.forward_ports.as_ref(),
                firewall,
            )?,
            Protocol::OpenVpn => {
                // Handle authentication check
                let auth_file = if provider != VpnProvider::Custom {
                    verify_auth(provider.get_dyn_openvpn_provider()?, uiclient)?
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
                ns.dns_config(&dns, &[], command.hosts_entries.as_ref())?;
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
                        ns.dns_config(&[newdns], &[], command.hosts_entries.as_ref())?;
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
                    command.hosts_entries.as_ref(),
                )?;
            }
            Protocol::OpenConnect => {
                let dns = base_dns.unwrap_or_else(|| vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
                // TODO: DNS suffixes?
                ns.dns_config(&dns, &[], command.hosts_entries.as_ref())?;
                ns.run_openconnect(
                    config_file.expect("No OpenConnect config file provided"),
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    firewall,
                    &server_name,
                    uiclient,
                )?;
            }
            Protocol::OpenFortiVpn => {
                // TODO: DNS handled by OpenFortiVpn directly?
                ns.run_openfortivpn(
                    config_file.expect("No OpenFortiVPN config file provided"),
                    command.open_ports.as_ref(),
                    command.forward_ports.as_ref(),
                    command.hosts_entries.as_ref(),
                    firewall,
                )?;
            }
        }

        if let Some(ref hosts) = open_hosts {
            vopono_core::util::open_hosts(&ns, hosts.to_vec(), firewall)?;
        }

        // Temporarily set env var referring to this network namespace IP
        // for the PostUp script and the application:
        std::env::set_var(
            "VOPONO_NS_IP",
            ns.veth_pair_ips.as_ref().unwrap().namespace_ip.to_string(),
        );

        // Run PostUp script (if any)
        // Temporarily set env var referring to this network namespace name
        if let Some(pucmd) = postup {
            std::env::set_var("VOPONO_NS", &ns.name);

            let mut sudo_args = Vec::new();
            if let Some(ref user) = user {
                sudo_args.push("--user");
                sudo_args.push(user);
            }
            if let Some(ref group) = group {
                sudo_args.push("--group");
                sudo_args.push(group);
            }

            if !sudo_args.is_empty() {
                let mut args = vec!["--preserve-env"];
                args.append(&mut sudo_args);
                args.push(&pucmd);

                std::process::Command::new("sudo").args(args).spawn()?;
            } else {
                std::process::Command::new(&pucmd).spawn()?;
            };

            std::env::remove_var("VOPONO_NS");
        }
    }

    // Set env var referring to the host IP for the application:
    std::env::set_var(
        "VOPONO_HOST_IP",
        ns.veth_pair_ips.as_ref().unwrap().host_ip.to_string(),
    );

    let ns = ns.write_lockfile(&command.application)?;

    let natpmpc = if protonvpn_port_forwarding {
        vopono_core::util::open_hosts(
            &ns,
            vec![vopono_core::network::natpmpc::PROTONVPN_GATEWAY],
            firewall,
        )?;
        Some(Natpmpc::new(&ns)?)
    } else {
        None
    };

    if let Some(pmpc) = natpmpc.as_ref() {
        vopono_core::util::open_ports(&ns, &[pmpc.local_port], firewall)?;
    }

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

    if !create_netns_only {
        let application = ApplicationWrapper::new(
            &ns,
            &command.application,
            user,
            group,
            working_directory.map(PathBuf::from),
            natpmpc,
        )?;

        let pid = application.handle.id();
        info!(
            "Application {} launched in network namespace {} with pid {}",
            &command.application, &ns.name, pid
        );

        if let Some(pmpc) = application.protonvpn_port_forwarding.as_ref() {
            info!("ProtonVPN Port Forwarding on port {}", pmpc.local_port)
        }
        let output = application.wait_with_output()?;
        io::stdout().write_all(output.stdout.as_slice())?;

        // Allow daemons to leave namespace open
        if vopono_core::util::check_process_running(pid) {
            info!(
            "Process {} still running, assumed to be daemon - will leave network namespace {} alive until ctrl+C received",
            pid, &ns.name
        );
            stay_alive(Some(pid), signals);
        } else if command.keep_alive {
            info!(
                "Keep-alive flag active - will leave network namespace {} alive until ctrl+C received", &ns.name
            );
            stay_alive(None, signals);
        }
    } else {
        info!(
            "Created netns {} - will leave network namespace alive until ctrl+C received",
            &ns.name
        );
        stay_alive(None, signals);
    }

    std::env::remove_var("VOPONO_NS_IP");
    std::env::remove_var("VOPONO_HOST_IP");

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
