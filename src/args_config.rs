// Handles using the args from either the CLI or config file

use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::anyhow;
use config::Config;
use log::warn;
use vopono_core::{
    config::{providers::VpnProvider, vpn::Protocol},
    network::{
        firewall::Firewall,
        network_interface::{NetworkInterface, get_active_interfaces},
        trojan::TrojanHost,
    },
    util::{get_config_file_protocol, vopono_dir},
};

use crate::args::ExecCommand;

macro_rules! command_else_config_option {
    // Get expression from command - command.expr
    // If None then read from Config .get("expr")
    // Returns None if absent in both
    ($field_id:ident, $command:ident, $config:ident) => {
        $command.$field_id.clone().or_else(|| {
            $config
                .get(stringify!($field_id))
                .or($config.get(&stringify!($field_id).replace('_', "-")))
                .map_err(|e| {
                    log::debug!("{:?}", e);
                    anyhow!("Failed to read config file")
                })
                .ok()
        })
    };
}

macro_rules! command_else_config_bool {
    // Get bool ident from command - command.expr
    // If None then read from Config .get("expr")
    // Returns false if absent in both
    ($field_id:ident, $command:ident, $config:ident) => {
        $command.$field_id
            || $config
                .get(stringify!($field_id))
                .or($config.get(&stringify!($field_id).replace('_', "-")))
                .map_err(|_e| anyhow!("Failed to read config file"))
                .ok()
                .unwrap_or(false)
    };
}

macro_rules! command_else_config_option_variant {
    // Get enum variant ident from command - command.expr
    // If None then read from Config .get("expr")
    // Returns None if absent in both
    ($field_id:ident, $command:ident, $config:ident) => {
        $command.$field_id.map(|x| x.to_variant()).or_else(|| {
            $config
                .get(stringify!($field_id))
                .or($config.get(&stringify!($field_id).replace('_', "-")))
                .map_err(|_e| anyhow!("Failed to read config file"))
                .ok()
        })
    };
}

macro_rules! error_and_bail {
    // log to error and bail
    ($msg:literal) => {
        log::error!("{}", $msg);
        anyhow::bail!($msg);
    };
}

// TODO: Generate this from procedural macro?
pub struct ArgsConfig {
    pub provider: VpnProvider,
    pub protocol: Protocol,
    pub interface: NetworkInterface,
    pub server: String,
    pub application: String,
    pub user: Option<String>,
    pub group: Option<String>,
    pub working_directory: Option<String>,
    pub custom: Option<PathBuf>,
    pub dns: Option<Vec<IpAddr>>,
    pub hosts: Option<Vec<String>>,
    pub open_hosts: Option<Vec<IpAddr>>,
    pub no_killswitch: bool,
    pub keep_alive: bool,
    pub open_ports: Option<Vec<u16>>,
    pub forward: Option<Vec<u16>>,
    pub no_proxy: bool,
    pub firewall: Firewall,
    pub disable_ipv6: bool,
    pub postup: Option<String>,
    pub predown: Option<String>,
    pub custom_netns_name: Option<String>,
    pub allow_host_access: bool,
    pub port_forwarding: bool,
    pub custom_port_forwarding: Option<VpnProvider>,
    pub port_forwarding_callback: Option<String>,
    pub create_netns_only: bool,
    pub trojan_host: Option<TrojanHost>,
    pub trojan_password: Option<String>,
    pub trojan_no_verify: bool,
    pub trojan_config: Option<PathBuf>,
}

impl ArgsConfig {
    /// Return new ExecCommand with args from config file if missing in CLI but present there
    /// Also handle CLI args consistency errors
    pub fn get_cli_or_config_args(command: ExecCommand, config: Config) -> anyhow::Result<Self> {
        // TODO: Automate field mapping with procedural macro over ExecCommand struct?
        let custom: Option<PathBuf> = command_else_config_option!(custom, command, config)
            .and_then(|p| {
                shellexpand::full(&p.to_string_lossy())
                    .ok()
                    .and_then(|s| PathBuf::from_str(s.as_ref()).ok())
            });

        // Note application cannot be defined in config file
        let application: String = shellexpand::full(&command.application)
            .map_err(|e| {
                anyhow!(
                    "Shell expansion error for application: {:?}, error: {:?}",
                    &command.application,
                    e
                )
            })
            .map(|c| c.to_string())?;
        let custom_netns_name = command_else_config_option!(custom_netns_name, command, config);
        let open_hosts = command_else_config_option!(open_hosts, command, config);
        let hosts = command_else_config_option!(hosts, command, config);
        let open_ports = command_else_config_option!(open_ports, command, config);
        let forward = command_else_config_option!(forward, command, config);
        let postup = command_else_config_option!(postup, command, config)
            .and_then(|p| shellexpand::full(&p).ok().map(|s| s.into_owned()));
        let predown = command_else_config_option!(predown, command, config)
            .and_then(|p| shellexpand::full(&p).ok().map(|s| s.into_owned()));
        let group = command_else_config_option!(group, command, config);
        let working_directory = command_else_config_option!(working_directory, command, config)
            .and_then(|p| shellexpand::full(&p).ok().map(|s| s.into_owned()));
        let dns = command_else_config_option!(dns, command, config);
        let user = command_else_config_option!(user, command, config)
            .or_else(|| std::env::var("SUDO_USER").ok());
        let port_forwarding_callback =
            command_else_config_option!(port_forwarding_callback, command, config)
                .and_then(|p| shellexpand::full(&p).ok().map(|s| s.into_owned()));

        let no_proxy = command_else_config_bool!(no_proxy, command, config);
        let keep_alive = command_else_config_bool!(keep_alive, command, config);
        let port_forwarding = command_else_config_bool!(port_forwarding, command, config);
        let allow_host_access = command_else_config_bool!(allow_host_access, command, config);
        let create_netns_only = command_else_config_bool!(create_netns_only, command, config);
        let disable_ipv6 = command_else_config_bool!(disable_ipv6, command, config);
        let no_killswitch = command_else_config_bool!(no_killswitch, command, config);

        let firewall = command_else_config_option_variant!(firewall, command, config)
            .ok_or_else(|| anyhow!("Failed to get Firewall variant from args"))
            .or_else(|_| vopono_core::util::get_firewall())?;
        let custom_port_forwarding =
            command_else_config_option_variant!(custom_port_forwarding, command, config);

        if custom_port_forwarding.is_some() && custom.is_none() {
            log::error!(
                "Custom port forwarding implementation is set, but not using custom provider config file. custom-port-forwarding setting will be ignored"
            );
        }

        // Assign network interface from args or vopono config file
        // Interface must be explicitly read as string
        let interface = command.interface.or_else(|| {
            config.get_string("interface").ok().and_then(|s| {
                NetworkInterface::from_str(&s)
                    .map_err(|e| {
                        log::error!("Failed to parse interface from config file: {e}");
                        anyhow!("Failed to parse interface from config file: {e}")
                    })
                    .ok()
            })
        });
        let interface: NetworkInterface = match interface {
            Some(x) => anyhow::Result::<NetworkInterface>::Ok(x),
            None => {
                let active_interfaces = get_active_interfaces()?;
                if active_interfaces.len() > 1 {
                    log::warn!(
                        "Multiple network interfaces are active: {:#?}, consider specifying the interface with the -i argument. Using {}",
                        &active_interfaces,
                        &active_interfaces[0]
                    );
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
        log::debug!("Interface: {}", &interface.name);

        let provider: VpnProvider;
        let server: String;
        let protocol: Protocol;

        // Assign protocol and server from args or vopono config file or custom config if used
        if let Some(path) = &custom {
            protocol = command_else_config_option!(protocol, command, config)
                .map(|x| x.to_variant())
                .ok_or_else(|| anyhow!("."))
                .or_else(|_| get_config_file_protocol(path))?;

            provider = VpnProvider::Custom;

            if protocol != Protocol::OpenConnect {
                // Encode filename with base58 so we can fit it within 16 chars for the veth pair name
                let sname = bs58::encode(&path.to_str().unwrap()).into_string();

                server = sname[0..std::cmp::min(11, sname.len())].to_string();
            } else {
                // For OpenConnect the server-name can be provided via the usual config or
                // command-line-options. Since it also can be provided via the custom-config we will
                // set an empty-string if it isn't provided.
                server = command_else_config_option!(server, command, config).unwrap_or_default();
            }
        } else {
            // Get server and provider
            provider = command_else_config_option_variant!(provider, command, config).ok_or_else(
                || {
                    let msg =
                "Enter a VPN provider as a command-line argument or in the vopono config.toml file";
                    log::error!("{msg}");
                    anyhow!(msg)
                },
            )?;

            if provider == VpnProvider::Custom {
                error_and_bail!("Must provide config file if using custom VPN Provider");
            }

            server = command_else_config_option!(server, command, config)
        // Work-around for providers which do not need a server - TODO: Clean this
         .or_else(|| if provider == VpnProvider::Warp {Some("warp".to_owned())} else {None})
         .or_else(|| if provider == VpnProvider::None {Some("none".to_owned())} else {None})
            .ok_or_else(|| {
                let msg = "VPN server prefix must be provided as a command-line argument or in the vopono config.toml file";
                log::error!("{msg}"); anyhow!(msg)})?;

            // Check protocol is valid for provider
            protocol = command_else_config_option_variant!(protocol, command, config)
                .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());
        }

        // TODO: Error handling
        let trojan_host = command_else_config_option!(trojan_host, command, config);

        let trojan_password = command_else_config_option!(trojan_password, command, config);
        let trojan_no_verify = command_else_config_bool!(trojan_no_verify, command, config);
        let trojan_config =
            command_else_config_option!(trojan_config, command, config).and_then(|p| {
                shellexpand::full(&p.to_string_lossy())
                    .ok()
                    .and_then(|s| PathBuf::from_str(s.as_ref()).ok())
            });

        if (trojan_host.is_some() || trojan_config.is_some()) && protocol != Protocol::Wireguard {
            error_and_bail!("Trojan is currently only supported for Wireguard forwarding");
        }
        if (trojan_host.is_some() && trojan_password.is_none()) && trojan_config.is_none() {
            error_and_bail!("Trojan host is set, but password is not provided");
        }
        if trojan_config.is_some()
            && (trojan_host.is_some() || trojan_password.is_some() || trojan_no_verify)
        {
            warn!("Trojan config file provided - ignoring other trojan settings");
        }

        if (provider == VpnProvider::Warp && protocol != Protocol::Warp)
            || (provider != VpnProvider::Warp && protocol == Protocol::Warp)
        {
            error_and_bail!("Cloudflare Warp protocol must use Warp provider");
        }

        if provider == VpnProvider::None && custom.is_some() {
            error_and_bail!("Custom config cannot be set when using None provider");
        }

        if (provider == VpnProvider::None && protocol != Protocol::None)
            || (provider != VpnProvider::None && protocol == Protocol::None)
        {
            error_and_bail!(
                "None protocol must use None provider - will run not run any VPN service inside netns"
            );
        }

        // TODO: Group some of these arguments into their own structs
        Ok(Self {
            provider,
            protocol,
            interface,
            server,
            application,
            user,
            group,
            working_directory,
            custom,
            dns,
            hosts,
            open_hosts,
            no_killswitch,
            keep_alive,
            open_ports,
            forward,
            no_proxy,
            firewall,
            disable_ipv6,
            postup,
            predown,
            custom_netns_name,
            allow_host_access,
            port_forwarding,
            custom_port_forwarding,
            port_forwarding_callback,
            create_netns_only,
            trojan_host,
            trojan_password,
            trojan_no_verify,
            trojan_config,
        })
    }

    /// Read vopono config file to Config struct
    pub fn get_config_file(command: &ExecCommand) -> anyhow::Result<Config> {
        let config_path = command
            .vopono_config
            .clone()
            .ok_or_else(|| anyhow!("No config file passed"))
            .or_else::<anyhow::Error, _>(|_| Ok(vopono_dir()?.join("config.toml")))?;

        let mut vopono_config_settings_builder =
            config::Config::builder();

        if let Ok(true) = fs::exists(&config_path) {
            vopono_config_settings_builder =
                vopono_config_settings_builder.add_source(config::File::from(config_path.clone()));
        }

        vopono_config_settings_builder.build().map_err(|e| {
            let msg = format!("Failed to parse config from: {}, err: {}", config_path.to_string_lossy(), e);
            log::error!("{msg}");
            anyhow!(msg)
        })
    }
}
