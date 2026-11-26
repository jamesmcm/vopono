// Handles using the args from either the CLI or config file

use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, anyhow};
use clap::ValueEnum;
use config::Config;
use log::warn;
use vopono_core::{
    config::{providers::VpnProvider, vpn::Protocol},
    network::{
        firewall::Firewall,
        network_interface::{NetworkInterface, get_active_interfaces, interface_has_default_route},
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
        $command
            .$field_id
            .map(|x| x.to_variant())
            .or_else(|| config_variant(&$config, stringify!($field_id)))
    };
}

fn config_variant<T>(config: &Config, name: &str) -> Option<T>
where
    T: strum::IntoEnumIterator + Clone + std::fmt::Display + Send + Sync + 'static,
{
    config
        .get_string(name)
        .or_else(|_| config.get_string(&name.replace('_', "-")))
        .ok()
        .and_then(|value| crate::args::WrappedArg::<T>::from_str(&value, true).ok())
        .map(|value| value.to_variant())
}

macro_rules! error_and_bail {
    // log to error and bail
    ($msg:literal) => {
        log::error!("{}", $msg);
        return Err(vopono_core::diagnostics::SetupError::Configuration($msg).into());
    };
}

/// Expand `~` and `$VAR` using the invoking user's home/environment instead of
/// root's when running inside the daemon.
pub(crate) fn expand_user_str(
    input: &str,
    user_name: Option<&str>,
    client_env: Option<&std::collections::HashMap<String, String>>,
) -> anyhow::Result<String> {
    let home = if vopono_core::util::is_daemon_mode() {
        user_name
            .and_then(|name| nix::unistd::User::from_name(name).ok().flatten())
            .map(|user| user.dir.to_string_lossy().into_owned())
            .or_else(|| client_env.and_then(|env| env.get("HOME").cloned()))
    } else {
        std::env::var("HOME").ok()
    };
    let expanded = shellexpand::full_with_context(
        input,
        || home.clone(),
        |var| -> Result<Option<String>, std::env::VarError> {
            if let Some(env) = client_env {
                Ok(env.get(var).cloned())
            } else if vopono_core::util::is_daemon_mode() {
                // Never expand root daemon environment variables for client config values.
                Ok(None)
            } else {
                match std::env::var(var) {
                    Ok(value) => Ok(Some(value)),
                    Err(std::env::VarError::NotPresent) => Ok(None),
                    Err(err) => Err(err),
                }
            }
        },
    )?;
    Ok(expanded.into_owned())
}

/// Connection selection shared by execution, launch diagnostics and MCP doctor.
/// Profile overlays are applied before this type reads CLI/config precedence.
#[derive(Debug)]
pub(crate) struct ConnectionSettings {
    pub provider: Option<VpnProvider>,
    pub protocol: Option<Protocol>,
    pub server: Option<String>,
    pub custom: Option<PathBuf>,
}
impl ConnectionSettings {
    pub fn read(command: &ExecCommand, config: &Config) -> anyhow::Result<Self> {
        Self::read_with_env(command, config, None)
    }

    pub fn read_with_env(
        command: &ExecCommand,
        config: &Config,
        client_env: Option<&std::collections::HashMap<String, String>>,
    ) -> anyhow::Result<Self> {
        let cli_provider = command.provider.as_ref().map(|p| p.to_variant());
        // Only inherit `custom` from config when CLI did not explicitly choose a
        // non-Custom provider (e.g., `--provider mullvad` or `--existing-netns`).
        let custom: Option<PathBuf> = if command.existing_netns.is_some() {
            None
        } else if command.custom.is_some() {
            command.custom.clone()
        } else if cli_provider
            .as_ref()
            .is_some_and(|provider| *provider != VpnProvider::Custom)
        {
            None
        } else {
            config
                .get::<PathBuf>("custom")
                .ok()
                .filter(|path| !path.as_os_str().is_empty())
        };
        let custom = custom
            .map(|path| {
                expand_user_str(&path.to_string_lossy(), command.user.as_deref(), client_env)
                    .map(PathBuf::from)
                    .map_err(|_| {
                        vopono_core::diagnostics::SetupError::Configuration(
                            "Could not expand the custom configuration path",
                        )
                    })
            })
            .transpose()?;
        let protocol = command
            .protocol
            .as_ref()
            .map(|p| p.to_variant())
            .or_else(|| config_variant(config, "protocol"));
        let provider = if custom.is_some() {
            Some(VpnProvider::Custom)
        } else {
            cli_provider
                .or_else(|| config_variant(config, "provider"))
                .or_else(|| (protocol == Some(Protocol::Ssh)).then_some(VpnProvider::Custom))
        };
        let protocol = if provider == Some(VpnProvider::None) {
            Some(Protocol::None)
        } else {
            protocol
        };
        Ok(Self {
            provider,
            protocol,
            server: command_else_config_option!(server, command, config),
            custom,
        })
    }

    pub fn detected_protocol(&self) -> anyhow::Result<Protocol> {
        if let Some(protocol) = &self.protocol {
            return Ok(protocol.clone());
        }
        if let Some(path) = &self.custom {
            return get_config_file_protocol(path).map_err(|_| {
                vopono_core::diagnostics::SetupError::Configuration(
                    "Could not detect the custom VPN protocol; check the file or specify --protocol"
                ).into()
            });
        }
        match self.provider.as_ref() {
            Some(VpnProvider::None | VpnProvider::Custom) => Ok(Protocol::None),
            Some(provider) => Ok(provider.get_dyn_provider().default_protocol()),
            None => Err(vopono_core::diagnostics::SetupError::Configuration(
                "Enter a VPN provider as a command-line argument or in the vopono config.toml file",
            )
            .into()),
        }
    }

    fn for_execution(&self) -> anyhow::Result<(VpnProvider, Protocol, String)> {
        use vopono_core::diagnostics::SetupError;
        let provider = self.provider.clone().ok_or(SetupError::Configuration(
            "Enter a VPN provider as a command-line argument or in the vopono config.toml file",
        ))?;
        let protocol = self.detected_protocol()?;
        if provider == VpnProvider::Custom && self.custom.is_none() && protocol != Protocol::Ssh {
            return Err(SetupError::Configuration(
                "Must provide config file if using custom VPN Provider",
            )
            .into());
        }
        let server = if let Some(path) = &self.custom {
            if protocol == Protocol::Ssh {
                self.server.clone().ok_or(SetupError::Configuration(
                    "SSH server or OpenSSH host alias must be provided with --server",
                ))?
            } else if protocol == Protocol::OpenConnect {
                self.server.clone().unwrap_or_default()
            } else {
                path.file_stem()
                    .and_then(|name| name.to_str())
                    .ok_or(SetupError::Configuration(
                        "Custom configuration must have a UTF-8 filename",
                    ))?
                    .to_owned()
            }
        } else {
            self.server.clone().or_else(|| provider.default_server()).ok_or(SetupError::Configuration(
                "VPN server prefix must be provided as a command-line argument or in the vopono config.toml file"
            ))?
        };
        if (provider == VpnProvider::Warp) != (protocol == Protocol::Warp)
            || (provider == VpnProvider::None) != (protocol == Protocol::None)
            || (protocol == Protocol::Ssh && provider != VpnProvider::Custom)
        {
            return Err(SetupError::ProtocolNotSupported { provider, protocol }.into());
        }
        Ok((provider, protocol, server))
    }

    pub fn doctor_command(&self, offline: bool) -> Vec<String> {
        let mut args = vec![
            "doctor".into(),
            "--json".into(),
            "--timeout-ms".into(),
            "500".into(),
        ];
        if let Some(path) = &self.custom {
            args.push(format!("--custom={}", path.to_string_lossy()));
        } else if let Some(provider) = &self.provider {
            args.push(format!("--provider={}", provider.id()));
            if let Some(server) = &self.server {
                args.push(format!("--server={server}"));
            }
        }
        if (self.custom.is_some() || self.provider.is_some())
            && let Some(protocol) = &self.protocol
        {
            args.push(format!("--protocol={}", protocol.id()));
        }
        if offline {
            args.push("--offline".into());
        }
        args
    }
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
    pub auth_user_pass: Option<PathBuf>,
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
    pub ssh_proxy_port: u16,
    pub ssh_user: Option<String>,
    pub ssh_port: Option<u16>,
    /// Emit a machine-readable launch report on stdout.
    pub json: bool,
}

impl ArgsConfig {
    /// Return new ExecCommand with args from config file if missing in CLI but present there
    /// Also handle CLI args consistency errors
    pub fn get_cli_or_config_args(command: ExecCommand, config: Config) -> anyhow::Result<Self> {
        Self::get_cli_or_config_args_with_env(command, config, None)
    }

    pub fn get_cli_or_config_args_with_env(
        command: ExecCommand,
        config: Config,
        client_env: Option<&std::collections::HashMap<String, String>>,
    ) -> anyhow::Result<Self> {
        // TODO: Automate field mapping with procedural macro over ExecCommand struct?
        let user_for_expand = command.user.clone();
        let connection = ConnectionSettings::read_with_env(&command, &config, client_env)?;
        let custom = connection.custom.clone();
        let auth_user_pass =
            command_else_config_option!(auth_user_pass, command, config).map(|p| {
                let raw = p.to_string_lossy();
                expand_user_str(&raw, user_for_expand.as_deref(), client_env)
                    .map(PathBuf::from)
                    .unwrap_or(p)
            });

        let application = if !command.create_netns_only
            && command.application.is_empty()
            && command.profile.is_some()
        {
            config
                .get_string("application")
                .map_err(|_| anyhow!("Named profile requires an application"))?
        } else {
            command.application.clone()
        };
        anyhow::ensure!(
            !application.is_empty() || command.create_netns_only,
            vopono_core::diagnostics::SetupError::Configuration(
                "An application or --profile is required (except with --create-netns-only)"
            )
        );
        let application: String = if command.literal_application {
            application
        } else {
            expand_user_str(&application, user_for_expand.as_deref(), client_env)
                .context("Failed to expand the application command")?
        };
        let custom_netns_name = command_else_config_option!(custom_netns_name, command, config);
        let open_hosts = command_else_config_option!(open_hosts, command, config);
        let hosts = command_else_config_option!(hosts, command, config);
        let open_ports = command_else_config_option!(open_ports, command, config);
        let forward = command_else_config_option!(forward, command, config);
        let postup = command_else_config_option!(postup, command, config)
            .map(|p| expand_user_str(&p, user_for_expand.as_deref(), client_env).unwrap_or(p));
        let predown = command_else_config_option!(predown, command, config)
            .map(|p| expand_user_str(&p, user_for_expand.as_deref(), client_env).unwrap_or(p));
        let group = command_else_config_option!(group, command, config);
        let working_directory = command_else_config_option!(working_directory, command, config)
            .map(|p| expand_user_str(&p, user_for_expand.as_deref(), client_env).unwrap_or(p));
        let dns = command_else_config_option!(dns, command, config);
        let user = command_else_config_option!(user, command, config)
            .or_else(|| std::env::var("SUDO_USER").ok());
        let port_forwarding_callback =
            command_else_config_option!(port_forwarding_callback, command, config)
                .map(|p| expand_user_str(&p, user_for_expand.as_deref(), client_env).unwrap_or(p));

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
                        active_interfaces,
                        active_interfaces[0]
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
        log::debug!("Interface: {}", interface.name);
        match interface_has_default_route(&interface.name) {
            Ok(true) => {}
            Ok(false) => warn!(
                "Selected network interface '{}' has no default route. This can happen with a stale interface value in vopono config and may prevent namespace connectivity.",
                interface.name
            ),
            Err(e) => warn!(
                "Could not verify connectivity for selected network interface '{}': {e}",
                interface.name
            ),
        }

        let (provider, protocol, server) = connection.for_execution()?;

        // TODO: Error handling
        let trojan_host = command_else_config_option!(trojan_host, command, config);

        let trojan_password = command_else_config_option!(trojan_password, command, config);
        let trojan_no_verify = command_else_config_bool!(trojan_no_verify, command, config);
        let trojan_config = command_else_config_option!(trojan_config, command, config).map(|p| {
            let raw = p.to_string_lossy();
            expand_user_str(&raw, user_for_expand.as_deref(), client_env)
                .map(PathBuf::from)
                .unwrap_or(p)
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

        let ssh_proxy_port = command
            .ssh_proxy_port
            .or_else(|| config.get("ssh_proxy_port").ok())
            .or_else(|| config.get("ssh-proxy-port").ok())
            .unwrap_or(1080);
        let ssh_user = command
            .ssh_user
            .or_else(|| config.get("ssh_user").ok())
            .or_else(|| config.get("ssh-user").ok());
        let ssh_port = command
            .ssh_port
            .or_else(|| config.get("ssh_port").ok())
            .or_else(|| config.get("ssh-port").ok());

        let json = command_else_config_bool!(json, command, config);

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
            auth_user_pass,
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
            ssh_proxy_port,
            ssh_user,
            ssh_port,
            json,
        })
    }

    /// Read vopono config file to Config struct
    pub fn get_config_file(command: &ExecCommand) -> anyhow::Result<Config> {
        let is_daemon = vopono_core::util::is_daemon_mode();
        let explicit_config = command.vopono_config.is_some();
        let default_config_path = if is_daemon {
            // Avoid probing fs::exists() as root in daemon mode; the unprivileged
            // helper attempts the read below and treats ENOENT as absent.
            vopono_dir().map(|p| p.join("config.toml")).ok()
        } else {
            vopono_dir()
                .map(|p| p.join("config.toml"))
                .ok()
                .filter(|v| fs::exists(v).unwrap_or(false))
        };

        let mut config_path = command.vopono_config.clone().or(default_config_path);
        let mut vopono_config_settings_builder = config::Config::builder();

        if let Some(path) = &mut config_path {
            if is_daemon {
                use config::FileFormat;
                const FORMATS: &[(&str, FileFormat)] = &[
                    ("toml", FileFormat::Toml),
                    ("json", FileFormat::Json),
                    ("yaml", FileFormat::Yaml),
                    ("yml", FileFormat::Yaml),
                    ("ini", FileFormat::Ini),
                    ("ron", FileFormat::Ron),
                    ("json5", FileFormat::Json5),
                ];
                // Read strictly through the privilege-dropped helper (never probing
                // path.is_file() as root) so daemon mode cannot act as an existence oracle.
                let ext_format = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .and_then(|ext| {
                        FORMATS
                            .iter()
                            .find_map(|(name, fmt)| (*name == ext).then_some(*fmt))
                    });
                let read_result: anyhow::Result<Option<(Vec<u8>, FileFormat)>> =
                    if let Some(format) = ext_format {
                        match vopono_core::util::owner_write::read_file_as_config_owner(path) {
                            Ok(bytes) => Ok(Some((bytes, format))),
                            Err(err)
                                if !explicit_config
                                    && (err.chain().any(|cause| {
                                        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                            io.kind() == std::io::ErrorKind::NotFound
                                        })
                                    }) || format!("{err:#}")
                                        .contains("No such file or directory")) =>
                            {
                                Ok(None)
                            }
                            Err(_) => Err(anyhow::Error::new(
                                vopono_core::diagnostics::Diagnostic::new(
                                    vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                                    vopono_core::diagnostics::DiagnosticState::Fail,
                                    &format!(
                                        "Could not read the vopono configuration file {}",
                                        path.display()
                                    ),
                                    Some("Check that the file exists and is readable by your user"),
                                ),
                            )),
                        }
                    } else {
                        let mut found = None;
                        for (ext, format) in FORMATS {
                            let mut candidate = path.as_os_str().to_owned();
                            candidate.push(format!(".{ext}"));
                            let candidate = PathBuf::from(candidate);
                            if let Ok(bytes) =
                                vopono_core::util::owner_write::read_file_as_config_owner(
                                    &candidate,
                                )
                            {
                                *path = candidate;
                                found = Some((bytes, *format));
                                break;
                            }
                        }
                        if let Some(result) = found {
                            Ok(Some(result))
                        } else {
                            Err(anyhow::Error::new(
                                vopono_core::diagnostics::Diagnostic::new(
                                    vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                                    vopono_core::diagnostics::DiagnosticState::Fail,
                                    &format!(
                                        "Could not read or find the vopono configuration file {}",
                                        path.display()
                                    ),
                                    Some("Check the file path, extension and read permissions"),
                                ),
                            ))
                        }
                    };
                if let Some((bytes, format)) = read_result? {
                    let content = String::from_utf8(bytes).map_err(|_| {
                        anyhow::Error::new(vopono_core::diagnostics::Diagnostic::new(
                            vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                            vopono_core::diagnostics::DiagnosticState::Fail,
                            &format!(
                                "Vopono configuration {} must be valid UTF-8",
                                path.display()
                            ),
                            Some("Ensure the configuration file is UTF-8 encoded"),
                        ))
                    })?;
                    vopono_config_settings_builder = vopono_config_settings_builder
                        .add_source(config::File::from_str(&content, format));
                }
            } else {
                vopono_config_settings_builder =
                    vopono_config_settings_builder.add_source(config::File::from(path.clone()));
            }
        }

        let settings = vopono_config_settings_builder.build().map_err(|error| {
            let path = config_path
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("config.toml"));
            // Include only the first summary line (e.g., line/column location) without
            // echoing raw file snippets that could contain secrets.
            let summary = error
                .to_string()
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .chars()
                .take(160)
                .collect::<String>();
            let message = if summary.is_empty() {
                format!(
                    "Could not read or parse the vopono configuration file {}",
                    path.display()
                )
            } else {
                format!(
                    "Could not read or parse the vopono configuration file {}: {summary}",
                    path.display()
                )
            };
            anyhow::Error::new(vopono_core::diagnostics::Diagnostic::new(
                vopono_core::diagnostics::DiagnosticCode::ProviderConfig,
                vopono_core::diagnostics::DiagnosticState::Fail,
                &message,
                Some("Check that the file is readable and its syntax matches the file extension"),
            ))
        })?;
        crate::profiles::select(settings, command.profile.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::ArgsConfig;
    use crate::args::{App, Command};
    use clap::Parser;
    use config::Config;
    use std::path::Path;

    #[test]
    fn connection_selection_is_shared_and_honors_cli_and_profile_precedence() {
        let config = Config::builder().add_source(config::File::from_str(
            "provider='mullvad'\nprotocol='wireguard'\nserver='se'\n[profiles.custom]\ncustom='/tmp/client.ovpn'\nprotocol='openvpn'\n",
            config::FileFormat::Toml,
        )).build().unwrap();
        let config = crate::profiles::select(config, Some("custom")).unwrap();
        for (explicit, expected) in [
            (None, vopono_core::config::vpn::Protocol::OpenVpn),
            (
                Some("wireguard"),
                vopono_core::config::vpn::Protocol::Wireguard,
            ),
        ] {
            let mut argv = vec!["vopono", "exec", "--profile", "custom"];
            if let Some(protocol) = explicit {
                argv.extend(["--protocol", protocol]);
            }
            let Some(Command::Exec(command)) = App::try_parse_from(argv).unwrap().cmd else {
                unreachable!()
            };
            let settings = super::ConnectionSettings::read(&command, &config).unwrap();
            let (provider, protocol, _) = settings.for_execution().unwrap();
            assert_eq!(
                provider,
                vopono_core::config::providers::VpnProvider::Custom
            );
            assert_eq!(protocol, expected);
            let args = settings.doctor_command(true);
            assert!(args.iter().any(|arg| arg == "--custom=/tmp/client.ovpn"));
            assert!(
                !args
                    .iter()
                    .any(|arg| arg.starts_with("--provider") || arg.starts_with("--server"))
            );
            assert!(
                args.iter()
                    .any(|arg| arg == &format!("--protocol={}", expected.id()))
            );
        }
    }

    #[test]
    fn global_custom_does_not_override_cli_provider_or_provider_profile() {
        let raw_config = Config::builder()
            .add_source(config::File::from_str(
                "custom='/tmp/global.ovpn'\nprotocol='openvpn'\n[profiles.mullvad_se]\nprovider='mullvad'\nprotocol='wireguard'\nserver='se'\n",
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();

        // Explicit CLI --provider overrides global custom.
        let Some(Command::Exec(cli_cmd)) = App::try_parse_from([
            "vopono",
            "exec",
            "--provider",
            "mullvad",
            "--server",
            "se",
            "true",
        ])
        .unwrap()
        .cmd
        else {
            unreachable!()
        };
        let cli_settings = super::ConnectionSettings::read(&cli_cmd, &raw_config).unwrap();
        assert!(cli_settings.custom.is_none());
        let (provider, _, server) = cli_settings.for_execution().unwrap();
        assert_eq!(
            provider,
            vopono_core::config::providers::VpnProvider::Mullvad
        );
        assert_eq!(server, "se");

        // Profile with explicit provider suppresses global custom.
        let selected = crate::profiles::select(raw_config, Some("mullvad_se")).unwrap();
        let Some(Command::Exec(profile_cmd)) =
            App::try_parse_from(["vopono", "exec", "--profile", "mullvad_se", "true"])
                .unwrap()
                .cmd
        else {
            unreachable!()
        };
        let profile_settings = super::ConnectionSettings::read(&profile_cmd, &selected).unwrap();
        assert!(profile_settings.custom.is_none());
        let (provider, protocol, server) = profile_settings.for_execution().unwrap();
        assert_eq!(
            provider,
            vopono_core::config::providers::VpnProvider::Mullvad
        );
        assert_eq!(protocol, vopono_core::config::vpn::Protocol::Wireguard);
        assert_eq!(server, "se");
    }

    fn custom_openvpn_command(auth_user_pass: Option<&str>) -> crate::args::ExecCommand {
        let mut args = vec![
            "vopono",
            "exec",
            "--custom",
            "vpn.ovpn",
            "--protocol",
            "openvpn",
            "--interface",
            "lo",
        ];
        if let Some(auth_user_pass) = auth_user_pass {
            args.extend(["--auth-user-pass", auth_user_pass]);
        }
        args.push("firefox");

        let app = App::try_parse_from(args).unwrap();
        let Command::Exec(command) = app.cmd.unwrap() else {
            panic!("expected exec command");
        };
        command
    }

    fn config_with_auth_path(path: &str) -> Config {
        Config::builder()
            .set_override("auth-user-pass", path)
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn cli_auth_user_pass_overrides_config_file() {
        let args = ArgsConfig::get_cli_or_config_args(
            custom_openvpn_command(Some("cli-auth.txt")),
            config_with_auth_path("config-auth.txt"),
        )
        .unwrap();

        assert_eq!(
            args.auth_user_pass,
            Some(Path::new("cli-auth.txt").to_path_buf())
        );
    }

    #[test]
    fn config_file_provides_auth_user_pass_when_cli_omits_it() {
        let args = ArgsConfig::get_cli_or_config_args(
            custom_openvpn_command(None),
            config_with_auth_path("config-auth.txt"),
        )
        .unwrap();

        assert_eq!(
            args.auth_user_pass,
            Some(Path::new("config-auth.txt").to_path_buf())
        );
    }

    #[test]
    fn profile_enum_values_accept_cli_spellings_and_literal_argv_is_not_expanded() {
        let app = App::try_parse_from([
            "vopono",
            "exec",
            "--interface",
            "lo",
            "--profile",
            "agent",
            "printf '$HOME' '$VOPONO_UNSET_MCP_LITERAL'",
        ])
        .unwrap();
        let Command::Exec(mut command) = app.cmd.unwrap() else {
            unreachable!()
        };
        command.literal_application = true;
        let config = Config::builder()
            .add_source(config::File::from_str(
                "[profiles.agent]\nprovider='none'\nprotocol='none'\nfirewall='nftables'\n",
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let config = crate::profiles::select(config, Some("agent")).unwrap();
        let args = ArgsConfig::get_cli_or_config_args(command, config).unwrap();
        assert_eq!(
            args.provider,
            vopono_core::config::providers::VpnProvider::None
        );
        assert_eq!(args.protocol, vopono_core::config::vpn::Protocol::None);
        assert_eq!(
            args.firewall,
            vopono_core::network::firewall::Firewall::NfTables
        );
        assert_eq!(
            vopono_core::util::parse_command_str(&args.application).unwrap(),
            ["printf", "$HOME", "$VOPONO_UNSET_MCP_LITERAL"]
        );
    }
}
