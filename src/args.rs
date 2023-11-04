use clap::Parser;
use clap::ValueEnum;
use std::fmt::Display;
use std::net::IpAddr;
use std::path::PathBuf;
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::network::firewall::Firewall;
use vopono_core::network::network_interface::NetworkInterface;

#[derive(Clone)]
pub struct WrappedArg<T: IntoEnumIterator + Clone + Display> {
    variant: T,
}

impl<T: IntoEnumIterator + Clone + Display> WrappedArg<T> {
    pub fn to_variant(&self) -> T {
        self.variant.clone()
    }
}

impl<T: IntoEnumIterator + Clone + Display> ValueEnum for WrappedArg<T> {
    fn from_str(input: &str, ignore_case: bool) -> core::result::Result<Self, String> {
        let use_input = input.trim().to_string();

        let found = if ignore_case {
            T::iter().find(|x| x.to_string().to_ascii_lowercase() == use_input.to_ascii_lowercase())
        } else {
            T::iter().find(|x| x.to_string() == use_input)
        };

        if let Some(f) = found {
            Ok(WrappedArg { variant: f })
        } else {
            // TODO - better error messages
            Err(format!("Invalid argument: {input}"))
        }
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        // TODO: Leak necessary?
        let name: &'static str = Box::leak(self.variant.to_string().into_boxed_str());

        Some(clap::builder::PossibleValue::new(name))
    }

    fn value_variants<'a>() -> &'a [Self] {
        // TODO: Leak necessary?
        Box::leak(Box::new(
            T::iter()
                .map(|x| WrappedArg { variant: x })
                .collect::<Vec<Self>>(),
        ))
    }
}

#[derive(Parser)]
#[clap(
    name = "vopono",
    about = "Launch applications in a temporary VPN network namespace",
    version,
    author
)]
pub struct App {
    /// Verbose output
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// read sudo password from program specified in SUDO_ASKPASS environment variable
    #[clap(short = 'A', long = "askpass")]
    pub askpass: bool,

    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(
        name = "exec",
        about = "Execute an application with the given VPN connection"
    )]
    Exec(ExecCommand),
    #[clap(
        name = "list",
        about = "List running vopono namespaces and applications"
    )]
    List(ListCommand),
    #[clap(
        name = "sync",
        about = "Synchronise local server lists with VPN providers"
    )]
    Synch(SynchCommand),
    #[clap(
        name = "servers",
        about = "List possible server configs for VPN provider, beginning with prefix"
    )]
    Servers(ServersCommand),
}

#[derive(Parser)]
pub struct SynchCommand {
    /// VPN Provider - will launch interactive menu if not provided
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: Option<WrappedArg<VpnProvider>>,

    /// VPN Protocol (if not given will try to sync both)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,
}

#[derive(Parser)]
pub struct ExecCommand {
    /// VPN Provider (must be given unless using custom config)
    #[clap(value_enum, long = "provider", short = 'p', ignore_case = true)]
    pub vpn_provider: Option<WrappedArg<VpnProvider>>,

    /// VPN Protocol (if not given will use default)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,

    /// Network Interface (if not given, will use first active network interface)
    #[clap(long = "interface", short = 'i', ignore_case = true)]
    pub interface: Option<NetworkInterface>,

    /// VPN Server prefix (must be given unless using custom config)
    #[clap(long = "server", short = 's')]
    pub server: Option<String>,

    /// Application to run (should be on PATH or full path to binary)
    pub application: String,

    /// User with which to run the application (default is current user)
    #[clap(long = "user", short = 'u')]
    pub user: Option<String>,

    /// Group with which to run the application
    #[clap(long = "group", short = 'g')]
    pub group: Option<String>,

    /// Working directory in which to run the application (default is current working directory)
    #[clap(long = "working-directory", short = 'w')]
    pub working_directory: Option<String>,

    /// Custom VPN Provider - OpenVPN or Wireguard config file (will override other settings)
    // TODO: Check From OsStr part works
    #[clap(long = "custom")]
    pub custom_config: Option<PathBuf>,

    /// DNS Server (will override provider's DNS server)
    #[clap(long = "dns", short = 'd')]
    pub dns: Option<Vec<IpAddr>>,

    /// List of /etc/hosts entries for the network namespace (e.g. "10.0.1.10 webdav.server01.lan","10.0.1.10 vaultwarden.server01.lan"). For a local host you should also provide the open-hosts option.
    #[clap(long = "hosts", use_value_delimiter = true)]
    pub hosts_entries: Option<Vec<String>>,

    /// List of host IP addresses to open on the network namespace (comma separated)
    #[clap(long = "open-hosts", use_value_delimiter = true)]
    pub open_hosts: Option<Vec<IpAddr>>,

    /// Disable killswitch
    #[clap(long = "no-killswitch")]
    pub no_killswitch: bool,

    /// Keep-alive - do not close network namespace when launched process terminates
    #[clap(long = "keep-alive", short = 'k')]
    pub keep_alive: bool,

    /// List of ports to open on network namespace (to allow port forwarding through the tunnel,
    /// e.g. for BitTorrent, etc.)
    #[clap(long = "open-ports", short = 'o')]
    pub open_ports: Option<Vec<u16>>,

    /// List of ports to forward from network namespace to host - useful for running servers and daemons
    #[clap(long = "forward", short = 'f')]
    pub forward_ports: Option<Vec<u16>>,

    /// Disable proxying to host machine when forwarding ports
    #[clap(long = "no-proxy")]
    pub no_proxy: bool,

    /// VPN Protocol (if not given will use default)
    #[clap(value_enum, long = "firewall", ignore_case = true)]
    pub firewall: Option<WrappedArg<Firewall>>,

    /// Block all IPv6 traffic
    #[clap(long = "disable-ipv6")]
    pub disable_ipv6: bool,

    /// Path or alias to executable PostUp script or binary for commands to run on the host after
    /// bringing up the namespace
    #[clap(long = "postup")]
    pub postup: Option<String>,

    /// Path or alias to executable PreDown script or binary for commands to run on the host after
    /// before shutting down the namespace
    #[clap(long = "predown")]
    pub predown: Option<String>,

    /// Path to vopono config TOML file (will be created if it does not exist)
    /// Default: ~/.config/vopono/config.toml
    #[clap(long = "vopono-config")]
    pub vopono_config: Option<PathBuf>,

    /// Custom name for the generated network namespace
    /// Will use this network namespace directly if it exists
    #[clap(long = "custom-netns-name")]
    pub custom_netns_name: Option<String>,
    /// Allow access to host from network namespace
    /// Useful for accessing services on the host locally
    #[clap(long = "allow-host-access")]
    pub allow_host_access: bool,

    /// Enable port forwarding for ProtonVPN connections
    #[clap(long = "protonvpn-port-forwarding")]
    pub protonvpn_port_forwarding: bool,
}

#[derive(Parser)]
pub struct ListCommand {
    /// VPN Provider
    #[clap(value_parser(clap::builder::PossibleValuesParser::from(&["namespaces", "applications"])))]
    pub list_type: Option<String>,
}

#[derive(Parser)]
pub struct ServersCommand {
    /// VPN Provider
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: WrappedArg<VpnProvider>,

    /// VPN Protocol (if not given will list all)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,

    /// VPN Server prefix
    #[clap(long = "prefix", short = 's')]
    pub prefix: Option<String>,
}
