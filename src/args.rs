use clap::Parser;
use clap::ValueEnum;
use serde::{Deserialize, Serialize}; // Import serde traits
use std::fmt::{Debug, Display}; // Import Debug
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::network::firewall::Firewall;
use vopono_core::network::network_interface::NetworkInterface;
use vopono_core::network::trojan::TrojanHost;
use vopono_core::util::hostname_to_ip;

#[derive(Clone, Debug)]
pub struct WrappedArg<T: IntoEnumIterator + Clone + Display> {
    variant: T,
}

// Manual implementation of Serialize/Deserialize to act as a transparent wrapper.
impl<T> Serialize for WrappedArg<T>
where
    T: IntoEnumIterator + Clone + Display + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.variant.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for WrappedArg<T>
where
    T: IntoEnumIterator + Clone + Display + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|variant| WrappedArg { variant })
    }
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
            T::iter().find(|x| x.to_string().eq_ignore_ascii_case(&use_input))
        } else {
            T::iter().find(|x| x.to_string() == use_input)
        };
        if let Some(f) = found {
            Ok(WrappedArg { variant: f })
        } else {
            Err(format!("Invalid argument: {input}"))
        }
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        let name: &'static str = Box::leak(self.variant.to_string().into_boxed_str());
        Some(clap::builder::PossibleValue::new(name))
    }

    fn value_variants<'a>() -> &'a [Self] {
        Box::leak(Box::new(
            T::iter()
                .map(|x| WrappedArg { variant: x })
                .collect::<Vec<Self>>(),
        ))
    }
}

#[derive(Parser, Debug)]
#[clap(
    name = "vopono",
    about = "Launch applications in a temporary VPN network namespace",
    version,
    author
)]
pub struct App {
    /// Verbose output
    #[clap(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    /// Suppress all output including application output.
    #[clap(long = "silent", global = true)]
    pub silent: bool,

    /// read sudo password from program specified in SUDO_ASKPASS environment variable
    #[clap(short = 'A', long = "askpass", global = true)]
    pub askpass: bool,

    #[clap(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Parser, Debug)]
pub enum Command {
    #[clap(name = "daemon", about = "Run the vopono daemon (requires root)")]
    Daemon,
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

#[derive(Parser, Debug)]
pub struct SynchCommand {
    /// VPN Provider - will launch interactive menu if not provided
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: Option<WrappedArg<VpnProvider>>,

    /// VPN Protocol (if not given will try to sync both)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,
}

#[derive(Parser, Clone, Serialize, Deserialize, Debug)]
pub struct ExecCommand {
    /// VPN Provider (must be given unless using custom config)
    #[clap(value_enum, long = "provider", short = 'p', ignore_case = true)]
    pub provider: Option<WrappedArg<VpnProvider>>,

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
    #[clap(long = "custom")]
    pub custom: Option<PathBuf>,

    /// DNS Server (will override provider's DNS server)
    #[clap(long = "dns", short = 'd')]
    pub dns: Option<Vec<IpAddr>>,

    /// List of /etc/hosts entries for the network namespace (e.g. "10.0.1.10 webdav.server01.lan","10.0.1.10 vaultwarden.server01.lan"). For a local host you should also provide the open-hosts option.
    #[clap(long = "hosts", use_value_delimiter = true)]
    pub hosts: Option<Vec<String>>,

    /// List of hostnames or IP addresses to open on the network namespace (comma separated)
    /// hostnames will be resolved locally to IP addresses
    #[clap(
        long = "open-hosts",
        use_value_delimiter = true,
        value_parser(parse_hosts_or_ips)
    )]
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
    pub forward: Option<Vec<u16>>,

    /// Disable proxying to host machine when forwarding ports
    #[clap(long = "no-proxy")]
    pub no_proxy: bool,

    /// Firewall to use
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

    /// Enable port forwarding for if supported
    #[clap(long = "port-forwarding")]
    pub port_forwarding: bool,

    /// Port forwarding implementation to use for custom config file with --custom-config
    #[clap(long = "custom-port-forwarding", ignore_case = true)]
    pub custom_port_forwarding: Option<WrappedArg<VpnProvider>>,

    /// Path or alias to executable script or binary to be called with the port as an argumnet
    /// when the port forwarding is refreshed (PIA only)
    #[clap(long = "port-forwarding-callback")]
    pub port_forwarding_callback: Option<String>,

    /// Only create network namespace (does not run application)
    #[clap(long = "create-netns-only")]
    pub create_netns_only: bool,

    /// Trojan server address - hostname or IP, will not verify SSL if IP address is given.
    /// Port is optional (default is 443).
    #[clap(long = "trojan-host")]
    pub trojan_host: Option<TrojanHost>,

    /// Trojan server password
    /// Set this in ~/.config/vopono/vopono.toml or use --trojan-config
    /// to avoid setting this in the command line
    #[clap(long = "trojan-password")]
    pub trojan_password: Option<String>,

    /// Disable SSL verification for Trojan server
    #[clap(long = "trojan-no-verify")]
    pub trojan_no_verify: bool,

    /// Trojan config file (will override other settings)
    #[clap(long = "trojan-config")]
    pub trojan_config: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ListCommand {
    /// VPN Provider
    #[clap(value_parser(clap::builder::PossibleValuesParser::from(&["namespaces", "applications"])))]
    pub list_type: Option<String>,
}

#[derive(Parser, Debug)]
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

fn parse_host_or_ip(arg: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = IpAddr::from_str(arg) {
        return Ok(ip);
    }

    Ok(hostname_to_ip(arg)?
        .into_iter()
        .next()
        .expect("Failed to resolve hostname"))
}

/// Parse a list of hosts/IPs separated by comma
fn parse_hosts_or_ips(arg: &str) -> anyhow::Result<IpAddr> {
    parse_host_or_ip(arg.trim()).map_err(|e| anyhow::anyhow!("Failed to parse host or IP: {}", e))
}
