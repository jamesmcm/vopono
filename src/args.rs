use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use super::providers::VpnProvider;
use super::vpn::Protocol;
use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

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
    #[clap(arg_enum, ignore_case = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Protocol (if not given will try to sync both)
    #[clap(arg_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<Protocol>,
}

#[derive(Parser)]
pub struct ExecCommand {
    /// VPN Provider (must be given unless using custom config)
    #[clap(arg_enum, long = "provider", short = 'p', ignore_case = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Protocol (if not given will use default)
    #[clap(arg_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<Protocol>,

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

    /// Custom VPN Provider - OpenVPN or Wireguard config file (will override other settings)
    #[clap(parse(from_os_str), long = "custom")]
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
    #[clap(arg_enum, long = "firewall", ignore_case = true)]
    pub firewall: Option<Firewall>,

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
}

#[derive(Parser)]
pub struct ListCommand {
    /// VPN Provider
    #[clap(possible_values = &["namespaces", "applications"])]
    pub list_type: Option<String>,
}

#[derive(Parser)]
pub struct ServersCommand {
    /// VPN Provider
    #[clap(arg_enum, ignore_case = true)]
    pub vpn_provider: VpnProvider,

    /// VPN Protocol (if not given will list all)
    #[clap(arg_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<Protocol>,

    /// VPN Server prefix
    #[clap(long = "prefix", short = 's')]
    pub prefix: Option<String>,
}
