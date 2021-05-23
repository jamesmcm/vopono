use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use super::providers::VpnProvider;
use super::vpn::Protocol;
use std::net::IpAddr;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "vopono",
    about = "Launch applications in a temporary VPN network namespace"
)]
pub struct App {
    /// Verbose output
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(
        name = "exec",
        about = "Execute an application with the given VPN connection"
    )]
    Exec(ExecCommand),
    #[structopt(
        name = "list",
        about = "List running vopono namespaces and applications"
    )]
    List(ListCommand),
    #[structopt(
        name = "sync",
        about = "Synchronise local server lists with VPN providers"
    )]
    Synch(SynchCommand),
    #[structopt(
        name = "servers",
        about = "List possible server configs for VPN provider, beginning with prefix"
    )]
    Servers(ServersCommand),
}

#[derive(StructOpt)]
pub struct SynchCommand {
    /// VPN Provider - will launch interactive menu if not provided
    #[structopt(possible_values = &VpnProvider::variants(), case_insensitive = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Protocol (if not given will try to sync both)
    #[structopt(long = "protocol", short="c", possible_values = &Protocol::variants(), case_insensitive = true)]
    pub protocol: Option<Protocol>,
}

#[derive(StructOpt)]
pub struct ExecCommand {
    /// VPN Provider (must be given unless using custom config)
    #[structopt(long = "provider", short="p", possible_values = &VpnProvider::variants(), case_insensitive = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Protocol (if not given will use default)
    #[structopt(long = "protocol", short="c", possible_values = &Protocol::variants(), case_insensitive = true)]
    pub protocol: Option<Protocol>,

    /// Network Interface (if not given, will use first active network interface)
    #[structopt(long = "interface", short = "i", case_insensitive = true)]
    pub interface: Option<NetworkInterface>,

    /// VPN Server prefix (must be given unless using custom config)
    #[structopt(long = "server", short = "s")]
    pub server: Option<String>,

    /// Application to run (should be on PATH or full path to binary)
    pub application: String,

    /// User with which to run the application (default is current user)
    #[structopt(long = "user", short = "u")]
    pub user: Option<String>,

    /// Custom VPN Provider - OpenVPN or Wireguard config file (will override other settings)
    #[structopt(parse(from_os_str), long = "custom")]
    pub custom_config: Option<PathBuf>,

    /// DNS Server (will override provider's DNS server)
    #[structopt(long = "dns", short = "d")]
    pub dns: Option<Vec<IpAddr>>,

    /// Disable killswitch
    #[structopt(long = "no-killswitch")]
    pub no_killswitch: bool,

    /// Keep-alive - do not close network namespace when launched process terminates
    #[structopt(long = "keep-alive", short = "k")]
    pub keep_alive: bool,

    /// List of ports to open on network namespace (to allow port forwarding through the tunnel,
    /// e.g. for BitTorrent, etc.)
    #[structopt(long = "open-ports", short = "o")]
    pub open_ports: Option<Vec<u16>>,

    /// List of ports to forward from network namespace to host - useful for running servers and daemons
    #[structopt(long = "forward", short = "f")]
    pub forward_ports: Option<Vec<u16>>,

    /// Disable proxying to host machine when forwarding ports
    #[structopt(long = "no-proxy")]
    pub no_proxy: bool,

    /// VPN Protocol (if not given will use default)
    #[structopt(long = "firewall",  possible_values = &Firewall::variants(), case_insensitive = true)]
    pub firewall: Option<Firewall>,

    /// Block all IPv6 traffic
    #[structopt(long = "disable-ipv6")]
    pub disable_ipv6: bool,

    /// Path or alias to executable PostUp script or binary for commands to run on the host after
    /// bringing up the namespace
    #[structopt(long = "postup")]
    pub postup: Option<String>,

    /// Path or alias to executable PreDown script or binary for commands to run on the host after
    /// before shutting down the namespace
    #[structopt(long = "predown")]
    pub predown: Option<String>,

    /// Path to vopono config TOML file (will be created if it does not exist)
    /// Default: ~/.config/vopono/config.toml
    #[structopt(long = "vopono-config")]
    pub vopono_config: Option<PathBuf>,
}

#[derive(StructOpt)]
pub struct ListCommand {
    /// VPN Provider
    #[structopt(possible_values = &["namespaces", "applications"])]
    pub list_type: Option<String>,
}

#[derive(StructOpt)]
pub struct ServersCommand {
    /// VPN Provider
    #[structopt(possible_values = &VpnProvider::variants(), case_insensitive = true)]
    pub vpn_provider: VpnProvider,

    /// VPN Protocol (if not given will list all)
    #[structopt(long = "protocol", short="c", possible_values = &Protocol::variants(), case_insensitive = true)]
    pub protocol: Option<Protocol>,

    /// VPN Server prefix
    #[structopt(long = "prefix", short = "s")]
    pub prefix: Option<String>,
}
