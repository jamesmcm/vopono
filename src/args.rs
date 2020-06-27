use super::network_interface::NetworkInterface;
use super::vpn::{Protocol, VpnProvider};
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
    Create(ExecCommand),
    #[structopt(name = "init", about = "Initialise vopono configuration")]
    Init,
    #[structopt(
        name = "list",
        about = "List running vopono namespaces and applications"
    )]
    List(ListCommand),
    // #[structopt(
    //     name = "default",
    //     about = "Get or set default VPN provider and server (UNIMPLEMENTED)"
    // )]
    // SetDefaults(SetDefaultsCommand),
}

#[derive(StructOpt)]
pub struct ExecCommand {
    /// VPN Provider (if not given will use default)
    #[structopt(long = "provider", short="p", possible_values = &VpnProvider::variants(), case_insensitive = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Protocol (if not given will use default)
    #[structopt(long = "protocol", short="c", possible_values = &Protocol::variants(), case_insensitive = true)]
    pub protocol: Option<Protocol>,

    /// Network Interface (if not given, will use first active network interface)
    #[structopt(long = "interface", short = "i", case_insensitive = true)]
    pub interface: Option<NetworkInterface>,

    /// VPN Server (if not given will use default)
    #[structopt(long = "server", short = "s")]
    pub server: Option<String>,

    /// Application to run (should be on PATH or full path to binary)
    pub application: String,

    /// User with which to run the application (default is current user)
    #[structopt(long = "user", short = "u")]
    pub user: Option<String>,

    /// Custom VPN Provider - OpenVPN or Wireguard config file
    #[structopt(parse(from_os_str), long = "custom")]
    pub custom_config: Option<PathBuf>,

    /// DNS Server (will override provider's DNS server)
    #[structopt(long = "dns", short = "d")]
    pub dns: Option<Vec<IpAddr>>,
}

#[derive(StructOpt)]
pub struct ListCommand {
    /// VPN Provider (if not given will use default)
    #[structopt(possible_values = &["namespaces", "applications"])]
    pub list_type: Option<String>,
}
// #[derive(StructOpt)]
// pub struct SetDefaultsCommand {
//     #[structopt(long = "provider", short="p", possible_values=&VpnProvider::variants())]
//     pub vpn_provider: Option<VpnProvider>,

//     /// VPN Server (if not given will use default)
//     #[structopt(long = "server", short = "s")]
//     pub server: String,
// }
