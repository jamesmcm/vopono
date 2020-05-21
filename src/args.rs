use super::vpn::VpnProvider;
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

    #[structopt(name = "default", about = "Get or set default VPN provider and server")]
    SetDefaults(SetDefaultsCommand),
}

#[derive(StructOpt)]
pub struct ExecCommand {
    /// VPN Provider (if not given will use default)
    #[structopt(long = "provider", short="p", possible_values = &VpnProvider::variants(), case_insensitive = true)]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Server (if not given will use default)
    #[structopt(long = "server", short = "s")]
    pub server: Option<String>,

    #[structopt(short, long)]
    pub application: String,
}

#[derive(StructOpt)]
pub struct SetDefaultsCommand {
    #[structopt(long = "provider", short="p", possible_values=&["pia"])]
    pub vpn_provider: Option<VpnProvider>,

    /// VPN Server (if not given will use default)
    #[structopt(long = "server", short = "s")]
    pub server: String,
}
