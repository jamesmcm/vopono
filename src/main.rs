mod application_wrapper;
mod args;
mod dns_config;
mod exec;
mod iptables;
mod list;
mod list_configs;
mod netns;
mod network_interface;
mod openvpn;
mod providers;
mod shadowsocks;
mod sync;
mod sysctl;
mod util;
mod veth_pair;
mod vpn;
mod wireguard;

use list::output_list;
use list_configs::print_configs;
use log::LevelFilter;
use netns::NetworkNamespace;
use structopt::StructOpt;
use sync::{sync_menu, synch};
use util::clean_dead_locks;
use util::clean_dead_namespaces;
use util::elevate_privileges;

// TODO:
// - Support update_resolv_conf with OpenVPN (i.e. get DNS server from OpenVPN headers)
// - Disable ipv6 traffic when not routed?
// - Allow for not saving OpenVPN creds to config

fn main() -> anyhow::Result<()> {
    // Get struct of args using structopt
    let app = args::App::from_args();

    // Set up logging
    let mut builder = pretty_env_logger::formatted_timed_builder();
    let log_level = if app.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter_level(log_level);
    builder.init();

    match app.cmd {
        args::Command::Exec(cmd) => {
            clean_dead_locks()?;

            elevate_privileges()?;
            clean_dead_namespaces()?;
            exec::exec(cmd)?
        }
        args::Command::List(listcmd) => {
            clean_dead_locks()?;
            output_list(listcmd)?;
        }
        args::Command::Synch(synchcmd) => {
            elevate_privileges()?;
            // If provider given then sync that, else prompt with menu
            if synchcmd.vpn_provider.is_none() {
                sync_menu()?;
            } else {
                synch(synchcmd.vpn_provider.unwrap(), synchcmd.protocol)?;
            }
        }
        args::Command::Servers(serverscmd) => {
            print_configs(serverscmd)?;
        }
    }
    Ok(())
}
