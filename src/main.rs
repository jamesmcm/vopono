#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]
#![allow(dead_code)]

mod args;
mod args_config;
mod cli_client;
mod exec;
mod list;
mod list_configs;
mod sync;

use clap::Parser;
use cli_client::CliClient;
use list::output_list;
use list_configs::print_configs;
use log::{debug, warn, LevelFilter};
use sync::{sync_menu, synch};
use vopono_core::util::clean_dead_locks;
use vopono_core::util::clean_dead_namespaces;
use vopono_core::util::elevate_privileges;
use which::which;

fn main() -> anyhow::Result<()> {
    // Get struct of args using structopt
    let app = args::App::parse();
    // Set up logging
    let mut builder = pretty_env_logger::formatted_timed_builder();
    let log_level = if app.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter_level(log_level);
    builder.init();

    let uiclient = CliClient {};
    match app.cmd {
        args::Command::Exec(cmd) => {
            clean_dead_locks()?;
            if which("pactl").is_ok() {
                let pa = vopono_core::util::pulseaudio::get_pulseaudio_server();
                if let Ok(pa) = pa {
                    std::env::set_var("PULSE_SERVER", pa);
                } else {
                    warn!(
                        "Could not parse PULSE_SERVER from pactl info output: {:?}",
                        pa
                    );
                }
            } else {
                debug!("pactl not found, will not set PULSE_SERVER");
            }
            elevate_privileges(app.askpass)?;
            clean_dead_namespaces()?;
            exec::exec(cmd, &uiclient, app.verbose)?
        }
        args::Command::List(listcmd) => {
            clean_dead_locks()?;
            output_list(listcmd)?;
        }
        args::Command::Synch(synchcmd) => {
            // If provider given then sync that, else prompt with menu
            if synchcmd.vpn_provider.is_none() {
                sync_menu(&uiclient)?;
            } else {
                synch(
                    synchcmd.vpn_provider.unwrap().to_variant(),
                    synchcmd.protocol.map(|x| x.to_variant()),
                    &uiclient,
                )?;
            }
        }
        args::Command::Servers(serverscmd) => {
            print_configs(serverscmd)?;
        }
    }
    Ok(())
}
