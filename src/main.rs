mod args;
mod netns;
mod vpn;

use anyhow::Context;
use args::{ExecCommand, SetDefaultsCommand};
use log::{debug, error, info, log_enabled, Level, LevelFilter};
use netns::NetworkNamespace;
use std::process::Command;
use structopt::StructOpt;

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
        args::Command::Create(cmd) => exec(cmd)?,
        args::Command::SetDefaults(cmd) => todo!(),
    }
    Ok(())
}

fn exec(command: ExecCommand) -> anyhow::Result<()> {
    // TODO: Handle when we must elevate privileges
    // TODO: Wrap in struct with destructor
    // Get server and provider (handle default case)
    let provider = command.vpn_provider.unwrap();
    let server = command.server.unwrap();
    // if protocol == OpenVPN
    let ns_name = format!("{}_{}", provider.to_string(), server.to_string());
    let ns = NetworkNamespace::new(ns_name)?;

    Ok(())
}
