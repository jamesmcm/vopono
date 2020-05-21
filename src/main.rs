mod args;
mod vpn;

use log::{debug, error, info, log_enabled, Level, LevelFilter};
use structopt::StructOpt;

fn main() {
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
}
