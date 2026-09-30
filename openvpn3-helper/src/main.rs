//! Entry point for the isolated OpenVPN 3 Core helper process.
//!
//! vopono starts this executable after entering the target network namespace,
//! so all OpenVPN Core state and threads remain inside this process.

mod process;
mod profile;

#[tokio::main]
async fn main() {
    if let Err(error) = process::run().await {
        eprintln!("vopono-openvpn3-helper: {error:#}");
        std::process::exit(1);
    }
}
