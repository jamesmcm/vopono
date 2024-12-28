// AzireVPN Port Forwarding needs to send one request from *INSIDE* the network namespace
// Then handle open port
// Attempt to destroy port forwarding on Drop

use std::net::IpAddr;

use super::Forwarder;

pub struct AzireVpnPortForwarding {
    pub port: u16,
    pub local_ip: IpAddr,
    // TODO: We could run check endpoint but it means we need to temporarily listen on this port too
    // But it would confirm success and give us our remote IP
    // TODO: Do we want to look up remote IP from ifconfig.co?
}

impl AzireVpnPortForwarding {
    pub fn new(access_token: &str, local_ip: IpAddr) -> anyhow::Result<Self> {
        let client = reqwest::blocking::Client::new();
        // Check if any port forwarding exists for current connection
        // If so, return that port
        // If not, create a new port forwarding
        client.post("https://api.azirevpn.com/v3/portforwardings")
    }
}

impl Forwarder for AzireVpnPortForwarding {
    fn forwarded_port(&self) -> u16 {
        self.port
    }
}

impl Drop for AzireVpnPortForwarding {
    fn drop(&mut self) {
        // Destroy port forwarding
    }
}
