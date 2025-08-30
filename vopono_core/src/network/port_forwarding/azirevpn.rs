// https://www.azirevpn.com/docs/api/portforwardings#create-portforwarding
// AzireVPN Port Forwarding needs to send one request from *INSIDE* the network namespace
// Then handle open port
// Attempt to destroy port forwarding on Drop

use std::net::IpAddr;

use crate::network::netns::NetworkNamespace;
use anyhow::Context;
use serde::Deserialize;

use super::Forwarder;

pub struct AzireVpnPortForwarding {
    pub port: u16,
    pub local_ip: IpAddr,
    pub access_token: String,
    pub netns_name: String,
    // TODO: We could run check endpoint but it means we need to temporarily listen on this port too
    // But it would confirm success and give us our remote IP
    // TODO: Do we want to look up remote IP from ifconfig.co?
}

// Unused since we use curl here for now
// #[derive(Serialize, Debug)]
// struct RequestBody {
//     internal_ipv4: String,
//     hidden: bool,
//     expires_in: u32,
// }

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct CreateResponse {
    status: String,
    data: CreateResponseData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct CreateResponseData {
    internal_ipv4: String,
    internal_ipv6: String,
    port: u16,
    hidden: bool,
    expires_at: u64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ListResponse {
    status: String,
    data: ListResponseData,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ListResponseData {
    internal_ipv4: String,
    internal_ipv6: String,
    ports: Vec<PortData>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct PortData {
    port: u16,
    hidden: bool,
    expires_at: u64,
}

impl AzireVpnPortForwarding {
    // This must run on forked process inside the network namespace
    // Could just use curl?
    pub fn new(
        netns: &NetworkNamespace,
        access_token: &str,
        local_ip: IpAddr,
    ) -> anyhow::Result<Self> {
        // Check if any port forwarding exists for current connection
        log::info!("Sleeping 10 seconds so connection is up before requesting port forwarding");
        std::thread::sleep(std::time::Duration::from_secs(10));
        let cmd = [
            "curl",
            Box::leak(
                format!("https://api.azirevpn.com/v3/portforwardings?internal_ipv4={local_ip}")
                    .into_boxed_str(),
            ),
            "-H",
            Box::leak(format!("Authorization: Bearer {access_token}").into_boxed_str()),
        ];

        let output = NetworkNamespace::exec_with_output(&netns.name, &cmd)?;
        let output_string = String::from_utf8(output.stdout.clone())?;
        log::debug!("AzireVPN Port forwarding list response: {output_string}");

        // TODO: Distinguish error from no port forwarding existing vs. network error ?
        let output_data_result: anyhow::Result<ListResponse> = serde_json::from_str(&output_string)
            .with_context(|| "Failed to parse JSON response from listing AzireVPN Port Forwarding");

        // If so, return that port
        if let Ok(output_data) = output_data_result
            && !output_data.data.ports.is_empty()
        {
            let port = output_data.data.ports[0].port;
            log::info!("Port forwarding already enabled on port {port}");
            return Ok(Self {
                port,
                local_ip,
                access_token: access_token.to_string(),
                netns_name: netns.name.clone(),
            });
        }

        // If not, create a new port forwarding
        // Retry up to 3 times

        let mut i = 1;
        let data = loop {
            let cmd = [
                "curl",
                "https://api.azirevpn.com/v3/portforwardings",
                "-H",
                Box::leak(format!("Authorization: Bearer {access_token}").into_boxed_str()),
                "--json",
                Box::leak(
                    format!(
                        "{{\"internal_ipv4\": \"{local_ip}\", \"hidden\": false, \"expires_in\": 30}}",
                    )
                    .into_boxed_str(),
                ),
            ];

            let output = NetworkNamespace::exec_with_output(&netns.name, &cmd)?;
            let output_string = String::from_utf8(output.stdout.clone())?;

            log::debug!("AzireVPN Port forwarding creation response: {output_string}");
            let maybe_data: anyhow::Result<CreateResponse> =
                serde_json::from_str(output_string.as_str()).with_context(
                    || "Failed to parse JSON response from creating AzireVPN Port Forwarding",
                );

            if let Ok(data) = maybe_data {
                break Ok(data);
            }
            if i >= 3 {
                log::error!("Failed to create AzireVPN Port Forwarding after 3 attempts");
                break Err(anyhow::anyhow!("Failed to create AzireVPN Port Forwarding"));
            }
            log::warn!(
                "Failed to create AzireVPN Port Forwarding on attempt {i}, sleeping 5 seconds and retrying"
            );
            std::thread::sleep(std::time::Duration::from_secs(5));

            i += 1;
        }?;

        log::info!(
            "AzireVPN Port forwarding enabled on port {}",
            data.data.port
        );
        Ok(Self {
            port: data.data.port,
            local_ip,
            access_token: access_token.to_string(),
            netns_name: netns.name.clone(),
        })
    }
}

impl Forwarder for AzireVpnPortForwarding {
    fn forwarded_port(&self) -> u16 {
        self.port
    }
}

impl Drop for AzireVpnPortForwarding {
    fn drop(&mut self) {
        let cmd = [
            "curl",
            "-X",
            "DELETE",
            "https://api.azirevpn.com/v3/portforwardings",
            "-H",
            Box::leak(format!("Authorization: Bearer {}", self.access_token).into_boxed_str()),
            "--json",
            Box::leak(
                format!(
                    "{{\"internal_ipv4\": \"{}\", \"port\": {}}}",
                    self.local_ip, self.port
                )
                .into_boxed_str(),
            ),
        ];

        // Note this must run BEFORE the network namespace is destroyed
        let output = std::process::Command::new("ip")
            .arg("netns")
            .arg("exec")
            .arg(&self.netns_name)
            .args(cmd)
            .output()
            .expect("Failed to destroy AzireVPN Port Forwarding");

        let output_string = String::from_utf8(output.stdout.clone()).unwrap();
        log::info!("AzireVPN Port forwarding destroyed: {output_string}");
    }
}
