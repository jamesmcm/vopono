// https://www.azirevpn.com/docs/api/portforwardings#create-portforwarding
// AzireVPN Port Forwarding needs to send one request from *INSIDE* the network namespace
// Then handle open port
// Attempt to destroy port forwarding on Drop

use std::net::IpAddr;
use std::process::Output;

use crate::network::netns::NetworkNamespace;
use anyhow::Context;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

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

#[derive(Deserialize, Debug)]
struct ApiStatus {
    status: String,
    message: Option<String>,
}

fn authorization_header(access_token: &str) -> String {
    format!("Authorization: Bearer {access_token}")
}

fn list_command(access_token: &str, local_ip: IpAddr) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-sS".to_string(),
        format!("https://api.azirevpn.com/v3/portforwardings?internal_ipv4={local_ip}"),
        "-H".to_string(),
        authorization_header(access_token),
    ]
}

fn create_command(access_token: &str, local_ip: IpAddr) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-sS".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "https://api.azirevpn.com/v3/portforwardings".to_string(),
        "-H".to_string(),
        authorization_header(access_token),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "--data-raw".to_string(),
        json!({
            "internal_ipv4": local_ip.to_string(),
            "hidden": false,
            "expires_in": 30,
        })
        .to_string(),
    ]
}

fn delete_command(access_token: &str, local_ip: IpAddr, port: u16) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-sS".to_string(),
        "-X".to_string(),
        "DELETE".to_string(),
        "https://api.azirevpn.com/v3/portforwardings".to_string(),
        "-H".to_string(),
        authorization_header(access_token),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "--data-raw".to_string(),
        json!({
            "internal_ipv4": local_ip.to_string(),
            "port": port,
        })
        .to_string(),
    ]
}

fn command_args(command: &[String]) -> Vec<&str> {
    command.iter().map(String::as_str).collect()
}

fn output_to_string(operation: &str, output: Output) -> anyhow::Result<String> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow::anyhow!(
            "AzireVPN Port Forwarding {operation} request failed: stdout: {stdout}, stderr: {stderr}, exit code: {}",
            output.status
        ));
    }

    String::from_utf8(output.stdout).with_context(|| {
        format!("Failed to parse UTF-8 response from AzireVPN Port Forwarding {operation}")
    })
}

fn exec_curl(netns_name: &str, operation: &str, command: &[String]) -> anyhow::Result<String> {
    let args = command_args(command);
    let output = NetworkNamespace::exec_with_output(netns_name, &args)?;
    output_to_string(operation, output)
}

fn parse_success_response<T: DeserializeOwned>(
    operation: &str,
    response_body: &str,
) -> anyhow::Result<T> {
    let value: serde_json::Value = serde_json::from_str(response_body).with_context(|| {
        format!("Failed to parse JSON response from AzireVPN Port Forwarding {operation}")
    })?;

    if let Ok(status) = serde_json::from_value::<ApiStatus>(value.clone())
        && status.status != "success"
    {
        let message = status
            .message
            .unwrap_or_else(|| "missing error message".to_string());
        return Err(anyhow::anyhow!(
            "AzireVPN Port Forwarding {operation} request returned {}: {message}",
            status.status
        ));
    }

    serde_json::from_value(value).with_context(|| {
        format!("Failed to parse success response from AzireVPN Port Forwarding {operation}")
    })
}

fn is_not_found_response(error: &anyhow::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("no port forwardings found")
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
        let cmd = list_command(access_token, local_ip);
        let output_string = exec_curl(&netns.name, "list", &cmd)?;
        log::debug!("AzireVPN Port forwarding list response: {output_string}");

        let output_data: Option<ListResponse> = match parse_success_response("list", &output_string)
        {
            Ok(output_data) => Some(output_data),
            Err(error) if is_not_found_response(&error) => {
                log::debug!(
                    "AzireVPN Port Forwarding list request found no existing port forwarding"
                );
                None
            }
            Err(error) => return Err(error),
        };

        // If so, return that port
        if let Some(output_data) = output_data
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
            let cmd = create_command(access_token, local_ip);
            let output_string = exec_curl(&netns.name, "create", &cmd)?;

            log::debug!("AzireVPN Port forwarding creation response: {output_string}");
            let maybe_data: anyhow::Result<CreateResponse> =
                parse_success_response("create", output_string.as_str());

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
        let cmd = delete_command(&self.access_token, self.local_ip, self.port);

        // Note this must run BEFORE the network namespace is destroyed
        let output = std::process::Command::new("ip")
            .arg("netns")
            .arg("exec")
            .arg(&self.netns_name)
            .args(&cmd)
            .output()
            .expect("Failed to destroy AzireVPN Port Forwarding");

        match output_to_string("delete", output) {
            Ok(output_string) => log::info!("AzireVPN Port forwarding destroyed: {output_string}"),
            Err(e) => log::error!("Failed to destroy AzireVPN Port Forwarding: {e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn create_command_uses_post_with_json_body() {
        let command = create_command("token", IpAddr::V4(Ipv4Addr::new(10, 0, 16, 181)));

        assert_eq!(command[0], "curl");
        assert!(command.windows(2).any(|args| args == ["-X", "POST"]));
        assert!(
            command
                .windows(2)
                .any(|args| args == ["-H", "Authorization: Bearer token"])
        );
        assert!(
            command
                .windows(2)
                .any(|args| args == ["-H", "Content-Type: application/json"])
        );

        let body_index = command.iter().position(|arg| arg == "--data-raw").unwrap() + 1;
        let body: serde_json::Value = serde_json::from_str(&command[body_index]).unwrap();
        assert_eq!(body["internal_ipv4"], "10.0.16.181");
        assert_eq!(body["hidden"], false);
        assert_eq!(body["expires_in"], 30);
    }

    #[test]
    fn list_command_uses_get_with_internal_ipv4_query() {
        let command = list_command("token", IpAddr::V4(Ipv4Addr::new(10, 0, 16, 181)));

        assert_eq!(command[0], "curl");
        assert!(command.iter().any(|arg| {
            arg == "https://api.azirevpn.com/v3/portforwardings?internal_ipv4=10.0.16.181"
        }));
        assert!(!command.iter().any(|arg| arg == "-X"));
        assert!(
            command
                .windows(2)
                .any(|args| args == ["-H", "Authorization: Bearer token"])
        );
    }

    #[test]
    fn delete_command_uses_delete_with_json_body() {
        let command = delete_command("token", IpAddr::V4(Ipv4Addr::new(10, 0, 16, 181)), 58532);

        assert!(command.windows(2).any(|args| args == ["-X", "DELETE"]));
        assert!(
            command
                .windows(2)
                .any(|args| args == ["-H", "Authorization: Bearer token"])
        );
        assert!(
            command
                .windows(2)
                .any(|args| args == ["-H", "Content-Type: application/json"])
        );

        let body_index = command.iter().position(|arg| arg == "--data-raw").unwrap() + 1;
        let body: serde_json::Value = serde_json::from_str(&command[body_index]).unwrap();
        assert_eq!(body["internal_ipv4"], "10.0.16.181");
        assert_eq!(body["port"], 58532);
    }

    #[test]
    fn parse_success_response_reports_api_error_message() {
        let err = parse_success_response::<CreateResponse>(
            "create",
            r#"{"status":"error","message":"The given data was invalid.","data":{"internal_ipv4":["The internal ipv4 field is required."]}}"#,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("AzireVPN Port Forwarding create request returned error")
        );
        assert!(err.to_string().contains("The given data was invalid."));
    }

    #[test]
    fn not_found_response_can_be_treated_as_empty_list() {
        let err = parse_success_response::<ListResponse>(
            "list",
            r#"{"status":"error","message":"Not found"}"#,
        )
        .unwrap_err();

        assert!(is_not_found_response(&err));
    }
}
