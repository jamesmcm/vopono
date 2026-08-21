use super::AirVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::UiClient;
use crate::util::delete_all_files_in_dir;
use anyhow::{anyhow, Context};
use log::debug;
use serde::Deserialize;
use std::fmt::Display;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

#[derive(Debug, Deserialize)]
struct StatusResponse {
    servers: Vec<AirServer>,
}

#[derive(Debug, Deserialize)]
struct AirServer {
    public_name: String,
}

impl OpenVpnProvider for AirVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        None
    }

    fn prompt_for_auth(&self, _uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        // AirVPN embeds the generated connection credentials in each profile;
        // the provider trait still requires this no-op authentication result.
        Ok(("unused".to_string(), "unused".to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        //NOTE: not required for AirVPN auth is inside ovpn file
        Ok(None)
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let config_choice = uiclient.get_configuration_choice(&ConfigType::default())?;
        let config_type = ConfigType::iter()
            .nth(config_choice)
            .ok_or_else(|| anyhow!("Invalid AirVPN OpenVPN configuration selection"))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create AirVPN HTTP client")?;

        let status_response: StatusResponse = client
            .get("https://airvpn.org/api/status/")
            .send()?
            .error_for_status()
            .context("AirVPN server status request failed")?
            .json()
            .context("Failed to parse AirVPN server status")?;
        let server_names = status_response
            .servers
            .iter()
            .map(|server| server.public_name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        if server_names.is_empty() {
            anyhow::bail!("AirVPN returned no servers while generating OpenVPN configs");
        }

        // TODO: DRY - factor this out to mod.rs (duplicated in Wireguard config generation)
        let api_key = std::env::var("AIRVPN_API_KEY").or_else(|_|
                uiclient.get_input(crate::config::providers::Input{prompt: "Enter your AirVPN API key (see https://airvpn.org/apisettings/ )".to_string(), validator: Some(Box::new(|value: &String| super::validate_api_key(value)))})
                  ).map_err(|_| {
                    anyhow!("Cannot generate AirVPN OpenVPN config files: AIRVPN_API_KEY is not defined in your environment variables. Get your key by activating API access in the Client Area at https://airvpn.org/apisettings/")
                })?.trim().to_string();
        super::validate_api_key(&api_key)
            .map_err(|error| anyhow!("Invalid AirVPN API key: {error}"))?;
        let zipfile = client
            .get("https://airvpn.org/api/generator/")
            .query(&[
                ("protocols", config_type.protocol_selector()),
                ("download", "zip".to_string()),
                ("system", "linux".to_string()),
                // Keep the generated profile IPv4-only to match vopono's
                // default namespace behavior; advanced IP-layer choices are
                // intentionally not frontend selectors.
                ("iplayer_exit", "ipv4".to_string()),
                ("servers", server_names),
            ])
            .header("API-KEY", api_key)
            .send()?
            .error_for_status()
            .context("AirVPN OpenVPN config request failed")?;
        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))
            .context("AirVPN returned an invalid OpenVPN archive")?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        for i in 0..zip.len() {
            let mut file_contents: Vec<u8> = Vec::with_capacity(4096);
            let mut file = zip.by_index(i)?;
            file.read_to_end(&mut file_contents)?;

            let original_name = file.name().to_string();
            let filename = if let Some("ovpn") = file
                .enclosed_name()
                .as_ref()
                .and_then(|p| p.extension())
                .and_then(|x| x.to_str())
            {
                let filename = openvpn_filename(&original_name);
                debug!("Writing OpenVPN config: {filename}");
                filename
            } else {
                original_name
            };

            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            outfile.write_all(file_contents.as_slice())?;
        }

        Ok(())
    }
}

#[derive(EnumIter, PartialEq, Default)]
enum ConfigType {
    #[default]
    Udp443,
    Tcp443,
    Udp53,
    Udp80,
    Udp1194,
    Udp2018,
    Tcp53,
    Tcp80,
    Tcp1194,
    Tcp2018,
}

impl ConfigType {
    fn transport(&self) -> &'static str {
        match self {
            Self::Udp53 | Self::Udp80 | Self::Udp443 | Self::Udp1194 | Self::Udp2018 => "udp",
            Self::Tcp53 | Self::Tcp80 | Self::Tcp443 | Self::Tcp1194 | Self::Tcp2018 => "tcp",
        }
    }

    fn port(&self) -> u16 {
        match self {
            Self::Udp53 | Self::Tcp53 => 53,
            Self::Udp80 | Self::Tcp80 => 80,
            Self::Udp443 | Self::Tcp443 => 443,
            Self::Udp1194 | Self::Tcp1194 => 1194,
            Self::Udp2018 | Self::Tcp2018 => 2018,
        }
    }

    fn protocol_selector(&self) -> String {
        format!("openvpn_1_{}_{}", self.transport(), self.port())
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.transport().to_uppercase(), self.port())
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt(&self) -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().filter_map(|x| x.description()).collect())
    }

    fn description(&self) -> Option<String> {
        Some(format!(
            "Protocol: {}, Port: {}, Entry IP: 1",
            self.transport().to_uppercase(),
            self.port()
        ))
    }
}

fn openvpn_filename(name: &str) -> String {
    let fields = name.split('_').collect::<Vec<_>>();
    match (fields.get(1), fields.get(2)) {
        (Some(location), Some(server)) => {
            let country_code = location.split('-').next().unwrap_or_default();
            if country_code.is_empty() || server.is_empty() {
                name.to_string()
            } else {
                format!("{}-{server}.ovpn", country_code.to_ascii_lowercase())
            }
        }
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{openvpn_filename, ConfigType};
    use strum::IntoEnumIterator;

    #[test]
    fn direct_generator_modes_have_stable_selectors() {
        let selectors = ConfigType::iter()
            .map(|config| config.protocol_selector())
            .collect::<Vec<_>>();
        assert_eq!(
            selectors,
            vec![
                "openvpn_1_udp_443",
                "openvpn_1_tcp_443",
                "openvpn_1_udp_53",
                "openvpn_1_udp_80",
                "openvpn_1_udp_1194",
                "openvpn_1_udp_2018",
                "openvpn_1_tcp_53",
                "openvpn_1_tcp_80",
                "openvpn_1_tcp_1194",
                "openvpn_1_tcp_2018",
            ]
        );
    }

    #[test]
    fn generator_names_are_reduced_to_stable_config_ids() {
        assert_eq!(
            openvpn_filename("AirVPN_CH-Zurich_Achernar_UDP-443.ovpn"),
            "ch-Achernar.ovpn"
        );
        assert_eq!(openvpn_filename("ca-Custom.ovpn"), "ca-Custom.ovpn");
    }
}
