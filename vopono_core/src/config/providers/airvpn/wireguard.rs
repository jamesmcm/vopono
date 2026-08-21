use super::AirVPN;
use crate::config::providers::{ConfigurationChoice, Provider, UiClient, WireguardProvider};
use anyhow::{Context, anyhow};
use serde::Deserialize;
use std::fs::{File, create_dir_all, read_dir, remove_dir_all, rename};
use std::io::Write;
use std::time::Duration;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Debug, Deserialize)]
struct StatusResponse {
    servers: Vec<AirServer>,
}

#[derive(Debug, Deserialize)]
struct AirServer {
    public_name: String,
    country_code: String,
}

#[derive(Debug, Deserialize)]
struct GeneratorError {
    error: Option<String>,
}

#[derive(Debug, Display, EnumIter, PartialEq, Default)]
enum WireguardConfigType {
    // Verified against the live AirVPN generator API. The web generator and
    // server documentation may also show 51820 under advanced settings, but
    // the authenticated API request currently returns an empty-package error
    // for it, so it is not exposed until that discrepancy is resolved.
    #[default]
    #[strum(to_string = "UDP 1637")]
    Udp1637,
    #[strum(to_string = "UDP 47107")]
    Udp47107,
}

impl WireguardConfigType {
    fn port(&self) -> u16 {
        match self {
            Self::Udp1637 => 1637,
            Self::Udp47107 => 47107,
        }
    }
}

impl ConfigurationChoice for WireguardConfigType {
    fn prompt(&self) -> String {
        "Which AirVPN Wireguard connection port do you wish to use".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| x.to_string()).collect()
    }

    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(
            Self::iter()
                .map(|x| format!("Wireguard UDP port {}", x.port()))
                .collect(),
        )
    }

    fn description(&self) -> Option<String> {
        Some(format!("Wireguard UDP port {}", self.port()))
    }
}

impl WireguardProvider for AirVPN {
    fn create_wireguard_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        // TODO: Factor out API key request to mod.rs since it is common for both Wireguard and
        // OpenVPN config generation
        let api_key = std::env::var("AIRVPN_API_KEY")
            .or_else(|_| {
                uiclient.get_input(crate::config::providers::Input {
                    prompt: "Enter your AirVPN API key (see https://airvpn.org/apisettings/ )"
                        .to_string(),
                    validator: Some(Box::new(|value: &String| super::validate_api_key(value))),
                })
            })
            .map_err(|_| {
                anyhow!(
                    "Cannot generate AirVPN Wireguard config files: AIRVPN_API_KEY is not defined in your environment variables. Get your key by activating API access in the Client Area at https://airvpn.org/apisettings/"
                )
            })?
            .trim()
            .to_string();
        super::validate_api_key(&api_key)
            .map_err(|error| anyhow!("Invalid AirVPN API key: {error}"))?;

        let config_choice = uiclient.get_configuration_choice(&WireguardConfigType::default())?;
        let port = WireguardConfigType::iter()
            .nth(config_choice)
            .context("Invalid AirVPN Wireguard port selection")?
            .port();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create AirVPN HTTP client")?;
        let servers: StatusResponse = client
            .get("https://airvpn.org/api/status/")
            .send()?
            .error_for_status()
            .context("AirVPN server status request failed")?
            .json()
            .context("Failed to parse AirVPN server status")?;

        if servers.servers.is_empty() {
            anyhow::bail!("AirVPN returned no servers while generating Wireguard configs");
        }

        let provider_dir = self.provider_dir()?;
        create_dir_all(&provider_dir)?;
        let staging_dir = provider_dir.join("wireguard.new");
        if staging_dir.exists() {
            remove_dir_all(&staging_dir)?;
        }
        create_dir_all(&staging_dir)?;

        let result = (|| -> anyhow::Result<()> {
            for server in servers.servers {
                let response = client
                    .get("https://airvpn.org/api/generator/")
                    .query(&[
                        ("protocols", format!("wireguard_1_udp_{port}")),
                        ("servers", server.public_name.clone()),
                        ("device", "default".to_string()),
                        ("resolve", "on".to_string()),
                        // Keep the stable generator defaults here; advanced
                        // IP-layer settings are not frontend selectors.
                        ("iplayer_entry", "ipv4".to_string()),
                    ])
                    .header("API-KEY", &api_key)
                    .send()
                    .with_context(|| {
                        format!(
                            "AirVPN Wireguard config request failed for {}",
                            server.public_name
                        )
                    })?
                    .error_for_status()
                    .with_context(|| {
                        format!(
                            "AirVPN rejected Wireguard config request for {}",
                            server.public_name
                        )
                    })?;
                let config = response.text().with_context(|| {
                    format!("Invalid AirVPN response for {}", server.public_name)
                })?;
                if !config.contains("[Interface]") || !config.contains("[Peer]") {
                    if let Ok(error) = serde_json::from_str::<GeneratorError>(&config)
                        && let Some(message) = error.error
                    {
                        anyhow::bail!(
                            "AirVPN generator rejected {}: {}",
                            server.public_name,
                            message
                        );
                    }
                    anyhow::bail!(
                        "AirVPN returned a non-Wireguard response for {}",
                        server.public_name
                    );
                }

                let filename = format!(
                    "{}-{}.conf",
                    server.country_code.to_ascii_lowercase(),
                    sanitize_filename(&server.public_name)
                );
                let config_path = staging_dir.join(&filename);
                let mut file = File::create(&config_path)?;
                file.write_all(config.as_bytes())?;
            }

            let wireguard_dir = self.wireguard_dir()?;
            create_dir_all(&wireguard_dir)?;
            for entry in read_dir(&wireguard_dir)?.flatten() {
                if entry.path().is_file() {
                    std::fs::remove_file(entry.path())?;
                }
            }
            for entry in read_dir(&staging_dir)?.flatten() {
                rename(entry.path(), wireguard_dir.join(entry.file_name()))?;
            }

            Ok(())
        })();

        if result.is_err() {
            let _ = remove_dir_all(&staging_dir);
        } else {
            remove_dir_all(&staging_dir)?;
            // This sidecar was previously consumed by the CLI frontend. Server
            // discovery now uses the generic config-file representation, so
            // remove any stale copy after a successful refresh.
            let _ = std::fs::remove_file(provider_dir.join("wireguard-servers.json"));
        }
        result
    }
}

fn sanitize_filename(name: &str) -> String {
    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "server".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::{WireguardConfigType, sanitize_filename};
    use strum::IntoEnumIterator;

    #[test]
    fn sanitizes_airvpn_server_names_for_config_files() {
        assert_eq!(sanitize_filename("Some Server/1"), "some-server-1");
        assert_eq!(sanitize_filename(""), "server");
    }

    #[test]
    fn generator_ports_are_the_live_supported_selectors() {
        assert_eq!(
            WireguardConfigType::iter()
                .map(|choice| choice.port())
                .collect::<Vec<_>>(),
            vec![1637, 47107]
        );
    }
}
