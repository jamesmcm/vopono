use super::AirVPN;
use crate::config::providers::{ConfigurationChoice, Provider, UiClient, WireguardProvider};
use anyhow::{Context, anyhow};
use log::debug;
use serde::Deserialize;
use std::fs::{File, create_dir_all, read_dir, remove_dir_all, rename};
use std::io::{Cursor, Read, Write};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};
use zip::ZipArchive;

#[derive(Debug, Deserialize)]
struct GeneratorError {
    error: Option<String>,
}

#[derive(Debug, Display, EnumIter, PartialEq, Default)]
enum WireguardConfigType {
    // Verified against the live AirVPN generator API (re-checked 2026-08-22):
    // UDP 1637 and 47107 return valid packages; 51820 plus the OpenVPN-style
    // ports (53, 80, 443, 1194, 2018) all return "zero files in package"
    // errors. Re-verify against the API before exposing any other port.
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
        let api_key = super::require_api_key(uiclient, "Wireguard")?;

        let config_choice = uiclient.get_configuration_choice(&WireguardConfigType::default())?;
        let port = WireguardConfigType::iter()
            .nth(config_choice)
            .context("Invalid AirVPN Wireguard port selection")?
            .port();
        let client = super::http_client()?;
        let servers = super::fetch_servers(&client)?;

        if servers.is_empty() {
            anyhow::bail!("AirVPN returned no servers while generating Wireguard configs");
        }

        let provider_dir = self.provider_dir()?;
        create_dir_all(&provider_dir)?;
        let staging_dir = provider_dir.join("wireguard.new");
        if staging_dir.exists() {
            remove_dir_all(&staging_dir)?;
        }
        create_dir_all(&staging_dir)?;

        // One generator request builds the package for every server at once
        // (verified live 2026-08-22), mirroring the OpenVPN flow; the
        // response is a zip archive, with failures reported as JSON errors.
        let result = (|| -> anyhow::Result<()> {
            let server_names = servers
                .iter()
                .map(|server| server.public_name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let response = client
                .get("https://airvpn.org/api/generator/")
                .query(&[
                    ("protocols", format!("wireguard_1_udp_{port}")),
                    ("servers", server_names),
                    ("download", "zip".to_string()),
                    ("system", "linux".to_string()),
                    ("device", "default".to_string()),
                    ("resolve", "on".to_string()),
                    // Keep the stable generator defaults here; advanced
                    // IP-layer settings are not frontend selectors.
                    ("iplayer_entry", "ipv4".to_string()),
                ])
                .header("API-KEY", &api_key)
                .send()
                .context("AirVPN Wireguard config request failed")?
                .error_for_status()
                .context("AirVPN rejected Wireguard config request")?;
            let body = response.bytes()?;
            let mut archive = match ZipArchive::new(Cursor::new(body.clone())) {
                Ok(archive) => archive,
                Err(_) => {
                    // The generator reports rejections as JSON, not archives;
                    // surface its message when it has one.
                    let message = serde_json::from_slice::<GeneratorError>(&body)
                        .ok()
                        .and_then(|error| error.error)
                        .unwrap_or_else(|| "AirVPN returned a non-Wireguard archive".to_string());
                    return Err(anyhow!(
                        "AirVPN generator rejected Wireguard request: {message}"
                    ));
                }
            };

            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                if file.enclosed_name().is_none() {
                    continue;
                }
                let original_name = file.name().to_string();
                let filename = super::generator_filename(&original_name, "conf");
                debug!("Writing Wireguard config: {filename}");
                let mut contents = Vec::with_capacity(4096);
                file.read_to_end(&mut contents)?;
                let config_path = staging_dir.join(filename.to_lowercase().replace(' ', "_"));
                let mut outfile = File::create(&config_path)?;
                outfile.write_all(contents.as_slice())?;
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

#[cfg(test)]
mod tests {
    use super::super::generator_filename;
    use super::WireguardConfigType;
    use strum::IntoEnumIterator;

    #[test]
    fn archive_entry_names_reduce_to_stable_config_ids() {
        assert_eq!(
            generator_filename("AirVPN_NL-Alblasserdam_Alcyone_UDP-1637.conf", "conf"),
            "netherlands-nl-Alcyone.conf"
        );
        assert_eq!(
            generator_filename("weird-entry.conf", "conf"),
            "weird-entry.conf"
        );
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
