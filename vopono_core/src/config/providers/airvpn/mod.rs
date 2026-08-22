mod openvpn;
mod wireguard;

use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::config::providers::{Input, UiClient};
use crate::config::vpn::Protocol;
use anyhow::Context;
use serde::Deserialize;
use std::time::Duration;

pub struct AirVPN {}

/// Subset of the AirVPN status API response used for config generation.
#[derive(Debug, Deserialize)]
pub(super) struct StatusResponse {
    pub servers: Vec<AirServer>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AirServer {
    pub public_name: String,
}

pub(super) fn validate_api_key(value: &str) -> Result<(), String> {
    let key = value.trim().as_bytes();
    if key.len() == 40
        && key
            .iter()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(character))
    {
        Ok(())
    } else {
        Err("AirVPN API keys must be 40 lower-case hexadecimal characters".to_string())
    }
}

/// Blocking HTTP client shared by the AirVPN config generators.
pub(super) fn http_client() -> anyhow::Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to create AirVPN HTTP client")
}

/// Reduce a generator archive entry name such as
/// `AirVPN_CH-Zurich_Achernar_UDP-443.ovpn` to the stable config id vopono
/// uses (`switzerland-ch-Achernar.{extension}`).
///
/// Falls back to the original name when it does not follow the generator's
/// `{word}_{location}_{server}_{...}` layout.
pub(super) fn generator_filename(entry_name: &str, extension: &str) -> String {
    let fields = entry_name.split('_').collect::<Vec<_>>();
    match (fields.first(), fields.get(1), fields.get(2)) {
        (Some(&"AirVPN"), Some(location), Some(server)) => {
            let country_code = location
                .split('-')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if country_code.is_empty() || server.is_empty() {
                entry_name.to_string()
            } else if let Some(country) =
                crate::util::country_map::code_to_country_map().get(country_code.as_str())
            {
                format!("{country}-{country_code}-{server}.{extension}")
            } else {
                format!("{country_code}-{server}.{extension}")
            }
        }
        _ => entry_name.to_string(),
    }
}

/// Fetch the live server list from the AirVPN status API.
pub(super) fn fetch_servers(client: &reqwest::blocking::Client) -> anyhow::Result<Vec<AirServer>> {
    let status: StatusResponse = client
        .get("https://airvpn.org/api/status/")
        .send()?
        .error_for_status()
        .context("AirVPN server status request failed")?
        .json()
        .context("Failed to parse AirVPN server status")?;
    Ok(status.servers)
}

/// Resolve the AirVPN API key from the environment or interactively.
///
/// Shared by both config generators; `protocol_label` only customises the
/// error message shown when no key can be obtained.
pub(super) fn require_api_key(
    uiclient: &dyn UiClient,
    protocol_label: &str,
) -> anyhow::Result<String> {
    std::env::var("AIRVPN_API_KEY")
        .or_else(|_| {
            uiclient.get_input(Input {
                prompt: "Enter your AirVPN API key (see https://airvpn.org/apisettings/ )"
                    .to_string(),
                validator: Some(Box::new(|value: &String| validate_api_key(value))),
            })
        })
        .map_err(|_| {
            anyhow::anyhow!(
                "Cannot generate AirVPN {protocol_label} config files: AIRVPN_API_KEY is not defined in your environment variables. Get your key by activating API access in the Client Area at https://airvpn.org/apisettings/"
            )
        })
        .and_then(|key| {
            let key = key.trim().to_string();
            validate_api_key(&key)
                .map_err(|error| anyhow::anyhow!("Invalid AirVPN API key: {error}"))?;
            Ok(key)
        })
}

impl Provider for AirVPN {
    fn alias(&self) -> String {
        "air".to_string()
    }

    fn alias_2char(&self) -> String {
        "ar".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::OpenVpn
    }
}

#[cfg(test)]
mod tests {
    use super::generator_filename;

    #[test]
    fn generator_names_are_reduced_to_stable_config_ids() {
        assert_eq!(
            generator_filename("AirVPN_CH-Zurich_Achernar_UDP-443.ovpn", "ovpn"),
            "switzerland-ch-Achernar.ovpn"
        );
        assert_eq!(
            generator_filename("AirVPN_NL-Alblasserdam_Alcyone_UDP-1637.conf", "conf"),
            "netherlands-nl-Alcyone.conf"
        );
        assert_eq!(
            generator_filename("AirVPN_RO-Bucharest_Canes_UDP-1637.conf", "conf"),
            "romania-ro-Canes.conf"
        );
        assert_eq!(
            generator_filename("ca-Custom.ovpn", "ovpn"),
            "ca-Custom.ovpn"
        );
    }
}
