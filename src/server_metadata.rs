use anyhow::Context;
use std::fs;
use std::path::Path;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::country_map::code_to_country_map;

pub(crate) fn id_parts(id: &str) -> Vec<String> {
    id.split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(crate) fn country_from_id(id: &str) -> (Option<String>, Option<String>) {
    let countries = code_to_country_map();
    let country_prefix = id.split('-').next().unwrap_or(id).to_ascii_lowercase();
    if let Some(country) = countries.get(country_prefix.as_str()) {
        return (Some(country_prefix), Some(title_case(country)));
    }

    countries
        .iter()
        .find(|(_, country)| normalize_country(country) == normalize_country(&country_prefix))
        .map(|(code, country)| (Some((*code).to_string()), Some(title_case(country))))
        .unwrap_or((None, None))
}

pub(crate) fn normalize_country(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "")
}

pub(crate) fn title_case(value: &str) -> String {
    value
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn config_hostname(path: &Path, protocol: &Protocol) -> anyhow::Result<Option<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read server config {}", path.display()))?;
    let hostname = match protocol {
        Protocol::Wireguard => content.lines().find_map(|line| {
            Some(
                line.strip_prefix("Endpoint")?
                    .split_once('=')?
                    .1
                    .trim()
                    .to_string(),
            )
        }),
        Protocol::OpenVpn => content.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("remote")).then(|| fields.next().unwrap_or_default().to_string())
        }),
        _ => None,
    };
    Ok(hostname.filter(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::{country_from_id, id_parts};

    #[test]
    fn extracts_generic_server_id_parts() {
        assert_eq!(id_parts("se-got-wg-001"), ["se", "got", "wg", "001"]);
    }

    #[test]
    fn derives_country_from_a_standard_config_id() {
        assert_eq!(
            country_from_id("se-got-wg-001"),
            (Some("se".to_string()), Some("Sweden".to_string()))
        );
    }
}
