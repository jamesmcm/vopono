use log::warn;
use std::collections::BTreeSet;
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

    // Direct ISO-code prefix match first (Mullvad-style "se-got-wg-001").
    if let Some(country) = countries.get(country_prefix.as_str()) {
        return (Some(country_prefix), Some(title_case(country)));
    }

    // Fall back to matching a full country name ("sweden-got-001"), which
    // some providers and custom config names use.
    let normalized_prefix = normalize_country(&country_prefix);
    if normalized_prefix.is_empty() {
        return (None, None);
    }
    countries
        .iter()
        .find(|(_, country)| normalize_country(country) == normalized_prefix)
        .map(|(code, country)| (Some((*code).to_string()), Some(title_case(country))))
        .unwrap_or((None, None))
}

/// Alias set for a server id, shared by the status snapshot and the servers
/// listing so both accept the same search terms.
///
/// Includes the id itself, its dash/underscore-separated parts, the derived
/// country code/name, and the caller's requested alias when present.
pub(crate) fn aliases_for(id: &str, requested: Option<&str>) -> BTreeSet<String> {
    let (country_code, country) = country_from_id(id);
    let mut aliases = BTreeSet::new();
    aliases.insert(id.to_string());
    if let Some(requested) = requested {
        aliases.insert(requested.to_ascii_lowercase());
    }
    for part in id_parts(id) {
        aliases.insert(part);
    }
    if let Some(code) = country_code {
        aliases.insert(code);
    }
    if let Some(country) = country {
        aliases.insert(country.to_ascii_lowercase());
    }
    aliases
}

pub(crate) fn normalize_country(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "")
}

/// Human-case a country name written with underscores, hyphens, or spaces.
pub(crate) fn title_case(value: &str) -> String {
    value
        .split(['_', '-', ' '])
        .filter(|part| !part.is_empty())
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

/// Best-effort hostname extraction from a server configuration file.
///
/// Returns `None` (with a logged warning) instead of an error so one unreadable
/// config cannot abort an entire listing.
pub(crate) fn config_hostname(path: &Path, protocol: &Protocol) -> Option<String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            warn!(
                "Could not read server config {} to extract hostname: {error}",
                path.display()
            );
            return None;
        }
    };
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
    hostname.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        aliases_for, config_hostname, country_from_id, id_parts, normalize_country, title_case,
    };
    use std::path::Path;
    use vopono_core::config::vpn::Protocol;

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

    #[test]
    fn derives_country_from_full_names_and_hyphenated_words() {
        assert_eq!(
            country_from_id("sweden-got-wg-001"),
            (Some("se".to_string()), Some("Sweden".to_string()))
        );
        // No country inference should succeed for arbitrary prefixes.
        assert_eq!(country_from_id("toronto-01"), (None, None));
    }

    #[test]
    fn title_case_handles_all_separators() {
        assert_eq!(title_case("united_kingdom"), "United Kingdom");
        assert_eq!(title_case("czech-republic"), "Czech Republic");
        assert_eq!(title_case("south africa"), "South Africa");
        assert_eq!(title_case(""), "");
    }

    #[test]
    fn normalize_strips_every_separator() {
        assert_eq!(normalize_country(" United-Kingdom_ "), "unitedkingdom");
    }

    #[test]
    fn alias_sets_include_requested_terms() {
        let aliases = aliases_for("se-got-wg-001", Some("SE-GOT"));
        for expected in [
            "se-got-wg-001",
            "se",
            "got",
            "wg",
            "001",
            "sweden",
            "se-got",
        ] {
            assert!(aliases.contains(expected), "missing alias {expected}");
        }
    }

    #[test]
    fn hostname_parsing_reads_both_config_formats() {
        let wg_dir = std::env::temp_dir().join("vopono-server-meta-test");
        std::fs::create_dir_all(&wg_dir).unwrap();
        let wg_path = wg_dir.join("se-test.conf");
        std::fs::write(
            &wg_path,
            "[Interface]\nPrivateKey = x\n\n[Peer]\nEndpoint = se1.example.com:51820\n",
        )
        .unwrap();
        assert_eq!(
            config_hostname(&wg_path, &Protocol::Wireguard),
            Some("se1.example.com:51820".to_string())
        );

        let ovpn_path = wg_dir.join("de-test.ovpn");
        std::fs::write(&ovpn_path, "client\ndev tun\nremote de1.example.com 1194\n").unwrap();
        assert_eq!(
            config_hostname(Path::new(&ovpn_path), &Protocol::OpenVpn),
            Some("de1.example.com".to_string())
        );

        // Missing files yield None rather than aborting callers.
        assert_eq!(
            config_hostname(
                Path::new(&wg_dir.join("does-not-exist.conf")),
                &Protocol::Wireguard
            ),
            None
        );
        let _ = std::fs::remove_dir_all(wg_dir);
    }
}
