use super::args::ServersCommand;
use anyhow::bail;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::get_configs_from_alias;

use crate::api;
use crate::errors::CliError;
use crate::server_metadata;

#[derive(Debug, Serialize)]
pub struct ServersDocument {
    pub version: u8,
    pub provider: String,
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Serialize)]
pub struct ServerEntry {
    pub id: String,
    pub protocol: String,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub hostname: Option<String>,
    pub config_file: String,
    pub aliases: Vec<String>,
}

pub fn print_configs(command: ServersCommand) -> anyhow::Result<()> {
    let provider = command.vpn_provider.to_variant();
    let protocols = protocols_to_list(&provider, command.protocol.map(|x| x.to_variant()))?;
    let prefix = command.prefix.as_deref().unwrap_or("");
    let country_filter = command
        .country
        .as_deref()
        .map(server_metadata::normalize_country);
    let mut servers = Vec::new();
    let mut seen = BTreeSet::new();

    for protocol in protocols {
        let directory = config_directory(&provider, &protocol)?;
        for path in get_configs_from_alias(&directory, prefix) {
            let key = format!("{}:{}", protocol.id(), path.display());
            if !seen.insert(key) {
                continue;
            }
            // get_configs_from_alias only returns existing files, so every
            // entry here is present on disk by construction.
            let entry = server_entry(&path, &protocol);
            if country_filter
                .as_ref()
                .is_some_and(|filter| !entry_matches_country(&entry, filter))
            {
                continue;
            }
            servers.push(entry);
        }
    }

    servers.sort_by(|left, right| {
        left.country_code
            .cmp(&right.country_code)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.protocol.cmp(&right.protocol))
    });

    if servers.is_empty() && !command.json {
        return Err(CliError::ServerNotFound {
            provider: provider.display_name().to_string(),
        }
        .into());
    }

    if command.json {
        return api::print_json(&ServersDocument {
            version: api::SCHEMA_VERSION,
            provider: provider.id().to_string(),
            servers,
        });
    }

    println!("id\tprotocol\tcountry_code\tcountry\thostname\tconfig_file");
    for server in servers {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            server.id,
            server.protocol,
            server.country_code.as_deref().unwrap_or(""),
            server.country.as_deref().unwrap_or(""),
            server.hostname.as_deref().unwrap_or(""),
            server.config_file,
        );
    }

    Ok(())
}

fn protocols_to_list(
    provider: &VpnProvider,
    requested: Option<Protocol>,
) -> anyhow::Result<Vec<Protocol>> {
    if matches!(
        provider,
        VpnProvider::Custom | VpnProvider::None | VpnProvider::Warp
    ) {
        bail!(
            "Provider {} does not expose synced server configuration files",
            provider.display_name()
        );
    }

    match requested {
        Some(protocol) => {
            // Single source of truth for protocol support lives in vopono_core.
            if provider.supported_sync_protocols().contains(&protocol) {
                Ok(vec![protocol])
            } else {
                Err(CliError::ProtocolNotSupported {
                    provider: provider.display_name().to_string(),
                    protocol: protocol.id().to_string(),
                }
                .into())
            }
        }
        None => Ok(provider.supported_sync_protocols()),
    }
}

fn config_directory(provider: &VpnProvider, protocol: &Protocol) -> anyhow::Result<PathBuf> {
    match protocol {
        Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
        Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
        _ => Err(CliError::ProtocolNotSupported {
            provider: provider.display_name().to_string(),
            protocol: protocol.id().to_string(),
        }
        .into()),
    }
}

fn server_entry(path: &Path, protocol: &Protocol) -> ServerEntry {
    let id = path
        .file_stem()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_default();
    let (country_code, country) = server_metadata::country_from_id(&id);
    let aliases = server_metadata::aliases_for(&id, None);

    ServerEntry {
        id,
        protocol: protocol.id().to_string(),
        country_code,
        country,
        // Best-effort: one unreadable config must not abort the listing.
        hostname: server_metadata::config_hostname(path, protocol),
        config_file: path.display().to_string(),
        aliases: aliases.into_iter().collect(),
    }
}

fn entry_matches_country(entry: &ServerEntry, filter: &str) -> bool {
    entry
        .country_code
        .as_deref()
        .is_some_and(|code| server_metadata::normalize_country(code) == filter)
        || entry
            .country
            .as_deref()
            .is_some_and(|country| server_metadata::normalize_country(country) == filter)
}
