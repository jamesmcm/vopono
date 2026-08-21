use super::args::ServersCommand;
use anyhow::bail;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::get_configs_from_alias;

use crate::errors::CliError;
use crate::providers::SCHEMA_VERSION;
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
    pub active: bool,
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
            let entry = server_entry(&path, &protocol)?;
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
        println!(
            "{}",
            serde_json::to_string_pretty(&ServersDocument {
                version: SCHEMA_VERSION,
                provider: provider.id().to_string(),
                servers,
            })?
        );
    } else if !servers.is_empty() {
        println!("id\tprotocol\tcountry_code\tcountry\thostname\tconfig_file\tactive");
        for server in servers {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                server.id,
                server.protocol,
                server.country_code.as_deref().unwrap_or(""),
                server.country.as_deref().unwrap_or(""),
                server.hostname.as_deref().unwrap_or(""),
                server.config_file,
                server.active,
            );
        }
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

    if let Some(protocol) = requested {
        match protocol {
            Protocol::OpenVpn if provider.get_dyn_openvpn_provider().is_ok() => {
                Ok(vec![Protocol::OpenVpn])
            }
            Protocol::Wireguard if provider.get_dyn_wireguard_provider().is_ok() => {
                Ok(vec![Protocol::Wireguard])
            }
            protocol => Err(CliError::ProtocolNotSupported {
                provider: provider.display_name().to_string(),
                protocol: protocol.id().to_string(),
            }
            .into()),
        }
    } else {
        let mut protocols = Vec::new();
        if provider.get_dyn_openvpn_provider().is_ok() {
            protocols.push(Protocol::OpenVpn);
        }
        if provider.get_dyn_wireguard_provider().is_ok() {
            protocols.push(Protocol::Wireguard);
        }
        Ok(protocols)
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

fn server_entry(path: &Path, protocol: &Protocol) -> anyhow::Result<ServerEntry> {
    let id = path
        .file_stem()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Invalid server config filename: {}", path.display()))?;
    let parts = server_metadata::id_parts(&id);
    let (country_code, country) = server_metadata::country_from_id(&id);
    let hostname = server_metadata::config_hostname(path, protocol)?;
    let mut aliases = BTreeSet::new();
    aliases.insert(id.clone());
    for part in &parts {
        aliases.insert(part.clone());
    }
    if let Some(code) = &country_code {
        aliases.insert(code.clone());
    }
    if let Some(name) = &country {
        aliases.insert(name.to_ascii_lowercase());
    }

    let entry = ServerEntry {
        id,
        protocol: protocol.id().to_string(),
        country_code,
        country,
        hostname,
        config_file: path.display().to_string(),
        active: path.is_file(),
        aliases: aliases.into_iter().collect(),
    };

    Ok(entry)
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
