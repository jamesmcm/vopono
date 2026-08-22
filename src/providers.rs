use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, create_dir_all};
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::get_configs_from_alias;

#[derive(Clone, Debug, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub protocols: Vec<String>,
    pub sync_supported: bool,
    pub requires_auth: bool,
    pub port_forwarding: bool,
    pub port_forwarding_automatic: bool,
    pub configured: bool,
    pub last_sync: Option<String>,
    pub server_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderProtocolInfo {
    pub configured: bool,
    pub last_sync: Option<String>,
    pub server_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderStatus {
    pub version: u8,
    pub provider: ProviderInfo,
    pub protocols: BTreeMap<String, ProviderProtocolInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvidersDocument {
    pub version: u8,
    pub providers: Vec<ProviderInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SyncMetadata {
    last_sync: Option<String>,
    #[serde(default)]
    protocols: BTreeMap<String, SyncProtocolMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SyncProtocolMetadata {
    last_sync: String,
    server_count: usize,
}

pub fn print_providers(json: bool) -> anyhow::Result<()> {
    let providers = provider_infos()?;
    if json {
        return crate::api::print_json(&ProvidersDocument {
            version: crate::api::SCHEMA_VERSION,
            providers,
        });
    }

    println!(
        "id\tname\tprotocols\tconfigured\tlast_sync\tport_forwarding\tautomatic_port_forwarding\tserver_count"
    );
    for provider in providers {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            provider.id,
            provider.name,
            provider.protocols.join(","),
            provider.configured,
            provider.last_sync.as_deref().unwrap_or("never"),
            provider.port_forwarding,
            provider.port_forwarding_automatic,
            provider.server_count
        );
    }
    Ok(())
}

pub fn print_provider_status(provider: VpnProvider, json: bool) -> anyhow::Result<()> {
    let status = provider_status(provider)?;
    if json {
        return crate::api::print_json(&status);
    }

    println!("provider\tconfigured\tlast_sync\tserver_count");
    println!(
        "{}\t{}\t{}\t{}",
        status.provider.id,
        status.provider.configured,
        status.provider.last_sync.as_deref().unwrap_or("never"),
        status.provider.server_count
    );
    for (protocol, info) in status.protocols {
        println!(
            "  {protocol}\tconfigured={}\tlast_sync={}\tserver_count={}",
            info.configured,
            info.last_sync.as_deref().unwrap_or("never"),
            info.server_count
        );
    }
    Ok(())
}

pub fn provider_status(provider: VpnProvider) -> anyhow::Result<ProviderStatus> {
    let info = provider_info(&provider)?;
    let metadata = read_sync_metadata(&provider)?;
    let mut protocol_status = BTreeMap::new();
    for protocol in provider.supported_sync_protocols() {
        let id = protocol.id().to_string();
        let server_count = config_count(&provider, protocol)?;
        let metadata_entry = metadata
            .as_ref()
            .and_then(|metadata| metadata.protocols.get(&id));
        protocol_status.insert(
            id,
            ProviderProtocolInfo {
                configured: server_count > 0,
                last_sync: metadata_entry.map(|entry| entry.last_sync.clone()),
                server_count,
            },
        );
    }

    Ok(ProviderStatus {
        version: crate::api::SCHEMA_VERSION,
        provider: info,
        protocols: protocol_status,
    })
}

pub fn provider_infos() -> anyhow::Result<Vec<ProviderInfo>> {
    VpnProvider::iter()
        .filter(|provider| !matches!(provider, VpnProvider::Custom | VpnProvider::None))
        .map(|provider| provider_info(&provider))
        .collect()
}

pub fn provider_info(provider: &VpnProvider) -> anyhow::Result<ProviderInfo> {
    let metadata = read_sync_metadata(provider)?;
    // Capability facts come from vopono_core so new providers cannot be
    // misreported by a stale CLI-side table.
    let sync_supported = provider.supports_sync();
    let protocols = provider.supported_sync_protocols();
    let mut server_count = 0;
    for protocol in &protocols {
        server_count += config_count(provider, protocol.clone())?;
    }
    let last_sync = metadata.as_ref().and_then(|metadata| {
        metadata.last_sync.clone().or_else(|| {
            metadata
                .protocols
                .values()
                .map(|x| x.last_sync.clone())
                .max()
        })
    });

    Ok(ProviderInfo {
        id: provider.id().to_string(),
        name: provider.display_name().to_string(),
        protocols: protocols
            .iter()
            .map(|protocol| protocol.id().to_string())
            .collect(),
        sync_supported,
        requires_auth: sync_supported,
        port_forwarding: provider.supports_port_forwarding(),
        port_forwarding_automatic: provider.has_automatic_port_forwarding(),
        configured: server_count > 0,
        last_sync,
        server_count,
    })
}

pub fn record_sync(provider: &VpnProvider, protocol: Protocol) -> anyhow::Result<()> {
    let provider_dir = provider.get_dyn_provider().provider_dir()?;
    create_dir_all(&provider_dir)?;
    // Co-located with the provider's configs; safe from clobbering because
    // sync flows only wipe per-protocol subdirectories (openvpn/, wireguard/).
    let metadata_path = provider_dir.join(".sync.json");
    let mut metadata = read_sync_metadata(provider)?.unwrap_or_default();
    let timestamp = Utc::now().to_rfc3339();
    metadata.last_sync = Some(timestamp.clone());
    metadata.protocols.insert(
        protocol.id().to_string(),
        SyncProtocolMetadata {
            last_sync: timestamp,
            server_count: config_count(provider, protocol)?,
        },
    );
    let file = File::create(metadata_path)?;
    serde_json::to_writer_pretty(file, &metadata)?;
    Ok(())
}

fn read_sync_metadata(provider: &VpnProvider) -> anyhow::Result<Option<SyncMetadata>> {
    if matches!(provider, VpnProvider::Custom | VpnProvider::None) {
        return Ok(None);
    }
    let provider_dir = provider.get_dyn_provider().provider_dir()?;
    let path = provider_dir.join(".sync.json");
    if !path.exists() {
        return Ok(None);
    }
    let file = File::open(&path)
        .with_context(|| format!("Failed to read provider metadata {}", path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("Failed to parse provider metadata {}", path.display()))
        .map(Some)
}

fn config_count(provider: &VpnProvider, protocol: Protocol) -> anyhow::Result<usize> {
    let directory = match protocol {
        Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir()?,
        Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir()?,
        _ => return Ok(0),
    };
    if !directory.exists() {
        return Ok(0);
    }
    Ok(get_configs_from_alias(&directory, "").len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_ids_are_stable_and_cli_friendly() {
        assert_eq!(VpnProvider::AirVPN.id(), "airvpn");
        assert_eq!(
            VpnProvider::PrivateInternetAccess.id(),
            "privateinternetaccess"
        );
        assert_eq!(Protocol::OpenVpn.id(), "openvpn");
    }

    #[test]
    fn provider_capabilities_are_derived_from_core() {
        let airvpn = provider_info(&VpnProvider::AirVPN).unwrap();
        assert!(airvpn.port_forwarding);
        assert!(!airvpn.port_forwarding_automatic);
        assert!(airvpn.sync_supported);
        assert_eq!(
            airvpn.protocols,
            vec!["openvpn".to_string(), "wireguard".to_string()]
        );

        let mullvad = provider_info(&VpnProvider::Mullvad).unwrap();
        assert!(!mullvad.port_forwarding);
        assert_eq!(mullvad.protocols, vec!["wireguard".to_string()]);
    }
}
