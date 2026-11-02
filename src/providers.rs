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
    /// Port forwarding availability per protocol id (e.g. `wireguard` ->
    /// true, `openvpn` -> false for AzireVPN).
    pub port_forwarding_by_protocol: BTreeMap<String, bool>,
    pub configured: bool,
    pub last_sync: Option<String>,
    pub server_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderProtocolInfo {
    pub configured: bool,
    pub last_sync: Option<String>,
    pub server_count: usize,
    /// Whether port forwarding is available over this protocol.
    pub port_forwarding: bool,
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
    #[serde(default)]
    configurations: BTreeMap<String, ConfigSyncMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConfigSyncMetadata {
    last_synced: String,
    fingerprint: String,
}

pub fn configuration_last_synced(
    provider: &VpnProvider,
    protocol: &Protocol,
    path: &std::path::Path,
) -> Option<String> {
    let metadata = read_sync_metadata(provider).ok()??;
    let filename = path.file_name()?.to_str()?;
    let config = metadata
        .protocols
        .get(protocol.id())?
        .configurations
        .get(filename)?;
    (vopono_core::diagnostics::config_fingerprint(path).ok()? == config.fingerprint)
        .then(|| config.last_synced.clone())
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
        let pf_by_protocol = provider
            .port_forwarding_by_protocol
            .iter()
            .map(|(protocol, supported)| format!("{protocol}:{supported}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            provider.id,
            provider.name,
            provider.protocols.join(","),
            provider.configured,
            provider.last_sync.as_deref().unwrap_or("never"),
            provider.port_forwarding,
            provider.port_forwarding_automatic,
            pf_by_protocol,
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
        let server_count = config_count(&provider, protocol.clone())?;
        let metadata_entry = metadata
            .as_ref()
            .and_then(|metadata| metadata.protocols.get(&id));
        protocol_status.insert(
            id,
            ProviderProtocolInfo {
                configured: server_count > 0,
                last_sync: metadata_entry.map(|entry| entry.last_sync.clone()),
                server_count,
                port_forwarding: provider.port_forwarding_for(protocol.clone()),
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
        port_forwarding_by_protocol: protocols
            .iter()
            .map(|protocol| {
                (
                    protocol.id().to_string(),
                    provider.port_forwarding_for(protocol.clone()),
                )
            })
            .collect(),
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
    let directory = match protocol {
        Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir()?,
        Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir()?,
        _ => anyhow::bail!("Sync metadata requires a provider-managed protocol"),
    };
    let configurations = get_configs_from_alias(&directory, "")
        .into_iter()
        .filter_map(|path| {
            let filename = path.file_name()?.to_str()?.to_owned();
            let fingerprint = vopono_core::diagnostics::config_fingerprint(&path).ok()?;
            Some((
                filename,
                ConfigSyncMetadata {
                    last_synced: timestamp.clone(),
                    fingerprint,
                },
            ))
        })
        .collect();
    metadata.protocols.insert(
        protocol.id().to_string(),
        SyncProtocolMetadata {
            last_sync: timestamp.clone(),
            server_count: config_count(provider, protocol.clone())?,
            configurations,
        },
    );
    atomic_metadata(&metadata_path, &serde_json::to_string_pretty(&metadata)?)?;

    // Global completion stamp so frontends can watch a single file (with e.g.
    // a FileView) instead of polling `providers --json` for new configs.
    let stamp = serde_json::json!({
        "timestamp": timestamp,
        "provider": provider.id(),
        "protocol": protocol.id().to_string(),
    });
    let stamp_path = vopono_core::util::vopono_dir()?.join(".last-sync");
    atomic_metadata(&stamp_path, &serde_json::to_string_pretty(&stamp)?)
        .with_context(|| format!("Failed to write sync stamp {}", stamp_path.display()))?;
    Ok(())
}

fn atomic_metadata(path: &std::path::Path, body: &str) -> anyhow::Result<()> {
    if vopono_core::util::write_file_as_config_owner(path, body, Some(0o600))? {
        return Ok(());
    }
    use std::io::Write;
    let mut temporary = tempfile::NamedTempFile::new_in(
        path.parent()
            .context("Metadata requires a parent directory")?,
    )?;
    temporary.write_all(body.as_bytes())?;
    temporary.persist(path)?;
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

/// A dedicated smoke command needs neither local configs nor an active subscription.
pub fn check_public(provider: VpnProvider, json: bool) -> anyhow::Result<i32> {
    use vopono_core::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticState};
    let result = vopono_core::config::providers::diagnostics::public_catalogue(
        &provider,
        std::time::Duration::from_secs(10),
    );
    let (diagnostic, count) = match result {
        Ok(Some(servers)) => (
            Diagnostic::new(
                DiagnosticCode::ProviderCatalogue,
                DiagnosticState::Pass,
                "Public provider schema and active endpoint metadata validated",
                None,
            ),
            servers.len(),
        ),
        Ok(None) => (
            Diagnostic::new(
                DiagnosticCode::ProviderCatalogue,
                DiagnosticState::Skipped,
                "No public catalogue adapter is implemented for this provider",
                None,
            ),
            0,
        ),
        Err(_) => (
            Diagnostic::new(
                DiagnosticCode::ProviderCatalogue,
                DiagnosticState::Fail,
                "Public provider catalogue request or schema validation failed",
                Some("Retry later; report persistent compatibility failures"),
            ),
            0,
        ),
    };
    let failed = diagnostic.state == DiagnosticState::Fail;
    if json {
        crate::api::print_json(
            &serde_json::json!({"version": crate::api::SCHEMA_VERSION, "provider": provider.id(), "server_count": count, "diagnostics": [diagnostic]}),
        )?;
    } else {
        println!(
            "{}\t{:?}\t{}\tservers={count}",
            provider.id(),
            diagnostic.state,
            diagnostic.message
        );
    }
    Ok(i32::from(failed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        // AirVPN forwards manually and protocol-independently.
        assert_eq!(
            airvpn.port_forwarding_by_protocol,
            BTreeMap::from([
                ("openvpn".to_string(), true),
                ("wireguard".to_string(), true)
            ])
        );

        let mullvad = provider_info(&VpnProvider::Mullvad).unwrap();
        assert!(!mullvad.port_forwarding);
        assert_eq!(mullvad.protocols, vec!["wireguard".to_string()]);
        assert_eq!(
            mullvad.port_forwarding_by_protocol,
            BTreeMap::from([("wireguard".to_string(), false)])
        );
    }

    #[test]
    fn port_forwarding_matrix_reflects_protocol_support() {
        use vopono_core::config::vpn::Protocol;
        // AzireVPN's forwarder only implements the Wireguard flow.
        assert!(VpnProvider::AzireVPN.port_forwarding_for(Protocol::Wireguard));
        assert!(!VpnProvider::AzireVPN.port_forwarding_for(Protocol::OpenVpn));
        // PIA and ProtonVPN forwarders are tunnel-agnostic.
        for provider in [VpnProvider::PrivateInternetAccess, VpnProvider::ProtonVPN] {
            assert!(provider.port_forwarding_for(Protocol::Wireguard));
            assert!(provider.port_forwarding_for(Protocol::OpenVpn));
        }
        assert!(!VpnProvider::Mullvad.port_forwarding_for(Protocol::Wireguard));
    }

    #[test]
    fn sync_writes_global_completion_stamp() {
        let dir = std::env::temp_dir().join(format!(
            "vopono-sync-stamp-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        vopono_core::util::set_config_dir_override(Some(dir.clone()));

        let wg_dir = VpnProvider::AirVPN
            .get_dyn_wireguard_provider()
            .unwrap()
            .wireguard_dir()
            .unwrap();
        fs::create_dir_all(&wg_dir).unwrap();
        let server = wg_dir.join("fixture.conf");
        fs::write(&server, "fixture configuration").unwrap();
        let result = record_sync(&VpnProvider::AirVPN, Protocol::Wireguard);
        assert!(
            configuration_last_synced(&VpnProvider::AirVPN, &Protocol::Wireguard, &server)
                .is_some()
        );
        fs::write(&server, "modified configuration").unwrap();
        assert!(
            configuration_last_synced(&VpnProvider::AirVPN, &Protocol::Wireguard, &server)
                .is_none()
        );
        vopono_core::util::set_config_dir_override(None);
        result.unwrap();

        let stamp_path = dir.join("vopono").join(".last-sync");
        let stamp: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(stamp_path).unwrap()).unwrap();
        assert_eq!(stamp["provider"], "airvpn");
        assert_eq!(stamp["protocol"], "wireguard");
        assert!(stamp["timestamp"].is_string());
        let _ = fs::remove_dir_all(dir);
    }
}
