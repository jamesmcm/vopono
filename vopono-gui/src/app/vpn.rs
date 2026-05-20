use super::utils::has_files;
use crate::gui_config::{ApplicationProfile, CustomVpnConfig, LaunchConfig};
use crate::launcher;
use std::path::{Path, PathBuf};
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::util::get_configs_from_alias;

#[derive(Clone)]
pub(super) struct SyncedVpnConfig {
    pub(super) provider: VpnProvider,
    pub(super) protocol: Protocol,
    pub(super) server: String,
    pub(super) path: PathBuf,
}

#[derive(Clone)]
pub(super) enum VpnChoice {
    Synced(SyncedVpnConfig),
    Custom {
        index: usize,
        config: CustomVpnConfig,
    },
}

impl VpnChoice {
    pub(super) fn primary_label(&self) -> String {
        match self {
            Self::Synced(config) => {
                format!("{} {} {}", config.provider, config.protocol, config.server)
            }
            Self::Custom { config, .. } => {
                format!("{} ({})", config.name, config.protocol)
            }
        }
    }

    pub(super) fn detail_label(&self) -> String {
        match self {
            Self::Synced(config) => config.path.display().to_string(),
            Self::Custom { config, .. } => config.path.display().to_string(),
        }
    }
}

pub(super) fn launch_vpn_choice(
    choice: &VpnChoice,
    app: &ApplicationProfile,
    launch: &LaunchConfig,
) -> anyhow::Result<String> {
    match choice {
        VpnChoice::Synced(config) => launcher::launch_provider_config(
            config.provider.clone(),
            config.protocol.clone(),
            &config.server,
            app,
            launch,
        ),
        VpnChoice::Custom { config, .. } => launcher::launch_custom_config(config, app, launch),
    }
}

pub(super) fn vpn_choices_from_configs(
    custom_configs: &[CustomVpnConfig],
    synced_configs: &[SyncedVpnConfig],
) -> Vec<VpnChoice> {
    custom_configs
        .iter()
        .enumerate()
        .map(|(index, config)| VpnChoice::Custom {
            index,
            config: config.clone(),
        })
        .chain(synced_configs.iter().cloned().map(VpnChoice::Synced))
        .collect()
}

pub(super) fn scan_synced_configs() -> Vec<SyncedVpnConfig> {
    let mut configs = Vec::new();

    for provider in VpnProvider::iter().filter(|provider| {
        !matches!(
            provider,
            VpnProvider::Custom | VpnProvider::None | VpnProvider::Warp
        )
    }) {
        if let Ok(openvpn) = provider.get_dyn_openvpn_provider()
            && let Ok(dir) = openvpn.openvpn_dir()
        {
            configs.extend(provider_configs_from_dir(
                &provider,
                Protocol::OpenVpn,
                &dir,
            ));
        }
        if let Ok(wireguard) = provider.get_dyn_wireguard_provider()
            && let Ok(dir) = wireguard.wireguard_dir()
        {
            configs.extend(provider_configs_from_dir(
                &provider,
                Protocol::Wireguard,
                &dir,
            ));
        }
    }

    configs.sort_by(|a, b| {
        a.provider
            .to_string()
            .cmp(&b.provider.to_string())
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| a.server.cmp(&b.server))
    });
    configs
}

fn provider_configs_from_dir(
    provider: &VpnProvider,
    protocol: Protocol,
    dir: &Path,
) -> Vec<SyncedVpnConfig> {
    if !dir.exists() {
        return Vec::new();
    }

    provider_configs_from_paths(provider, protocol, get_configs_from_alias(dir, ""))
}

fn provider_configs_from_paths(
    provider: &VpnProvider,
    protocol: Protocol,
    paths: Vec<PathBuf>,
) -> Vec<SyncedVpnConfig> {
    paths
        .into_iter()
        .filter_map(|path| {
            let server = path.file_name()?.to_str()?.to_string();
            Some(SyncedVpnConfig {
                provider: provider.clone(),
                protocol: protocol.clone(),
                server,
                path,
            })
        })
        .collect()
}

pub(super) fn provider_config_state(provider: &VpnProvider) -> String {
    let mut states = Vec::new();
    if let Ok(openvpn) = provider.get_dyn_openvpn_provider() {
        states.push(format!(
            "OpenVPN {}",
            if openvpn.openvpn_dir().is_ok_and(|dir| has_files(&dir)) {
                "configured"
            } else {
                "missing"
            }
        ));
    }
    if let Ok(wireguard) = provider.get_dyn_wireguard_provider() {
        states.push(format!(
            "WireGuard {}",
            if wireguard.wireguard_dir().is_ok_and(|dir| has_files(&dir)) {
                "configured"
            } else {
                "missing"
            }
        ));
    }
    if states.is_empty() {
        "no syncable protocols".to_string()
    } else {
        states.join(" / ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synced_config_server_uses_filename_with_extension() {
        let path = PathBuf::from("/tmp/se-stockholm.conf");
        let configs = provider_configs_from_paths(
            &VpnProvider::Mullvad,
            Protocol::Wireguard,
            vec![path.clone()],
        );
        assert_eq!(configs[0].server, "se-stockholm.conf");
        assert_eq!(configs[0].path, path);
    }

    #[test]
    fn launch_vpn_choices_put_custom_configs_first() {
        let custom = CustomVpnConfig {
            name: "AirVPN custom".to_string(),
            path: PathBuf::from("/tmp/airvpn.conf"),
            protocol: "wireguard".to_string(),
            usage_count: 0,
        };
        let synced = SyncedVpnConfig {
            provider: VpnProvider::Mullvad,
            protocol: Protocol::Wireguard,
            server: "se-stockholm.conf".to_string(),
            path: PathBuf::from("/tmp/se-stockholm.conf"),
        };

        let choices = vpn_choices_from_configs(&[custom], &[synced]);
        assert!(matches!(choices[0], VpnChoice::Custom { .. }));
        assert!(matches!(choices[1], VpnChoice::Synced(_)));
    }

    #[test]
    fn provider_configs_ignore_paths_without_file_names() {
        let configs = provider_configs_from_paths(
            &VpnProvider::Mullvad,
            Protocol::Wireguard,
            vec!["/".into()],
        );
        assert!(configs.is_empty());
    }
}
