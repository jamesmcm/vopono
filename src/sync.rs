use anyhow::bail;
use clap::ValueEnum;
use dialoguer::MultiSelect;
use log::info;
use vopono_core::config::providers::{UiClient, VpnProvider};
use vopono_core::config::vpn::Protocol;

use crate::args::WrappedArg;
use crate::providers::record_sync;

pub fn sync_menu(uiclient: &dyn UiClient, protocol: Option<Protocol>) -> anyhow::Result<()> {
    let variants = WrappedArg::<VpnProvider>::value_variants()
        .iter()
        .filter(|x| {
            let provider = x.to_variant();
            provider.supports_sync()
                && protocol
                    .as_ref()
                    .is_none_or(|protocol| supports_sync_protocol(&provider, protocol))
        })
        .map(|x| x.to_variant().to_string())
        .collect::<Vec<String>>();

    let selection: Vec<usize> = MultiSelect::new()
        .with_prompt("Which VPN providers do you wish to synchronise? Press Space to select and Enter to continue")
        .items(variants.as_slice())
        .interact()?;

    if selection.is_empty() {
        bail!("Must choose at least one VPN provider to sync");
    }

    for provider in selection
        .into_iter()
        .flat_map(|x| WrappedArg::<VpnProvider>::from_str(&variants[x], true))
    {
        synch(provider.to_variant(), &protocol, uiclient)?;
    }

    Ok(())
}

pub fn synch(
    provider: VpnProvider,
    protocol: &Option<Protocol>,
    uiclient: &dyn UiClient,
) -> anyhow::Result<()> {
    // The sudo fallback may discover missing provider data after elevation.
    // Keep generation and publication under the user's filesystem identity.
    if nix::unistd::geteuid().is_root()
        && let (Some(uid), Some(gid)) = vopono_core::util::resolve_config_owner()?
        && !uid.is_root()
    {
        use std::os::unix::process::CommandExt;
        let user = nix::unistd::User::from_uid(uid)?
            .ok_or_else(|| anyhow::anyhow!("Unknown config owner"))?;
        let account = std::ffi::CString::new(user.name)?;
        let mut child = std::process::Command::new(std::env::current_exe()?);
        child
            .arg("sync")
            .arg(provider.id())
            .env("HOME", &user.dir)
            .env("XDG_CONFIG_HOME", vopono_core::util::config_dir()?);
        if let Some(protocol) = protocol {
            child.args(["--protocol", protocol.id()]);
        }
        unsafe {
            child.pre_exec(move || {
                nix::unistd::initgroups(&account, gid)?;
                nix::unistd::setgid(gid)?;
                nix::unistd::setuid(uid)?;
                Ok(())
            });
        }
        anyhow::ensure!(
            child.status()?.success(),
            "Provider synchronization failed; installed files were preserved"
        );
        return Ok(());
    }
    let protocols = match protocol {
        Some(protocol) => vec![protocol.clone()],
        None => provider.supported_sync_protocols(),
    };
    anyhow::ensure!(
        protocols
            .iter()
            .all(|p| matches!(p, Protocol::OpenVpn | Protocol::Wireguard)),
        "Synchronization is only supported for provider-managed OpenVPN and WireGuard configurations"
    );
    vopono_core::config::providers::transaction::run(
        &provider,
        &protocols,
        || generate(provider.clone(), protocol, uiclient),
        || {
            for protocol in &protocols {
                record_sync(&provider, protocol.clone())?;
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn generate(
    provider: VpnProvider,
    protocol: &Option<Protocol>,
    uiclient: &dyn UiClient,
) -> anyhow::Result<()> {
    match protocol {
        Some(Protocol::OpenVpn) => {
            info!("Starting OpenVPN configuration...");
            let provider = provider.get_dyn_openvpn_provider()?;
            provider.create_openvpn_config(uiclient)?;
            // downcast?
        }
        Some(Protocol::Wireguard) => {
            info!("Starting Wireguard configuration...");
            let provider = provider.get_dyn_wireguard_provider()?;
            provider.create_wireguard_config(uiclient)?;
        }
        Some(Protocol::AmneziaWG) => {
            bail!("vopono sync not supported for AmneziaWG protocol");
        }
        Some(Protocol::OpenConnect) => {
            bail!("vopono sync not supported for OpenConnect protocol");
        }
        Some(Protocol::OpenFortiVpn) => {
            bail!("vopono sync not supported for OpenFortiVpn protocol");
        }
        Some(Protocol::Ssh) => {
            bail!("vopono sync is not needed for SSH protocol");
        }
        Some(Protocol::Warp) => {
            bail!("vopono sync not supported for Cloudflare Warp protocol");
        }
        Some(Protocol::None) => {
            bail!("vopono sync not supported for None protocol");
        }
        // Sync OpenVPN first so credentials are cached for Wireguard to reuse
        None => {
            if let Ok(p) = provider.get_dyn_openvpn_provider() {
                info!("Starting OpenVPN configuration...");
                p.create_openvpn_config(uiclient)?;
            }
            if let Ok(p) = provider.get_dyn_wireguard_provider() {
                info!("Starting Wireguard configuration...");
                p.create_wireguard_config(uiclient)?;
            }
        }
    }

    Ok(())
}

fn supports_sync_protocol(provider: &VpnProvider, protocol: &Protocol) -> bool {
    // Single source of truth in vopono_core.
    provider.supported_sync_protocols().contains(protocol)
}
