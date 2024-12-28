use anyhow::bail;
use clap::ValueEnum;
use dialoguer::MultiSelect;
use log::{error, info};
use vopono_core::config::providers::{UiClient, VpnProvider};
use vopono_core::config::vpn::Protocol;
use vopono_core::util::set_config_permissions;

use crate::args::WrappedArg;

pub fn sync_menu(uiclient: &dyn UiClient, protocol: Option<Protocol>) -> anyhow::Result<()> {
    let variants = WrappedArg::<VpnProvider>::value_variants()
        .iter()
        .filter(|x| {
            ![VpnProvider::Custom, VpnProvider::None, VpnProvider::Warp].contains(&x.to_variant())
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
    // TODO: Separate availability from functionality, so we can filter disabled protocols from the UI
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
        Some(Protocol::OpenConnect) => {
            error!("vopono sync not supported for OpenConnect protocol");
        }
        Some(Protocol::OpenFortiVpn) => {
            error!("vopono sync not supported for OpenFortiVpn protocol");
        }
        Some(Protocol::Warp) => {
            error!("vopono sync not supported for Cloudflare Warp protocol");
        }
        Some(Protocol::None) => {
            error!("vopono sync not supported for None protocol");
        }
        // TODO: Fix this asking for same credentials twice
        None => {
            if let Ok(p) = provider.get_dyn_wireguard_provider() {
                info!("Starting Wireguard configuration...");
                p.create_wireguard_config(uiclient)?;
            }
            if let Ok(p) = provider.get_dyn_openvpn_provider() {
                info!("Starting OpenVPN configuration...");
                p.create_openvpn_config(uiclient)?;
            }
        }
    }

    set_config_permissions()?;
    Ok(())
}
