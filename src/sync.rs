use super::providers::VpnProvider;
use super::util::set_config_permissions;
use super::vpn::Protocol;
use anyhow::bail;
use dialoguer::MultiSelect;
use log::info;
use std::str::FromStr;

pub fn sync_menu() -> anyhow::Result<()> {
    let variants = VpnProvider::variants()
        .iter()
        .filter(|x| **x != "Custom")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();

    let selection = MultiSelect::new()
        .with_prompt("Which VPN providers do you wish to synchronise? Press Space to select and Enter to continue")
        .items(variants.as_slice())
        .interact()?;

    if selection.is_empty() {
        bail!("Must choose at least one VPN provider to sync");
    }

    // TODO: Allow for overriding default port here
    for provider in selection
        .into_iter()
        .map(|x| VpnProvider::from_str(&variants[x]))
        .flatten()
    {
        synch(provider, None)?;
    }

    Ok(())
}

pub fn synch(provider: VpnProvider, protocol: Option<Protocol>) -> anyhow::Result<()> {
    match protocol {
        Some(Protocol::OpenVpn) => {
            info!("Starting OpenVPN configuration...");
            let provider = provider.get_dyn_openvpn_provider()?;
            provider.create_openvpn_config()?;
            // downcast?
        }
        Some(Protocol::Wireguard) => {
            info!("Starting Wireguard configuration...");
            let provider = provider.get_dyn_wireguard_provider()?;
            provider.create_wireguard_config()?;
        }
        None => {
            if let Ok(p) = provider.get_dyn_wireguard_provider() {
                info!("Starting Wireguard configuration...");
                p.create_wireguard_config()?;
            }
            if let Ok(p) = provider.get_dyn_openvpn_provider() {
                info!("Starting OpenVPN configuration...");
                p.create_openvpn_config()?;
            }
        }
    }

    set_config_permissions()?;
    Ok(())
}
