use super::args::ServersCommand;
use crate::providers::VpnProvider;
use crate::util::get_configs_from_alias;
use crate::vpn::Protocol;
use anyhow::bail;

pub fn print_configs(cmd: ServersCommand) -> anyhow::Result<()> {
    let provider = cmd.vpn_provider;
    if provider == VpnProvider::Custom {
        bail!("Config listing not implemented for Custom provider files");
    }

    // Check protocol is valid for provider
    let protocol = cmd
        .protocol
        .clone()
        .unwrap_or_else(|| provider.get_dyn_provider().default_protocol());

    // Check config files exist for provider
    let cdir = match protocol {
        Protocol::OpenVpn => provider.get_dyn_openvpn_provider()?.openvpn_dir(),
        Protocol::Wireguard => provider.get_dyn_wireguard_provider()?.wireguard_dir(),
        Protocol::OpenConnect => bail!("Config listing not implemented for OpenConnect"),
    }?;
    if !cdir.exists() || cdir.read_dir()?.next().is_none() {
        bail!(
            "Config files for {} {} do not exist, run vopono sync",
            provider,
            protocol
        );
    }

    // Use get_configs_from_alias
    let prefix = cmd.prefix.unwrap_or_else(String::new);
    println!("provider\tprotocol\tconfig_file");
    if (cmd.protocol.is_none() && provider.get_dyn_openvpn_provider().is_ok())
        || cmd.protocol == Some(Protocol::OpenVpn)
    {
        let openvpn_configs = get_configs_from_alias(
            &provider.get_dyn_openvpn_provider()?.openvpn_dir()?,
            &prefix,
        );

        for config in openvpn_configs {
            println!(
                "{}\topenvpn\t{}",
                provider,
                config.file_name().unwrap().to_str().unwrap()
            );
        }
    };

    if (cmd.protocol.is_none() && provider.get_dyn_wireguard_provider().is_ok())
        || cmd.protocol == Some(Protocol::Wireguard)
    {
        let wg_configs = get_configs_from_alias(
            &provider.get_dyn_wireguard_provider()?.wireguard_dir()?,
            &prefix,
        );

        for config in wg_configs {
            println!(
                "{}\twireguard\t{}",
                provider,
                config.file_name().unwrap().to_str().unwrap()
            );
        }
    };
    Ok(())
}
