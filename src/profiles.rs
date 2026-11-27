use crate::args::{ExecCommand, ProfileSubcommand, ProfilesCommand};
use anyhow::{Context, ensure};
use config::Config;
use std::path::Path;

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub fn select(config: Config, name: Option<&str>) -> anyhow::Result<Config> {
    let Some(name) = name else {
        return Ok(config);
    };
    ensure!(
        valid_name(name),
        "Profile names must contain 1-64 letters, digits, underscores or hyphens"
    );
    let profile = config
        .get_table(&format!("profiles.{name}"))
        .context("Named profile was not found")?;
    let mut builder = Config::builder().add_source(config);
    for (key, value) in &profile {
        // Profile data is ordinary user configuration, subject to the same
        // daemon identity overrides and script restrictions as direct exec.
        ensure!(
            key != "profiles" && key != "profile",
            "Nested profile definitions are not supported"
        );
        let underscored = key.replace('-', "_");
        // Readers accept both spellings. Override both so a global setting
        // cannot win merely because it uses the other spelling. As elsewhere
        // in argument resolution, an explicit underscore spelling takes precedence.
        if &underscored != key && profile.contains_key(&underscored) {
            continue;
        }
        builder = builder
            .set_override(key.replace('_', "-"), value.clone())?
            .set_override(underscored, value.clone())?;
    }
    let profile_sets_non_custom_provider = profile
        .get("provider")
        .and_then(|v| v.clone().into_string().ok())
        .is_some_and(|p| !p.eq_ignore_ascii_case("custom"));
    let profile_sets_ssh_protocol = profile
        .get("protocol")
        .and_then(|v| v.clone().into_string().ok())
        .is_some_and(|p| p.eq_ignore_ascii_case("ssh"));
    if (profile_sets_non_custom_provider || profile_sets_ssh_protocol)
        && !profile.contains_key("custom")
    {
        // Prevent a top-level `custom` default from overriding a profile's explicit
        // non-custom `provider` or SSH `protocol`.
        builder = builder.set_override("custom", "")?;
    }
    let profile_selects_connection =
        profile.contains_key("custom") || profile.contains_key("provider");
    if profile_selects_connection && !profile.contains_key("protocol") {
        // Prevent a top-level `protocol` default (e.g. `protocol = "Wireguard"`)
        // from overriding auto-detection or provider defaults for this profile.
        builder = builder.set_override("protocol", "")?;
    }
    Ok(builder.build()?)
}

/// Resolve settings needed before daemon forwarding supplies launch defaults.
/// Resolve again on the daemon using its authenticated user's config tree.
pub fn prepare(command: &mut ExecCommand) -> anyhow::Result<()> {
    let config = crate::args_config::ArgsConfig::get_config_file(command)?;
    if command.working_directory.is_none() {
        command.working_directory = config
            .get_string("working_directory")
            .or_else(|_| config.get_string("working-directory"))
            .ok();
    }
    // Pull path-bearing profile/config options onto the command so client-side
    // resolution against the invoking user's CWD/HOME applies before daemon forwarding.
    if command.existing_netns.is_none()
        && command.custom.is_none()
        && command
            .provider
            .as_ref()
            .is_none_or(|p| p.to_variant() == vopono_core::config::providers::VpnProvider::Custom)
        && !command.protocol.as_ref().is_some_and(|p| {
            matches!(
                p.to_variant(),
                vopono_core::config::vpn::Protocol::Ssh | vopono_core::config::vpn::Protocol::Warp
            )
        })
        && let Ok(path) = config.get_string("custom")
        && !path.is_empty()
    {
        command.custom = Some(std::path::PathBuf::from(path));
    }
    for (slot, key) in [
        (&mut command.auth_user_pass, "auth_user_pass"),
        (&mut command.trojan_config, "trojan_config"),
    ] {
        if slot.is_none()
            && let Ok(path) = config
                .get_string(key)
                .or_else(|_| config.get_string(&key.replace('_', "-")))
            && !path.is_empty()
        {
            *slot = Some(std::path::PathBuf::from(path));
        }
    }
    for (slot, key) in [
        (&mut command.postup, "postup"),
        (&mut command.predown, "predown"),
        (
            &mut command.port_forwarding_callback,
            "port_forwarding_callback",
        ),
    ] {
        if slot.is_none()
            && let Ok(val) = config
                .get_string(key)
                .or_else(|_| config.get_string(&key.replace('_', "-")))
            && !val.is_empty()
        {
            *slot = Some(val);
        }
    }
    for (flag, name) in [
        (&mut command.monitor, "monitor"),
        (&mut command.recover, "recover"),
        (&mut command.keep_alive, "keep_alive"),
        (&mut command.create_netns_only, "create_netns_only"),
        (&mut command.json, "json"),
    ] {
        *flag |= config
            .get_bool(name)
            .or_else(|_| config.get_bool(&name.replace('_', "-")))
            .unwrap_or(false);
    }
    if !command.create_netns_only
        && command.application.is_empty()
        && let Some(name) = &command.profile
    {
        command.application = config
            .get_string("application")
            .with_context(|| format!("Profile {name:?} requires an application"))?;
    }
    ensure!(
        !command.recover || command.monitor,
        "Recovery requires monitoring"
    );
    Ok(())
}

pub fn run(command: ProfilesCommand) -> anyhow::Result<()> {
    let explicit_config = command.vopono_config.is_some();
    let path = command
        .vopono_config
        .unwrap_or(vopono_core::util::vopono_dir()?.join("config.toml"));
    match command.command {
        ProfileSubcommand::List(format) => {
            let names = if !explicit_config && !path.exists() {
                Vec::new()
            } else {
                let path = path.canonicalize().with_context(|| {
                    format!("Configuration file {} was not found", path.display())
                })?;
                let config = crate::args_config::load_config_file_redacted(&path)?;
                let mut names: Vec<_> = config
                    .get_table("profiles")
                    .unwrap_or_default()
                    .into_keys()
                    .filter(|name| valid_name(name))
                    .collect();
                names.sort();
                names
            };
            if format.json {
                crate::api::print_json(
                    &serde_json::json!({"version": crate::api::SCHEMA_VERSION, "profiles": names}),
                )?;
            } else {
                for name in names {
                    println!("{name}");
                }
            }
        }
        ProfileSubcommand::Export { name, output } => {
            let path = path
                .canonicalize()
                .with_context(|| format!("Configuration file {} was not found", path.display()))?;
            let config = crate::args_config::load_config_file_redacted(&path)?;
            let selected = select(config, Some(&name))?;
            ensure!(
                !selected.get_string("application")?.is_empty(),
                "Profile application is empty"
            );
            let executable = std::env::current_exe()?;
            let desktop = desktop_entry(&name, &executable, &path)?;
            // create_new avoids accidental overwrites and following pre-existing symlinks.
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o644)
                .open(&output)?;
            file.write_all(desktop.as_bytes())?;
            println!("{}", output.display());
        }
    }
    Ok(())
}
fn desktop_arg(value: &str) -> anyhow::Result<String> {
    ensure!(
        !value.contains(['\n', '\r', '\0']),
        "Desktop arguments cannot contain newlines or NUL"
    );
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    // Desktop entry string values apply an additional backslash escaping layer.
    Ok(format!("\"{}\"", escaped.replace('\\', "\\\\")))
}
fn desktop_entry(name: &str, executable: &Path, config: &Path) -> anyhow::Result<String> {
    ensure!(valid_name(name), "Invalid profile name");
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=vopono: {name}\nExec={} exec --profile {name} --vopono-config {}\nTerminal=true\nCategories=Network;\n",
        desktop_arg(executable.to_str().context("Non-UTF8 executable path")?)?,
        desktop_arg(config.to_str().context("Non-UTF8 config path")?)?
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_resolves_working_directory_with_cli_profile_default_precedence() {
        use clap::Parser;

        for (global_key, profile_key) in [
            ("working-directory", "working-directory"),
            ("working_directory", "working_directory"),
            ("working-directory", "working_directory"),
            ("working_directory", "working-directory"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let config = directory.path().join("config.toml");
            std::fs::write(
                &config,
                format!(
                    "{global_key}='/global'\n[profiles.launch]\n{profile_key}='/profile'\napplication='pwd'\n"
                ),
            )
            .unwrap();
            for (profile, explicit, expected) in [
                (false, false, "/global"),
                (true, false, "/profile"),
                (true, true, "/explicit"),
            ] {
                let mut args = vec![
                    "vopono",
                    "exec",
                    "--vopono-config",
                    config.to_str().unwrap(),
                ];
                if profile {
                    args.extend(["--profile", "launch"]);
                }
                if explicit {
                    args.extend(["--working-directory", "/explicit"]);
                }
                let Some(crate::args::Command::Exec(mut command)) =
                    crate::args::App::try_parse_from(args).unwrap().cmd
                else {
                    unreachable!()
                };
                prepare(&mut command).unwrap();
                assert_eq!(command.working_directory.as_deref(), Some(expected));
            }
        }
    }

    #[test]
    fn selected_profile_overrides_defaults_without_affecting_other_profiles() {
        let config = Config::builder().add_source(config::File::from_str("provider='mullvad'\n[profiles.downloads]\nserver='se'\napplication='torrent'\n[profiles.browser]\nserver='de'\n", config::FileFormat::Toml)).build().unwrap();
        let selected = select(config.clone(), Some("downloads")).unwrap();
        assert_eq!(selected.get_string("server").unwrap(), "se");
        assert_eq!(selected.get_string("provider").unwrap(), "mullvad");
        assert!(config.get_string("server").is_err());
        assert!(select(config.clone(), Some("missing")).is_err());
        assert!(select(config, Some("../../escape")).is_err());
    }
    #[test]
    fn prepare_does_not_inherit_custom_for_existing_netns() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "custom = \"/tmp/default.conf\"\n").unwrap();
        let Some(crate::args::Command::Exec(mut command)) = crate::args::App::try_parse_from([
            "vopono",
            "exec",
            "--vopono-config",
            config.to_str().unwrap(),
            "--existing-netns",
            "vo_existing",
            "true",
        ])
        .unwrap()
        .cmd
        else {
            unreachable!()
        };
        prepare(&mut command).unwrap();
        assert!(command.custom.is_none());
    }

    #[test]
    fn desktop_export_keeps_shell_metacharacters_and_field_codes_literal() {
        let entry = desktop_entry(
            "downloads",
            Path::new("/opt/a b/$vopono%"),
            Path::new("/tmp/config.toml"),
        )
        .unwrap();
        assert!(entry.contains("\\\\$vopono%%"));
        assert!(entry.contains("--profile downloads"));
        assert!(desktop_entry("bad\nExec=evil", Path::new("x"), Path::new("x")).is_err());
    }

    #[test]
    fn profiles_do_not_inherit_incompatible_top_level_protocol_or_custom() {
        let config = Config::builder()
            .add_source(config::File::from_str(
                "provider = 'mullvad'\nprotocol = 'wireguard'\ncustom = '/tmp/default.ovpn'\n\
                 [profiles.work]\ncustom = '/tmp/work.ovpn'\napplication = 'curl'\n\
                 [profiles.ssh_box]\nprotocol = 'ssh'\nserver = 'work-proxy'\napplication = 'curl'\n\
                 [profiles.json_mon]\nprovider = 'airvpn'\nserver = 'at'\nmonitor = true\njson = true\napplication = 'curl'\n",
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();
        let work = select(config.clone(), Some("work")).unwrap();
        assert_eq!(work.get_string("protocol").unwrap(), "");
        let ssh_box = select(config.clone(), Some("ssh_box")).unwrap();
        assert_eq!(ssh_box.get_string("custom").unwrap(), "");
        let json_mon = select(config, Some("json_mon")).unwrap();
        assert_eq!(json_mon.get_string("protocol").unwrap(), "");
        assert_eq!(json_mon.get_string("custom").unwrap(), "");
    }

    #[test]
    fn prepare_propagates_json_and_allows_cli_recover_with_profile_monitor() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "[profiles.mon]\nprovider = 'airvpn'\nserver = 'at'\nmonitor = true\njson = true\napplication = 'true'\n",
        )
        .unwrap();
        let Some(crate::args::Command::Exec(mut command)) = crate::args::App::try_parse_from([
            "vopono",
            "exec",
            "--vopono-config",
            config.to_str().unwrap(),
            "--profile",
            "mon",
            "--recover",
        ])
        .unwrap()
        .cmd
        else {
            unreachable!()
        };
        prepare(&mut command).unwrap();
        assert!(command.monitor);
        assert!(command.recover);
        assert!(command.json);
    }

    #[test]
    fn prepare_does_not_inherit_custom_for_cli_ssh_or_warp_protocol() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "custom = '/tmp/default.ovpn'\n").unwrap();
        for proto in ["ssh", "warp"] {
            let Some(crate::args::Command::Exec(mut command)) = crate::args::App::try_parse_from([
                "vopono",
                "exec",
                "--vopono-config",
                config.to_str().unwrap(),
                "--protocol",
                proto,
                "--server",
                "mybox",
                "true",
            ])
            .unwrap()
            .cmd
            else {
                unreachable!()
            };
            prepare(&mut command).unwrap();
            assert!(
                command.custom.is_none(),
                "top-level custom leaked onto --protocol {proto}"
            );
        }
    }
}
