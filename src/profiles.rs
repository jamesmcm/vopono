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
    Ok(builder.build()?)
}

/// Resolve settings needed before daemon forwarding supplies launch defaults.
/// Resolve again on the daemon using its authenticated user's config tree.
pub fn prepare(command: &mut ExecCommand) -> anyhow::Result<()> {
    let config = crate::args_config::ArgsConfig::get_config_file(command)?;
    if command.application.is_empty() && command.profile.is_some() {
        command.application = config
            .get_string("application")
            .context("Named profile requires an application")?;
    }
    if command.working_directory.is_none() {
        command.working_directory = config
            .get_string("working_directory")
            .or_else(|_| config.get_string("working-directory"))
            .ok();
    }
    for (flag, name) in [
        (&mut command.monitor, "monitor"),
        (&mut command.recover, "recover"),
        (&mut command.keep_alive, "keep-alive"),
        (&mut command.create_netns_only, "create-netns-only"),
    ] {
        *flag |= config
            .get_bool(name)
            .or_else(|_| config.get_bool(&name.replace('-', "_")))
            .unwrap_or(false);
    }
    ensure!(
        !command.recover || command.monitor,
        "Recovery requires monitoring"
    );
    Ok(())
}

pub fn run(command: ProfilesCommand) -> anyhow::Result<()> {
    let path = command
        .vopono_config
        .unwrap_or(vopono_core::util::vopono_dir()?.join("config.toml"));
    let path = path.canonicalize()?;
    let config = Config::builder()
        .add_source(config::File::from(path.clone()))
        .build()?;
    match command.command {
        ProfileSubcommand::List(format) => {
            let mut names: Vec<_> = config
                .get_table("profiles")
                .unwrap_or_default()
                .into_keys()
                .collect();
            names.sort();
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
}
