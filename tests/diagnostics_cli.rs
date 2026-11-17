use serde_json::Value;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vopono"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

#[test]
fn doctor_output_modes_preserve_failures_and_redaction() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[Interface]\nPrivateKey=NEVER_SHARE_FORMAT_KEY\n",
    )
    .unwrap();
    for (options, table, colored) in [
        (vec![], true, false),
        (vec!["--color", "always"], true, true),
        (vec!["--color", "never"], true, false),
        (vec!["--plain", "--color", "always"], false, false),
        (vec!["--plaintext"], false, false),
    ] {
        let mut args = vec![
            "doctor",
            "--custom",
            config.path().to_str().unwrap(),
            "--offline",
        ];
        args.extend(options);
        let output = run(&args);
        assert!(!output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("NEVER_SHARE"));
        assert_eq!(text.contains('\x1b'), colored);
        assert_eq!(text.contains('│'), table);
        if table {
            assert!(text.contains("VPN configuration") && text.contains("FAIL"));
        } else {
            assert!(text.starts_with("scope\tcheck\tstate\tmessage\taction\n"));
            assert!(text.contains("host\tprovider_config\tfail\t"));
            assert!(text.lines().all(|line| line.split('\t').count() == 5));
        }
    }
    assert!(!run(&["doctor", "--plain", "--json"]).status.success());
}

#[test]
fn doctor_auto_colour_respects_terminal_no_color_and_dumb_terminal() {
    use std::io::Read;
    use std::process::Stdio;
    for (term, no_color, colored) in [
        ("xterm-256color", None, true),
        ("xterm-256color", Some("1"), false),
        ("xterm-256color", Some(""), true),
        ("dumb", None, false),
    ] {
        let size = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let terminal = nix::pty::openpty(Some(&size), None).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_vopono"));
        command
            .args(["doctor", "--custom", "/dev/null", "--offline"])
            .env("TERM", term)
            .env_remove("RUST_LOG")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .stdout(Stdio::from(terminal.slave))
            .stderr(Stdio::null());
        if let Some(value) = no_color {
            command.env("NO_COLOR", value);
        }
        let mut child = command.spawn().unwrap();
        // Command retains the parent's slave FD until dropped.
        drop(command);
        let mut output = Vec::new();
        let read = std::fs::File::from(terminal.master).read_to_end(&mut output);
        assert!(read.is_ok() || read.unwrap_err().raw_os_error() == Some(nix::libc::EIO));
        child.wait().unwrap();
        assert_eq!(
            output.contains(&0x1b),
            colored,
            "TERM={term}, NO_COLOR={no_color:?}"
        );
    }
}

#[test]
fn doctor_reports_invalid_configuration_without_echoing_secrets() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        config.path(),
        "[Interface]\nPrivateKey = DO_NOT_SHARE_THIS_KEY\n[Peer]\nPublicKey = invalid\n",
    )
    .unwrap();
    let output = run(&[
        "doctor",
        "--custom",
        config.path().to_str().unwrap(),
        "--offline",
        "--json",
    ]);
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "provider_config" && d["state"] == "fail")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_SHARE"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_SHARE"));
}

#[test]
fn offline_doctor_accepts_a_complete_wireguard_profile_without_starting_a_tunnel() {
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config.path(), "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n").unwrap();
    let output = run(&[
        "doctor",
        "--custom",
        config.path().to_str().unwrap(),
        "--offline",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "provider_config" && d["state"] == "pass")
    );
    assert_eq!(report["daemon"]["cli_version"], env!("CARGO_PKG_VERSION"));
    assert!(report["daemon"]["available"].is_boolean());
    assert_eq!(report["diagnostics"][0]["code"], "daemon_availability");
    assert_eq!(report["diagnostics"][1]["code"], "daemon_version");
    assert!(report["host_network"]["dns"]["nameservers"].is_array());
    assert!(report["host_network"]["default_routes"].is_array());
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "tunnel_handshake" && d["state"] == "skipped")
    );
    assert!(!report.to_string().contains("AAAAAAAAAA"));
    let diagnostics = report["diagnostics"].as_array().unwrap();
    assert!(
        diagnostics
            .iter()
            .all(|d| d["code"] != "host_dns" && d["code"] != "host_connectivity")
    );
    assert!(diagnostics.iter().any(|d| d["code"] == "host_forwarding"));
    assert!(diagnostics.iter().any(|d| d["code"] == "host_firewall"));
    assert!(diagnostics.iter().any(|d| d["code"] == "app_armor"));
}

#[test]
fn special_provider_variants_produce_json_instead_of_panicking() {
    for provider in ["custom", "none", "warp"] {
        let output = run(&["doctor", "--provider", provider, "--offline", "--json"]);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["version"], 1);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}

#[test]
fn doctor_recognizes_a_selected_pia_bootstrap_template() {
    let directory = tempfile::tempdir().unwrap();
    let configs = directory.path().join("vopono/pia/wireguard");
    std::fs::create_dir_all(&configs).unwrap();
    std::fs::write(configs.join("fixture.conf"), "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 127.0.0.1/32\nDNS = 127.0.0.1\n[Peer]\nPublicKey =\nEndpoint = 192.0.2.1:1337\nAllowedIPs = 0.0.0.0/0\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vopono"))
        .args([
            "doctor",
            "--provider",
            "privateinternetaccess",
            "--protocol",
            "wireguard",
            "--server",
            "fixture",
            "--offline",
            "--json",
        ])
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{report}");
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "provider_config")
        .unwrap();
    assert_eq!(diagnostic["state"], "warning");
    assert!(
        diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("PIA bootstrap template")
    );
    assert!(!report.to_string().contains("AAAAAAAAAA"));
}

#[test]
fn desktop_profile_export_contains_only_a_cli_invocation_and_refuses_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let desktop = directory.path().join("downloads.desktop");
    std::fs::write(&config, "[profiles.downloads]\nprovider='mullvad'\nserver='se'\napplication='torrent --token=private-token'\n").unwrap();
    let output = run(&[
        "profiles",
        "--vopono-config",
        config.to_str().unwrap(),
        "export",
        "downloads",
        "--output",
        desktop.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let entry = std::fs::read_to_string(&desktop).unwrap();
    assert!(entry.contains("exec --profile downloads"));
    assert!(!entry.contains("private-token"));
    let repeated = run(&[
        "profiles",
        "--vopono-config",
        config.to_str().unwrap(),
        "export",
        "downloads",
        "--output",
        desktop.to_str().unwrap(),
    ]);
    assert!(!repeated.status.success());
    assert_eq!(entry, std::fs::read_to_string(desktop).unwrap());
}
