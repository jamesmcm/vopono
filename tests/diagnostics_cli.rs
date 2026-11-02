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
    assert_eq!(report["diagnostics"][0]["code"], "provider_config");
    assert_eq!(report["diagnostics"][0]["state"], "fail");
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
    assert_eq!(report["diagnostics"][0]["state"], "pass");
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "tunnel_handshake" && d["state"] == "skipped")
    );
    assert!(!report.to_string().contains("AAAAAAAAAA"));
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
