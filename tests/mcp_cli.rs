use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn run(input: &[u8], extra: &[&str]) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vopono"))
        .args(["mcp", "serve"])
        .args(extra)
        .env("XDG_CONFIG_HOME", directory.path())
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("MCP did not exit on input EOF");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn stdio_handshake_discovery_and_validation_emit_only_json_rpc_lines() {
    if nix::unistd::Uid::current().is_root() {
        return;
    }
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"profiles_list","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"job_cancel","arguments":{"job_id":"someone-elses-job"}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_profile","arguments":{"profile":"valid","argv":["echo","NEVER_SHARE"]}}}),
    ];
    let input = requests
        .iter()
        .map(|request| format!("{request}\n"))
        .collect::<String>();
    let output = run(input.as_bytes(), &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 5);
    assert!(
        replies[0]["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("does not route the harness")
    );
    assert_eq!(replies[1]["result"]["tools"].as_array().unwrap().len(), 8);
    assert!(
        replies[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "run_profile")
            .unwrap()["inputSchema"]["properties"]
            .get("argv")
            .is_none()
    );
    assert_eq!(
        replies[2]["result"]["structuredContent"]["profiles"],
        json!([])
    );
    assert_eq!(replies[3]["result"]["isError"], true);
    assert_eq!(replies[4]["result"]["isError"], true);
    assert!(!replies[4].to_string().contains("NEVER_SHARE"));
}

#[test]
fn malformed_and_oversized_messages_are_bounded_without_echoing_input() {
    if nix::unistd::Uid::current().is_root() {
        return;
    }
    let malformed = run(b"NEVER_SHARE_NOT_JSON\n", &[]);
    let reply: Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(reply["error"]["code"], -32700);
    assert!(!reply.to_string().contains("NEVER_SHARE"));
    let oversized = run(&vec![b'x'; 1024 * 1024 + 1], &[]);
    let reply: Value = serde_json::from_slice(&oversized.stdout).unwrap();
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("1 MiB")
    );
}

#[test]
fn cli_rejects_invalid_limits_and_root_execution() {
    let output = Command::new(env!("CARGO_BIN_EXE_vopono"))
        .args(["mcp", "serve", "--max-jobs", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    if nix::unistd::Uid::current().is_root() {
        let output = run(b"", &[]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ordinary user"));
    }
}
