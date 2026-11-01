//! Local MCP stdio adapter. No network listener, privilege escalation or new
//! daemon wire format: tools reuse the existing CLI and authenticated socket.
mod jobs;

use crate::args::{App, ExecCommand, McpServeCommand};
use anyhow::{Context, ensure};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

const MAX_MESSAGE: usize = 1024 * 1024;
const PROTOCOL: &str = "2025-11-25";
const INSTRUCTIONS: &str = "Use named profiles to run local applications in vopono namespaces. Only those applications (or clients explicitly configured for a namespace-hosted proxy) use that network. Installing this MCP server does not route the harness, built-in browser, remote web search, other MCP servers, or model API calls through a VPN. Jobs require an already-running privileged daemon; this server runs as the ordinary user and never uses sudo or provisions provider keys. Poll jobs and output, and cancel jobs you no longer need. A connected probe alone does not prove VPN authentication or isolation.";

struct Server {
    options: McpServeCommand,
    initialized: bool,
    ready: bool,
    jobs: jobs::Jobs,
}
impl Server {
    fn new(options: McpServeCommand) -> anyhow::Result<Self> {
        Ok(Self {
            jobs: jobs::Jobs::new(options.max_jobs as usize)?,
            options,
            initialized: false,
            ready: false,
        })
    }
    fn request(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let valid_id = id.as_ref().is_none_or(|id| {
            id.is_string()
                || id
                    .as_number()
                    .is_some_and(|number| number.is_i64() || number.is_u64())
        });
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || !request["method"].is_string()
            || !valid_id
        {
            return Some(rpc_error(Value::Null, -32600, "Invalid JSON-RPC request"));
        }
        let method = request["method"].as_str().unwrap();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        if !params.is_object() {
            return id.map(|id| rpc_error(id, -32602, "Parameters must be an object"));
        }
        let Some(id) = id else {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            // Notifications never launch jobs. No requests are sent to clients,
            // and this server advertises only the tools capability.
            return None;
        };
        if method == "initialize" {
            if self.initialized {
                return Some(rpc_error(id, -32600, "Already initialized"));
            }
            let Some(requested) = params["protocolVersion"].as_str() else {
                return Some(rpc_error(id, -32602, "Missing protocolVersion"));
            };
            if !params["capabilities"].is_object() || !params["clientInfo"].is_object() {
                return Some(rpc_error(
                    id,
                    -32602,
                    "Missing client capabilities or clientInfo",
                ));
            }
            let version =
                if [PROTOCOL, "2025-06-18", "2025-03-26", "2024-11-05"].contains(&requested) {
                    requested
                } else {
                    PROTOCOL
                };
            self.initialized = true;
            return Some(rpc_result(
                id,
                json!({"protocolVersion":version,
                "capabilities":{"tools":{}},"serverInfo":{"name":"vopono","version":env!("CARGO_PKG_VERSION")},
                "instructions":INSTRUCTIONS}),
            ));
        }
        if method == "ping" {
            return Some(rpc_result(id, json!({})));
        }
        if !self.ready {
            return Some(rpc_error(id, -32002, "Initialize the MCP session first"));
        }
        match method {
            "tools/list" => {
                if params.get("cursor").is_some() {
                    Some(rpc_error(id, -32602, "This server does not paginate tools"))
                } else {
                    Some(rpc_result(
                        id,
                        json!({"tools":tools(self.options.allow_command,self.options.max_job_seconds)}),
                    ))
                }
            }
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    return Some(rpc_error(id, -32602, "Missing tool name"));
                };
                if !TOOL_NAMES.contains(&name) {
                    return Some(rpc_error(id, -32602, "Unknown tool"));
                }
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let result = match self.call(name, arguments) {
                    Ok((value, failed)) => tool_result(value, failed),
                    Err(error) => tool_result(
                        json!({"version":1,"error":{"message":error.to_string()}}),
                        true,
                    ),
                };
                Some(rpc_result(id, result))
            }
            _ => Some(rpc_error(id, -32601, "Method not found")),
        }
    }
    fn profile(&self, name: &str) -> anyhow::Result<ExecCommand> {
        ensure!(
            crate::profiles::valid_name(name),
            "Profile names must contain 1-64 letters, digits, underscores or hyphens"
        );
        ensure!(
            self.options.allow_profiles.is_empty()
                || self
                    .options
                    .allow_profiles
                    .iter()
                    .any(|allowed| allowed == name),
            "Profile is not allowed by this MCP server"
        );
        let command = App::try_parse_from(["vopono", "exec", "--profile", name])?;
        let Some(crate::args::Command::Exec(mut command)) = command.cmd else {
            unreachable!()
        };
        command.vopono_config = self.options.vopono_config.clone();
        Ok(command)
    }
    fn settings(&self, name: &str) -> anyhow::Result<config::Config> {
        crate::args_config::ArgsConfig::get_config_file(&self.profile(name)?).map_err(|_| {
            anyhow::anyhow!("Could not load the named profile; check the configured TOML file")
        })
    }
    fn call(&mut self, name: &str, arguments: Value) -> anyhow::Result<(Value, bool)> {
        match name {
            "status" => {
                let _: Empty = arguments_as(arguments)?;
                let status = crate::list::status_snapshot()
                    .map_err(|_| anyhow::anyhow!("Could not inspect local vopono status"))?;
                let namespaces:Vec<_> = status.namespaces.into_iter().map(|ns|json!({
                    "id":ns.id,"provider":ns.provider,"protocol":ns.protocol,"health":ns.health,
                    "applications":ns.applications.into_iter().map(|a|json!({"id":a.id,"pid":a.pid})).collect::<Vec<_>>(),
                    "port_forwarding":ns.port_forwarding,"host_forwarded_ports":ns.host_forwarded_ports})).collect();
                Ok((
                    json!({"version":1,"daemon":status.daemon,"namespaces":namespaces,
                    "inspection_errors":status.errors.len()}),
                    false,
                ))
            }
            "profiles_list" => {
                let _: Empty = arguments_as(arguments)?;
                let app = App::try_parse_from(["vopono", "exec"])?;
                let Some(crate::args::Command::Exec(mut command)) = app.cmd else {
                    unreachable!()
                };
                command.vopono_config = self.options.vopono_config.clone();
                let settings = crate::args_config::ArgsConfig::get_config_file(&command)
                    .map_err(|_| anyhow::anyhow!("Could not read configured profiles"))?;
                let mut profiles: Vec<_> = settings
                    .get_table("profiles")
                    .unwrap_or_default()
                    .into_keys()
                    .filter(|name| {
                        self.options.allow_profiles.is_empty()
                            || self.options.allow_profiles.contains(name)
                    })
                    .collect();
                profiles.sort();
                Ok((
                    json!({"version":1,"profiles":profiles,"allow_command":self.options.allow_command}),
                    false,
                ))
            }
            "doctor" => {
                let input: DoctorInput = arguments_as(arguments)?;
                let settings = self.settings(&input.profile)?;
                let mut args = vec![
                    "doctor".to_owned(),
                    "--json".into(),
                    "--timeout-ms".into(),
                    "500".into(),
                ];
                for (key, flag) in [
                    ("custom", "--custom"),
                    ("provider", "--provider"),
                    ("protocol", "--protocol"),
                    ("server", "--server"),
                ] {
                    if key == "server" && settings.get_string("provider").is_err() {
                        continue;
                    }
                    if let Ok(value) = settings.get_string(key) {
                        args.extend([flag.into(), value]);
                    }
                }
                if input.offline {
                    args.push("--offline".into());
                }
                jobs::json_command(&args, Duration::from_secs(25)).map_err(|_| {
                    anyhow::anyhow!("Doctor could not complete within its output/time limits")
                })
            }
            "check" => {
                let input: CheckInput = arguments_as(arguments)?;
                ensure!(
                    (1..=5000).contains(&input.timeout_ms),
                    "timeout_ms must be between 1 and 5000"
                );
                vopono_core::network::netns::validate_netns_name(&input.namespace)?;
                let command = crate::args::CheckCommand {
                    id: input.namespace,
                    port: 443,
                    timeout_ms: input.timeout_ms,
                    v4_host: None,
                    v6_host: None,
                    dns_host: None,
                    skip_ipv4: false,
                    skip_ipv6: input.skip_ipv6,
                    skip_dns: input.skip_dns,
                    json: true,
                };
                let status = crate::forward_check_to_daemon(
                    &command,
                    crate::check::DEFAULT_V4_HOST,
                    crate::check::DEFAULT_V6_HOST,
                    crate::check::DEFAULT_DNS_HOST,
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Daemon connectivity check failed; no sudo fallback was attempted"
                    )
                })?;
                let failed = !status.connected;
                Ok((
                    serde_json::to_value(crate::check::ConnectivityDocument {
                        version: 1,
                        result: status,
                    })?,
                    failed,
                ))
            }
            "run_profile" => {
                ensure!(
                    self.options.allow_command || arguments.get("argv").is_none(),
                    "argv overrides require starting the MCP server with --allow-command"
                );
                let input: RunInput = arguments_as(arguments)?;
                let mut command = self.profile(&input.profile)?;
                if let Some(argv) = input.argv {
                    ensure!(
                        self.options.allow_command,
                        "argv overrides require starting the MCP server with --allow-command"
                    );
                    command.application = quote_argv(&argv)?;
                    command.literal_application = true;
                }
                crate::profiles::prepare(&mut command).map_err(|_| {
                    anyhow::anyhow!(
                        "Could not prepare the profile application; check its configuration"
                    )
                })?;
                ensure!(
                    !command.create_netns_only,
                    "MCP jobs require an application; create-netns-only profiles are unsupported"
                );
                ensure!(
                    !command.application.is_empty(),
                    "The profile must define an application or an authorized argv override"
                );
                let timeout = input
                    .timeout_seconds
                    .unwrap_or(self.options.max_job_seconds);
                ensure!(
                    timeout > 0 && timeout <= self.options.max_job_seconds,
                    "Job timeout exceeds this MCP server's configured limit"
                );
                Ok((
                    self.jobs
                        .start(command, input.profile, Duration::from_secs(timeout))?,
                    false,
                ))
            }
            "job_status" | "job_cancel" => {
                let input: JobInput = arguments_as(arguments)?;
                let job = self.jobs.get(&input.job_id)?;
                Ok((
                    if name == "job_cancel" {
                        job.cancel()
                    } else {
                        job.status()
                    },
                    false,
                ))
            }
            "job_output" => {
                let input: OutputInput = arguments_as(arguments)?;
                ensure!(
                    (1..=16384).contains(&input.max_bytes),
                    "max_bytes must be between 1 and 16384 per stream"
                );
                Ok((
                    self.jobs.get(&input.job_id)?.output(
                        input.stdout_offset,
                        input.stderr_offset,
                        input.max_bytes,
                    ),
                    false,
                ))
            }
            _ => unreachable!(),
        }
    }
}

const TOOL_NAMES: &[&str] = &[
    "status",
    "profiles_list",
    "doctor",
    "check",
    "run_profile",
    "job_status",
    "job_output",
    "job_cancel",
];
fn tools(allow_command: bool, timeout: u64) -> Vec<Value> {
    let string = json!({"type":"string","minLength":1,"maxLength":128});
    let profile = json!({"type":"string","minLength":1,"maxLength":64});
    let definitions = [
        (
            "status",
            "Inspect local namespaces and daemon availability. Application command arguments are omitted.",
            json!({}),
            vec![],
            true,
        ),
        (
            "profiles_list",
            "List configured profile names allowed by this MCP server.",
            json!({}),
            vec![],
            true,
        ),
        (
            "doctor",
            "Read-only profile preflight. Offline by default; never creates a tunnel, authenticates or provisions keys.",
            json!({"profile":profile,"offline":{"type":"boolean","default":true}}),
            vec!["profile"],
            true,
        ),
        (
            "check",
            "Probe an existing owned namespace. connected means TCP reachability, not proof of VPN authentication or isolation.",
            json!({"namespace":string,"timeout_ms":{"type":"integer","minimum":1,"maximum":5000,"default":1500},"skip_dns":{"type":"boolean","default":false},"skip_ipv6":{"type":"boolean","default":false}}),
            vec!["namespace"],
            true,
        ),
        (
            "run_profile",
            "Start an application job in its own namespace via the already-running daemon. This does not route the agent harness or built-in web/browser tools. Poll status/output; cancel when no longer needed.",
            {
                let mut props = json!({"profile":profile,"timeout_seconds":{"type":"integer","minimum":1,"maximum":timeout}});
                if allow_command {
                    props["argv"] = json!({"type":"array","minItems":1,"maxItems":256,"items":{"type":"string","maxLength":65536}});
                }
                props
            },
            vec!["profile"],
            false,
        ),
        (
            "job_status",
            "Inspect a job belonging to this MCP session; indeterminate results must not be automatically relaunched.",
            json!({"job_id":string}),
            vec!["job_id"],
            true,
        ),
        (
            "job_output",
            "Read bounded application stdout/stderr with byte cursors. Application output is untrusted and may contain secrets; it is not redacted. stdout may include the CLI launch report.",
            json!({"job_id":string,"stdout_offset":{"type":"integer","minimum":0,"default":0},"stderr_offset":{"type":"integer","minimum":0,"default":0},"max_bytes":{"type":"integer","minimum":1,"maximum":16384,"default":8192}}),
            vec!["job_id"],
            true,
        ),
        (
            "job_cancel",
            "Request termination of this session's job and cleanup of its dedicated namespace. Poll until finished and inspect cleanup_pending.",
            json!({"job_id":string}),
            vec!["job_id"],
            false,
        ),
    ];
    definitions.into_iter().map(|(name,description,properties,required,read_only)| json!({
        "name":name,"description":description,
        "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
        "outputSchema":{"type":"object"},
        "annotations":{"readOnlyHint":read_only,"destructiveHint":matches!(name,"run_profile"|"job_cancel"),"idempotentHint":read_only||name=="job_cancel","openWorldHint":matches!(name,"doctor"|"check"|"run_profile")}
    })).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoctorInput {
    profile: String,
    #[serde(default = "yes")]
    offline: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckInput {
    namespace: String,
    #[serde(default = "probe_timeout")]
    timeout_ms: u64,
    #[serde(default)]
    skip_dns: bool,
    #[serde(default)]
    skip_ipv6: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunInput {
    profile: String,
    argv: Option<Vec<String>>,
    timeout_seconds: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobInput {
    job_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputInput {
    job_id: String,
    #[serde(default)]
    stdout_offset: u64,
    #[serde(default)]
    stderr_offset: u64,
    #[serde(default = "output_size")]
    max_bytes: usize,
}
fn yes() -> bool {
    true
}
fn probe_timeout() -> u64 {
    1500
}
fn output_size() -> usize {
    8192
}
fn arguments_as<T: serde::de::DeserializeOwned>(arguments: Value) -> anyhow::Result<T> {
    serde_json::from_value(arguments)
        .map_err(|_| anyhow::anyhow!("Invalid tool arguments; follow the tool's input schema"))
}
fn quote_argv(argv: &[String]) -> anyhow::Result<String> {
    ensure!(
        !argv.is_empty() && argv.len() <= 256 && !argv[0].is_empty(),
        "argv must contain an executable and at most 256 arguments"
    );
    ensure!(
        argv.iter().map(String::len).sum::<usize>() <= 65536
            && argv.iter().all(|arg| !arg.contains('\0')),
        "argv exceeds its size limit or contains NUL"
    );
    Ok(argv
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" "))
}
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn tool_result(value: Value, failed: bool) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":failed})
}

pub fn serve(options: McpServeCommand) -> anyhow::Result<()> {
    ensure!(
        !nix::unistd::getuid().is_root() && !nix::unistd::geteuid().is_root(),
        "Run vopono mcp serve as your ordinary user, not root"
    );
    // Pin a relative config path before any job working directories are resolved.
    let mut options = options;
    if let Some(path) = options.vopono_config.as_mut() {
        *path = path
            .canonicalize()
            .context("MCP configuration file was not found")?;
    }
    let stopping = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, stopping.clone())?;
    }
    let mut server = Server::new(options)?;
    let input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut pending = Vec::new();
    loop {
        if stopping.load(Ordering::Acquire) {
            break;
        }
        let mut poll = nix::libc::pollfd {
            fd: input.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { nix::libc::poll(&mut poll, 1, 100) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if ready == 0 {
            continue;
        }
        // Read directly from the FD: StdinLock's internal buffering can hold a
        // second request while poll reports that the kernel pipe is empty.
        let mut chunk = [0u8; 8192];
        let count =
            unsafe { nix::libc::read(input.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if count == 0 {
            break;
        }
        if count < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        pending.extend_from_slice(&chunk[..count as usize]);
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            if end > MAX_MESSAGE {
                write_message(
                    &mut output,
                    &rpc_error(Value::Null, -32600, "MCP message exceeds 1 MiB"),
                )?;
                return Ok(());
            }
            let line: Vec<_> = pending.drain(..=end).collect();
            let reply = match serde_json::from_slice(&line) {
                Ok(value) => server.request(value),
                Err(_) => Some(rpc_error(Value::Null, -32700, "Invalid JSON")),
            };
            if let Some(reply) = reply {
                write_message(&mut output, &reply)?;
            }
        }
        if pending.len() > MAX_MESSAGE {
            write_message(
                &mut output,
                &rpc_error(Value::Null, -32600, "MCP message exceeds 1 MiB"),
            )?;
            break;
        }
    }
    Ok(())
}
fn write_message(output: &mut impl Write, value: &Value) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn job_application_registered(namespace: &str) -> bool {
    vopono_core::util::vopono_dir()
        .ok()
        .and_then(|base| std::fs::read_dir(base.join("locks").join(namespace)).ok())
        .is_some_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with("client-"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn server() -> Server {
        Server::new(McpServeCommand {
            vopono_config: None,
            allow_profiles: vec![],
            allow_command: false,
            max_jobs: 1,
            max_job_seconds: 30,
        })
        .unwrap()
    }
    #[test]
    fn lifecycle_negotiation_notifications_and_tool_failures_follow_json_rpc() {
        let mut server = server();
        assert_eq!(
            server
                .request(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
                .unwrap()["error"]["code"],
            -32002
        );
        let initialize = json!({"jsonrpc":"2.0","id":"hello","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
        assert_eq!(
            server.request(initialize).unwrap()["result"]["protocolVersion"],
            "2025-06-18"
        );
        assert!(
            server
                .request(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .is_none()
        );
        let tools = server
            .request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
            .unwrap();
        assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 8);
        let result=server.request(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":"foreign"}}})).unwrap();
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            serde_json::from_str::<Value>(result["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap(),
            result["result"]["structuredContent"]
        );
        assert_eq!(
            server
                .request(
                    json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"absent"}})
                )
                .unwrap()["error"]["code"],
            -32602
        );
    }
    #[test]
    fn argv_roundtrips_without_shell_expansion_and_rejects_invalid_input() {
        let argv: Vec<String> = vec![
            "printf",
            "",
            "a b",
            "a'b",
            "$(touch /tmp/no)",
            "$HOME",
            "a\nb",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            vopono_core::util::parse_command_str(&quote_argv(&argv).unwrap()).unwrap(),
            argv
        );
        assert!(quote_argv(&[]).is_err());
        assert!(quote_argv(&["bad\0argument".into()]).is_err());
    }
    #[test]
    fn invalid_arguments_do_not_echo_values_and_disabled_overrides_cannot_run() {
        let mut server = server();
        let error = server
            .call("status", json!({"secret":"NEVER_SHARE"}))
            .unwrap_err();
        assert!(!error.to_string().contains("NEVER_SHARE"));
        assert!(
            server
                .call("run_profile", json!({"profile":"x","argv":["true"]}))
                .unwrap_err()
                .to_string()
                .contains("--allow-command")
        );
        assert!(
            server
                .call("job_cancel", json!({"job_id":"other-session"}))
                .is_err()
        );
    }
}
