//! Read-only host evidence. Never return raw firewall rules or audit records.
use super::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State, DnsFailure};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: usize = 1024 * 1024;
const FIREWALL_ACTION: &str = "Inspect counters and rule order with sudo nft -a list ruleset, sudo iptables -nvL FORWARD --line-numbers and sudo ip6tables -nvL FORWARD --line-numbers; check namespace veth exceptions in DOCKER-USER and ufw-before-forward. Do not flush the ruleset";
const APPARMOR_ACTION: &str = "Run sudo aa-status and sudo journalctl -k --since '-15 min' --grep 'apparmor=\"DENIED\"'; review the wg/awg profile and the actual temporary config path in the denial. Add a narrowly scoped local policy override if needed; do not disable AppArmor. See https://github.com/jamesmcm/vopono/issues/392";

pub fn host_dns(result: Result<Vec<std::net::IpAddr>, DnsFailure>) -> Diagnostic {
    match result {
        Ok(_) => Diagnostic::new(
            Code::HostDns,
            State::Pass,
            "Host system resolver resolved one.one.one.one; provider APIs and hostname VPN endpoints use host DNS before the tunnel is available",
            None,
        ),
        Err(error) => Diagnostic::new(
            Code::HostDns,
            State::Fail,
            &format!(
                "Host resolution of one.one.one.one failed: {error}; an existing IP-based tunnel can still work"
            ),
            Some(
                "Inspect /etc/resolv.conf and, when using systemd-resolved, resolvectl status; repair host DNS before syncing providers or connecting to hostname endpoints",
            ),
        ),
    }
}

pub fn inspect(skip_ipv6: bool) -> Vec<Diagnostic> {
    inspect_until(skip_ipv6, Instant::now() + Duration::from_secs(3))
}

pub(super) fn inspect_until(skip_ipv6: bool, deadline: Instant) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (label, path) in [
        ("IPv4", "/proc/sys/net/ipv4/ip_forward"),
        ("IPv6", "/proc/sys/net/ipv6/conf/all/forwarding"),
    ] {
        if skip_ipv6 && label == "IPv6" {
            continue;
        }
        diagnostics.push(forwarding(
            label,
            std::fs::read_to_string(path).ok().as_deref(),
        ));
    }
    for (tool, label) in [("iptables-save", "IPv4"), ("ip6tables-save", "IPv6")] {
        if skip_ipv6 && label == "IPv6" {
            continue;
        }
        let result = read_command(tool, &["-t", "filter"], deadline);
        diagnostics.extend(match result.and_then(|text| iptables_diagnostics(&text, label)) {
            Some(found) => found,
            None => vec![unavailable(&format!("{label} iptables rules could not be inspected (missing tool, permissions, timeout or unrecognized output)"))],
        });
    }
    diagnostics.extend(match read_command("nft", &["--json", "list", "ruleset"], deadline)
        .and_then(|text| nft_diagnostics(&text, skip_ipv6)) {
        Some(found) => found,
        None => vec![unavailable("Native nftables rules could not be inspected (missing tool, permissions, timeout or unrecognized output)")],
    });
    diagnostics.extend(apparmor(deadline));
    diagnostics
}

fn unavailable(message: &str) -> Diagnostic {
    Diagnostic::new(
        Code::HostFirewall,
        State::Skipped,
        message,
        Some(
            "Use an updated root vopono daemon for automatic host inspection, or inspect with sudo nft -a list ruleset and sudo iptables-save -t filter",
        ),
    )
}

fn forwarding(label: &str, value: Option<&str>) -> Diagnostic {
    let value = value.map(str::trim);
    let (state, message, action) = match value {
        Some("1") => (
            State::Pass,
            format!("Host {label} forwarding is enabled"),
            None,
        ),
        Some("0") => (
            State::Warning,
            format!(
                "Host {label} forwarding is disabled; namespace traffic that traverses the host needs it"
            ),
            Some(
                "vopono enables forwarding during setup; if an existing namespace is broken, inspect sysctl settings and services that may reset them",
            ),
        ),
        _ => (
            State::Skipped,
            format!("Host {label} forwarding setting could not be read"),
            Some("Inspect net.ipv4.ip_forward and net.ipv6.conf.all.forwarding with sysctl"),
        ),
    };
    Diagnostic::new(Code::HostForwarding, state, &message, action)
}

fn iptables_diagnostics(text: &str, family: &str) -> Option<Vec<Diagnostic>> {
    if !text.lines().any(|line| line == "*filter") || !text.lines().any(|line| line == "COMMIT") {
        return None;
    }
    let mut policies = BTreeSet::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Ok(words) = shell_words::split(trimmed) else {
            continue;
        };
        if words.len() > 1
            && [":INPUT", ":OUTPUT", ":FORWARD"].contains(&words[0].as_str())
            && words[1] == "DROP"
        {
            policies.insert(words[0].trim_start_matches(':').to_owned());
        }
        if words.first().is_some_and(|s| s == "-A") && words.len() > 3 {
            for pair in words[2..].windows(2) {
                if pair[0] == "-j" || pair[0] == "-g" {
                    edges
                        .entry(words[1].clone())
                        .or_default()
                        .insert(pair[1].clone());
                }
            }
        }
    }
    Some(rule_evidence(
        &format!("{family} iptables"),
        policies,
        &edges,
        &["INPUT".into(), "OUTPUT".into(), "FORWARD".into()],
    ))
}

fn reachable(edges: &BTreeMap<String, BTreeSet<String>>, roots: &[String]) -> BTreeSet<String> {
    let mut pending = roots.to_vec();
    let mut visited = BTreeSet::new();
    while let Some(chain) = pending.pop() {
        if visited.insert(chain.clone())
            && let Some(targets) = edges.get(&chain)
        {
            pending.extend(targets.iter().cloned());
        }
    }
    visited
}

fn rule_evidence(
    label: &str,
    policies: BTreeSet<String>,
    edges: &BTreeMap<String, BTreeSet<String>>,
    roots: &[String],
) -> Vec<Diagnostic> {
    let reached = reachable(edges, roots);
    let mut observations = Vec::new();
    if !policies.is_empty() {
        observations.push(format!(
            "default DROP policy on {}",
            policies.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if reached
        .iter()
        .any(|chain| chain.starts_with("ufw") || chain.contains("/ufw"))
    {
        observations.push("UFW chains are hooked into host packet processing, even if the UFW service says inactive".into());
    }
    if reached
        .iter()
        .any(|chain| chain.contains("DOCKER") || chain.contains("docker-bridges/"))
    {
        observations.push("Docker chains are hooked into host packet processing".into());
    }
    if reached.contains("DROP") || reached.contains("REJECT") {
        observations.push("chains referenced by host hooks contain DROP/REJECT rules".into());
    }
    let (state, message) = if observations.is_empty() {
        (
            State::Pass,
            format!(
                "{label}: no recognized host filtering hazards found in the inspected snapshot; packet acceptance is not proven"
            ),
        )
    } else {
        (
            State::Skipped,
            format!(
                "{label}: {}; context only, packet interference is unverified; use the live connectivity and enabled service probes to identify failures",
                observations.join("; ")
            ),
        )
    };
    vec![Diagnostic::new(
        Code::HostFirewall,
        state,
        &message,
        (state != State::Pass).then_some(FIREWALL_ACTION),
    )]
}

fn nft_diagnostics(text: &str, skip_ipv6: bool) -> Option<Vec<Diagnostic>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let entries = value.get("nftables")?.as_array()?;
    let mut policies = BTreeSet::new();
    let mut roots = Vec::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in entries {
        if let Some(chain) = entry.get("chain") {
            let family = chain.get("family")?.as_str()?;
            if skip_ipv6 && family == "ip6" {
                continue;
            }
            let id = format!(
                "{family}/{}/{}",
                chain.get("table")?.as_str()?,
                chain.get("name")?.as_str()?
            );
            if matches!(
                chain.get("hook").and_then(|s| s.as_str()),
                Some(
                    "input"
                        | "output"
                        | "forward"
                        | "prerouting"
                        | "postrouting"
                        | "ingress"
                        | "egress"
                )
            ) {
                roots.push(id.clone());
                if chain.get("policy").and_then(|s| s.as_str()) == Some("drop") {
                    policies.insert(format!("{family} {}", chain.get("hook")?.as_str()?));
                }
            }
        }
        if let Some(rule) = entry.get("rule") {
            let Some(family) = rule.get("family").and_then(|v| v.as_str()) else {
                continue;
            };
            if skip_ipv6 && family == "ip6" {
                continue;
            }
            let Some(table) = rule.get("table").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(chain_name) = rule.get("chain").and_then(|v| v.as_str()) else {
                continue;
            };
            let id = format!("{family}/{table}/{chain_name}");
            let Some(exprs) = rule.get("expr").and_then(|v| v.as_array()) else {
                continue;
            };
            for expr in exprs {
                collect_nft_expr_edges(expr, family, table, &id, &mut edges);
            }
        }
    }
    Some(rule_evidence("nftables", policies, &edges, &roots))
}

fn collect_nft_expr_edges(
    value: &serde_json::Value,
    family: &str,
    table: &str,
    id: &str,
    edges: &mut BTreeMap<String, BTreeSet<String>>,
) {
    if let Some(obj) = value.as_object() {
        for verdict in ["drop", "reject"] {
            if obj.contains_key(verdict) {
                edges
                    .entry(id.to_owned())
                    .or_default()
                    .insert(verdict.to_uppercase());
            }
        }
        for jump in ["jump", "goto"] {
            if let Some(target) = obj
                .get(jump)
                .and_then(|s| s.get("target"))
                .and_then(|s| s.as_str())
            {
                edges
                    .entry(id.to_owned())
                    .or_default()
                    .insert(format!("{family}/{table}/{target}"));
            }
        }
        for nested in ["vmap", "map", "data", "set"] {
            if let Some(child) = obj.get(nested) {
                collect_nft_expr_edges(child, family, table, id, edges);
            }
        }
    } else if let Some(items) = value.as_array() {
        for item in items {
            collect_nft_expr_edges(item, family, table, id, edges);
        }
    }
}

pub fn apparmor_diagnostics() -> Vec<Diagnostic> {
    apparmor(Instant::now() + Duration::from_secs(1))
}

fn apparmor(deadline: Instant) -> Vec<Diagnostic> {
    let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled").ok();
    let profiles = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles").ok();
    let mut diagnostics = vec![apparmor_profiles(enabled.as_deref(), profiles.as_deref())];
    if enabled.as_deref().is_some_and(|s| s.trim() == "Y") {
        let logs = if nix::unistd::geteuid().is_root() {
            read_command(
                "journalctl",
                &[
                    "--quiet",
                    "--no-pager",
                    "--kernel",
                    "--since",
                    "-15min",
                    "--lines",
                    "2000",
                    "--output",
                    "cat",
                ],
                deadline,
            )
        } else {
            None
        };
        diagnostics.push(apparmor_denials(logs.as_deref()));
    }
    diagnostics
}

fn apparmor_profiles(enabled: Option<&str>, profiles: Option<&str>) -> Diagnostic {
    let (state, message) = if enabled.is_some_and(|s| s.trim() == "N") {
        (State::Pass, "AppArmor is disabled in the running kernel")
    } else if let Some(profiles) = profiles {
        if profiles.lines().any(|line| {
            line.split_once(" (").is_some_and(|(name, mode)| {
                matches!(
                    name,
                    "wg" | "/usr/bin/wg"
                        | "/usr/sbin/wg"
                        | "awg"
                        | "/usr/bin/awg"
                        | "/usr/sbin/awg"
                ) && matches!(mode, "enforce)" | "kill)")
            })
        }) {
            (
                State::Warning,
                "An enforcing wg/awg AppArmor profile is loaded; it may deny access to vopono's temporary WireGuard configuration (issue #392)",
            )
        } else {
            (
                State::Pass,
                "No recognized enforcing wg/awg profile found in the readable AppArmor profile list; other confinement is not excluded",
            )
        }
    } else {
        (
            State::Skipped,
            "AppArmor kernel state or loaded profiles could not be inspected",
        )
    };
    Diagnostic::new(
        Code::AppArmor,
        state,
        message,
        (state != State::Pass).then_some(APPARMOR_ACTION),
    )
}

fn apparmor_denials(logs: Option<&str>) -> Diagnostic {
    let Some(logs) = logs else {
        return Diagnostic::new(
            Code::AppArmor,
            State::Skipped,
            "Recent kernel AppArmor denials could not be inspected",
            Some(APPARMOR_ACTION),
        );
    };
    let denied = logs.lines().any(|line| {
        let fields = shell_words::split(line).unwrap_or_default();
        fields.iter().any(|s| s == "apparmor=DENIED")
            && fields.iter().any(|s| {
                matches!(
                    s.as_str(),
                    "comm=wg"
                        | "comm=awg"
                        | "profile=wg"
                        | "profile=awg"
                        | "profile=/usr/bin/wg"
                        | "profile=/usr/sbin/wg"
                        | "profile=/usr/bin/awg"
                        | "profile=/usr/sbin/awg"
                )
            })
    });
    Diagnostic::new(
        Code::AppArmor,
        if denied { State::Warning } else { State::Pass },
        if denied {
            "Recent kernel records contain an AppArmor denial for wg/awg; this may explain a configuration or tunnel setup failure"
        } else {
            "No matching wg/awg AppArmor denial found in the available recent kernel records; absence is not proof of permission"
        },
        denied.then_some(APPARMOR_ACTION),
    )
}

/// Fixed system tools only, with bounded time and output. No shell or sudo.
pub fn system_tool(tool: &str) -> Option<std::path::PathBuf> {
    if tool.is_empty() || tool.contains('/') || tool == "." || tool == ".." {
        return None;
    }
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(tool))
        .find(|path| path.is_file())
}

pub(super) fn read_command(tool: &str, args: &[&str], deadline: Instant) -> Option<String> {
    command_result(tool, args, deadline).and_then(|(success, output)| success.then_some(output))
}

pub(super) fn command_result(
    tool: &str,
    args: &[&str],
    deadline: Instant,
) -> Option<(bool, String)> {
    let deadline = deadline.min(Instant::now() + Duration::from_millis(750));
    if Instant::now() >= deadline {
        return None;
    }
    let executable = system_tool(tool)?;
    let mut child = Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .ok()?;
    let mut reaped = false;
    let mut reached_eof = false;
    let result = (|| {
        let mut stdout = child.stdout.take()?;
        let flags = OFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFL).ok()?);
        fcntl(&stdout, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).ok()?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        reached_eof = true;
                        break;
                    }
                    Ok(count) => {
                        if bytes.len() + count > LIMIT {
                            return None;
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return None,
                }
                if Instant::now() >= deadline {
                    return None;
                }
            }
            if let Some(status) = child.try_wait().ok()? {
                reaped = true;
                // Bounded non-blocking drain in case output was buffered or a grandchild
                // inherited stdout briefly after the direct child exited.
                if !reached_eof {
                    loop {
                        match stdout.read(&mut buffer) {
                            Ok(0) => {
                                reached_eof = true;
                                break;
                            }
                            Ok(count) => {
                                if bytes.len() + count > LIMIT {
                                    return None;
                                }
                                bytes.extend_from_slice(&buffer[..count]);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                if Instant::now() >= deadline {
                                    return None;
                                }
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return None,
                        }
                    }
                }
                return String::from_utf8(bytes)
                    .ok()
                    .map(|text| (status.success(), text));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_none() && (!reaped || !reached_eof) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(child.id() as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    if !reaped {
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_dns_is_independent_of_namespace_connectivity_and_preserves_failure_reason() {
        let diagnostic = host_dns(Err(DnsFailure::Timeout));
        assert_eq!(diagnostic.code, Code::HostDns);
        assert_eq!(diagnostic.state, State::Fail);
        assert!(diagnostic.message.contains("timed out"));
        assert!(diagnostic.message.contains("tunnel can still work"));
        assert!(diagnostic.action.unwrap().contains("/etc/resolv.conf"));
        assert_eq!(
            host_dns(Ok(vec!["1.1.1.1".parse().unwrap()])).state,
            State::Pass
        );
    }

    #[test]
    fn forwarding_is_evidence_without_changing_sysctls() {
        assert_eq!(forwarding("IPv4", Some("1\n")).state, State::Pass);
        assert_eq!(forwarding("IPv4", Some("0\n")).state, State::Warning);
        assert_eq!(forwarding("IPv6", None).state, State::Skipped);
    }

    #[test]
    fn hooked_ufw_docker_and_drop_policies_are_reported_without_raw_rules() {
        let text = "# Don't edit this generated file\n*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n:ufw-before-forward - [0:0]\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j ufw-before-forward\n-A ufw-before-forward -m comment --comment SECRET_RULE -j REJECT\nCOMMIT\n";
        let found = iptables_diagnostics(text, "IPv4").unwrap();
        assert_eq!(found[0].state, State::Skipped);
        assert!(found[0].message.contains("interference is unverified"));
        for observation in ["FORWARD", "UFW", "Docker", "DROP/REJECT"] {
            assert!(found[0].message.contains(observation), "{observation}");
        }
        assert!(
            !serde_json::to_string(&found)
                .unwrap()
                .contains("SECRET_RULE")
        );
    }

    #[test]
    fn unhooked_chains_do_not_imply_interference_and_jump_cycles_terminate() {
        let text = "*filter\n:FORWARD ACCEPT [0:0]\n:DOCKER-USER - [0:0]\n:ufw-before-forward - [0:0]\n-A DOCKER-USER -j DROP\n-A ufw-before-forward -j ufw-before-forward\nCOMMIT\n";
        assert_eq!(
            iptables_diagnostics(text, "IPv4").unwrap()[0].state,
            State::Pass
        );
        let text = text.replace("COMMIT", "-A FORWARD -j ufw-before-forward\nCOMMIT");
        assert_eq!(
            iptables_diagnostics(&text, "IPv4").unwrap()[0].state,
            State::Skipped
        );
    }

    #[test]
    fn nft_base_hooks_and_later_drop_policies_are_inspected() {
        let snapshot = serde_json::json!({"nftables":[
            {"chain":{"family":"inet","table":"vopono_bridge","name":"forward","hook":"forward","prio":-10,"policy":"accept"}},
            {"chain":{"family":"ip","table":"filter","name":"FORWARD","hook":"forward","prio":0,"policy":"drop"}},
            {"chain":{"family":"ip","table":"filter","name":"ufw-before-forward"}},
            {"rule":{"family":"ip","table":"filter","chain":"FORWARD","expr":[{"jump":{"target":"ufw-before-forward"}}]}},
            {"rule":{"family":"ip","table":"filter","chain":"ufw-before-forward","comment":"SECRET_RULE","expr":[{"drop":null}]}}
        ]});
        let found = nft_diagnostics(&snapshot.to_string(), false).unwrap();
        assert_eq!(found[0].state, State::Skipped);
        assert!(found[0].message.contains("ip forward"));
        assert!(found[0].message.contains("UFW"));
        assert!(found[0].message.contains("DROP/REJECT"));
        assert!(
            !serde_json::to_string(&found)
                .unwrap()
                .contains("SECRET_RULE")
        );
    }

    #[test]
    fn native_docker_hooks_are_detected_without_docker_user_and_ipv6_can_be_skipped() {
        let snapshot = serde_json::json!({"nftables":[
            {"chain":{"family":"ip6","table":"docker-bridges","name":"filter-FORWARD","hook":"forward","policy":"accept"}}
        ]});
        let text = snapshot.to_string();
        assert!(
            nft_diagnostics(&text, false).unwrap()[0]
                .message
                .contains("Docker")
        );
        assert_eq!(nft_diagnostics(&text, true).unwrap()[0].state, State::Pass);
    }

    #[test]
    fn unreadable_or_malformed_snapshots_do_not_pass() {
        assert!(iptables_diagnostics("permission denied", "IPv4").is_none());
        assert!(nft_diagnostics("{}", false).is_none());
        assert!(nft_diagnostics("not json", false).is_none());
        assert_eq!(unavailable("inspection failed").state, State::Skipped);
    }

    #[test]
    fn apparmor_profile_presence_is_not_a_confirmed_denial() {
        assert_eq!(apparmor_profiles(Some("N\n"), None).state, State::Pass);
        assert_eq!(apparmor_profiles(Some("Y\n"), None).state, State::Skipped);
        assert_eq!(
            apparmor_profiles(Some("Y"), Some("wg (complain)\n")).state,
            State::Pass
        );
        assert_eq!(
            apparmor_profiles(Some("Y"), Some("wg (enforce)\n")).state,
            State::Warning
        );
        assert_eq!(
            apparmor_profiles(Some("Y"), Some("/usr/bin/awg (enforce)\n")).state,
            State::Warning
        );
    }

    #[test]
    fn apparmor_issue_392_denials_are_recognized_and_redacted_for_both_temp_paths() {
        for path in ["/tmp/vopono_wg.conf", "/tmp/.tmpSECRET_PATH"] {
            let record = format!(
                "audit: apparmor=\"DENIED\" operation=\"open\" profile=\"wg\" name=\"{path}\" pid=42 comm=\"wg\" requested_mask=\"r\" denied_mask=\"r\""
            );
            let diagnostic = apparmor_denials(Some(&record));
            assert_eq!(diagnostic.state, State::Warning);
            assert!(diagnostic.action.as_deref().unwrap().contains("issues/392"));
            let report = serde_json::to_string(&diagnostic).unwrap();
            assert!(!report.contains(path));
            assert!(!report.contains("pid=42"));
        }
        assert_eq!(
            apparmor_denials(Some("apparmor=\"DENIED\" comm=\"firefox\"")).state,
            State::Pass
        );
        assert_eq!(
            apparmor_denials(Some("apparmor=\"ALLOWED\" comm=\"wg\"")).state,
            State::Pass
        );
        assert_eq!(apparmor_denials(None).state, State::Skipped);
    }

    #[test]
    fn command_capture_bounds_output_time_and_reaps_children() {
        assert_eq!(
            command_result("false", &[], Instant::now() + Duration::from_secs(1)).map(|s| s.0),
            Some(false)
        );
        assert_eq!(
            read_command(
                "printf",
                &["diagnostic-ok"],
                Instant::now() + Duration::from_secs(1)
            )
            .as_deref(),
            Some("diagnostic-ok")
        );
        let started = Instant::now();
        assert!(read_command("sleep", &["5"], started + Duration::from_millis(25)).is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(read_command("yes", &[], Instant::now() + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn nft_diagnostics_inspects_vmap_and_tolerates_rules_without_expr() {
        let ruleset = serde_json::json!({
            "nftables": [
                {"chain": {"family": "inet", "table": "filter", "name": "forward", "hook": "forward", "policy": "accept"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "forward"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "forward", "expr": [
                    {"vmap": {"key": {"meta": {"key": "iifname"}}, "data": {"set": [["eth0", {"drop": null}]]}}}
                ]}}
            ]
        });
        let diags = nft_diagnostics(&ruleset.to_string(), false)
            .expect("missing expr must not abort nftables inspection");
        assert!(
            diags
                .iter()
                .any(|d| d.state == State::Skipped && d.message.contains("DROP/REJECT"))
        );
    }
}
