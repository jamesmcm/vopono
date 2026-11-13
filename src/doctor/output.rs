//! Human tables and stable, undecorated records share the same report.
use super::{Code, Diagnostic, Report, State};
use crate::args::DoctorColor;
use console::{Style, measure_text_width};
use std::fmt::Write;
use std::io::IsTerminal;

pub(super) fn render(report: &Report, plain: bool, color: DoctorColor) -> String {
    if plain {
        return plaintext(report);
    }
    let color = match color {
        DoctorColor::Always => true,
        DoctorColor::Never => false,
        DoctorColor::Auto => {
            std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                && std::env::var_os("TERM").is_none_or(|value| value != "dumb")
        }
    };
    pretty(report, console::Term::stdout().size().1 as usize, color)
}

fn diagnostics(report: &Report) -> impl Iterator<Item = &Diagnostic> {
    report
        .diagnostics
        .iter()
        .chain(report.host_network.iter().flat_map(|n| &n.diagnostics))
        .chain(report.namespaces.iter().flat_map(|ns| {
            ns.diagnostics
                .iter()
                .chain(ns.network.iter().flat_map(|n| &n.diagnostics))
        }))
}

fn escaped(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || c == '\\' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn code(code: Code) -> String {
    serde_json::to_value(code)
        .expect("diagnostic code is serializable")
        .as_str()
        .expect("diagnostic code is a string")
        .to_owned()
}

fn state(state: State) -> &'static str {
    match state {
        State::Pass => "pass",
        State::Warning => "warning",
        State::Fail => "fail",
        State::Skipped => "skipped",
    }
}

fn health(health: Option<&crate::health::Health>) -> (&'static str, String) {
    let Some(health) = health else {
        return (
            "unavailable",
            "No cached monitor sample; monitoring may be disabled".into(),
        );
    };
    let state = match health.state {
        crate::health::State::Connected => "connected",
        crate::health::State::Degraded => "degraded",
        crate::health::State::Reconnecting => "reconnecting",
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut details = format!(
        "Cached sample {}s ago; checked_at={}; reconnect_attempts={}",
        now.saturating_sub(health.checked_at),
        health.checked_at,
        health.reconnect_attempts
    );
    if let Some(error) = &health.last_error {
        write!(details, "; {error}").unwrap();
    }
    (state, details)
}

fn plaintext(report: &Report) -> String {
    let mut output = String::from("scope\tcheck\tstate\tmessage\taction\n");
    let mut rows = |scope: &str, diagnostics: &[Diagnostic]| {
        for d in diagnostics {
            writeln!(
                output,
                "{}\t{}\t{}\t{}\t{}",
                escaped(scope),
                code(d.code),
                state(d.state),
                escaped(&d.message),
                escaped(d.action.as_deref().unwrap_or(""))
            )
            .unwrap();
        }
    };
    rows("host", &report.diagnostics);
    if let Some(network) = &report.host_network {
        rows("host", &network.diagnostics);
    }
    for ns in &report.namespaces {
        let scope = format!("namespace:{}", ns.id);
        rows(&scope, &ns.diagnostics);
        if let Some(network) = &ns.network {
            rows(&scope, &network.diagnostics);
        }
    }
    for ns in &report.namespaces {
        let (state, message) = health(ns.health.as_ref());
        writeln!(
            output,
            "namespace:{}\tmonitor_health\t{state}\t{}\t",
            escaped(&ns.id),
            escaped(&message)
        )
        .unwrap();
    }
    output
}

fn pretty(report: &Report, width: usize, color: bool) -> String {
    let heading = Style::new().bold().cyan().force_styling(color);
    let mut counts = [0usize; 4];
    for d in diagnostics(report) {
        counts[match d.state {
            State::Pass => 0,
            State::Warning => 1,
            State::Fail => 2,
            State::Skipped => 3,
        }] += 1;
    }
    let mut output = format!(
        "{}\n{} passed · {} warnings · {} failed · {} skipped\n",
        heading.apply_to("Vopono doctor"),
        counts[0],
        counts[1],
        counts[2],
        counts[3]
    );
    let host = report
        .diagnostics
        .iter()
        .chain(report.host_network.iter().flat_map(|n| &n.diagnostics))
        .collect::<Vec<_>>();
    writeln!(output, "\n{}", heading.apply_to("Host / configuration")).unwrap();
    table(&mut output, &host, width, color);
    for ns in &report.namespaces {
        writeln!(
            output,
            "\n{}",
            heading.apply_to(escaped(&format!(
                "Namespace {} ({}, {})",
                ns.id, ns.provider, ns.protocol
            )))
        )
        .unwrap();
        let (state, details) = health(ns.health.as_ref());
        for line in wrap(
            &format!("Monitor: {state}. {}", escaped(&details)),
            width.max(40),
        ) {
            writeln!(output, "{line}").unwrap();
        }
        let rows = ns
            .diagnostics
            .iter()
            .chain(ns.network.iter().flat_map(|n| &n.diagnostics))
            .collect::<Vec<_>>();
        table(&mut output, &rows, width, color);
        writeln!(output, "Details: vopono check {} --json", escaped(&ns.id)).unwrap();
    }
    output
}

fn label(code: Code) -> &'static str {
    match code {
        Code::ProviderConfig => "VPN configuration",
        Code::ProviderCatalogue => "Provider catalogue",
        Code::ConfigFreshness => "Config freshness",
        Code::HostConnectivity => "Host connectivity",
        Code::EndpointDns => "Endpoint DNS",
        Code::EndpointTransport => "Endpoint transport",
        Code::NamespaceRouting => "Namespace routing",
        Code::TunnelAuthentication => "VPN authentication",
        Code::TunnelTls => "VPN TLS",
        Code::TunnelHandshake => "VPN handshake",
        Code::NamespaceDns => "Namespace DNS",
        Code::TunnelConnectivity => "VPN connectivity",
        Code::ProbeUnavailable => "Probe availability",
        Code::HostDns => "Host DNS",
        Code::HostForwarding => "Host forwarding",
        Code::HostFirewall => "Host firewall",
        Code::AppArmor => "AppArmor",
        Code::DnsConfiguration => "DNS configuration",
        Code::NetworkInterface => "Network interfaces",
        Code::HostLink => "Host / namespace link",
        Code::TailscaleDns => "Tailscale DNS",
        Code::NetworkManager => "NetworkManager",
        Code::DaemonAvailability => "Daemon availability",
        Code::DaemonVersion => "Daemon version",
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && measure_text_width(&line) + 1 + measure_text_width(word) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        for c in word.chars() {
            if measure_text_width(&line) + measure_text_width(&c.to_string()) > width {
                lines.push(std::mem::take(&mut line));
            }
            line.push(c);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn table(output: &mut String, diagnostics: &[&Diagnostic], width: usize, color: bool) {
    let width = width.clamp(40, 140);
    let columns = [
        7,
        (width / 4).clamp(12, 24),
        width - 17 - (width / 4).clamp(12, 24),
    ];
    let border = |output: &mut String, left: char, middle: char, right: char| {
        write!(output, "{left}").unwrap();
        for (index, width) in columns.iter().enumerate() {
            write!(
                output,
                "{}{}",
                "─".repeat(width + 2),
                if index == 2 { right } else { middle }
            )
            .unwrap();
        }
        output.push('\n');
    };
    border(output, '┌', '┬', '┐');
    row(
        output,
        ["STATE", "CHECK", "DETAILS"],
        columns,
        Style::new().bold().force_styling(color),
    );
    border(output, '├', '┼', '┤');
    for (index, d) in diagnostics.iter().enumerate() {
        let (status, style) = match d.state {
            State::Pass => ("PASS", Style::new().green()),
            State::Warning => ("WARN", Style::new().yellow()),
            State::Fail => ("FAIL", Style::new().red()),
            State::Skipped => ("SKIP", Style::new().dim()),
        };
        let check = wrap(label(d.code), columns[1]);
        let mut details = wrap(&escaped(&d.message), columns[2]);
        if let Some(action) = &d.action {
            details.push(String::new());
            details.extend(wrap(&format!("Action: {}", escaped(action)), columns[2]));
        }
        for line in 0..check.len().max(details.len()) {
            row(
                output,
                [
                    if line == 0 { status } else { "" },
                    check.get(line).map_or("", String::as_str),
                    details.get(line).map_or("", String::as_str),
                ],
                columns,
                style.clone().bold().force_styling(color),
            );
        }
        if index + 1 < diagnostics.len() {
            border(output, '├', '┼', '┤');
        }
    }
    border(output, '└', '┴', '┘');
}

fn row(output: &mut String, cells: [&str; 3], widths: [usize; 3], style: Style) {
    output.push('│');
    for (index, (cell, width)) in cells.into_iter().zip(widths).enumerate() {
        let padded = format!(
            "{cell}{}",
            " ".repeat(width.saturating_sub(measure_text_width(cell)))
        );
        if index == 0 {
            write!(output, " {} │", style.apply_to(padded)).unwrap();
        } else {
            write!(output, " {padded} │").unwrap();
        }
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            version: 1,
            diagnostics: vec![
                Diagnostic::new(
                    Code::HostDns,
                    State::Fail,
                    "Resolver unreachable",
                    Some("Check host DNS and routing"),
                ),
                Diagnostic::new(
                    Code::DaemonAvailability,
                    State::Pass,
                    "Daemon reachable",
                    None,
                ),
            ],
            namespaces: vec![],
            host_network: None,
            daemon: None,
        }
    }

    #[test]
    fn tables_wrap_details_preserve_actions_and_colour_only_when_requested() {
        let report = report();
        let output = pretty(&report, 60, false);
        assert!(output.contains("1 passed · 0 warnings · 1 failed · 0 skipped"));
        assert!(output.contains("FAIL") && output.contains("Host DNS"));
        assert!(output.contains("Action:"));
        assert!(!output.contains('\x1b'));
        for width in [40, 60, 80, 140] {
            assert!(
                pretty(&report, width, false)
                    .lines()
                    .filter(|line| line.starts_with('│') || line.starts_with('┌'))
                    .all(|line| measure_text_width(line) == width)
            );
        }
        assert!(pretty(&report, 80, true).contains("\x1b["));
    }

    #[test]
    fn plain_records_escape_controls_and_never_inherit_colour() {
        let mut report = report();
        report.diagnostics[0].message = "DNS\tbad\n\x1b[31m".into();
        let plain = render(&report, true, DoctorColor::Always);
        assert!(plain.starts_with("scope\tcheck\tstate\tmessage\taction\n"));
        assert!(plain.contains("host\thost_dns\tfail\tDNS\\tbad\\n"));
        assert_eq!(plain.lines().count(), 3);
        assert!(plain.lines().all(|line| line.split('\t').count() == 5));
        assert!(!plain.contains('\x1b') && !plain.contains('│'));
    }

    #[test]
    fn wraps_unicode_and_long_unbroken_values_without_losing_content() {
        let value = "a界b界c界abcdefghijklmnopqrstuvwxyz";
        let lines = wrap(value, 9);
        assert_eq!(lines.concat(), value);
        assert!(lines.iter().all(|line| measure_text_width(line) <= 9));
    }
}
