//! Check only recorded service paths, without opening firewall exceptions.
use super::host::{read_command, system_tool};
use super::{Diagnostic, DiagnosticCode as Code, DiagnosticState as State};
use crate::network::netns::NamespaceSnapshot;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
struct Listener {
    tcp: bool,
    address: IpAddr,
    port: u16,
    dual_stack: bool,
}

impl Listener {
    fn accepts(&self, target: IpAddr) -> bool {
        self.address == target
            || (self.address.is_ipv4() == target.is_ipv4() && self.address.is_unspecified())
            || (self.dual_stack && self.address.is_unspecified() && target.is_ipv4())
            || matches!((self.address, target), (IpAddr::V6(address), IpAddr::V4(target)) if address.to_ipv4_mapped() == Some(target))
    }

    fn matches_family(&self, ipv6: bool) -> bool {
        if ipv6 {
            matches!(self.address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none())
        } else {
            self.address.is_ipv4()
                || matches!(
                    self.address,
                    IpAddr::V6(v6) if (self.dual_stack && v6.is_unspecified()) || v6.to_ipv4_mapped().is_some()
                )
        }
    }
}

fn listeners(text: &str, ipv6: bool) -> Option<Vec<Listener>> {
    let mut parsed = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        // ss -H -n -l -t -u: protocol, state, queues, local, peer.
        let words: Vec<_> = line.split_whitespace().collect();
        let tcp = match *words.first()? {
            "tcp" => true,
            "udp" => false,
            _ => return None,
        };
        let Some((address, port)) = words.get(4).and_then(|local| local.rsplit_once(':')) else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            // Skip unbound sockets (e.g., `0.0.0.0:*`) without discarding the snapshot.
            continue;
        };
        // Strip interface scope (%ifname) before brackets/wildcard so
        // SO_BINDTODEVICE sockets like *%eth0:68 and [::]%eth0:546 parse.
        let Some(host) = address.split('%').next() else {
            continue;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let host = if host == "*" {
            if ipv6 { "::" } else { "0.0.0.0" }
        } else {
            host
        };
        let Ok(address) = host.parse() else {
            continue;
        };
        parsed.push(Listener {
            tcp,
            address,
            port,
            dual_stack: ipv6 && words.contains(&"v6only:0"),
        });
    }
    Some(parsed)
}

fn socket_snapshot(
    namespace: Option<&str>,
    ipv6: bool,
    deadline: Instant,
) -> Option<Vec<Listener>> {
    let ss = system_tool("ss")?;
    let flags = [
        "-H",
        "-n",
        "-l",
        "-t",
        "-u",
        "-e",
        if ipv6 { "-6" } else { "-4" },
    ];
    let text = if let Some(namespace) = namespace {
        let mut args = vec!["netns", "exec", namespace, ss.to_str()?];
        args.extend(flags);
        read_command("ip", &args, deadline)?
    } else {
        read_command("ss", &flags, deadline)?
    };
    listeners(&text, ipv6)
}

fn all_sockets(namespace: Option<&str>, deadline: Instant) -> Option<Vec<Listener>> {
    let v4 = socket_snapshot(namespace, false, deadline);
    // Even with --skip-ipv6, a dual-stack IPv6 listener can accept IPv4.
    // Keep IPv4 results if IPv6 is disabled on the host/kernel.
    let v6 = socket_snapshot(namespace, true, deadline);
    match (v4, v6) {
        (Some(mut sockets), Some(v6_sockets)) => {
            sockets.extend(v6_sockets);
            Some(sockets)
        }
        (Some(sockets), None) | (None, Some(sockets)) => Some(sockets),
        (None, None) => None,
    }
}

fn tcp_connect(
    namespace: Option<&str>,
    target: SocketAddr,
    timeout_ms: u64,
    deadline: Instant,
) -> Option<bool> {
    let namespace = namespace
        .map(|name| {
            crate::network::netns::validate_netns_name(name).ok()?;
            std::fs::File::open(format!("/run/netns/{name}")).ok()
        })
        .map(|res| res.ok_or(()))
        .transpose()
        .ok()?;
    // setns affects only this short-lived thread. Never move a daemon worker
    // (or the process's filesystem/resolver) into the client's namespace.
    std::thread::Builder::new()
        .name("doctor-tcp".into())
        .spawn(move || {
            if let Some(namespace) = namespace {
                nix::sched::setns(namespace, nix::sched::CloneFlags::CLONE_NEWNET).ok()?;
            }
            let requested = Duration::from_millis(timeout_ms.clamp(1, 500));
            let remaining = deadline.checked_duration_since(Instant::now())?;
            if remaining.is_zero() {
                return None;
            }
            let truncated = remaining < requested;
            let timeout = remaining.min(requested);
            match TcpStream::connect_timeout(&target, timeout) {
                Ok(_) => Some(true),
                Err(error)
                    if truncated
                        && (error.kind() == std::io::ErrorKind::TimedOut
                            || Instant::now() >= deadline) =>
                {
                    None
                }
                Err(_) => Some(false),
            }
        })
        .ok()?
        .join()
        .ok()?
}

fn tcp_diagnostic(context: &str, result: Option<bool>) -> Diagnostic {
    let (state, result) = match result {
        Some(true) => (State::Pass, "succeeded"),
        Some(false) => (
            State::Warning,
            "failed; the expected TCP path is unavailable",
        ),
        None => (State::Skipped, "unavailable or inspection budget exhausted"),
    };
    Diagnostic::new(
        Code::HostLink,
        state,
        &format!("{context}: TCP connect {result}"),
        (state == State::Warning).then_some("Check the listener binding, routes and matching host/namespace firewall rules; a TCP failure does not identify which rule blocked it"),
    )
}

pub(super) fn inspect(
    state: &NamespaceSnapshot,
    offline: bool,
    skip_ipv6: bool,
    timeout_ms: u64,
    deadline: Instant,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let host_access = state.state.allow_host_access.or_else(|| {
        state
            .dns_config
            .as_ref()
            .and_then(|dns| dns.allow_host_access)
    });
    if host_access != Some(true) {
        diagnostics.push(Diagnostic::new(Code::HostLink, State::Skipped,
            if host_access == Some(false) { "Host-service TCP probe skipped: --allow-host-access was not enabled" }
            else { "Host-service TCP probe skipped: host-access policy was not recorded in this snapshot" }, None));
    }
    let mut ports: BTreeSet<_> = state
        .state
        .open_ports
        .iter()
        .chain(&state.state.host_forwarded_ports)
        .copied()
        .collect();
    if let Some(forward) = &state.state.port_forwarding {
        ports.insert(forward.port);
    }
    let sockets = (!ports.is_empty())
        .then(|| all_sockets(Some(&state.name), deadline))
        .flatten();
    let host_sockets = (!state.state.host_forwarded_ports.is_empty())
        .then(|| all_sockets(None, deadline))
        .flatten();
    if !ports.is_empty() && sockets.is_none() {
        diagnostics.push(Diagnostic::new(
            Code::HostLink,
            State::Skipped,
            "Namespace TCP/UDP listener inspection unavailable",
            None,
        ));
    }
    // Keep large port lists from exceeding the daemon response bound.
    if ports.len() > 64 {
        diagnostics.push(Diagnostic::new(
            Code::HostLink,
            State::Skipped,
            "Service inspection is limited to the first 64 configured ports",
            None,
        ));
    }
    for ipv6 in [false, true] {
        if ipv6 && skip_ipv6 {
            continue;
        }
        let pair = state.veth_pair_ips.as_ref().and_then(|ips| {
            if ipv6 {
                ips.ipv6.as_ref()
            } else {
                ips.ipv4.as_ref()
            }
        });
        if host_access == Some(true)
            && let Some(pair) = pair
        {
            let context = format!("--allow-host-access namespace -> host {}", pair.host_ip);
            if offline {
                diagnostics.push(tcp_diagnostic(&format!("{context} (--offline)"), None));
            } else {
                // A listener we own distinguishes a closed service from a
                // broken path. Drop it after the connect; no data is sent.
                match TcpListener::bind(SocketAddr::new(pair.host_ip, 0)) {
                    Ok(listener) => {
                        if let Ok(target) = listener.local_addr() {
                            let result = tcp_connect(Some(&state.name), target, timeout_ms, deadline);
                            let mut diagnostic = tcp_diagnostic(
                                &format!("{context} (temporary listener {target})"), result);
                            if result == Some(false) {
                                diagnostic.action = Some("The host firewall may intentionally restrict service ports; this ephemeral-port failure does not prove all host services are unreachable. Inspect matching host INPUT and namespace OUTPUT rules and routes".into());
                            }
                            diagnostics.push(diagnostic);
                        } else {
                            diagnostics.push(tcp_diagnostic(&context, None));
                        }
                    }
                    Err(_) => diagnostics.push(Diagnostic::new(Code::HostLink, State::Skipped,
                        &format!("{context}: could not bind a temporary listener to the recorded host veth address"), None)),
                }
            }
        }
        for &port in ports.iter().take(64) {
            let forwarded = !ipv6 && state.state.host_forwarded_ports.contains(&port);
            let host_veth_allowed = state.state.open_ports.contains(&port)
                || state.state.host_forwarded_ports.contains(&port);
            let context = format!(
                "{} namespace port {port}",
                if ipv6 { "IPv6" } else { "IPv4" }
            );
            let tcp_listener = if let Some(sockets) = &sockets {
                let on_port: Vec<_> = sockets
                    .iter()
                    .filter(|s| s.port == port && s.matches_family(ipv6))
                    .collect();
                let bindings = on_port
                    .iter()
                    .map(|s| {
                        format!(
                            "{} {}",
                            if s.tcp { "TCP" } else { "UDP" },
                            SocketAddr::new(s.address, s.port)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                diagnostics.push(Diagnostic::new(Code::HostLink, State::Skipped,
                    &format!("{context}: {}; listener presence alone does not verify firewall acceptance or public VPN ingress",
                        if bindings.is_empty() { "no TCP/UDP listener; an open firewall port does not start a service" } else { &bindings }), None));
                let has_tcp = pair.is_some_and(|pair| {
                    on_port
                        .iter()
                        .any(|s| s.tcp && s.accepts(pair.namespace_ip))
                });
                if let Some(pair) = pair
                    && has_tcp
                    && host_veth_allowed
                {
                    let target = SocketAddr::new(pair.namespace_ip, port);
                    let result = (!offline)
                        .then(|| tcp_connect(None, target, timeout_ms, deadline))
                        .flatten();
                    diagnostics.push(tcp_diagnostic(
                        &format!(
                            "host -> {context} at {target}{}",
                            if offline { " (--offline)" } else { "" }
                        ),
                        result,
                    ));
                }
                Some(has_tcp)
            } else {
                None
            };
            if forwarded && pair.is_some() {
                let listener = host_sockets
                    .as_ref()
                    .map(|sockets| sockets.iter().any(|s| s.tcp && s.port == port));
                diagnostics.push(relay_diagnostic(port, listener, tcp_listener));
            }
        }
    }
    if let Some(forward) = &state.state.port_forwarding {
        diagnostics.push(Diagnostic::new(Code::HostLink, State::Skipped,
            &format!("Provider-forwarded port {} ({}): public TCP/UDP ingress requires a probe from outside the VPN; local listener and veth results do not verify the provider mapping",
                forward.port, if forward.automatic { "automatically managed" } else { "manually configured" }), None));
    }
    diagnostics
}

fn relay_diagnostic(port: u16, listener: Option<bool>, backend: Option<bool>) -> Diagnostic {
    let (state, details) = match (listener, backend) {
        (None, _) => (State::Skipped, "host TCP listener inspection unavailable"),
        (Some(false), _) => (
            State::Skipped,
            "no host TCP listener; --no-proxy or an inactive relay may explain this",
        ),
        (Some(true), None) => (
            State::Skipped,
            "host TCP listener found, but namespace listener inspection was unavailable",
        ),
        (Some(true), Some(false)) => (
            State::Warning,
            "host TCP listener exists, but no namespace TCP listener accepts the IPv4 veth address; the configured relay has no backend",
        ),
        (Some(true), Some(true)) => (
            State::Skipped,
            "host TCP listener and namespace backend binding found; listener ownership and end-to-end relay data transfer are unverified",
        ),
    };
    Diagnostic::new(Code::HostLink, state, &format!("--forward {port}: {details}"),
        (state == State::Warning).then_some("Start the namespace service on 0.0.0.0 or its IPv4 veth address; a UDP-only, loopback-only or tunnel-address-only socket cannot serve the TCP host relay"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_bindings_distinguish_protocol_family_and_loopback() {
        let text =
            "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.1:8080 0.0.0.0:*\n";
        let found = listeners(text, false).unwrap();
        assert!(found[0].tcp && found[0].accepts("10.200.1.2".parse().unwrap()));
        assert!(!found[0].accepts("fd42::2".parse().unwrap()));
        assert!(!found[1].tcp && !found[1].accepts("10.200.1.2".parse().unwrap()));
        let found = listeners(
            "tcp LISTEN 0 128 [::]:8080 [::]:*\nudp UNCONN 0 0 *:9000 *:*",
            true,
        )
        .unwrap();
        assert!(found[0].accepts("fd42::2".parse().unwrap()));
        assert!(found[1].address.is_ipv6() && found[1].address.is_unspecified());
        assert!(!found[0].accepts("10.200.1.2".parse().unwrap()));
        let dual = listeners("tcp LISTEN 0 128 *:8080 *:* v6only:0", true).unwrap();
        assert!(dual[0].accepts("10.200.1.2".parse().unwrap()));
        let only6 = listeners("tcp LISTEN 0 128 *:8080 *:* v6only:1", true).unwrap();
        assert!(!only6[0].accepts("10.200.1.2".parse().unwrap()));
        // Device-bound DHCP/VRF sockets must parse cleanly without failing the snapshot.
        let scoped4 = listeners("udp UNCONN 0 0 *%eth0:68 0.0.0.0:*\n", false).unwrap();
        assert_eq!(scoped4[0].port, 68);
        assert!(scoped4[0].address.is_unspecified() && scoped4[0].address.is_ipv4());
        let scoped6 = listeners("udp UNCONN 0 0 [::]%eth0:546 [::]:*\n", true).unwrap();
        assert_eq!(scoped6[0].port, 546);
        assert!(scoped6[0].address.is_unspecified() && scoped6[0].address.is_ipv6());
        // Non-wildcard IPv6 sockets with default v6only:0 must not match IPv4 family.
        let v6_loopback = listeners("tcp LISTEN 0 128 [::1]:8080 [::]:* v6only:0", true).unwrap();
        assert!(!v6_loopback[0].matches_family(false));
        assert!(v6_loopback[0].matches_family(true));
        // IPv4-mapped IPv6 listeners match IPv4, not IPv6.
        let mapped = listeners(
            "tcp LISTEN 0 128 [::ffff:10.200.1.2]:8080 *:* v6only:0",
            true,
        )
        .unwrap();
        assert!(mapped[0].matches_family(false));
        assert!(!mapped[0].matches_family(true));
        assert!(mapped[0].accepts("10.200.1.2".parse().unwrap()));
        // Unbound sockets (`0.0.0.0:*`) must be skipped without discarding valid listeners.
        let with_unbound = listeners(
            "udp UNCONN 0 0 0.0.0.0:* 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n",
            false,
        )
        .unwrap();
        assert_eq!(with_unbound.len(), 1);
        assert_eq!(with_unbound[0].port, 8080);
        assert!(listeners("permission denied", false).is_none());
        assert_eq!(listeners("", false), Some(Vec::new()));
    }

    #[test]
    fn relay_checks_do_not_confuse_missing_proxies_with_missing_backends() {
        assert_eq!(
            relay_diagnostic(8080, None, Some(false)).state,
            State::Skipped
        );
        assert_eq!(
            relay_diagnostic(8080, Some(false), Some(true)).state,
            State::Skipped
        );
        assert_eq!(
            relay_diagnostic(8080, Some(true), None).state,
            State::Skipped
        );
        assert_eq!(
            relay_diagnostic(8080, Some(true), Some(false)).state,
            State::Warning
        );
        assert_eq!(
            relay_diagnostic(8080, Some(true), Some(true)).state,
            State::Skipped
        );
    }

    #[test]
    fn tcp_probe_checks_a_known_listener_and_obeys_its_deadline() {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = socket.local_addr().unwrap();
        assert_eq!(
            tcp_connect(None, target, 50, Instant::now() + Duration::from_secs(1)),
            Some(true)
        );
        assert_eq!(tcp_connect(None, target, 50, Instant::now()), None);
        assert_eq!(tcp_diagnostic("test", Some(false)).state, State::Warning);
        assert_eq!(tcp_diagnostic("test", None).state, State::Skipped);
    }
}
