//! Freeze daemon OpenVPN input into a private runtime directory. Configuration
//! options are an execution/file-I/O language, not merely network settings.
use anyhow::{Context, ensure};
use std::path::{Path, PathBuf};

/// Bound the amount of attacker-controlled data copied into `/run`.
pub(crate) const MAX_REFERENCED_FILES: usize = 32;
pub(crate) const MAX_REFERENCED_BYTES: usize = 16 * 1024 * 1024;

fn account_reference(bytes: &[u8], count: &mut usize, total: &mut usize) -> anyhow::Result<()> {
    *count = count
        .checked_add(1)
        .context("OpenVPN reference count overflow")?;
    ensure!(
        *count <= MAX_REFERENCED_FILES,
        "OpenVPN configuration references too many files (maximum {MAX_REFERENCED_FILES})"
    );
    *total = total
        .checked_add(bytes.len())
        .context("OpenVPN reference size overflow")?;
    ensure!(
        *total <= MAX_REFERENCED_BYTES,
        "OpenVPN referenced files exceed the {MAX_REFERENCED_BYTES}-byte limit"
    );
    Ok(())
}

/// Only these client settings may reach the privileged external process.
/// File inputs are copied separately; plugin/script/log/include options fail closed.
fn allowed(option: &str) -> bool {
    matches!(
        option,
        "client"
            | "dev"
            | "dev-type"
            | "proto"
            | "remote"
            | "remote-random"
            | "remote-random-hostname"
            | "resolv-retry"
            | "nobind"
            | "bind"
            | "local"
            | "lport"
            | "port"
            | "rport"
            | "persist-key"
            | "persist-tun"
            | "persist-remote-ip"
            | "persist-local-ip"
            | "auth-nocache"
            | "auth-retry"
            | "auth-token"
            | "key-direction"
            | "cipher"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "ncp-ciphers"
            | "auth"
            | "tls-cipher"
            | "tls-ciphersuites"
            | "tls-version-min"
            | "tls-version-max"
            | "tls-cert-profile"
            | "remote-cert-tls"
            | "remote-cert-ku"
            | "remote-cert-eku"
            | "verify-x509-name"
            | "verify-hash"
            | "x509-username-field"
            | "ns-cert-type"
            | "reneg-sec"
            | "reneg-bytes"
            | "reneg-pkts"
            | "hand-window"
            | "tran-window"
            | "ping"
            | "ping-exit"
            | "ping-restart"
            | "keepalive"
            | "connect-retry"
            | "connect-retry-max"
            | "connect-timeout"
            | "explicit-exit-notify"
            | "float"
            | "pull"
            | "pull-filter"
            | "route"
            | "route-ipv6"
            | "route-nopull"
            | "redirect-gateway"
            | "redirect-private"
            | "route-delay"
            | "route-metric"
            | "route-gateway"
            | "dhcp-option"
            | "block-outside-dns"
            | "tun-mtu"
            | "tun-mtu-extra"
            | "link-mtu"
            | "mssfix"
            | "fragment"
            | "sndbuf"
            | "rcvbuf"
            | "fast-io"
            | "comp-lzo"
            | "compress"
            | "allow-compression"
            | "topology"
            | "ifconfig"
            | "ifconfig-ipv6"
            | "ifconfig-noexec"
            | "route-noexec"
            | "verb"
            | "mute"
            | "mute-replay-warnings"
            | "suppress-timestamps"
            | "machine-readable-output"
            | "socket-flags"
            | "tls-client"
            | "tls-timeout"
            | "replay-window"
            | "replay-warnings"
            | "http-proxy-option"
            | "http-proxy-retry"
            | "socks-proxy-retry"
            | "allow-recursive-routing"
            | "inactive"
            | "push-peer-info"
            | "preresolve"
            | "tls-exit"
            | "tls-crypt-v2-allow-noncookie"
            | "auth-gen-token"
            | "dns-updown"
    )
}
fn input_file(option: &str) -> bool {
    matches!(
        option,
        "ca" | "cert"
            | "key"
            | "pkcs12"
            | "tls-auth"
            | "tls-crypt"
            | "tls-crypt-v2"
            | "auth-user-pass"
            | "extra-certs"
            | "crl-verify"
            | "dh"
    )
}

/// Shared by sanitization and endpoint parsing so accepted credential blocks
/// stay opaque throughout preflight and launch.
pub(crate) fn inline_file(tag: &str) -> bool {
    input_file(tag) || tag == "http-proxy-user-pass"
}

pub(crate) fn snapshot(
    config: &Path,
    runtime: &Path,
    auth: Option<&Path>,
) -> anyhow::Result<(PathBuf, Option<PathBuf>)> {
    let raw = crate::util::owner_write::read_file_as_config_owner(config)?;
    let content = std::str::from_utf8(&raw).context("OpenVPN config must be UTF-8")?;
    let parent = config.parent().unwrap_or(Path::new("."));
    let mut referenced_files = 0usize;
    let mut referenced_bytes = 0usize;
    let safe = sanitize(content, |reference, index| {
        let bytes = crate::util::owner_write::read_file_as_config_owner(&parent.join(reference))?;
        account_reference(&bytes, &mut referenced_files, &mut referenced_bytes)?;
        let path = runtime.join(format!("input-{index}"));
        std::fs::write(&path, bytes)?;
        Ok(path)
    })?;
    let path = runtime.join("client.ovpn");
    std::fs::write(&path, safe)?;
    let auth = auth
        .map(|auth| -> anyhow::Result<_> {
            let path = runtime.join("auth.txt");
            std::fs::write(
                &path,
                crate::util::owner_write::read_file_as_config_owner(auth)?,
            )?;
            Ok(path)
        })
        .transpose()?;
    Ok((path, auth))
}

pub(crate) fn validate(content: &str, config: &Path) -> anyhow::Result<()> {
    let mut referenced_files = 0usize;
    let mut referenced_bytes = 0usize;
    sanitize(content, |reference, _| {
        let path = config.parent().unwrap_or(Path::new(".")).join(reference);
        let bytes = crate::util::owner_write::read_file_as_config_owner(&path)?;
        account_reference(&bytes, &mut referenced_files, &mut referenced_bytes)?;
        Ok(path)
    })?;
    Ok(())
}

fn sanitize(
    content: &str,
    mut copy: impl FnMut(&str, usize) -> anyhow::Result<PathBuf>,
) -> anyhow::Result<String> {
    ensure!(
        !content.contains('\0'),
        "NUL bytes are not supported in daemon OpenVPN configurations"
    );
    let mut output = String::new();
    let mut inline: Option<String> = None;
    let mut file_index = 0;
    for line in content.lines().map(str::trim) {
        if let Some(tag) = &inline {
            let closing = format!("</{tag}>");
            // OpenVPN ends inline data at a closing-tag prefix. Reject any
            // suffix so it cannot see directives that we treat as opaque data.
            // Check embedded tags too: OpenVPN reads long lines in chunks,
            // which can put an embedded tag at the start of a parser read.
            if line.contains(&closing) {
                ensure!(line == closing, "Ambiguous OpenVPN inline closing tag");
                inline = None;
            }
            output.push_str(line);
            output.push('\n');
            continue;
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('<') {
            let tag = line
                .strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .context("Malformed inline OpenVPN block")?;
            // Connection blocks are option scopes, never opaque inline data.
            if tag == "connection" || tag == "/connection" {
                output.push_str(line);
                output.push('\n');
                continue;
            }
            ensure!(
                inline_file(tag),
                "Unsupported inline OpenVPN block in daemon configuration"
            );
            inline = Some(tag.to_owned());
            output.push_str(line);
            output.push('\n');
            continue;
        }
        let fields =
            shell_words::split(line).map_err(|_| anyhow::anyhow!("Malformed OpenVPN directive"))?;
        let option = fields
            .first()
            .context("Empty OpenVPN directive")?
            .trim_start_matches("--");
        // Never permit --dev /dev/... to open an arbitrary host file or reuse
        // a host interface through --dev-node or --iproute.
        if option == "dev" {
            ensure!(
                fields.len() == 2
                    && fields.get(1).is_some_and(|v| v.len() < libc::IFNAMSIZ
                        && (v == "tun"
                            || v.starts_with("tun") && v[3..].bytes().all(|b| b.is_ascii_digit()))),
                "Daemon OpenVPN requires a tun device"
            );
        }
        if option == "dev-type" {
            ensure!(
                fields.len() == 2 && fields[1] == "tun",
                "Daemon OpenVPN requires dev-type tun"
            );
        }
        if option == "setenv" {
            let variable = fields.get(1).map(String::as_str).unwrap_or("");
            let safe_variable = variable == "CLIENT_CERT"
                || variable.starts_with("UV_")
                    && variable
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            let safe_optional = variable == "opt"
                && fields
                    .get(2)
                    .is_some_and(|option| option == "block-outside-dns");
            ensure!(
                fields.len() == 3 && (safe_variable || safe_optional),
                "Unsafe OpenVPN environment directive in daemon configuration"
            );
            output.push_str(line);
            output.push('\n');
            continue;
        }
        if input_file(option) {
            if let Some(file) = fields.get(1) {
                // `dh none` is a valid directive disabling DH, not a file
                // reference. Preserve it; do not try to copy a file named none.
                if option == "dh" && file == "none" {
                    output.push_str(line);
                    output.push('\n');
                    continue;
                }
                if file != "[inline]" {
                    ensure!(
                        fields.len() <= 3 && !(option == "crl-verify" && fields.get(2).is_some()),
                        "Unsupported OpenVPN file directive arguments"
                    );
                    file_index += 1;
                    let path = copy(file, file_index)?;
                    let path = path.to_str().context("Invalid runtime path")?;
                    output.push_str(option);
                    output.push(' ');
                    output.push_str(path);
                    if let Some(direction) = fields.get(2) {
                        ensure!(
                            direction == "0" || direction == "1",
                            "Invalid TLS key direction"
                        );
                        output.push(' ');
                        output.push_str(direction);
                    }
                    output.push('\n');
                    continue;
                }
            }
        } else if matches!(option, "socks-proxy" | "http-proxy") {
            // Proxy auth files need separate snapshot support; never pass arbitrary paths.
            ensure!(
                fields.len() <= 3,
                "Proxy authentication files are not supported in daemon profiles"
            );
        } else {
            ensure!(
                allowed(option),
                "Unsupported or unsafe OpenVPN directive in daemon configuration; plugins, scripts, nested configs and file outputs are disabled"
            );
        }
        output.push_str(line);
        output.push('\n');
    }
    ensure!(inline.is_none(), "Unclosed OpenVPN inline block");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_inline_closing_tag_suffixes_that_hide_privileged_directives() {
        for tag in ["ca", "cert", "key", "auth-user-pass", "tls-crypt"] {
            for suffix in [" trailing-content", "# comment", "\0"] {
                for directive in [
                    "plugin /tmp/evil.so",
                    "log /root/target",
                    "config other.ovpn",
                ] {
                    let text = format!(
                        "client\n<{tag}>\n</{tag}>{suffix}\n{directive}\n<{tag}>\n</{tag}>\n"
                    );
                    assert!(sanitize(&text, |_, _| unreachable!()).is_err());
                }
            }
        }
        let text = format!(
            "<ca>\n{}</ca>\nlog /root/target\n<ca>\n</ca>\n",
            "A".repeat(4096)
        );
        assert!(sanitize(&text, |_, _| unreachable!()).is_err());
    }
    #[test]
    fn denies_execution_includes_and_arbitrary_file_outputs_in_every_scope() {
        for directive in [
            "plugin /tmp/evil.so",
            "config nested.ovpn",
            "log /root/target",
            "status /root/target",
            "writepid /root/target",
            "up evil",
            "tls-verify evil",
            "iproute /tmp/evil",
            "setenv opt plugin /tmp/evil.so",
            "setenv LD_PRELOAD /tmp/evil.so",
            "dev-node /root/target",
            "dev tun12345678901234567890",
            "dev-type tap",
            "replay-persist /root/target",
        ] {
            let text = format!("client\n<connection>\n{directive}\n</connection>\n");
            assert!(
                sanitize(&text, |_, _| unreachable!()).is_err(),
                "accepted {directive}"
            );
        }
    }
    #[test]
    fn accepts_dh_none_legacy_ciphers_and_inline_proxy_credentials() {
        let safe = sanitize(
            "client\ndh none\nncp-ciphers AES-256-GCM\n<http-proxy-user-pass>\nuser\npass\n</http-proxy-user-pass>\n",
            |_, _| unreachable!(),
        )
        .unwrap();
        assert!(safe.contains("dh none"));
        assert!(safe.contains("ncp-ciphers AES-256-GCM"));
        assert!(safe.contains("<http-proxy-user-pass>"));
    }

    #[test]
    fn inline_proxy_credentials_survive_preflight_snapshot_and_endpoint_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("client.ovpn");
        // Inline data can resemble directives; it must never become another endpoint.
        std::fs::write(
            &config,
            "client\ndev tun\nremote 192.0.2.1 443 tcp-client\n<http-proxy-user-pass>\nremote hidden.test 1194\nprivate-password\n</http-proxy-user-pass>\n",
        )
        .unwrap();
        let endpoints =
            crate::diagnostics::validate_config(&config, &crate::config::vpn::Protocol::OpenVpn)
                .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "192.0.2.1");
        assert!(endpoints[0].tcp);

        let runtime = temp.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let (frozen, _) = snapshot(&config, &runtime, None).unwrap();
        let remotes = super::super::openvpn::get_remotes_from_config(&frozen).unwrap();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].port, 443);
    }

    #[test]
    fn bounds_referenced_file_count_and_total_bytes() {
        let mut count = 0;
        let mut total = 0;
        for _ in 0..MAX_REFERENCED_FILES {
            account_reference(b"x", &mut count, &mut total).unwrap();
        }
        assert!(account_reference(b"x", &mut count, &mut total).is_err());

        let mut count = 0;
        let mut total = 0;
        account_reference(&vec![0; MAX_REFERENCED_BYTES], &mut count, &mut total).unwrap();
        assert!(account_reference(b"x", &mut count, &mut total).is_err());
    }

    #[test]
    fn snapshot_rejects_excessive_references_before_copying_them() {
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("ca.pem");
        std::fs::write(&ca, "certificate").unwrap();
        let config = temp.path().join("client.ovpn");
        let mut body = String::from("client\ndev tun\n");
        for _ in 0..=MAX_REFERENCED_FILES {
            body.push_str(&format!("ca {}\n", ca.display()));
        }
        std::fs::write(&config, body).unwrap();
        let runtime = temp.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        assert!(snapshot(&config, &runtime, None).is_err());
    }

    #[test]
    fn snapshots_external_credentials_and_does_not_parse_inline_keys_as_options() {
        let mut copied = Vec::new();
        let safe = sanitize("client\ndev tun\nsetenv CLIENT_CERT 0\nsetenv opt block-outside-dns\nca 'ca file.crt'\ntls-auth ta.key 1\n<key>\nPRIVATE KEY MATERIAL\n</key>\nremote localhost 1194", |path, index| {
            copied.push(path.to_owned()); Ok(PathBuf::from(format!("/run/private/input-{index}")))
        }).unwrap();
        assert_eq!(copied, ["ca file.crt", "ta.key"]);
        assert!(safe.contains("tls-auth /run/private/input-2 1"));
        assert!(!safe.contains("ta.key"));
    }
}
