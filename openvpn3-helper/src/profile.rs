//! Compatibility handling for OpenVPN 2 profiles consumed by OpenVPN 3 Core.

pub(super) fn has_client_certificate_material(profile: &str) -> bool {
    let mut inline_data_block = None;
    for line in profile.lines() {
        match parse_profile_line(line, &mut inline_data_block) {
            Some(ProfileLine::InlineDataBlock(tag))
                if matches!(tag.as_str(), "cert" | "key" | "pkcs12") =>
            {
                return true;
            }
            Some(ProfileLine::Directive(line)) => {
                let directive = line.split_whitespace().next().unwrap_or_default();
                if matches!(
                    directive.to_ascii_lowercase().as_str(),
                    "cert" | "key" | "pkcs12" | "cryptoapicert" | "pkcs11-id"
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

pub(super) fn adapt_for_openvpn3(profile: &str) -> (String, bool) {
    if !has_directive(profile, "remote") {
        return (profile.to_string(), false);
    }

    let mut adapted = String::with_capacity(profile.len());
    let mut inline_data_block = None;
    let mut removed_ping_timer_rem = false;
    for line in profile.split_inclusive('\n') {
        if let Some(ProfileLine::Directive(option)) =
            parse_profile_line(line, &mut inline_data_block)
        {
            let directive = option.split_whitespace().next().unwrap_or_default();
            if directive.eq_ignore_ascii_case("ping-timer-rem") {
                removed_ping_timer_rem = true;
                continue;
            }
        }

        adapted.push_str(line);
    }

    (adapted, removed_ping_timer_rem)
}

fn has_directive(profile: &str, wanted: &str) -> bool {
    let mut inline_data_block = None;
    for line in profile.lines() {
        if let Some(ProfileLine::Directive(option)) =
            parse_profile_line(line, &mut inline_data_block)
            && option
                .split_whitespace()
                .next()
                .is_some_and(|directive| directive.eq_ignore_ascii_case(wanted))
        {
            return true;
        }
    }
    false
}

enum ProfileLine<'a> {
    Directive(&'a str),
    InlineDataBlock(String),
}

fn parse_profile_line<'a>(
    line: &'a str,
    inline_data_block: &mut Option<String>,
) -> Option<ProfileLine<'a>> {
    let line = line.trim();
    if let Some(block) = inline_data_block.as_ref() {
        if inline_tag(line).as_deref() == Some(&format!("/{block}")) {
            *inline_data_block = None;
        }
        return None;
    }
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    if let Some(tag) = inline_tag(line) {
        if !tag.starts_with('/') && is_inline_data_tag(&tag) {
            *inline_data_block = Some(tag.clone());
            return Some(ProfileLine::InlineDataBlock(tag));
        }
        return None;
    }
    Some(ProfileLine::Directive(line))
}

fn inline_tag(line: &str) -> Option<String> {
    let tag = line.strip_prefix('<')?.strip_suffix('>')?.trim();
    (!tag.is_empty()).then(|| tag.to_ascii_lowercase())
}

fn is_inline_data_tag(tag: &str) -> bool {
    matches!(
        tag,
        "askpass"
            | "auth-user-pass"
            | "ca"
            | "cert"
            | "crl-verify"
            | "dh"
            | "extra-certs"
            | "http-proxy-user-pass"
            | "key"
            | "pkcs12"
            | "secret"
            | "tls-auth"
            | "tls-crypt"
            | "tls-crypt-v2"
    )
}

#[cfg(test)]
mod tests {
    use super::{adapt_for_openvpn3, has_client_certificate_material};

    #[test]
    fn password_only_provider_profile_does_not_require_client_cert() {
        let profile =
            "client\nauth-user-pass\n<ca>\nserver CA\n</ca>\n<tls-crypt>\nkey\n</tls-crypt>\n";
        assert!(!has_client_certificate_material(profile));
    }

    #[test]
    fn detects_client_certificate_file_directives() {
        assert!(has_client_certificate_material(
            "cert client.crt\nkey client.key\n"
        ));
        assert!(has_client_certificate_material("pkcs12 client.p12\n"));
        assert!(has_client_certificate_material(
            "cryptoapicert CERTIFICATE\\\\MY\\\\VPN"
        ));
    }

    #[test]
    fn detects_inline_client_certificate_and_key_blocks() {
        assert!(has_client_certificate_material(
            "<cert>\nmaterial\n</cert>\n"
        ));
        assert!(has_client_certificate_material("<key>\nmaterial\n</key>\n"));
    }

    #[test]
    fn ignores_comments_that_mention_client_keys() {
        assert!(!has_client_certificate_material(
            "# cert unused.pem\n; key unused.pem\n<ca>\nserver CA\n</ca>\n"
        ));
    }

    #[test]
    fn strips_ping_timer_rem_when_a_remote_is_configured() {
        let profile = "client\nremote vpn.example 1194\nping-timer-rem\nresolv-retry infinite\n";
        let (adapted, removed) = adapt_for_openvpn3(profile);

        assert!(removed);
        assert!(adapted.contains("remote vpn.example 1194\n"));
        assert!(!adapted.lines().any(|line| line.trim() == "ping-timer-rem"));
        assert!(adapted.contains("resolv-retry infinite\n"));
    }

    #[test]
    fn keeps_ping_timer_rem_without_an_explicit_remote() {
        let profile = "client\nping-timer-rem\n";
        let (adapted, removed) = adapt_for_openvpn3(profile);

        assert!(!removed);
        assert_eq!(adapted, profile);
    }

    #[test]
    fn does_not_strip_option_text_from_inline_data_blocks() {
        let profile =
            "client\nremote vpn.example 1194\n<ca>\nping-timer-rem\n</ca>\nping-timer-rem\n";
        let (adapted, removed) = adapt_for_openvpn3(profile);

        assert!(removed);
        assert!(adapted.contains("<ca>\nping-timer-rem\n</ca>\n"));
        assert_eq!(
            adapted
                .lines()
                .filter(|line| line.trim() == "ping-timer-rem")
                .count(),
            1
        );
    }
}
