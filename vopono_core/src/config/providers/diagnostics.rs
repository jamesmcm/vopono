//! Public, credential-free compatibility checks. Uses the same schemas as sync.
use super::VpnProvider;
use crate::diagnostics::{Diagnostic, DiagnosticCode, DiagnosticState};
use serde::Serialize;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct CatalogueServer {
    pub id: String,
    pub addresses: Vec<IpAddr>,
    pub public_key: Option<String>,
}

pub fn public_catalogue(
    provider: &VpnProvider,
    timeout: Duration,
) -> anyhow::Result<Option<Vec<CatalogueServer>>> {
    let url = match provider {
        VpnProvider::Mullvad => "https://api.mullvad.net/www/relays/wireguard/",
        VpnProvider::PrivateInternetAccess => {
            "https://serverlist.piaservers.net/vpninfo/servers/v6"
        }
        _ => return Ok(None),
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client.get(url).send()?.error_for_status()?;
    let mut body = String::new();
    response
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut body)?;
    anyhow::ensure!(
        body.len() <= 8 * 1024 * 1024,
        "Public catalogue exceeded size limit"
    );
    parse_catalogue(provider, &body).map(Some)
}

pub fn parse_catalogue(provider: &VpnProvider, body: &str) -> anyhow::Result<Vec<CatalogueServer>> {
    let servers = match provider {
        VpnProvider::Mullvad => super::mullvad::diagnostic_catalogue(body)?,
        VpnProvider::PrivateInternetAccess => super::pia::diagnostic_catalogue(body)?,
        _ => anyhow::bail!("No public catalogue adapter for this provider"),
    };
    anyhow::ensure!(
        !servers.is_empty(),
        "Public catalogue contains no active servers"
    );
    anyhow::ensure!(
        servers
            .iter()
            .all(|s| !s.id.is_empty() && !s.addresses.is_empty()),
        "Invalid public server record"
    );
    Ok(servers)
}

/// Endpoint identity is stronger than a file's alias; absence is authoritative only for literal IPs.
pub fn compare_endpoint(
    servers: &[CatalogueServer],
    ips: &[IpAddr],
    literal: bool,
    public_key: Option<&str>,
) -> Diagnostic {
    let found = servers
        .iter()
        .find(|s| s.addresses.iter().any(|ip| ips.contains(ip)));
    match found {
        Some(server)
            if public_key
                .zip(server.public_key.as_deref())
                .is_some_and(|(a, b)| a != b) =>
        {
            Diagnostic::new(
                DiagnosticCode::ProviderCatalogue,
                DiagnosticState::Fail,
                "Endpoint exists but the provider's WireGuard public key differs",
                Some(
                    "Run vopono sync for this provider and protocol; do not rotate client keys automatically",
                ),
            )
        }
        Some(_) => Diagnostic::new(
            DiagnosticCode::ProviderCatalogue,
            DiagnosticState::Pass,
            "Configured endpoint is in the current public catalogue",
            None,
        ),
        None => Diagnostic::new(
            DiagnosticCode::ProviderCatalogue,
            if literal {
                DiagnosticState::Fail
            } else {
                DiagnosticState::Warning
            },
            "Configured endpoint was not found in the current public catalogue; DNS rotation may affect hostname comparisons",
            Some("Run vopono sync for this provider and protocol, then select an available server"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mullvad_fixture_uses_sync_schema_and_checks_key_changes() {
        let servers =
            parse_catalogue(&VpnProvider::Mullvad, include_str!("fixtures/mullvad.json")).unwrap();
        assert_eq!(servers.len(), 1);
        let ips = vec!["192.0.2.1".parse().unwrap()];
        assert_eq!(
            compare_endpoint(&servers, &ips, true, Some("changed")).state,
            DiagnosticState::Fail
        );
        assert_eq!(
            compare_endpoint(&servers, &ips, true, None).state,
            DiagnosticState::Pass
        );
        assert!(parse_catalogue(&VpnProvider::Mullvad, "[]").is_err());
        assert!(parse_catalogue(&VpnProvider::Mullvad, "[{\"hostname\":\"x\"}]").is_err());
    }
    #[test]
    fn pia_signed_envelope_uses_first_line_without_authentication() {
        let servers = parse_catalogue(
            &VpnProvider::PrivateInternetAccess,
            include_str!("fixtures/pia.txt"),
        )
        .unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "test");
        assert_eq!(
            compare_endpoint(&servers, &["192.0.2.99".parse().unwrap()], false, None).state,
            DiagnosticState::Warning
        );
    }
}
