mod wireguard;

use super::{Provider, WireguardProvider};
use crate::config::vpn::Protocol;
use base64::Engine;
use reqwest::blocking::Client;
use serde::Deserialize;

#[derive(serde::Serialize)]
struct AccessTokenRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
}

#[derive(Deserialize, Debug)]
struct User {
    devices: Vec<Device>,
}

#[derive(Deserialize, Debug)]
struct Login {
    user: User,
    token: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Device {
    name: String,
    pubkey: String,
    ipv4_address: ipnet::Ipv4Net,
    ipv6_address: ipnet::Ipv6Net,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Error {
    errno: u32,
    error: String,
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.pubkey,)
    }
}

/// MozillaVPN is a wrapper for Wireguard using OAuth authentication with Mozilla services
/// Supports Wireguard only
pub struct MozillaVPN {}

impl Provider for MozillaVPN {
    fn alias(&self) -> String {
        "mozilla".to_string()
    }

    fn alias_2char(&self) -> String {
        "mz".to_string()
    }

    fn default_protocol(&self) -> Protocol {
        Protocol::Wireguard
    }
}

impl MozillaVPN {
    const V2_URL: &'static str = "https://vpn.mozilla.org/api/v2";

    fn base_url(&self) -> &'static str {
        "https://vpn.mozilla.org/api/v1"
    }

    // TODO: Make this work with GUI - i.e. if terminal is not accessible
    /// Login with OAuth login (adapted from MozWire crate: https://github.com/NilsIrl/MozWire/blob/trunk/src/main.rs )
    fn get_login(&self, client: &Client) -> anyhow::Result<Login> {
        // no token given
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        use rand::RngCore;
        use sha2::Digest;
        let mut code_verifier_random = [0u8; 32];
        let mut os_rng = rand::rngs::OsRng::new().unwrap();
        os_rng.fill_bytes(&mut code_verifier_random);
        let mut code_verifier = [0u8; 43];
        BASE64_URL_SAFE_NO_PAD.encode_slice(code_verifier_random, &mut code_verifier)?;
        let mut code_challenge = String::with_capacity(43);
        BASE64_URL_SAFE_NO_PAD
            .encode_string(sha2::Sha256::digest(code_verifier), &mut code_challenge);

        use tiny_http::{Method, Server};

        let server = Server::http("127.0.0.1:0").unwrap();

        let login_url = format!(
            "{}/vpn/login/linux?code_challenge_method=S256&code_challenge={}&port={}",
            Self::V2_URL,
            code_challenge,
            server
                .server_addr()
                .to_ip()
                .expect("Failed to get SocketAddr")
                .port()
        );

        eprint!("Please visit {}.", login_url);

        match webbrowser::open(&login_url) {
            Ok(_) => eprint!(" Link opened in browser."),
            Err(_) => eprint!(" Failed to open link in browser, please visit it manually."),
        }
        eprintln!();

        let code;
        let code_url_regex = regex::Regex::new(r"\A/\?code=([0-9a-f]{80})\z").unwrap();
        for request in server.incoming_requests() {
            if *request.method() == Method::Get {
                if let Some(caps) = code_url_regex.captures(request.url()) {
                    code = caps.get(1).unwrap();
                    let response = client
                        .post(format!("{}/vpn/login/verify", Self::V2_URL))
                        .header("User-Agent", "Why do you need a user agent???")
                        .json(&AccessTokenRequest {
                            code: code.as_str(),
                            code_verifier: std::str::from_utf8(&code_verifier).unwrap(),
                        })
                        .send()
                        .unwrap();
                    return Ok(response.json::<Login>().unwrap());
                }
            }
        }
        unreachable!("Server closed without receiving code")
    }
}

fn validate_hostname(hostname: &str) -> bool {
    hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
}
