use anyhow::{Context, anyhow};
use ipnet::IpNet;
use log::{debug, warn};
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{char, line_ending, multispace0, multispace1},
    combinator::{all_consuming, eof, map, opt, peek},
    multi::{many_till, many0},
    sequence::{delimited, preceded, separated_pair, terminated},
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

// A key is alphanumeric, e.g., "Address"
fn parse_key<'a>(input: &'a str) -> IResult<&'a str, &'a str> {
    take_while1(|c: char| c.is_alphanumeric()).parse(input)
}

// A value is everything after '=' until the end of the line, trimmed.
// It also handles and removes inline comments.
fn parse_value<'a>(input: &'a str) -> IResult<&'a str, &'a str> {
    map(is_not("\n\r"), |s: &str| {
        s.split('#').next().unwrap_or("").trim()
    })
    .parse(input)
}

// A key-value pair is `Key = Value`
fn parse_key_value<'a>(input: &'a str) -> IResult<&'a str, (&'a str, &'a str)> {
    separated_pair(
        parse_key,
        delimited(multispace0, tag("="), multispace0),
        parse_value,
    )
    .parse(input)
}

// A section header is `[Name]`
fn parse_section_header<'a>(input: &'a str) -> IResult<&'a str, &'a str> {
    delimited(
        char('['),
        take_while1(|c: char| c.is_alphanumeric()),
        char(']'),
    )
    .parse(input)
}

// A line can be a comment, whitespace, or a key-value pair.
// We only want to keep the key-value pairs.
fn parse_line<'a>(input: &'a str) -> IResult<&'a str, Option<(&'a str, &'a str)>> {
    alt((
        map(parse_key_value, Some),
        // Comment or empty line
        map(
            (opt(preceded(char('#'), is_not("\n\r"))), line_ending),
            |_| None,
        ),
        // Handle last line without a line ending
        map(preceded(char('#'), is_not("\n\r")), |_| None),
    ))
    .parse(input)
}

// A section is a header followed by lines, until the next section or EOF.
fn parse_section<'a>(input: &'a str) -> IResult<&'a str, (&'a str, Vec<(&'a str, &'a str)>)> {
    let (input, name) = terminated(parse_section_header, multispace0).parse(input)?;

    // It's followed by many lines until the next section header or end of file
    let (input, lines) = many_till(
        parse_line,
        peek(alt((map(parse_section_header, |_| ()), map(eof, |_| ())))),
    )
    .parse(input)?;

    // Filter out the Nones (comments/whitespace) and collect the pairs
    let pairs = lines.0.into_iter().flatten().collect();

    Ok((input, (name, pairs)))
}

// A custom space/comment consumer.
// This will consume any amount of whitespace (including newlines) and full-line comments.
fn spc<'a>(input: &'a str) -> IResult<&'a str, ()> {
    map(
        many0(alt((
            // Consume one or more whitespace characters (including newlines)
            map(multispace1, |_| ()),
            // Consume a comment line
            map(
                terminated(
                    preceded(multispace0, preceded(char('#'), is_not("\n\r"))),
                    alt((line_ending, eof)),
                ),
                |_| (),
            ),
        ))),
        |_| (),
    )
    .parse(input)
}

// The main parser for the whole config file.
fn parse_config<'a>(input: &'a str) -> IResult<&'a str, Vec<(&'a str, Vec<(&'a str, &'a str)>)>> {
    all_consuming(many0(preceded(spc, parse_section))).parse(input)
    // all_consuming(many0(preceded(multispace0, parse_section))).parse(input)
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Address", deserialize_with = "de_vec_ipnet")]
    pub address: Vec<IpNet>,
    #[serde(rename = "DNS", deserialize_with = "de_vec_ipaddr")]
    pub dns: Option<Vec<IpAddr>>,
    #[serde(rename = "MTU")]
    pub mtu: Option<String>,
}

impl std::fmt::Debug for WireguardInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardInterface")
            .field("private_key", &"********".to_string())
            .field("address", &self.address)
            .field("dns", &self.dns)
            .finish()
    }
}

impl Display for WireguardConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // --- Interface Section ---
        writeln!(f, "[Interface]")?;
        writeln!(f, "PrivateKey = {}", self.interface.private_key)?;

        // Join addresses with ", " for a single line
        let addresses = self
            .interface
            .address
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        writeln!(f, "Address = {}", addresses)?;

        if let Some(mtu) = &self.interface.mtu {
            writeln!(f, "MTU = {}", mtu)?;
        }

        // Write each DNS server on a new line, which is idiomatic
        if let Some(dns_servers) = &self.interface.dns {
            for dns in dns_servers {
                writeln!(f, "DNS = {}", dns)?;
            }
        }

        // --- Peer Section ---
        writeln!(f, "\n[Peer]")?;
        writeln!(f, "PublicKey = {}", self.peer.public_key)?;

        let allowed_ips = self
            .peer
            .allowed_ips
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        writeln!(f, "AllowedIPs = {}", allowed_ips)?;

        writeln!(f, "Endpoint = {}", self.peer.endpoint)?;

        if let Some(keepalive) = &self.peer.keepalive {
            writeln!(f, "PersistentKeepalive = {}", keepalive)?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WireguardEndpoint {
    HostnameWithPort(String, u16),
    IpWithPort(SocketAddr),
}

impl WireguardEndpoint {
    pub fn ip_or_hostname(&self) -> String {
        match self {
            WireguardEndpoint::HostnameWithPort(host, _) => host.clone(),
            WireguardEndpoint::IpWithPort(addr) => addr.ip().to_string(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            WireguardEndpoint::HostnameWithPort(_, port) => *port,
            WireguardEndpoint::IpWithPort(addr) => addr.port(),
        }
    }
    pub fn resolve_ip(&self) -> anyhow::Result<IpAddr> {
        match self {
            WireguardEndpoint::HostnameWithPort(host, _) => {
                let addr = host
                    .to_socket_addrs()
                    .map_err(|_| anyhow!("Failed to resolve hostname"))?
                    .next()
                    .ok_or_else(|| anyhow!("No address found for hostname"))?;
                Ok(addr.ip())
            }
            WireguardEndpoint::IpWithPort(addr) => Ok(addr.ip()),
        }
    }

    pub fn is_ip(&self) -> bool {
        match self {
            WireguardEndpoint::HostnameWithPort(_, _) => false,
            WireguardEndpoint::IpWithPort(_) => true,
        }
    }
}

impl FromStr for WireguardEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            Ok(WireguardEndpoint::IpWithPort(addr))
        } else if let Some((host, port)) = s.rsplit_once(':') {
            // Use rsplit_once for IPv6 addresses
            let port = port.parse::<u16>().map_err(|_| anyhow!("Invalid port"))?;
            let host = host.trim_matches(|c| c == '[' || c == ']').to_string(); // Handle [ipv6:add:ress]
            Ok(WireguardEndpoint::HostnameWithPort(host.to_string(), port))
        } else {
            Err(anyhow!("Invalid Wireguard endpoint format"))
        }
    }
}

impl Display for WireguardEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireguardEndpoint::HostnameWithPort(host, port) => write!(f, "{host}:{port}"),
            WireguardEndpoint::IpWithPort(addr) => write!(f, "{addr}"),
        }
    }
}

impl Serialize for WireguardEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WireguardEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<WireguardEndpoint>()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Debug, Serialize, PartialEq, Eq)]
pub struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "AllowedIPs", deserialize_with = "de_vec_ipnet")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(rename = "Endpoint")]
    pub endpoint: WireguardEndpoint,
    #[serde(rename = "PersistentKeepalive")]
    pub keepalive: Option<String>,
}

#[derive(Deserialize, Debug, Serialize, PartialEq, Eq)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    pub interface: WireguardInterface,
    #[serde(rename = "Peer")]
    pub peer: WireguardPeer,
}

impl FromStr for WireguardConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (remaining, parsed_sections) = parse_config(s.trim())
            .map_err(|e| anyhow!("Failed to parse Wireguard config: {}", e))?;

        if !remaining.trim().is_empty() {
            return Err(anyhow!("Unexpected trailing data in config: {}", remaining));
        }

        let mut interface = None;
        let mut peer = None;

        for (section_name, kvs) in parsed_sections {
            match section_name {
                "Interface" => {
                    let mut private_key = None;
                    let mut addresses = Vec::new();
                    let mut dns_servers = Vec::new();
                    let mut mtu = None;

                    for (key, value) in kvs {
                        match key {
                            "PrivateKey" => private_key = Some(value.to_string()),
                            "Address" => {
                                addresses.extend(value.split(',').map(|s| s.trim().to_string()))
                            }
                            "DNS" => {
                                dns_servers.extend(value.split(',').map(|s| s.trim().to_string()))
                            }
                            "MTU" => mtu = Some(value.to_string()),
                            _ => warn!("Unknown key in [Interface] section: {}", key),
                        }
                    }

                    let parsed_addresses = addresses
                        .iter()
                        .map(|a| a.parse::<IpNet>())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse Address field")?;

                    let parsed_dns = dns_servers
                        .iter()
                        .map(|d| d.parse::<IpAddr>())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse DNS field")?;

                    interface = Some(WireguardInterface {
                        private_key: private_key
                            .context("Missing PrivateKey in [Interface] section")?,
                        address: parsed_addresses,
                        dns: if parsed_dns.is_empty() {
                            None
                        } else {
                            Some(parsed_dns)
                        },
                        mtu,
                    });
                }
                "Peer" => {
                    let mut public_key = None;
                    let mut allowed_ips = Vec::new();
                    let mut endpoint = None;
                    let mut keepalive = None;

                    for (key, value) in kvs {
                        match key {
                            "PublicKey" => public_key = Some(value.to_string()),
                            "AllowedIPs" => {
                                allowed_ips.extend(value.split(',').map(|s| s.trim().to_string()))
                            }
                            "Endpoint" => endpoint = Some(value.to_string()),
                            "PersistentKeepalive" => keepalive = Some(value.to_string()),
                            _ => warn!("Unknown key in [Peer] section: {}", key),
                        }
                    }

                    let parsed_allowed_ips = allowed_ips
                        .iter()
                        .map(|a| a.parse::<IpNet>())
                        .collect::<Result<Vec<_>, _>>()
                        .context("Failed to parse AllowedIPs field")?;

                    let parsed_endpoint = endpoint
                        .context("Missing Endpoint in [Peer] section")?
                        .parse::<WireguardEndpoint>()
                        .context("Failed to parse Endpoint field")?;

                    peer = Some(WireguardPeer {
                        public_key: public_key.context("Missing PublicKey in [Peer] section")?,
                        allowed_ips: parsed_allowed_ips,
                        endpoint: parsed_endpoint,
                        keepalive,
                    });
                }
                _ => warn!("Unknown section in config: {}", section_name),
            }
        }

        Ok(WireguardConfig {
            interface: interface.context("Missing [Interface] section in config")?,
            peer: peer.context("Missing [Peer] section in config")?,
        })
    }
}

pub fn de_vec_ipnet<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // serde::de::value::StringDeserializer::deserialize_string(deserializer)?;
    let raw = String::deserialize(deserializer)?;
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpNet>())
        .collect::<Result<Vec<IpNet>, ipnet::AddrParseError>>()
    {
        Ok(x) => Ok(x),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpNet deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_vec_ipaddr<'de, D>(deserializer: D) -> Result<Option<Vec<IpAddr>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = match String::deserialize(deserializer) {
        Ok(s) => s,
        Err(e) => {
            debug!("Missing optional DNS field in Wireguard config - serde");
            debug!("serde: {e:?}");
            return Ok(None);
        }
    };
    debug!("Deserializing: {raw} to Vec<IpAddr>");
    let strings = raw.split(',');
    match strings
        .map(|x| x.trim().parse::<IpAddr>())
        .collect::<Result<Vec<IpAddr>, _>>()
    {
        Ok(x) => Ok(Some(x)),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}

pub fn de_socketaddr<'de, D>(deserializer: D) -> Result<std::net::SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    match raw.trim().to_socket_addrs() {
        Ok(mut x) => Ok(x.next().unwrap()),
        Err(x) => Err(serde::de::Error::custom(anyhow!(
            "Wireguard IpAddr deserialisation error: {:?}",
            x
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // The config from the prompt, with dummy keys and an IPv4 endpoint for simplicity.
    const TEST_CONFIG_DUPLICATE_DNS: &str = r#"
# This is a comment
[Interface]
# Add IPv6 address alongside IPv4
Address = 10.200.200.2/32, fd42:42:42::2/128
PrivateKey = dGhpcyBpcyBhIGR1bW15IHByaXZhdGUga2V5ISEhISEhIQ==
DNS = 8.8.8.8
# Uncomment the IPv6 DNS server for full IPv6 support
DNS = 2001:4860:4860::8888
MTU = 1420

[Peer]
PublicKey = dGhpcyBpcyBhIGR1bW15IHB1YmxpYyBrZXkhISEhISEhIQ==
Endpoint = 199.50.100.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"#;

    // A second config with an IPv6 endpoint in brackets
    const TEST_CONFIG_IPV6_ENDPOINT: &str = r#"
[Interface]
Address = 10.0.0.5/24
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
Endpoint = [2d01:4e9:c013:c690::1]:51820
AllowedIPs = 0.0.0.0/0
"#;

    #[test]
    fn test_parse_config_with_duplicate_dns() {
        let config = WireguardConfig::from_str(TEST_CONFIG_DUPLICATE_DNS).unwrap();

        // Check Interface
        assert_eq!(
            config.interface.private_key,
            "dGhpcyBpcyBhIGR1bW15IHByaXZhdGUga2V5ISEhISEhIQ=="
        );
        assert_eq!(config.interface.address.len(), 2);
        assert_eq!(
            config.interface.address[0],
            "10.200.200.2/32".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            config.interface.address[1],
            "fd42:42:42::2/128".parse::<IpNet>().unwrap()
        );

        // This is the main check for the fix
        let dns_servers = config.interface.dns.unwrap();
        assert_eq!(dns_servers.len(), 2);
        assert_eq!(dns_servers[0], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(
            dns_servers[1],
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );

        // Check Peer
        assert_eq!(config.peer.endpoint.to_string(), "199.50.100.1:51820");
        assert_eq!(config.peer.allowed_ips.len(), 2);
        assert_eq!(config.peer.keepalive, Some("25".to_string()));
    }

    #[test]
    fn test_parse_config_with_ipv6_endpoint() {
        let config = WireguardConfig::from_str(TEST_CONFIG_IPV6_ENDPOINT).unwrap();
        let expected_socket_addr: SocketAddr = "[2d01:4e9:c013:c690::1]:51820".parse().unwrap();
        assert_eq!(
            config.peer.endpoint,
            WireguardEndpoint::IpWithPort(expected_socket_addr)
        );
        assert_eq!(
            config.peer.endpoint.to_string(),
            "[2d01:4e9:c013:c690::1]:51820"
        );
    }

    #[test]
    fn test_tostring_format() {
        let config = WireguardConfig::from_str(TEST_CONFIG_DUPLICATE_DNS).unwrap();
        let output = config.to_string();

        // Check for key components in the output string
        assert!(output.starts_with("[Interface]"));
        assert!(output.contains("Address = 10.200.200.2/32, fd42:42:42::2/128"));
        assert!(output.contains("\n[Peer]\n"));
        assert!(output.contains("PersistentKeepalive = 25"));

        // Crucially, check that both DNS entries were written as separate lines
        let dns_line_count = output
            .lines()
            .filter(|line| line.starts_with("DNS = "))
            .count();
        assert_eq!(dns_line_count, 2);
        assert!(output.contains("DNS = 8.8.8.8"));
        assert!(output.contains("DNS = 2001:4860:4860::8888"));
    }

    #[test]
    fn test_parser_and_tostring_roundtrip() {
        // 1. Parse the original string into a config struct
        let original_config = WireguardConfig::from_str(TEST_CONFIG_DUPLICATE_DNS).unwrap();

        // 2. Convert that struct back into a new string
        let generated_string = original_config.to_string();

        // 3. Parse the *newly generated* string
        let roundtrip_config = WireguardConfig::from_str(&generated_string).unwrap();

        // 4. The struct from the original string should be identical to the one
        //    from the generated string. This proves that to_string() creates a valid
        //    and complete representation of the config data.
        assert_eq!(original_config, roundtrip_config);

        // Also test the other config
        let original_config_2 = WireguardConfig::from_str(TEST_CONFIG_IPV6_ENDPOINT).unwrap();
        let generated_string_2 = original_config_2.to_string();
        let roundtrip_config_2 = WireguardConfig::from_str(&generated_string_2).unwrap();
        assert_eq!(original_config_2, roundtrip_config_2);
    }
}
