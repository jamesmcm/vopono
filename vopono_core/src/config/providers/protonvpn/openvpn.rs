use super::ProtonVPN;
use super::{ConfigurationChoice, OpenVpnProvider};
use crate::config::providers::{Input, Password, UiClient};
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use anyhow::anyhow;
use log::{debug, info};
use regex::Regex;
use reqwest::Url;
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use std::fmt::Display;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zip::ZipArchive;

impl ProtonVPN {
    fn build_url(
        &self,
        category: &ConfigType,
        tier: &Tier,
        protocol: &OpenVpnProtocol,
    ) -> anyhow::Result<Url> {
        let cat = if tier == &Tier::Free {
            "Server".to_string()
        } else {
            category.url_part()
        };
        Ok(Url::parse(&format!(
            "https://account.protonvpn.com/api/vpn/config?Category={}&Tier={}&Platform=Linux&Protocol={}",
            cat,
            tier.url_part(),
            protocol
        ))?)
    }

    pub fn parse_auth_cookie(
        uiclient: &dyn UiClient,
    ) -> anyhow::Result<(&'static str, &'static str)> {
        let auth_pattern = Box::leak(Box::new(Regex::new(
            r"^[;\s\t]*AUTH-([^=\t:;\s]+)[\s\t=: ]+([^\s\t;=]+)[;\s\t]*$",
        )?));

        let raw_auth_cookie  = Box::leak(uiclient.get_input(Input {
            prompt: "Please log-in at https://account.protonvpn.com/dashboard and then visit https://account.protonvpn.com/account and copy the value of the cookie of the form \"AUTH-xxx=yyy\" where xxx is equal to the value of the \"x-pm-uid\" request header, in the request from your browser's network request inspector (check the request it makes to https://account.protonvpn.com/api/vpn for example). Note there may be multiple AUTH-xxx=yyy request headers, copy the one where xxx is equal to the value of the x-pm-uid header.".to_owned(),
             validator: Some(Box::new(|s: &String| if auth_pattern.is_match(s) {
                Ok(())
            } else {
                Err("The authorization code must be in the format AUTH-xxx=yyy, AUTH-xxx: yyy, or AUTH-xxx\tyyy, with an optional semicolon at the end".to_owned())
            }
                ))
             })?.into_boxed_str());

        debug!("Using AUTH cookie: {}", &raw_auth_cookie);

        // Extract the key and value parts and standardize to AUTH-xxx=yyy format
        let maybe_captures = auth_pattern.captures(raw_auth_cookie);
        let uid = maybe_captures
            .as_ref()
            .and_then(|c| c.get(1))
            .ok_or(anyhow!("Failed to parse uid from auth cookie"))?;

        info!(
            "x-pm-uid should be {} according to AUTH cookie: {}",
            uid.as_str(),
            raw_auth_cookie
        );
        let value = maybe_captures
            .and_then(|c| c.get(2))
            .ok_or(anyhow!("Failed to parse cookie value from auth cookie"))?;

        let leaked_uid = Box::leak(uid.as_str().to_owned().into_boxed_str());

        // Create the standardized form
        let auth_cookie =
            Box::leak(format!("AUTH-{}={}", uid.as_str(), value.as_str()).into_boxed_str());
        debug!("Parsed AUTH cookie: {}", &auth_cookie);
        Ok((auth_cookie, leaked_uid))
    }
}
impl OpenVpnProvider for ProtonVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        // None will use DNS from OpenVPN headers if present
        None
        // TODO: ProtonVPN DNS servers do not respond
        // let path = self.openvpn_dir().ok()?.join("dns.txt");
        // let ip_str = match std::fs::read_to_string(&path) {
        //     Err(x) => {
        //         error!("Failed to read DNS file: {}: {:?}", path.display(), x);
        //         return None;
        //     }
        //     Ok(x) => x,
        // };

        // let ip = match Ipv4Addr::from_str(&ip_str.trim()) {
        //     Err(x) => {
        //         error!("Failed to convert IP string: {}: {:?}", ip_str, x);
        //         return None;
        //     }
        //     Ok(x) => x,
        // };

        // Some(vec![IpAddr::V4(ip)])
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        let username = uiclient.get_input(Input {
            prompt:
                "ProtonVPN OpenVPN username (see: https://account.protonvpn.com/account#openvpn ) - add +pmp suffix if using --port-forwarding - note not all servers support this feature"
                    .to_string(),
            validator: None,
        })?;

        let password = uiclient.get_password(Password {
            prompt: "OpenVPN Password".to_string(),
            confirm: true,
        })?;
        Ok((username.trim().to_string(), password.trim().to_string()))
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        let code_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        let tier = Tier::index_to_variant(uiclient.get_configuration_choice(&Tier::default())?);
        let config_choice = if tier != Tier::Free {
            ConfigType::index_to_variant(uiclient.get_configuration_choice(&ConfigType::default())?)
        } else {
            // Dummy as not used for Free
            ConfigType::Standard
        };
        let protocol = OpenVpnProtocol::index_to_variant(
            uiclient.get_configuration_choice(&OpenVpnProtocol::default())?,
        );

        // Create the standardized form
        let (auth_cookie, uid) = Self::parse_auth_cookie(uiclient)?;

        let url = self.build_url(&config_choice, &tier, &protocol)?;

        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static(auth_cookie));

        headers.insert(
            HeaderName::from_static("x-pm-uid"),
            HeaderValue::from_static(uid),
        );
        let client = reqwest::blocking::Client::new();

        let zipfile = client.get(url).headers(headers).send()?;

        let mut zip = ZipArchive::new(Cursor::new(zipfile.bytes()?))?;
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir)?;
        for i in 0..zip.len() {
            // Modify auth line for config
            // Write to config dir
            let mut file_contents: Vec<u8> = Vec::with_capacity(2048);
            let mut file = zip.by_index(i).unwrap();
            file.read_to_end(&mut file_contents)?;

            let file_contents = std::str::from_utf8(&file_contents)?;
            let file_contents = file_contents
                .split('\n')
                .filter(|&x| !(x.starts_with("up ") || x.starts_with("down ")))
                .collect::<Vec<&str>>()
                .join("\n");

            // TODO: sanitized_name is now deprecated but there is not a simple alternative
            #[allow(deprecated)]
            let filename = if let Some("ovpn") = file
                .sanitized_name()
                .extension()
                .map(|x| x.to_str().expect("Could not convert OsStr"))
            {
                // Also handle server case from free servers
                let mut hostname: Option<String> = None;
                let mut code = file.name().split('.').next().unwrap();
                if code.contains("free") {
                    // Free case
                    let mut iter_split = code.split('-');
                    let fcode = iter_split.next().unwrap();
                    hostname = Some(iter_split.next().unwrap().to_owned());
                    code = fcode;
                } else if code.contains('-') {
                    // SecureCore
                    let mut iter_split = code.split('-');
                    let start = iter_split.next().unwrap();
                    let end = iter_split.next().unwrap();
                    let number = iter_split.next().unwrap();
                    hostname = Some(format!("{start}_{number}"));
                    code = end;
                }
                let country = code_map
                    .get(code)
                    .unwrap_or_else(|| panic!("Could not find code in map: {code}"));
                let host_str = if let Some(host) = hostname {
                    format!("-{host}")
                } else {
                    String::new()
                };
                format!("{}-{}{}.ovpn", country, code, &host_str)
            } else {
                file.name().to_string()
            };

            debug!("Reading file: {}", file.name());
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{file_contents}")?;
        }

        // TODO: ProtonVPN DNS servers do not connect
        // Write DNS file (protocol dependent)
        // let dns_string = match protocol {
        //     OpenVpnProtocol::TCP => "10.7.7.1",
        //     OpenVpnProtocol::UDP => "10.8.8.1",
        // };

        // let mut dns_file = File::create(self.openvpn_dir()?.join("dns.txt"))?;
        // write!(dns_file, "{}", dns_string)?;

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{user}\n{pass}")?;
            info!(
                "ProtonVPN OpenVPN config written to {}",
                openvpn_dir.display()
            );
        }
        Ok(())
    }
}

#[derive(EnumIter, PartialEq, Default)]
enum Tier {
    Plus,
    #[default]
    Free,
}

impl Tier {
    fn url_part(&self) -> String {
        match self {
            Self::Plus => "2".to_string(),
            Self::Free => "0".to_string(),
        }
    }
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Plus => "Plus",
            Self::Free => "Free",
        };
        write!(f, "{s}")
    }
}

impl ConfigurationChoice for Tier {
    fn prompt(&self) -> String {
        "Choose your ProtonVPN account tier".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().map(|x| x.description().unwrap()).collect())
    }

    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::Plus => "Plus Account provides more VPN servers and SecureCore configuration",
                Self::Free => "Free VPN servers only",
            }
            .to_string(),
        )
    }
}

#[derive(EnumIter, PartialEq, Default)]
enum ConfigType {
    SecureCore,
    #[default]
    Standard,
}

impl ConfigType {
    fn url_part(&self) -> String {
        match self {
            Self::SecureCore => "SecureCore".to_string(),
            Self::Standard => "Country".to_string(),
        }
    }
    fn index_to_variant(index: usize) -> Self {
        Self::iter().nth(index).expect("Invalid index")
    }
}

impl Display for ConfigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SecureCore => "SecureCore",
            Self::Standard => "Standard",
        };
        write!(f, "{s}")
    }
}

impl ConfigurationChoice for ConfigType {
    fn prompt(&self) -> String {
        "Please choose the set of OpenVPN configuration files you wish to install".to_string()
    }

    fn all_names(&self) -> Vec<String> {
        Self::iter().map(|x| format!("{x}")).collect()
    }
    fn all_descriptions(&self) -> Option<Vec<String>> {
        Some(Self::iter().map(|x| x.description().unwrap()).collect())
    }
    fn description(&self) -> Option<String> {
        Some(
            match self {
                Self::SecureCore => {
                    "Connect via SecureCore bridge for additional security (Plus accounts only)"
                }
                Self::Standard => {
                    "Standard OpenVPN connection (available servers depend on account tier)"
                }
            }
            .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module

    #[derive(Debug)]
    struct MockUiClient {
        input_to_provide: String,
        // We can add flags here to simulate errors from get_input if needed,
        // but for these tests, we primarily care about the validation and parsing
        // based on the input_to_provide.
    }

    impl UiClient for MockUiClient {
        fn get_input(&self, input: Input) -> anyhow::Result<String> {
            // Check if a validator is provided, as it is in parse_auth_cookie
            if let Some(validator) = &input.validator {
                // Run the validator provided by the function under test
                match validator(&self.input_to_provide) {
                    Ok(_) => Ok(self.input_to_provide.clone()),
                    Err(msg) => Err(anyhow!("Input validation failed: {}", msg)),
                }
            } else {
                // No validator provided, just return the input
                Ok(self.input_to_provide.clone())
            }
        }

        // Implement other methods as unimplemented! or return dummy values
        // as they are not called by the function under test.
        fn get_configuration_choice(
            &self,
            _conf_choice: &dyn ConfigurationChoice,
        ) -> anyhow::Result<usize> {
            unimplemented!("get_configuration_choice not needed for this test")
        }

        fn get_bool_choice(
            &self,
            _bool_choice: crate::config::providers::BoolChoice,
        ) -> anyhow::Result<bool> {
            unimplemented!("get_bool_choice not needed for this test")
        }

        fn get_input_numeric_u16(
            &self,
            _input: crate::config::providers::InputNumericu16,
        ) -> anyhow::Result<u16> {
            unimplemented!("get_input_numeric_u16 not needed for this test")
        }

        fn get_password(&self, _password: Password) -> anyhow::Result<String> {
            unimplemented!("get_password not needed for this test")
        }
    }

    // Helper function to run a test case
    fn run_test(input: &str) -> anyhow::Result<(&'static str, &'static str)> {
        let mock_client = MockUiClient {
            input_to_provide: input.to_string(),
        };
        ProtonVPN::parse_auth_cookie(&mock_client)
    }

    // --- Positive Test Cases ---

    #[test]
    fn test_basic_equal_separator() {
        let result = run_test("AUTH-abc=123");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-abc=123");
        assert_eq!(uid, "abc");
    }

    #[test]
    fn test_basic_tab_separator() {
        let result = run_test("AUTH-abc\t123");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-abc=123");
        assert_eq!(uid, "abc");
    }

    #[test]
    fn test_basic_colon_separator() {
        let result = run_test("AUTH-abc: 123");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-abc=123");
        assert_eq!(uid, "abc");
    }

    #[test]
    fn test_basic_equal_separator_semicolon() {
        let result = run_test("AUTH-def=456;");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-def=456");
        assert_eq!(uid, "def");
    }

    #[test]
    fn test_basic_tab_separator_semicolon() {
        let result = run_test("AUTH-def\t456;");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-def=456");
        assert_eq!(uid, "def");
    }

    #[test]
    fn test_basic_colon_separator_semicolon() {
        let result = run_test("AUTH-def: 456;");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-def=456");
        assert_eq!(uid, "def");
    }

    #[test]
    fn test_no_space_after_colon() {
        let result = run_test("AUTH-id:content");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-id=content");
        assert_eq!(uid, "id");
    }

    #[test]
    fn test_space_around_equal() {
        let result = run_test("AUTH-name = data");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-name=data");
        assert_eq!(uid, "name");
    }

    #[test]
    fn test_multiple_spaces_as_separator() {
        // The regex [\s\t=: ]+ allows multiple spaces/tabs/=/
        let result = run_test("AUTH-token   secret");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-token=secret");
        assert_eq!(uid, "token");
    }

    #[test]
    fn test_multiple_spaces_around_equal() {
        let result = run_test("AUTH-profile  =  info");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-profile=info");
        assert_eq!(uid, "profile");
    }

    #[test]
    fn test_multiple_spaces_after_colon() {
        let result = run_test("AUTH-session:  data");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-session=data");
        assert_eq!(uid, "session");
    }

    #[test]
    fn test_uid_with_hyphens_and_underscores() {
        let result = run_test("AUTH-user_id-123=some_value-with-hyphens");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-user_id-123=some_value-with-hyphens");
        assert_eq!(uid, "user_id-123");
    }

    #[test]
    fn test_value_with_special_chars_allowed() {
        // Value can contain chars like :, +, etc. as long as not space, tab, semicolon
        let result = run_test("AUTH-key=value:and:colons+plus");
        assert!(result.is_ok());
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-key=value:and:colons+plus");
        assert_eq!(uid, "key");
    }

    // --- Negative Test Cases (Should fail validation in MockUiClient) ---

    #[test]
    fn test_negative_missing_hyphen() {
        let result = run_test("AUTHxyz=123");
        assert!(result.is_err());
        // Optionally check the error message if needed
        // assert!(result.unwrap_err().to_string().contains("validation failed"));
    }

    #[test]
    fn test_negative_incomplete_prefix() {
        let result = run_test("AUTH-");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_empty_uid() {
        // Regex `([^=\t:;\s]+)` requires at least one char for UID
        let result = run_test("AUTH- =123");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_lowercase_auth() {
        let result = run_test("auth-lower=123");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_wrong_prefix() {
        let result = run_test("PREFIX-abc=123");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_missing_separator_and_value() {
        let result = run_test("AUTH-abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_empty_value_equal() {
        // Regex `([^\s\t;]+)` requires at least one char for value
        let result = run_test("AUTH-user=");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_empty_value_colon() {
        // Regex `([^\s\t;]+)` requires at least one char for value
        let result = run_test("AUTH-access: "); // Note space after colon is part of separator
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_newline_in_value() {
        let result = run_test("AUTH-key=\n789");
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-key=789");
        assert_eq!(uid, "key");
    }

    #[test]
    fn test_crlf_in_value() {
        let result = run_test("AUTH-account=\r\ndetails");
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-account=details");
        assert_eq!(uid, "account");
    }

    #[test]
    fn test_negative_space_in_uid() {
        let result = run_test("AUTH-user id=value");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_space_in_value() {
        // Value group `([^\s\t;]+)` does not allow space
        let result = run_test("AUTH-uid=value part");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_tab_in_value() {
        // Value group `([^\s\t;]+)` does not allow tab
        let result = run_test("AUTH-uid=value\tpart");
        assert!(result.is_err());
    }

    #[test]
    fn test_negative_semicolon_in_value() {
        // Value group `([^\s\t;]+)` does not allow semicolon
        let result = run_test("AUTH-uid=value;part");
        assert!(result.is_err());
    }

    #[test]
    fn test_trailing_space_after_semicolon() {
        // Regex requires `$` immediately after optional `;`
        let result = run_test("AUTH-uid=value; ");
        let (cookie, uid) = result.unwrap();
        assert_eq!(cookie, "AUTH-uid=value");
        assert_eq!(uid, "uid");
    }

    #[test]
    fn test_negative_no_separator() {
        let result = run_test("AUTH-uidvalue");
        assert!(result.is_err());
    }
}
