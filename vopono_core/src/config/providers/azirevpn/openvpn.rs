use super::AzireVPN;
use super::OpenVpnProvider;
use crate::config::providers::UiClient;
use crate::config::vpn::OpenVpnProtocol;
use crate::util::delete_all_files_in_dir;
use log::{debug, info};
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

impl OpenVpnProvider for AzireVPN {
    // AzireVPN details: https://www.azirevpn.com/docs/servers
    // TODO: Add IPv6 DNS
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        Some(vec![
            IpAddr::V4(Ipv4Addr::new(91, 231, 153, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 211, 0, 2)),
        ])
    }

    fn prompt_for_auth(&self, uiclient: &dyn UiClient) -> anyhow::Result<(String, String)> {
        self.request_userpass(uiclient)
    }

    fn auth_file_path(&self) -> anyhow::Result<Option<PathBuf>> {
        Ok(Some(self.openvpn_dir()?.join("auth.txt")))
    }

    fn create_openvpn_config(&self, uiclient: &dyn UiClient) -> anyhow::Result<()> {
        let protocol = uiclient.get_configuration_choice(&OpenVpnProtocol::default())?;
        // TODO: Allow port selection, TLS version selection
        let openvpn_dir = self.openvpn_dir()?;
        let country_map = crate::util::country_map::code_to_country_map();
        create_dir_all(&openvpn_dir)?;
        delete_all_files_in_dir(&openvpn_dir)?;
        for alias in self.server_aliases() {
            let url = format!("https://www.azirevpn.com/cfg/openvpn/generate?country={}&os=linux-cli&nat=1&port=random&protocol={}&tls=gcm&keys=0", alias, protocol);
            let file = reqwest::blocking::get(&url)?.bytes()?;

            let file_contents = std::str::from_utf8(&file)?;
            let file_contents = file_contents
                .split('\n')
                .filter(|&x| !(x.starts_with("up ") || x.starts_with("down ")))
                .collect::<Vec<&str>>()
                .join("\n");

            let country = country_map
                .get(&alias[0..2])
                .expect("Could not map country to name");
            let filename = format!("{}-{}.ovpn", country, alias);
            debug!("Writing file: {}", filename);
            let mut outfile =
                File::create(openvpn_dir.join(filename.to_lowercase().replace(' ', "_")))?;
            write!(outfile, "{}", file_contents)?;
        }

        // Write OpenVPN credentials file
        let (user, pass) = self.prompt_for_auth(uiclient)?;
        let auth_file = self.auth_file_path()?;
        if auth_file.is_some() {
            let mut outfile = File::create(auth_file.unwrap())?;
            write!(outfile, "{}\n{}", user, pass)?;
            info!(
                "AzireVPN OpenVPN config written to {}",
                openvpn_dir.display()
            );
        }
        Ok(())
    }
}
