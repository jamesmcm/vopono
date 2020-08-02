use super::{ConfigurationChoice, OpenVpnProvider, Provider};
use crate::vpn::OpenVpnProtocol;
use anyhow::Context;
use serde::Deserialize;
use std::fs::create_dir_all;
use std::fs::File;
use std::include_str;
use std::io::{Cursor, Write};
use std::net::IpAddr;

pub struct TigerVPN {}

#[derive(Deserialize)]
struct Server {
    country_name: String,
    country_alias: String,
    hostname: String,
}

impl TigerVPN {
    fn get_default_openvpn_settings() -> Vec<&'static str> {
        vec![
            "client",
            "pull",
            "comp-lzo adaptive",
            "ca ca.crt",
            "dev tun",
            "tls-client",
            "script-security 2",
            "cipher AES-256-CBC",
            "mute 10",
            "route-delay 5",
            "redirect-gateway def1",
            "resolv-retry infinite",
            "persist-key",
            "persist-tun",
            "remote-cert-tls server",
            "mssfix",
        ]
    }

    fn get_serverlist() -> anyhow::Result<Vec<Server>> {
        let serverlist = include_str!("serverlist.csv");
        let mut rdr = csv::Reader::from_reader(Cursor::new(serverlist));
        let mut out = Vec::with_capacity(16);
        for result in rdr.deserialize() {
            // Notice that we need to provide a type hint for automatic
            // deserialization.
            let record: Server = result?;
            out.push(record);
        }
        Ok(out)
    }
}

impl Provider for TigerVPN {
    fn alias(&self) -> String {
        "tig".to_string()
    }
}

impl OpenVpnProvider for TigerVPN {
    fn provider_dns(&self) -> Option<Vec<IpAddr>> {
        None
    }

    fn create_openvpn_config(&self) -> anyhow::Result<()> {
        let openvpn_dir = self.openvpn_dir()?;
        create_dir_all(&openvpn_dir);
        let protocol = OpenVpnProtocol::choose_one()?;
        let mut settings = Self::get_default_openvpn_settings();

        let (port, proto_str) = match protocol {
            OpenVpnProtocol::UDP => ("1194", "udp"),
            OpenVpnProtocol::TCP => ("443", "tcp-client"),
        };

        for server in Self::get_serverlist()? {
            let filename = format!("{}-{}.ovpn", server.country_name, server.country_alias);
            let file = File::create(openvpn_dir.join(filename))?;
            let mut this_settings = settings.clone();

            let remote_str = format!("remote {} {} {}", server.hostname, port, proto_str);
            this_settings.push(remote_str.as_str());

            write!(file, "{}", this_settings.join("\n"))?;
        }

        let ca = include_str!("tig_ca.crt");
        {
            let file = File::create(openvpn_dir.join("ca.crt"))
                .context("Could not create mullvad CA file")?;
            let mut write_buf = std::io::BufWriter::new(file);
            write!(write_buf, "{}", ca)?;
        }
        Ok(())
    }
}
