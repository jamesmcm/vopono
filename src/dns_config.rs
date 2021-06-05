use anyhow::Context;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub struct DnsConfig {
    ns_name: String,
}

impl DnsConfig {
    pub fn new(ns_name: String, servers: &[IpAddr], suffixes: &[&str]) -> anyhow::Result<Self> {
        std::fs::create_dir_all(format!("/etc/netns/{}", ns_name))
            .with_context(|| format!("Failed to create directory: /etc/netns/{}", ns_name))?;

        let mut f = std::fs::File::create(format!("/etc/netns/{}/resolv.conf", ns_name))
            .with_context(|| {
                format!(
                    "Failed to open resolv.conf: /etc/netns/{}/resolv.conf",
                    ns_name
                )
            })?;

        debug!(
            "Setting namespace {} DNS server to {}",
            ns_name,
            &servers
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<String>>()
                .join(", ")
        );

        let suffix = suffixes.join(" ");
        if !suffix.is_empty() {
            writeln!(f, "search {}", suffix).with_context(|| {
                format!(
                    "Failed to overwrite resolv.conf: /etc/netns/{}/resolv.conf",
                    ns_name
                )
            })?;
        }

        for dns in servers {
            writeln!(f, "nameserver {}", dns).with_context(|| {
                format!(
                    "Failed to overwrite resolv.conf: /etc/netns/{}/resolv.conf",
                    ns_name
                )
            })?;
        }

        Ok(Self { ns_name })
    }
}

impl Drop for DnsConfig {
    fn drop(&mut self) {
        let path = format!("/etc/netns/{}", self.ns_name);
        match std::fs::remove_dir_all(&path) {
            Ok(_) => {}
            Err(e) => warn!(
                "Failed to delete network namespace directory: {}: {:?}",
                &path, e
            ),
        }
    }
}
