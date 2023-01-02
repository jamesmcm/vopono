use anyhow::Context;
use log::{debug, warn};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;

#[derive(Serialize, Deserialize, Debug)]
pub struct DnsConfig {
    ns_name: String,
}

impl DnsConfig {
    pub fn new(
        ns_name: String,
        servers: &[IpAddr],
        suffixes: &[&str],
        hosts_entries: Option<&Vec<String>>,
    ) -> anyhow::Result<Self> {
        let dir_path = format!("/etc/netns/{ns_name}");
        std::fs::create_dir_all(&dir_path)
            .with_context(|| format!("Failed to create directory: {}", &dir_path))?;
        std::fs::set_permissions(&dir_path, PermissionsExt::from_mode(0o644))
            .with_context(|| format!("Failed to set directory permissions for {dir_path}"))?;

        let resolv_conf_path = format!("/etc/netns/{ns_name}/resolv.conf");
        let mut resolv = std::fs::File::create(&resolv_conf_path)
            .with_context(|| format!("Failed to open resolv.conf: {}", &resolv_conf_path))?;
        std::fs::set_permissions(&resolv_conf_path, PermissionsExt::from_mode(0o644))
            .with_context(|| format!("Failed to set file permissions for {resolv_conf_path}"))?;

        debug!(
            "Setting namespace {} DNS server to {}",
            ns_name,
            &servers
                .iter()
                .map(|x| format!("{x}"))
                .collect::<Vec<String>>()
                .join(", ")
        );

        let suffix = suffixes.join(" ");
        if !suffix.is_empty() {
            writeln!(resolv, "search {suffix}").with_context(|| {
                format!(
                    "Failed to overwrite resolv.conf: /etc/netns/{ns_name}/resolv.conf"
                )
            })?;
        }

        for dns in servers {
            writeln!(resolv, "nameserver {dns}").with_context(|| {
                format!(
                    "Failed to overwrite resolv.conf: /etc/netns/{ns_name}/resolv.conf"
                )
            })?;
        }

        if let Some(my_hosts_entries) = hosts_entries {
            let hosts_path = format!("/etc/netns/{ns_name}/hosts");
            let mut hosts = std::fs::File::create(&hosts_path)
                .with_context(|| format!("Failed to open hosts: {}", &hosts_path))?;
            std::fs::set_permissions(&hosts_path, PermissionsExt::from_mode(0o644))
                .with_context(|| format!("Failed to set file permissions for {}", &hosts_path))?;

            for hosts_enty in my_hosts_entries {
                writeln!(hosts, "{hosts_enty}").with_context(|| {
                    format!("Failed to overwrite hosts: /etc/netns/{ns_name}/hosts")
                })?;
            }
        }

        if std::path::Path::new("/etc/nsswitch.conf").exists() {
            let nsswitch_src = std::fs::File::open("/etc/nsswitch.conf")
                .with_context(|| "Failed to open nsswitch.conf: /etc/nsswitch.conf")?;

            let nsswitch_path = format!("/etc/netns/{ns_name}/nsswitch.conf");
            let mut nsswitch = std::fs::File::create(&nsswitch_path)
                .with_context(|| format!("Failed to open nsswitch.conf: {nsswitch_path}"))?;
            std::fs::set_permissions(&nsswitch_path, PermissionsExt::from_mode(0o644))
                .with_context(|| {
                    format!("Failed to set file permissions for {}", &nsswitch_path)
                })?;

            for line in std::io::BufReader::new(nsswitch_src).lines() {
                writeln!(
                    nsswitch,
                    "{}",
                    Regex::new(r"^hosts:.*$")
                        .unwrap()
                        .replace(&line?, |_caps: &Captures| {
                            "hosts: files mymachines myhostname dns"
                        })
                )
                .with_context(|| {
                    format!(
                        "Failed to overwrite nsswitch.conf: /etc/netns/{ns_name}/nsswitch.conf"
                    )
                })?;
            }
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
