use anyhow::Context;
use log::{debug, warn};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;

use crate::util::open_hosts;

use super::firewall::Firewall;
use super::netns::{NetworkNamespace, VethPairIPs};

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
        host_ips: &VethPairIPs,
        allow_host_access: bool,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        let dir_path = format!("/etc/netns/{ns_name}");
        std::fs::create_dir_all(&dir_path)
            .with_context(|| format!("Failed to create directory: {}", &dir_path))?;
        std::fs::set_permissions(&dir_path, PermissionsExt::from_mode(0o755)) // Directories usually need execute permission
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
            writeln!(resolv, "search {suffix}")?;
        }

        for dns in servers {
            writeln!(resolv, "nameserver {dns}")?;
        }

        let mut effective_hosts_entries = Vec::new();
        if allow_host_access {
            debug!("--allow-host-access is true, adding host IPs to hosts file as vopono.host");
            if let Some(ipv4_pair) = &host_ips.ipv4 {
                let entry = format!("{} vopono.host", ipv4_pair.host_ip);
                debug!("Adding host entry: '{}'", &entry);
                effective_hosts_entries.push(entry);
            }
            if let Some(ipv6_pair) = &host_ips.ipv6 {
                let entry = format!("{} vopono.host", ipv6_pair.host_ip);
                debug!("Adding host entry: '{}'", &entry);
                effective_hosts_entries.push(entry);
            }
        }

        if let Some(my_hosts_entries) = hosts_entries {
            effective_hosts_entries.extend(my_hosts_entries.iter().cloned())
        };

        if !effective_hosts_entries.is_empty() {
            let hosts_path = format!("/etc/netns/{ns_name}/hosts");
            let mut hosts = std::fs::File::create(&hosts_path)
                .with_context(|| format!("Failed to open hosts: {}", &hosts_path))?;
            std::fs::set_permissions(&hosts_path, PermissionsExt::from_mode(0o644))
                .with_context(|| format!("Failed to set file permissions for {}", &hosts_path))?;

            // Add some default entries for completeness
            writeln!(hosts, "127.0.0.1\tlocalhost")?;
            writeln!(hosts, "::1\t\tlocalhost")?;

            for hosts_entry in effective_hosts_entries {
                writeln!(hosts, "{hosts_entry}")?;
            }
        }

        if std::path::Path::new("/etc/nsswitch.conf").exists() {
            let nsswitch_src = std::fs::File::open("/etc/nsswitch.conf")?;
            let nsswitch_path = format!("/etc/netns/{ns_name}/nsswitch.conf");
            let mut nsswitch = std::fs::File::create(&nsswitch_path)?;
            std::fs::set_permissions(&nsswitch_path, PermissionsExt::from_mode(0o644))?;

            let hosts_re = Regex::new(r"^hosts:.*$").expect("Failed to compile hosts regex");
            for line in std::io::BufReader::new(nsswitch_src).lines() {
                writeln!(
                    nsswitch,
                    "{}",
                    hosts_re.replace(&line?, |_caps: &Captures| {
                        "hosts: files dns" // Simplified for clarity in a container/netns
                    })
                )?;
            }
        }

        // Note: open_hosts will also need to be dual-stack aware, similar to open_dns_ports
        open_hosts(&ns_name, servers, firewall)?;

        if !servers.is_empty() {
            log::debug!("Opening firewall for DNS servers: {servers:?}");
            open_dns_ports(&ns_name, servers, firewall)?;
        }

        Ok(Self { ns_name })
    }
}

// TODO: Do we want to handle disable_ipv6 here? Warn if using ipv6 host with ipv6 disabled
fn open_dns_ports(netns_name: &str, hosts: &[IpAddr], firewall: Firewall) -> anyhow::Result<()> {
    for host in hosts {
        let host_str = &host.to_string();
        match firewall {
            Firewall::IpTables => {
                let iptables_cmd = if host.is_ipv4() {
                    "iptables"
                } else {
                    "ip6tables"
                };

                NetworkNamespace::exec(
                    netns_name,
                    &[
                        iptables_cmd,
                        "-A",
                        "OUTPUT",
                        "-p",
                        "udp",
                        "-d",
                        host_str,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    netns_name,
                    &[
                        iptables_cmd,
                        "-A",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "-d",
                        host_str,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
            Firewall::NfTables => {
                let addr_family_keyword = if host.is_ipv4() { "ip" } else { "ip6" };

                NetworkNamespace::exec(
                    netns_name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        netns_name,
                        "output",
                        addr_family_keyword,
                        "daddr",
                        host_str,
                        "udp",
                        "dport",
                        "53",
                        "counter",
                        "accept",
                    ],
                )?;
                NetworkNamespace::exec(
                    netns_name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        netns_name,
                        "output",
                        addr_family_keyword,
                        "daddr",
                        host_str,
                        "tcp",
                        "dport",
                        "53",
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }
    }
    Ok(())
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
