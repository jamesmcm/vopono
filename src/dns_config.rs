use super::util::sudo_command;
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DnsConfig {
    ns_name: String,
}

impl DnsConfig {
    pub fn new(ns_name: String) -> anyhow::Result<Self> {
        // TODO: Do this by requesting escalated privileges to current binary and use std::fs
        sudo_command(&["mkdir", "-p", &format!("/etc/netns/{}", ns_name)])
            .with_context(|| format!("Failed to create directory: /etc/netns/{}", ns_name))?;

        sudo_command(&[
            "sh",
            "-c",
            &format!(
                "echo 'nameserver 8.8.8.8' > /etc/netns/{}/resolv.conf",
                ns_name
            ),
        ])
        .with_context(|| {
            format!(
                "Failed to overwrite resolv.conf: /etc/netns/{}/resolv.conf",
                ns_name
            )
        })?;

        Ok(Self { ns_name })
    }
}

impl Drop for DnsConfig {
    fn drop(&mut self) {
        //TODO: Do this a much safer way!!
        sudo_command(&["rm", "-rf", &format!("/etc/netns/{}", self.ns_name)]).expect(&format!(
            "Failed to delete resolv.conf for {}",
            self.ns_name
        ));
    }
}
