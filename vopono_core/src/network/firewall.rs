use super::netns::NetworkNamespace;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Display, EnumIter)]
pub enum Firewall {
    IpTables,
    NfTables,
}

pub fn disable_ipv6(netns: &NetworkNamespace, firewall: Firewall) -> anyhow::Result<()> {
    match firewall {
        Firewall::IpTables => {
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "INPUT", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "INPUT", "-j", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "FORWARD", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "FORWARD", "-j", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-P", "OUTPUT", "DROP"])?;
            NetworkNamespace::exec(&netns.name, &["ip6tables", "-I", "OUTPUT", "-j", "DROP"])?;
        }
        Firewall::NfTables => {
            NetworkNamespace::exec(&netns.name, &["nft", "add", "table", "ip6", &netns.name])?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_input",
                    "{ type filter hook input priority -1 ; policy drop; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_output",
                    "{ type filter hook output priority -1 ; policy drop; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip6",
                    &netns.name,
                    "drop_ipv6_forward",
                    "{ type filter hook forward priority -1 ; policy drop; }",
                ],
            )?;
        }
    }
    Ok(())
}
