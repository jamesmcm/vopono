use crate::netns::NetworkNamespace;
use clap::arg_enum;
use serde::{Deserialize, Serialize};

arg_enum! {
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Copy)]
pub enum Firewall {
    IpTables,
    NfTables,
}
}

pub fn disable_ipv6(netns: &NetworkNamespace, firewall: Firewall) -> anyhow::Result<()> {
    match firewall {
        Firewall::IpTables => {
            netns.exec(&["ip6tables", "-P", "INPUT", "DROP"])?;
            netns.exec(&["ip6tables", "-I", "INPUT", "-j", "DROP"])?;
            netns.exec(&["ip6tables", "-P", "FORWARD", "DROP"])?;
            netns.exec(&["ip6tables", "-I", "FORWARD", "-j", "DROP"])?;
            netns.exec(&["ip6tables", "-P", "OUTPUT", "DROP"])?;
            netns.exec(&["ip6tables", "-I", "OUTPUT", "-j", "DROP"])?;
        }
        Firewall::NfTables => {
            netns.exec(&["nft", "add", "table", "ip6", &netns.name])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "ip6",
                &netns.name,
                "drop_ipv6_input",
                "{ type filter hook input priority -1 ; policy drop; }",
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "ip6",
                &netns.name,
                "drop_ipv6_output",
                "{ type filter hook output priority -1 ; policy drop; }",
            ])?;
            netns.exec(&[
                "nft",
                "add",
                "chain",
                "ip6",
                &netns.name,
                "drop_ipv6_forward",
                "{ type filter hook forward priority -1 ; policy drop; }",
            ])?;
        }
    }
    Ok(())
}
