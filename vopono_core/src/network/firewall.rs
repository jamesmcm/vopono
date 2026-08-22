use super::netns::NetworkNamespace;
use log::debug;
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

/// Tag return traffic entering the namespace through the host veth with the
/// Wireguard fwmark. These packets are the only tunnel-related traffic that
/// arrives outside the tunnel device; without the tag their reverse-path
/// lookup follows the fwmark policy routing table back to the tunnel device
/// instead of the ingress interface, so hosts enforcing strict reverse-path
/// filtering (rp_filter=1) silently drop them. Requires
/// net.ipv4.conf.*.src_valid_mark=1 (set during Wireguard setup) for the
/// kernel to honour the mark during source validation. Rules live inside the
/// namespace and are discarded with it.
pub fn tag_return_traffic(
    netns: &NetworkNamespace,
    ingress_iface: &str,
    fwmark: &str,
    firewall: Firewall,
) -> anyhow::Result<()> {
    debug!(
        "Tagging return traffic on {ingress_iface} with fwmark {fwmark} in netns {}",
        netns.name
    );
    match firewall {
        Firewall::IpTables => NetworkNamespace::exec(
            &netns.name,
            &[
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-i",
                ingress_iface,
                "-j",
                "MARK",
                "--set-xmark",
                fwmark,
            ],
        )?,
        Firewall::NfTables => {
            NetworkNamespace::exec(&netns.name, &["nft", "add", "table", "ip", &netns.name])?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    &netns.name,
                    "prerouting_mark",
                    "{ type filter hook prerouting priority -150 ; }",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    &netns.name,
                    "prerouting_mark",
                    &format!("iifname \"{ingress_iface}\" meta mark set {fwmark}"),
                ],
            )?;
        }
    }
    Ok(())
}
