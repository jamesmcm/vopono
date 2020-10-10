use crate::netns::NetworkNamespace;

pub fn open_ports(netns: &NetworkNamespace, ports: &[u16]) -> anyhow::Result<()> {
    // TODO: Add switch to use nftables
    // TODO: Allow UDP port forwarding?
    for port in ports {
        netns.exec(&[
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])?;
        netns.exec(&[
            "iptables",
            "-I",
            "OUTPUT",
            "-p",
            "tcp",
            "--sport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])?;
    }
    Ok(())
}
