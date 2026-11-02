//! Read-only, destination-specific route lookup using Linux NETLINK_ROUTE.
//! Sockets are created in the calling thread's namespace; never calls setns.
use anyhow::{Context, bail, ensure};
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto,
    setsockopt, socket, sockopt,
};
use nix::sys::time::{TimeVal, TimeValLike};
use std::net::IpAddr;
use std::os::fd::AsRawFd;

#[derive(Debug, PartialEq, Eq)]
pub struct Route {
    pub interface_index: u32,
    pub(crate) signature: Vec<u8>,
}

pub fn lookup(destination: IpAddr) -> anyhow::Result<Route> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    setsockopt(&fd, sockopt::ReceiveTimeout, &TimeVal::milliseconds(1000))?;
    let request = route_request(destination);
    sendto(
        fd.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )
    .context("Sending route lookup")?;
    let mut response = [0u8; 8192];
    let length =
        recv(fd.as_raw_fd(), &mut response, MsgFlags::empty()).context("Receiving route lookup")?;
    parse_response(&response[..length])
}

fn route_request(destination: IpAddr) -> Vec<u8> {
    let address = match destination {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let len = 16 + 12 + 4 + address.len();
    let mut request = Vec::with_capacity(len);
    request.extend_from_slice(&(len as u32).to_ne_bytes());
    request.extend_from_slice(&26u16.to_ne_bytes()); // RTM_GETROUTE
    request.extend_from_slice(&1u16.to_ne_bytes()); // NLM_F_REQUEST
    request.extend_from_slice(&1u32.to_ne_bytes()); // sequence
    request.extend_from_slice(&0u32.to_ne_bytes()); // kernel assigns port id
    request.extend_from_slice(&[
        if destination.is_ipv4() { 2 } else { 10 },
        if destination.is_ipv4() { 32 } else { 128 },
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    request.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    request.extend_from_slice(&((4 + address.len()) as u16).to_ne_bytes());
    request.extend_from_slice(&1u16.to_ne_bytes()); // RTA_DST
    request.extend_from_slice(&address);
    request
}

fn parse_response(mut bytes: &[u8]) -> anyhow::Result<Route> {
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 16, "Truncated netlink header");
        let len = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into()?);
        ensure!(len >= 16 && len <= bytes.len(), "Invalid netlink length");
        ensure!(
            u32::from_ne_bytes(bytes[8..12].try_into()?) == 1,
            "Unexpected netlink sequence"
        );
        let payload = &bytes[16..len];
        if kind == 2 {
            // NLMSG_ERROR: signed negative errno, never a string from the kernel.
            ensure!(payload.len() >= 4, "Truncated netlink error");
            let errno = i32::from_ne_bytes(payload[..4].try_into()?);
            if errno < 0 {
                return Err(std::io::Error::from_raw_os_error(errno.saturating_neg()).into());
            }
        } else if kind == 24 {
            // RTM_NEWROUTE
            ensure!(payload.len() >= 12, "Truncated route message");
            ensure!(
                [1, 2, 3, 5].contains(&payload[7]),
                "Destination is blocked or unreachable"
            );
            let mut attrs = &payload[12..];
            let mut interface_index = None;
            let mut signature = Vec::new();
            while attrs.len() >= 4 {
                let attr_len = u16::from_ne_bytes(attrs[..2].try_into()?) as usize;
                let attr_kind = u16::from_ne_bytes(attrs[2..4].try_into()?);
                ensure!(
                    attr_len >= 4 && attr_len <= attrs.len(),
                    "Invalid route attribute length"
                );
                if attr_kind == 4 {
                    // RTA_OIF
                    ensure!(attr_len >= 8, "Truncated route interface");
                    interface_index = Some(u32::from_ne_bytes(attrs[4..8].try_into()?));
                }
                // Interface, gateway and preferred source identify underlay
                // changes even when the interface name remains the same.
                if [4, 5, 7].contains(&attr_kind) {
                    signature.extend_from_slice(&attrs[..attr_len]);
                }
                let next = (attr_len + 3) & !3;
                if next > attrs.len() {
                    break;
                }
                attrs = &attrs[next..];
            }
            if let Some(interface_index) = interface_index {
                return Ok(Route {
                    interface_index,
                    signature,
                });
            }
        }
        let next = (len + 3) & !3;
        if next > bytes.len() {
            break;
        }
        bytes = &bytes[next..];
    }
    bail!("No usable route returned")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_lookup_supports_both_loopback_families_without_root() {
        assert_eq!(
            lookup("127.0.0.1".parse().unwrap())
                .unwrap()
                .interface_index,
            1
        );
        assert_eq!(lookup("::1".parse().unwrap()).unwrap().interface_index, 1);
    }
    #[test]
    fn rejects_truncated_and_malformed_kernel_messages() {
        for len in 0..28 {
            assert!(parse_response(&vec![0; len]).is_err());
        }
        let mut message = route_request("127.0.0.1".parse().unwrap());
        message[4..6].copy_from_slice(&24u16.to_ne_bytes());
        message[23] = 7; // RTN_UNREACHABLE
        assert!(parse_response(&message).is_err());
        message[23] = 1;
        message[28..30].copy_from_slice(&2u16.to_ne_bytes());
        assert!(parse_response(&message).is_err());
    }
}
