//! Delete one obsolete tunnel UDP mapping, never flush host connection state.
use anyhow::ensure;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto,
    setsockopt, socket, sockopt,
};
use nix::sys::time::{TimeVal, TimeValLike};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    result.extend_from_slice(&kind.to_ne_bytes());
    result.extend_from_slice(payload);
    result.resize((result.len() + 3) & !3, 0);
    result
}

pub(crate) fn delete_udp(source: SocketAddr, destination: SocketAddr) -> anyhow::Result<()> {
    ensure!(
        source.is_ipv4() == destination.is_ipv4() && source.port() > 0 && destination.port() > 0,
        "Invalid tunnel connection tuple"
    );
    let (src_kind, dst_kind, src, dst) = match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (1, 2, src.octets().to_vec(), dst.octets().to_vec()),
        (IpAddr::V6(src), IpAddr::V6(dst)) => (3, 4, src.octets().to_vec(), dst.octets().to_vec()),
        _ => unreachable!(),
    };
    let mut ip = attribute(src_kind, &src);
    ip.extend(attribute(dst_kind, &dst));
    let mut protocol = attribute(1, &[17]);
    protocol.extend(attribute(2, &source.port().to_be_bytes()));
    protocol.extend(attribute(3, &destination.port().to_be_bytes()));
    let mut tuple = attribute(1 | 0x8000, &ip);
    tuple.extend(attribute(2 | 0x8000, &protocol));
    let tuple = attribute(1 | 0x8000, &tuple);
    let mut request = Vec::new();
    request.extend_from_slice(&((20 + tuple.len()) as u32).to_ne_bytes());
    request.extend_from_slice(&258u16.to_ne_bytes()); // CTNETLINK / CT_DELETE
    request.extend_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    request.extend_from_slice(&1u32.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(&[if source.is_ipv4() { 2 } else { 10 }, 0, 0, 0]);
    request.extend(tuple);
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkNetFilter,
    )?;
    setsockopt(&fd, sockopt::ReceiveTimeout, &TimeVal::milliseconds(1000))?;
    sendto(
        fd.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )?;
    let mut bytes = [0u8; 4096];
    let length = recv(fd.as_raw_fd(), &mut bytes, MsgFlags::empty())?;
    ensure!(
        length >= 20
            && u16::from_ne_bytes(bytes[4..6].try_into()?) == 2
            && u32::from_ne_bytes(bytes[8..12].try_into()?) == 1,
        "Invalid conntrack acknowledgement"
    );
    let error = i32::from_ne_bytes(bytes[16..20].try_into()?);
    if error < 0 && error != -libc::ENOENT {
        return Err(std::io::Error::from_raw_os_error(-error).into());
    }
    Ok(())
}
