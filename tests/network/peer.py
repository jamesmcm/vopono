"""Disposable TCP and DNS services inside the synthetic VPN peer namespace."""
import ipaddress
import socket
import struct
import threading


def tcp(family):
    listener = socket.socket(family)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 443))
    listener.listen()
    while True:
        connection, _ = listener.accept()
        connection.close()


def dns():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("0.0.0.0", 53))
    while True:
        query, client = listener.recvfrom(4096)
        offset = 12
        while query[offset]:
            offset += query[offset] + 1
        offset += 1
        kind = struct.unpack("!H", query[offset:offset + 2])[0]
        end = offset + 4
        address = ipaddress.ip_address("2606:4700:4700::1111" if kind == 28 else "1.1.1.1").packed
        answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(address)) + address
        listener.sendto(query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end] + answer, client)


for family in (socket.AF_INET, socket.AF_INET6):
    threading.Thread(target=tcp, args=(family,), daemon=True).start()
dns()
