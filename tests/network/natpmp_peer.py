"""Credential-free NAT-PMP provider fixture, including one transient rejection."""
import json
from pathlib import Path
import socket
import struct
import sys
import time

log, reject = map(Path, sys.argv[1:])
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('10.2.0.1', 5351))
while True:
    query, client = listener.recvfrom(4096)
    opcode = query[1]
    failure = opcode in (1, 2) and reject.exists()
    if failure:
        reject.unlink()
    with log.open('a') as stream:
        stream.write(json.dumps({'opcode': opcode, 'failed': failure, 'time': time.monotonic()}) + '\n')
    result = 2 if failure else 0
    header = struct.pack('!BBHI', 0, opcode + 128, result, 1)
    if opcode == 0:
        response = header + socket.inet_aton('1.1.1.1')
    else:
        private_port = struct.unpack('!H', query[4:6])[0]
        response = header + struct.pack('!HHI', private_port, 43129, 60)
    listener.sendto(response, client)
