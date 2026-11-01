"""Shared host relay and real NAT-PMP renewals through a disposable provider."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from common import Context, command, wait_for

ctx = Context(*sys.argv[1:])
name = ctx.namespace('leases')
command('ip', '-n', 'peer', 'addr', 'add', '10.2.0.1/32', 'dev', 'wgpeer')
events = ctx.scratch / 'lease-events.jsonl'
reject = ctx.scratch / 'reject-renewal'
with (ctx.scratch / 'natpmp-peer.log').open('w') as log:
    provider = subprocess.Popen(['ip', 'netns', 'exec', 'peer', 'python3',
        str(Path(__file__).with_name('natpmp_peer.py')), str(events), str(reject)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
callback_log = ctx.scratch / 'config/callbacks.jsonl'
callback = ctx.user_file('port-callback.py',
    '#!/usr/bin/python3\nimport json,os,sys\n'
    f'with open({str(callback_log)!r},"a") as stream:\n'
    ' stream.write(json.dumps({"uid":os.getuid(),"port":int(sys.argv[1])})+"\\n")\n', 0o755)
creator = ctx.spawn(['exec', '--custom', str(ctx.scratch / 'client.conf'), '--protocol', 'wireguard',
    '--custom-netns-name', 'leases', '--interface', 'uplink', '--firewall', 'nftables',
    '--forward', '43128', '--custom-port-forwarding', 'protonvpn',
    '--port-forwarding-callback', str(callback), 'sleep 240'], 'lease-creator.log')
def ready():
    if creator.poll() is not None:
        raise AssertionError((ctx.scratch / 'lease-creator.log').read_text())
    return bool(ctx.status(name)['applications'])


wait_for(ready)
creator_pid = ctx.status(name)['applications'][0]['pid']
server = ctx.user_file('relay-server.py',
    'import socket\ns=socket.socket(); s.bind(("0.0.0.0",43128)); s.listen()\n'
    'while True:\n c,_=s.accept(); c.sendall(b"shared relay"); c.close()\n', 0o644)
second = ctx.spawn(['exec', '--existing-netns', name, '--interface', 'uplink',
    'python3 ' + str(server)], 'lease-second.log')


def relay():
    with socket.create_connection(('127.0.0.1', 43128), timeout=1) as stream:
        return stream.recv(32) == b'shared relay'


def callbacks():
    return [json.loads(line) for line in callback_log.read_text().splitlines()]


wait_for(relay)
ctx.client('stop', 'application', str(creator_pid), '--json')
wait_for(relay)
assert ctx.status(name)['port_forwarding']['port'] == 43129
reject.touch()
wait_for(lambda: any(json.loads(line)['failed'] for line in events.read_text().splitlines()), seconds=60)
wait_for(lambda: len(callbacks()) >= 2, seconds=45)
assert relay()
ctx.restart(abrupt=True)
wait_for(lambda: len(callbacks()) >= 3)
wait_for(relay)
assert all(item == {'uid': ctx.uid, 'port': 43129} for item in callbacks())
assert ctx.status(name)['port_forwarding']['port'] == 43129
ctx.client('stop', 'namespace', name, '--json')
wait_for(lambda: not Path('/run/netns/' + name).exists())
second.wait(timeout=10)
creator.wait(timeout=10)
count = len(events.read_text().splitlines())
time.sleep(46)  # Longer than the normal 45-second lease-renewal interval.
assert len(events.read_text().splitlines()) == count, 'Stopped namespace kept renewing its lease'
probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
probe.bind(('::', 43128))
probe.close()
provider.terminate()
provider.wait(timeout=10)
print('PASS: creator exit, relay lifetime, lease retry, user callback, crash restoration and final cleanup', flush=True)
