"""Real relay and application survival through orderly and abrupt daemon exit."""
import json
import os
from pathlib import Path
import socket
import sys
from common import Context, wait_for

ctx = Context(*sys.argv[1:])
name = ctx.namespace('restarted')
server = ctx.user_file('echo.py',
    'import socket\ns=socket.socket(); s.bind(("0.0.0.0",43128)); s.listen()\n'
    'while True:\n c,_=s.accept(); c.sendall(b"alive"); c.close()\n', 0o644)
app = ctx.spawn(['exec', '--provider', 'none', '--custom-netns-name', 'restarted',
    '--interface', 'uplink', '--firewall', 'nftables', '--forward', '43128',
    '--keep-alive', 'python3 ' + str(server)], 'app-restart.log')


def echo():
    with socket.create_connection(('127.0.0.1', 43128), timeout=1) as stream:
        return stream.recv(16) == b'alive'


wait_for(echo)
app_pid = ctx.status(name)['applications'][0]['pid']
inode = os.stat('/run/netns/' + name).st_ino
for abrupt in (False, True):
    ctx.restart(abrupt)
    wait_for(echo)
    assert Path(f'/proc/{app_pid}').exists()
    assert len(ctx.status(name)['applications']) == 1
    assert os.stat('/run/netns/' + name).st_ino == inode
# A stale record cannot cause the daemon to adopt an unrelated replacement.
record = Path('/run/vopono/namespace-owners/stale')
record.write_text('{"uid":1000,"device":0,"inode":0,"namespace":"invalid"}')
record.chmod(0o600)
ctx.restart()
assert not record.exists()
ctx.client('stop', 'namespace', name, '--json')
wait_for(lambda: not Path('/run/netns/' + name).exists())
app.wait(timeout=10)
# Model a crash after the durable stop intent, before namespace teardown.
ctx.client('exec', '--provider', 'none', '--custom-netns-name', 'interrupted',
           '--interface', 'uplink', '--firewall', 'nftables', '--create-netns-only', '')
interrupted = ctx.namespace('interrupted')
intent = Path('/run/vopono/namespace-owners') / interrupted
saved = json.loads(intent.read_text())
saved['lifecycle'] = 'stopping'
intent.write_text(json.dumps(saved))
ctx.restart(abrupt=True)
wait_for(lambda: not Path('/run/netns/' + interrupted).exists())
ctx.client('exec', '--provider', 'none', '--custom-netns-name', 'interrupted',
           '--interface', 'uplink', '--firewall', 'nftables', '--create-netns-only', '')
ctx.client('stop', 'namespace', interrupted, '--json')
print('PASS: graceful/crash restart restores relays, preserves one app and rejects stale intent', flush=True)
