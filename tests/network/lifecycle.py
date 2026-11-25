"""Real relay and application survival through orderly and abrupt daemon exit."""
import json
import os
from pathlib import Path
import socket
import sys
from common import Context, application_pid, wait_for

ctx = Context(*sys.argv[1:])
name = ctx.namespace('restarted')
server = ctx.user_file('echo.py',
    'import select, socket\n'
    'servers = [socket.create_server(("0.0.0.0", port)) for port in (43128, 43130)]\n'
    'while True:\n'
    ' for server in select.select(servers, [], [])[0]:\n'
    '  conn, _ = server.accept()\n'
    '  with conn: conn.sendall(b"alive")\n', 0o644)
app = ctx.spawn(['exec', '--provider', 'none', '--custom-netns-name', 'restarted',
    '--interface', 'uplink', '--firewall', 'nftables', '--forward', '43128',
    '--forward', '43130', '--keep-alive', 'python3 ' + str(server)], 'app-restart.log')


def echo(port=43128):
    with socket.create_connection(('127.0.0.1', port), timeout=1) as stream:
        return stream.recv(16) == b'alive'


wait_for(echo)
app_pid = wait_for(lambda: application_pid(ctx.status(name)))
inode = os.stat('/run/netns/' + name).st_ino
for abrupt in (False, True):
    if abrupt:
        ctx.restart(abrupt=True)
        wait_for(echo)
    else:
        with socket.socket() as blocker:
            def occupy_relay_port():
                blocker.bind(('127.0.0.1', 43130))
                blocker.listen()

            ctx.restart(after_exit=occupy_relay_port)
            # A conflict on one port must not take the other relay offline.
            wait_for(echo)
        # Releasing the port must restore the relay without another restart.
    wait_for(lambda: echo(43130))
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
print('PASS: restart retries conflicting relays, preserves one app and rejects stale intent', flush=True)
