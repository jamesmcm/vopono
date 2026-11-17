"""Replace the host underlay while a real WireGuard application remains alive."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time
from common import Context, application_pid
from isolation import LeakProbe

binary, scratch_arg, user = sys.argv[1:]
scratch = Path(scratch_arg)
uid = pwd.getpwnam(user).pw_uid
base = ['runuser', '-u', user, '--', 'env', f'XDG_CONFIG_HOME={scratch / "config"}', binary]
name = f'underlay-u{uid}'
context = Context(binary, scratch_arg, user)
original_path = os.environ['PATH']
tools = scratch / 'recovery-tools'
tools.mkdir()
actual_nft = shutil.which('nft')
failure = scratch / 'reject-endpoint-repair'
rejected = scratch / 'endpoint-repair-rejected'
shim = tools / 'nft'
shim.write_text(
    '#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n'
    f'if Path({str(failure)!r}).exists() and "-f" in sys.argv:\n'
    ' batch=Path(sys.argv[sys.argv.index("-f")+1]).read_text()\n'
    f' if "vopono-recovery-endpoint" in batch and {name!r} in batch:\n'
    f'  Path({str(rejected)!r}).touch(); raise SystemExit(42)\n'
    f'os.execv({actual_nft!r}, [{actual_nft!r}, *sys.argv[1:]])\n')
shim.chmod(0o755)
os.environ['PATH'] = str(tools) + os.pathsep + original_path
context.restart()
profile = scratch / 'rotating.conf'
profile.write_text((scratch / 'client.conf').read_text().replace('192.0.2.2:51820', 'rotating.test:51820'))
os.chown(profile, uid, pwd.getpwnam(user).pw_gid)
with Path('/etc/hosts').open('a') as hosts:
    hosts.write('\n192.0.2.2 rotating.test\n')

def command(*args):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, timeout=15)

def client(*args):
    return command(*base, *args)

def wait_for(condition, seconds=80):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = condition()
        if result:
            return result
        time.sleep(.5)
    status = json.loads(client('status', '--json').stdout)
    health = next((ns['health'] for ns in status['namespaces'] if ns['id'] == name), None)
    raise AssertionError(
        f'Underlay recovery timed out ({condition.__name__}); last health: {json.dumps(health)}')

def connected():
    result = client('check', name, '--timeout-ms', '300', '--skip-dns', '--skip-ipv6', '--json')
    return json.loads(result.stdout)['result']['connected']

def reachable():
    try:
        return connected()
    except subprocess.SubprocessError:
        return False

def isolated():
    probe.assert_isolated()
    result = command('ip', 'netns', 'exec', name, 'python3', '-c',
                     'import socket; s=socket.socket(); s.settimeout(.3)\n'
                     'try: s.connect(("192.0.2.2",443))\n'
                     'except OSError: raise SystemExit(0)\n'
                     'raise SystemExit(1)')
    assert result.returncode == 0

with (scratch / 'underlay-client.log').open('w') as log:
    app = subprocess.Popen(base + ['exec', '--custom', str(profile),
        '--protocol', 'wireguard', '--custom-netns-name', 'underlay', '--interface', 'uplink',
        '--firewall', 'nftables', '--open-ports', '4446', '--monitor', '--recover', 'sleep 360'],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
wait_for(reachable)
inode = os.stat('/run/netns/' + name).st_ino
def registered_pid():
    status = json.loads(client('status', '--json').stdout)
    return application_pid(next(ns for ns in status['namespaces'] if ns['id'] == name))


pid = wait_for(registered_pid)
probe = LeakProbe(Context(binary, scratch_arg, user), name,
                  [('192.0.2.2', 51820), ('192.0.2.3', 51820)])
probe.wait_for_tunnel()
probe.wait_for_tunnel(ipv6=True)
# Rotate the DNS endpoint and make the original literal address unusable.
# Removing a primary IPv4 address may also remove secondary addresses in its
# subnet. Add the replacement after removal so it becomes the new primary.
failure.touch()
command('ip', '-n', 'peer', 'addr', 'delete', '192.0.2.2/24', 'dev', 'peerlink')
command('ip', '-n', 'peer', 'addr', 'add', '192.0.2.3/24', 'dev', 'peerlink')
Path('/etc/hosts').write_text(Path('/etc/hosts').read_text().replace('192.0.2.2 rotating.test', '192.0.2.3 rotating.test'))


def failed_repair_is_isolated():
    isolated()
    health = next(ns['health'] for ns in json.loads(client('status', '--json').stdout)['namespaces']
                  if ns['id'] == name)
    error = (health or {}).get('last_error') or ''
    return (rejected.exists() and 'nft failed during network repair' in error
            and 'exit status: 42' in error)


wait_for(failed_repair_is_isolated)
assert not reachable(), 'Failed endpoint repair unexpectedly restored connectivity'
failure.unlink()
wait_for(reachable)
print('PASS: failed endpoint-firewall repair preserves isolation before a successful retry', flush=True)
record = json.loads((Path('/run/vopono/namespace-owners') / name).read_text())
wait_for(lambda: json.loads((Path('/run/vopono/namespace-owners') / name).read_text())['namespace']['wireguard']['recovery']['address'] == '192.0.2.3')
# A new gateway/source on the same interface must invalidate the old UDP
# conntrack tuple. Keep the old address installed so the kernel does not flush
# the mapping for us, and make the old source unusable at the peer.
command('ip', 'addr', 'add', '192.0.4.1/24', 'dev', 'uplink')
command('ip', '-n', 'peer', 'addr', 'add', '192.0.4.2/24', 'dev', 'peerlink')
command('ip', 'route', 'replace', '192.0.2.3/32', 'via', '192.0.4.2',
        'dev', 'uplink', 'src', '192.0.4.1')
for chain, flag in [('INPUT', '-s'), ('OUTPUT', '-d')]:
    command('ip', 'netns', 'exec', 'peer', 'iptables', '-I', chain, flag, '192.0.2.1', '-j', 'DROP')
assert not reachable(), 'Old source unexpectedly remained usable'
wait_for(reachable)
assert os.stat('/run/netns/' + name).st_ino == inode
assert Path('/proc/' + str(pid)).exists()
for chain, flag in [('INPUT', '-s'), ('OUTPUT', '-d')]:
    command('ip', 'netns', 'exec', 'peer', 'iptables', '-D', chain, flag, '192.0.2.1', '-j', 'DROP')
command('ip', 'route', 'delete', '192.0.2.3/32')
command('ip', 'addr', 'delete', '192.0.4.1/24', 'dev', 'uplink')
command('ip', '-n', 'peer', 'addr', 'delete', '192.0.4.2/24', 'dev', 'peerlink')
wait_for(reachable)
print('PASS: same-interface gateway/source recovery preserves application and namespace identity', flush=True)

command('ip', 'link', 'add', 'uplink2', 'type', 'veth', 'peer', 'name', 'peerlink2')
command('ip', 'link', 'set', 'peerlink2', 'netns', 'peer')
command('ip', 'addr', 'add', '192.0.3.1/24', 'dev', 'uplink2')
command('ip', 'link', 'set', 'uplink2', 'up')
command('ip', '-n', 'peer', 'addr', 'add', '192.0.3.2/24', 'dev', 'peerlink2')
command('ip', '-n', 'peer', 'link', 'set', 'peerlink2', 'up')
command('ip', '-n', 'peer', 'addr', 'add', '192.0.2.2/32', 'dev', 'lo')
command('ip', '-n', 'peer', 'addr', 'add', '192.0.2.3/32', 'dev', 'lo')
command('ip', 'link', 'delete', 'uplink')
command('ip', 'route', 'replace', 'default', 'via', '192.0.3.2', 'dev', 'uplink2')
# Poll leakage throughout repair, not merely once after the connection returns.
def recovered():
    isolated()
    return reachable()
wait_for(recovered)
assert os.stat('/run/netns/' + name).st_ino == inode
assert Path('/proc/' + str(pid)).exists()
health = next(ns for ns in json.loads(client('status', '--json').stdout)['namespaces'] if ns['id'] == name)['health']
assert health['reconnect_attempts'] >= 1
# The recovery replacement must remove the old underlay's NAT rule, not just
# add a second one.
listing = command('nft', '-j', 'list', 'table', 'inet', 'vopono_nat')
comments = [item['rule']['comment']
            for item in json.loads(listing.stdout)['nftables']
            if 'rule' in item and 'comment' in item['rule']]
assert any(comment.endswith('_uplink2') for comment in comments), comments
assert not any(comment.endswith('_uplink') for comment in comments), comments

# A later repair replaces the monitor's snapshot. That snapshot must remain
# inert: dropping it must not remove the currently installed NAT/bridge rules.
def monitor_health():
    namespaces = json.loads(client('status', '--json').stdout)['namespaces']
    return next(ns for ns in namespaces if ns['id'] == name)['health']


# Wait for a successful monitor sample after the interface repair has finished;
# connectivity can return before that repair's health update is published.
def monitor_reconnected():
    current = monitor_health()
    return current['state'] == 'connected' and current['checked_at'] > health['checked_at']


wait_for(monitor_reconnected)
attempts = monitor_health()['reconnect_attempts']
command('ip', '-n', 'peer', 'link', 'set', 'wgpeer', 'down')


def repaired_again():
    return monitor_health()['reconnect_attempts'] > attempts


wait_for(repaired_again)
for table in ('vopono_nat', 'vopono_bridge'):
    listing = command('nft', '-j', 'list', 'table', 'inet', table)
    comments = [item['rule'].get('comment', '')
                for item in json.loads(listing.stdout)['nftables'] if 'rule' in item]
    assert any(comment.endswith('_uplink2') for comment in comments), (table, comments)
command('ip', '-n', 'peer', 'link', 'set', 'wgpeer', 'up')
wait_for(recovered)
wait_for(monitor_reconnected)
assert os.stat('/run/netns/' + name).st_ino == inode
assert Path('/proc/' + str(pid)).exists()
probe.close()
probe.assert_isolated()
client('stop', 'namespace', name, '--json')
app.wait(timeout=10)
# Recovery must not leave the old interface's masquerade/bridge rules behind.
for table in ('vopono_nat', 'vopono_bridge'):
    removed = subprocess.run(['nft', 'list', 'table', 'inet', table],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert removed.returncode != 0, f'Recovery leaked nftables table {table}'
print('PASS: DNS rotation, underlay replacement and repeated recovery preserve firewall rules, namespace/app identity and isolation', flush=True)

os.environ['PATH'] = original_path
context.restart()
