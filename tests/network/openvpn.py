"""Real TLS OpenVPN connections, redacted failures and frozen-input recovery."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from common import Context, command, wait_for

ctx = Context(*sys.argv[1:])
scratch = ctx.scratch
host_dns = Path('/etc/resolv.conf').read_bytes()


def failure_details(kind, error, traceback):
    for path in [scratch / 'openvpn-server.log', scratch / 'tls-client.log', *Path('/run').glob('vopono-openvpn-*/openvpn.log')]:
        if path.exists():
            print(f'Failure diagnostics: {path.name}', flush=True)
            print('\n'.join(path.read_text(errors='replace').splitlines()[-35:]), flush=True)
    sys.__excepthook__(kind, error, traceback)


sys.excepthook = failure_details


def certificate(name, usage=None):
    key, csr, cert = [scratch / f'{name}.{ext}' for ext in ('key', 'csr', 'crt')]
    command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
            '-out', str(csr), '-subj', f'/CN={name}')
    if usage:
        extension = scratch / f'{name}.ext'
        extension.write_text(f'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\n')
        command('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(scratch / 'ca.crt'),
                '-CAkey', str(scratch / 'ca.key'), '-CAcreateserial', '-days', '1',
                '-out', str(cert), '-extfile', str(extension))
    else:
        command('openssl', 'x509', '-req', '-in', str(csr), '-signkey', str(key),
                '-days', '1', '-out', str(cert), '-extfile', '/dev/stdin', timeout=15)
    return key, cert


# CA extensions are explicit so certificate validation behaves consistently
# across OpenSSL/OpenVPN versions.
command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', str(scratch / 'ca.key'), '-out', str(scratch / 'ca.crt'),
        '-subj', '/CN=vopono-test-ca', '-addext', 'basicConstraints=critical,CA:TRUE')
server_key, server_cert = certificate('server', 'serverAuth')
client_key, client_cert = certificate('client', 'clientAuth')
for path in (scratch / 'ca.crt', client_key, client_cert):
    os.chown(path, ctx.uid, ctx.gid)
    path.chmod(0o600)
server = scratch / 'server.ovpn'
server.write_text(f'''dev tun
proto udp
local 192.0.2.2
port 1194
server 10.8.0.0 255.255.255.0
topology subnet
ca {scratch / 'ca.crt'}
cert {server_cert}
key {server_key}
dh none
data-ciphers AES-256-GCM
push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
keepalive 1 10
persist-key
persist-tun
verb 3
''')
server_log = scratch / 'openvpn-server.log'
with server_log.open('w') as log:
    peer = subprocess.Popen(['ip', 'netns', 'exec', 'peer', 'openvpn', '--config', str(server)],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
wait_for(lambda: 'Initialization Sequence Completed' in server_log.read_text(), seconds=20)
profile = ctx.user_file('tls-client.ovpn', f'''client
dev tun
proto udp
remote 192.0.2.2
nobind
persist-key
persist-tun
ca '{scratch / 'ca.crt'}'
cert '{client_cert}'
key '{client_key}'
remote-cert-tls server
data-ciphers AES-256-GCM
verb 3
''')
preflight = json.loads(ctx.client('doctor', '--custom', str(profile), '--offline', '--json').stdout)
assert preflight['diagnostics'][0]['state'] == 'pass'
name = ctx.namespace('tls')
app = ctx.spawn(['exec', '--custom', str(profile), '--protocol', 'openvpn',
    '--custom-netns-name', 'tls', '--interface', 'uplink', '--firewall', 'nftables',
    '--monitor', '--recover', 'sleep 240'], 'tls-client.log')


def connected():
    return json.loads(ctx.client('check', name, '--skip-ipv6', '--skip-dns', '--json').stdout)['result']['connected']


wait_for(lambda: bool(ctx.status(name)['applications']), seconds=30)
wait_for(connected, seconds=30)
assert Path('/etc/resolv.conf').read_bytes() == host_dns
inode = os.stat('/run/netns/' + name).st_ino
app_pid = ctx.status(name)['applications'][0]['pid']
record = json.loads((Path('/run/vopono/namespace-owners') / name).read_text())
runtime = Path(record['namespace']['openvpn']['runtime_dir'])
old_child = int((runtime / 'child.pid').read_text())
# Destroy the original source, then kill the real tunnel child. Recovery must
# use its root-owned frozen TLS/config inputs and leave the app running.
profile.write_text('plugin /tmp/must-never-load.so\n')
os.kill(old_child, signal.SIGKILL)
wait_for(lambda: int((runtime / 'child.pid').read_text()) != old_child, seconds=90)
wait_for(connected, seconds=30)
assert os.stat('/run/netns/' + name).st_ino == inode
assert Path(f'/proc/{app_pid}').exists()
checked_before_restart = ctx.status(name)['health']['checked_at']
ctx.restart(abrupt=True)
wait_for(connected)
wait_for(lambda: ctx.status(name)['health']['checked_at'] > checked_before_restart,
         seconds=25)
ctx.client('stop', 'namespace', name, '--json')
assert not runtime.exists()
assert Path('/etc/resolv.conf').read_bytes() == host_dns
app.wait(timeout=10)

# Explicit server authentication rejection must retain its typed diagnosis and
# collect independent config/DNS/route evidence without echoing credentials.
reject = scratch / 'reject-auth.sh'
reject.write_text('#!/bin/sh\nexit 1\n')
reject.chmod(0o755)
auth_server = scratch / 'auth-server.ovpn'
auth_server.write_text(server.read_text().replace('port 1194', 'port 1195').replace('dev tun', 'dev tun_auth').replace('10.8.0.0', '10.9.0.0') +
    f'auth-user-pass-verify {reject} via-file\nscript-security 2\nverify-client-cert none\n')
with (scratch / 'openvpn-auth-server.log').open('w') as log:
    auth_peer = subprocess.Popen(['ip', 'netns', 'exec', 'peer', 'openvpn', '--config', str(auth_server)],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
wait_for(lambda: 'Initialization Sequence Completed' in (scratch / 'openvpn-auth-server.log').read_text())
auth = ctx.user_file('credentials.txt', 'test-user\nNEVER_SHARE_PASSWORD\n')
base_profile = f'''client
dev tun
proto udp
nobind
ca '{scratch / 'ca.crt'}'
cert '{client_cert}'
key '{client_key}'
remote-cert-tls server
data-ciphers AES-256-GCM
'''
auth_profile = ctx.user_file('auth-client.ovpn', base_profile + f'remote 192.0.2.2 1195\nauth-user-pass {auth}\n')
result = ctx.client('exec', '--custom', str(auth_profile), '--protocol', 'openvpn',
    '--custom-netns-name', 'authfail', '--interface', 'uplink', '--firewall', 'nftables', '--json', 'true', check=False, timeout=30)
assert result.returncode != 0
report = json.loads(result.stdout)['error']['diagnostics']
assert report[0]['code'] == 'tunnel_authentication', result.stdout
assert any(d['code'] == 'provider_config' and d['state'] == 'pass' for d in report)
# Daemon launch diagnostics must not probe the host network as root.
assert not any(d['code'] == 'endpoint_dns' for d in report)
assert 'NEVER_SHARE_PASSWORD' not in result.stdout + result.stderr

# A valid but wrong trust root triggers a TLS error, rather than a timeout or
# a generic authentication failure.
command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', str(scratch / 'wrong.key'), '-out', str(scratch / 'wrong.crt'),
        '-subj', '/CN=unrelated-test-ca', '-addext', 'basicConstraints=critical,CA:TRUE')
os.chown(scratch / 'wrong.crt', ctx.uid, ctx.gid)
tls_profile = ctx.user_file('wrong-ca.ovpn', base_profile.replace(str(scratch / 'ca.crt'), str(scratch / 'wrong.crt')) + 'remote 192.0.2.2 1194\n')
result = ctx.client('exec', '--custom', str(tls_profile), '--protocol', 'openvpn',
    '--custom-netns-name', 'tlsfail', '--interface', 'uplink', '--firewall', 'nftables', '--json', 'true', check=False, timeout=30)
assert result.returncode != 0
assert json.loads(result.stdout)['error']['diagnostics'][0]['code'] == 'tunnel_tls', result.stdout
assert Path('/etc/resolv.conf').read_bytes() == host_dns
for process in (peer, auth_peer):
    process.terminate()
    process.wait(timeout=10)
print('PASS: local OpenVPN TLS, typed AUTH/TLS errors, host DNS, frozen-input recovery and crash adoption', flush=True)
