"""Real TLS OpenVPN connections, redacted failures and frozen-input recovery."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from common import Context, application_pid, command, wait_for
from isolation import LeakProbe

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
assert any(d['code'] == 'provider_config' and d['state'] == 'pass'
           for d in preflight['diagnostics'])
valid_profile = profile.read_text()
tcp_server = scratch / 'tcp-server.ovpn'
tcp_server.write_text(server.read_text().replace('proto udp', 'proto tcp-server')
                      .replace('port 1194', 'port 1196').replace('dev tun', 'dev tun_tcp')
                      .replace('10.8.0.0', '10.10.0.0').replace('10.8.0.1', '10.10.0.1'))
with (scratch / 'openvpn-tcp-server.log').open('w') as log:
    tcp_peer = subprocess.Popen(['ip', 'netns', 'exec', 'peer', 'openvpn', '--config', str(tcp_server)],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
# A TCP server initializes its tunnel only when its first client connects.
for backend, transport in [('nftables', 'udp'), ('iptables', 'udp'),
                           ('nftables', 'tcp-client'), ('iptables', 'tcp-client')]:
    short = 'tun_n' if backend == 'nftables' else 'tun_i'
    name = ctx.namespace(short)
    port = 1194 if transport == 'udp' else 1196
    contents = valid_profile.replace('proto udp', 'proto ' + transport).replace('remote 192.0.2.2', f'remote 192.0.2.2 {port}')
    profile = ctx.user_file('tls-' + backend + '.ovpn', contents)
    app = ctx.spawn(['exec', '--custom', str(profile), '--protocol', 'openvpn',
        '--custom-netns-name', short, '--interface', 'uplink', '--firewall', backend, '--open-ports', '4446',
        '--monitor', '--recover', 'sleep 240'], 'tls-client.log')


    def connected():
        return json.loads(ctx.client('check', name, '--skip-ipv6', '--skip-dns', '--json').stdout)['result']['connected']


    app_pid = wait_for(lambda: application_pid(ctx.status(name)), seconds=30)
    wait_for(connected, seconds=30)
    assert Path('/etc/resolv.conf').read_bytes() == host_dns
    inode = os.stat('/run/netns/' + name).st_ino
    record = json.loads((Path('/run/vopono/namespace-owners') / name).read_text())
    runtime = Path(record['namespace']['openvpn']['runtime_dir'])
    old_child = int((runtime / 'child.pid').read_text())
    # Force the original bootstrap DNS address onto the underlay. Its setup
    # exceptions must not remain an application bypass after VPN startup.
    ips = record['namespace']['veth_pair_ips']['ipv4']
    veth = record['namespace']['veth_pair']['source']
    command('ip', '-n', name, 'route', 'add', '8.8.8.8/32', 'via', ips['host_ip'], 'dev', veth)
    probe = LeakProbe(ctx, name, [('192.0.2.2', port), ('8.8.8.8', 53), ('8.8.8.8', 4445)])
    probe.wait_for_tunnel()
    routes = json.loads(command('ip', '-j', '-n', name, 'route', 'show').stdout)
    tunnel_routes = [r for r in routes if r['dst'] in ('0.0.0.0/1', '128.0.0.0/1')]
    assert len(tunnel_routes) == 2
    try:
        for route in tunnel_routes:
            command('ip', '-n', name, 'route', 'delete', route['dst'])
        time.sleep(.5)
        probe.assert_isolated()
    finally:
        for route in tunnel_routes:
            command('ip', '-n', name, 'route', 'replace', route['dst'], 'via', route['gateway'], 'dev', route['dev'])
    probe.wait_for_tunnel()
    # Destroy the original source, then kill the real tunnel child. Recovery must
    # use its root-owned frozen TLS/config inputs and leave the app running.
    profile.write_text('plugin /tmp/must-never-load.so\n')
    os.kill(old_child, signal.SIGKILL)
    wait_for(lambda: int((runtime / 'child.pid').read_text()) != old_child, seconds=90)
    wait_for(connected, seconds=30)
    assert os.stat('/run/netns/' + name).st_ino == inode
    assert Path(f'/proc/{app_pid}').exists()
    daemon = ctx.restart(abrupt=True)
    wait_for(connected)
    # Timestamps have one-second resolution: the replacement's first sample can
    # share the old sample's timestamp, then remain unchanged until the heartbeat.
    # The writer PID identifies the restarted monitor without that timing race.
    wait_for(lambda: ctx.status(name)['health']['daemon_pid'] == daemon.pid,
             seconds=25)
    probe.wait_for_tunnel()
    probe.close()
    probe.assert_isolated()
    ctx.client('stop', 'namespace', name, '--json')
    assert not runtime.exists()
    assert Path('/etc/resolv.conf').read_bytes() == host_dns
    app.wait(timeout=10)
    print(f'PASS: {backend} OpenVPN {transport} prevents plaintext across route loss, process recovery and daemon restart', flush=True)


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
for process in (peer, tcp_peer, auth_peer):
    process.terminate()
    process.wait(timeout=10)
print('PASS: local OpenVPN TLS, typed AUTH/TLS errors, host DNS, frozen-input recovery and crash adoption', flush=True)
