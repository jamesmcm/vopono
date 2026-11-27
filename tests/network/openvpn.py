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
trusted_profile = ctx.user_file('trusted-client.ovpn', f'cd "{scratch}"\n' + valid_profile)
direct_env = {**os.environ, 'XDG_CONFIG_HOME': str(scratch / 'config'),
              'SUDO_USER': ctx.user, 'SUDO_UID': str(ctx.uid), 'SUDO_GID': str(ctx.gid)}
direct = subprocess.run(
    [ctx.binary, 'exec', '--custom', str(trusted_profile), '--protocol', 'openvpn',
     '--interface', 'uplink', '--firewall', 'nftables', 'printf trusted-openvpn'],
    env=direct_env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
)
assert direct.returncode == 0 and 'trusted-openvpn' in direct.stdout, direct.stderr
refused = ctx.client('exec', '--custom', str(trusted_profile), '--protocol', 'openvpn',
                     '--interface', 'uplink', '--firewall', 'nftables', '--json', 'true', check=False)
assert refused.returncode != 0 and any('directive "cd"' in d['message']
    for d in json.loads(refused.stdout)['error']['diagnostics'])
print('PASS: trusted direct OpenVPN accepts a working-directory directive while the daemon refuses it', flush=True)
# The installed service normally inherits umask 022. A private runtime
# directory must also be created under that umask.
ctx.restart(umask=0o022)
auth_override = ctx.user_file('override-auth.txt', 'fixture-user\nfixture-password\n')
contents = valid_profile + 'auth-user-pass missing-profile-auth.txt\n'
help_text = command('openvpn', '--help', check=False).stdout
if '--disable-dco' in help_text:
    contents += 'disable-dco\n'
override_profile = ctx.user_file('override-auth-client.ovpn', contents)
override_name = ctx.namespace('auth_override')
override_application = ctx.spawn([
    'exec', '--custom', str(override_profile), '--protocol', 'openvpn',
    '--auth-user-pass', str(auth_override), '--interface', 'uplink', '--firewall', 'nftables',
    '--custom-netns-name', 'auth_override', 'sleep 180',
], 'auth-override.log')
wait_for(lambda: application_pid(ctx.status(override_name)))
[runtime] = Path('/run').glob('vopono-openvpn-*')
assert runtime.stat().st_mode & 0o777 == 0o700
for item in [runtime / 'auth.txt', *runtime.glob('input-*')]:
    assert item.stat().st_mode & 0o777 == 0o600
ctx.client('stop', 'namespace', override_name, '--json')
override_application.wait(timeout=15)
rejected_profile = ctx.user_file('unsupported-client.ovpn', valid_profile + 'plugin SECRET_ARGUMENT\n')
rejected = ctx.client(
    'exec', '--custom', str(rejected_profile), '--protocol', 'openvpn', '--interface',
    'uplink', '--firewall', 'nftables', '--json', 'true', check=False,
)
assert rejected.returncode != 0
assert 'OpenVPN directive "plugin" on line' in json.loads(rejected.stdout)['error']['message']
assert 'SECRET_ARGUMENT' not in rejected.stdout + rejected.stderr
print('PASS: OpenVPN uses private inputs with umask 022, honors auth overrides and reports rejected directives', flush=True)

# After the VPN dies, namespace DNS is blocked by the kill switch even when
# host DNS can still resolve the same transport endpoint.
hostname = 'vpn-recovery.test'
hostname_profile = ctx.user_file(
    'hostname-client.ovpn', valid_profile.replace('proto udp', 'proto udp4')
    .replace('remote 192.0.2.2', f'remote {hostname}'))
hostname_name = ctx.namespace('hostname_recovery')
resolv = Path('/etc/resolv.conf')
resolv.write_text('nameserver 192.0.2.2\noptions timeout:1 attempts:1\n')
hostname_app = ctx.spawn([
    'exec', '--custom', str(hostname_profile), '--protocol', 'openvpn',
    '--interface', 'uplink', '--firewall', 'nftables', '--dns', '192.0.2.2',
    '--custom-netns-name', 'hostname_recovery', '--monitor', '--recover', 'sleep 150',
], 'hostname-client.log')
try:
    assert command('getent', 'ahostsv4', hostname).stdout.startswith('192.0.2.2 ')
    app_pid = wait_for(lambda: application_pid(ctx.status(hostname_name)), seconds=30)
    record = json.loads((Path('/run/vopono/namespace-owners') / hostname_name).read_text())
    runtime = Path(record['namespace']['openvpn']['runtime_dir'])
    assert 'remote 192.0.2.2' in (runtime / 'recovery.ovpn').read_text()
    old_child = int((runtime / 'child.pid').read_text())
    os.kill(old_child, signal.SIGKILL)
    wait_for(lambda: int((runtime / 'child.pid').read_text()) != old_child, seconds=75)
    def hostname_tunnel_is_up():
        return ctx.client('check', hostname_name, '--skip-ipv6', '--skip-dns',
                          '--timeout-ms', '500', check=False).returncode == 0
    wait_for(hostname_tunnel_is_up, seconds=20)
    assert Path(f'/proc/{app_pid}').exists()
finally:
    ctx.client('stop', 'namespace', hostname_name, '--json', check=False)
    hostname_app.wait(timeout=15)
    resolv.write_bytes(host_dns)
print('PASS: OpenVPN recovers a hostname endpoint with no namespace bootstrap DNS', flush=True)

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
    if backend == 'iptables' and transport == 'tcp-client':
        # The OpenVPN process must exit even when its supervisor cannot run
        # normal shutdown. The application remains available for explicit stop.
        supervisor_pid = record['namespace']['openvpn']['pid']
        child_pid = int((runtime / 'child.pid').read_text())
        os.kill(supervisor_pid, signal.SIGKILL)
        wait_for(lambda: not Path(f'/proc/{child_pid}').exists()
                 or 'State:\tZ' in Path(f'/proc/{child_pid}/status').read_text())
        assert Path(f'/proc/{app_pid}').exists()
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

# A daemon crash during an unfinished OpenVPN handshake must NEVER fail open:
# the namespace has an active underlay/NAT route before the killswitch is
# installed, so the restarted daemon must tear it down and refuse attachment.
hang_name = ctx.namespace('ovpn-crash-handshake')
hang_profile = ctx.user_file(
    'hang-client.ovpn',
    base_profile + 'remote 192.0.2.2 1199\n',
)
hanging = ctx.spawn(
    [
        'exec',
        '--custom',
        str(hang_profile),
        '--protocol',
        'openvpn',
        '--custom-netns-name',
        'ovpn-crash-handshake',
        '--interface',
        'uplink',
        '--firewall',
        'nftables',
        'true',
    ],
    'ovpn-crash-handshake.log',
)
owner_record = Path('/run/vopono/namespace-owners') / hang_name
wait_for(
    lambda: Path('/run/netns', hang_name).exists()
    and owner_record.exists()
    and subprocess.run(
        ['nft', 'list', 'table', 'inet', 'vopono_bridge'],
        stdin=subprocess.DEVNULL,
        capture_output=True,
    ).returncode == 0
)
assert json.loads(owner_record.read_text())['lifecycle'] == 'initializing'
# Crash the daemon mid-handshake (before OpenVPN connects or installs killswitch).
ctx.restart(abrupt=True)
hanging.wait(timeout=15)
# Restarted daemon must have torn down the unfinished namespace and host rules before serving clients.
assert not Path('/run/netns', hang_name).exists(), 'unfinished namespace survived daemon restart'
assert not owner_record.exists(), 'initializing ownership record survived daemon restart'
for table in ('vopono_nat', 'vopono_bridge'):
    assert subprocess.run(
        ['nft', 'list', 'table', 'inet', table],
        stdin=subprocess.DEVNULL,
        capture_output=True,
    ).returncode != 0, f'unfinished handshake leaked nftables table {table}'
attach = ctx.client(
    'exec',
    '--existing-netns',
    hang_name,
    '--interface',
    'uplink',
    'python3 -c "import urllib.request; print(urllib.request.urlopen(\'http://192.0.2.2:18080\', timeout=2).read())"',
    check=False,
    timeout=15,
)
assert attach.returncode != 0, f'unexpectedly attached to crashed handshake namespace: {attach.stdout}'
assert Path('/etc/resolv.conf').read_bytes() == host_dns

for process in (peer, tcp_peer, auth_peer):
    process.terminate()
    process.wait(timeout=10)
print('PASS: local OpenVPN TLS, typed AUTH/TLS errors, host DNS, frozen-input recovery, handshake-crash fail-closed and crash adoption', flush=True)
