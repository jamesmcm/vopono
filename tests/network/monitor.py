"""Detect live forwarding and DNS changes without replacing external policy."""
import json
from pathlib import Path
import subprocess
import sys

from common import Context, command, wait_for

context = Context(*sys.argv[1:])
namespace = context.namespace('test_wg')


def health():
    return context.status(namespace)['health']


def connected():
    current = health()
    return current if current and current['state'] == 'connected' else None


initial = wait_for(connected, seconds=40)
assert initial['daemon_version'] and initial['daemon_pid']
codes = {d['code'] for d in initial['diagnostics']}
assert {'host_dns', 'endpoint_dns', 'dns_configuration', 'network_interface',
        'host_link', 'host_forwarding', 'host_firewall', 'app_armor',
        'network_manager'} <= codes, codes
report = json.loads(context.client('doctor', '--namespace', namespace,
                                  '--offline', '--json').stdout)
veth = report['namespaces'][0]['network']['host_veth']

command('nft', 'add', 'table', 'inet', 'monitor_test')
try:
    command('nft', 'add', 'chain', 'inet', 'monitor_test', 'forward',
            '{ type filter hook forward priority -200; policy accept; }')
    command('nft', 'add', 'rule', 'inet', 'monitor_test', 'forward',
            'iifname', veth, 'drop')

    def firewall_detected():
        current = health()
        if (current['state'] != 'connected'
                and current['diagnostics_checked_at'] > initial['diagnostics_checked_at']
                and any(d['code'] == 'host_firewall' and d['state'] == 'warning'
                        and 'DROP/REJECT' in d['message'] for d in current['diagnostics'])):
            return current

    wait_for(firewall_detected, seconds=50)
    # Monitoring/recovery must leave an administrator's external policy intact.
    command('nft', 'list', 'table', 'inet', 'monitor_test')
finally:
    command('nft', 'delete', 'table', 'inet', 'monitor_test')

restored = wait_for(connected, seconds=45)
dns = Path('/etc/netns', namespace, 'resolv.conf')
original = dns.read_text()
try:
    dns.write_text('nameserver 100.100.100.100\noptions timeout:1 attempts:1\n')

    def dns_detected():
        current = health()
        if (current['state'] == 'degraded'
                and current['diagnostics_checked_at'] > restored['diagnostics_checked_at']
                and any(d['code'] == 'tailscale_dns' and d['state'] == 'warning'
                        for d in current['diagnostics'])):
            assert current['last_error'] == 'Namespace DNS probe failed'
            assert current['reconnect_attempts'] == restored['reconnect_attempts']
            return current

    wait_for(dns_detected, seconds=50)
finally:
    dns.write_text(original)

restored = wait_for(connected, seconds=45)
# An IPv6-only filter must not be hidden by the successful IPv4 TCP probe.
nft_namespace = ('ip', 'netns', 'exec', namespace, 'nft')
command(*nft_namespace, 'add', 'table', 'ip6', 'monitor_family_test')
try:
    command(*nft_namespace, 'add', 'chain', 'ip6', 'monitor_family_test', 'output',
            '{ type filter hook output priority -200; policy accept; }')
    command(*nft_namespace, 'add', 'rule', 'ip6', 'monitor_family_test', 'output',
            'tcp', 'dport', '443', 'drop')

    def partial_failure_detected():
        current = health()
        if current['state'] == 'degraded' and 'IPv6 TCP' in (current['last_error'] or ''):
            assert current['reconnect_attempts'] == restored['reconnect_attempts']
            return current

    wait_for(partial_failure_detected, seconds=50)
finally:
    command(*nft_namespace, 'delete', 'table', 'ip6', 'monitor_family_test')

wait_for(connected, seconds=45)
print('PASS: monitor detects firewall, MagicDNS and partial-family changes and preserves external policy')

# A missing address family in the profile must not create permanent degradation.
for family, address, resolver in [('IPv4', '10.66.0.3/32', '10.66.0.1'),
                                  ('IPv6', 'fd66::3/128', 'fd66::1')]:
    private = command('wg', 'genkey').stdout.strip()
    public = subprocess.run(['wg', 'pubkey'], input=private, text=True,
                            capture_output=True, check=True).stdout.strip()
    command('ip', 'netns', 'exec', 'peer', 'wg', 'set', 'wgpeer', 'peer', public,
            'allowed-ips', address)
    short = 'monitor_' + family.lower()
    single_namespace = context.namespace(short)
    profile = (context.scratch / 'client.conf').read_text()
    lines = [f'PrivateKey = {private}' if line.startswith('PrivateKey =') else
             f'Address = {address}' if line.startswith('Address =') else
             f'DNS = {resolver}' if line.startswith('DNS =') else line
             for line in profile.splitlines()]
    path = context.user_file(short + '.conf', '\n'.join(lines) + '\n')
    app = context.spawn(['exec', '--custom', str(path), '--protocol', 'wireguard',
                         '--custom-netns-name', short, '--interface', 'uplink',
                         '--firewall', 'nftables', '--monitor', '--recover', 'sleep 120'],
                        short + '.log')
    try:
        def single_family_connected():
            current = context.status(single_namespace)['health']
            return current if current and current['state'] == 'connected' else None

        current = wait_for(single_family_connected, seconds=40)
        assert current['reconnect_attempts'] == 0
        probes = [d for d in current['diagnostics'] if d['code'] == 'tunnel_connectivity']
        assert len(probes) == 1 and probes[0]['message'].startswith(family + ' TCP'), probes
    finally:
        context.client('stop', 'namespace', single_namespace, '--json', check=False)
        app.wait(timeout=20)
        command('ip', 'netns', 'exec', 'peer', 'wg', 'set', 'wgpeer', 'peer', public, 'remove')

print('PASS: IPv4-only and IPv6-only monitors probe only their configured families')
