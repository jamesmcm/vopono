"""Topology inspection through the authenticated daemon in the isolated harness."""
import json
from pathlib import Path
import subprocess
import sys

from common import Context, command, wait_for

context = Context(*sys.argv[1:])
namespace = context.namespace('test_wg')
offline = json.loads(context.client('doctor', '--namespace', namespace,
                                    '--offline', '--json').stdout)
assert offline['daemon']['available'] and offline['daemon']['versions_match']
assert offline['daemon']['version'] == offline['daemon']['cli_version']
assert offline['host_network']['dns']['nameservers']
assert any(route['interface'] == 'uplink'
           for route in offline['host_network']['default_routes'])
network = offline['namespaces'][0]['network']
assert network['dns']['nameservers'] == ['10.66.0.1']
assert network['dns']['hosts_lookup'] == ['files', 'dns']
assert network['host_veth'] and network['namespace_veth']
assert network['tunnel_interfaces']
assert network['configured_host_uplink'] == 'uplink'
assert network['recorded_veth_addresses']['ipv4']
assert network['routes'] and not network['link_probes']
assert all(d['code'] != 'probe_unavailable' for d in network['diagnostics'])

# Host DNS may fail independently of a healthy namespace in this isolated net.
output = context.client('doctor', '--namespace', namespace, '--timeout-ms', '500',
                        '--json', check=False)
report = json.loads(output.stdout)
result = report['namespaces'][0]
assert result['connectivity']['connected']
assert result['connectivity']['dns']['resolved_ips']
assert any(d['code'] == 'host_dns' for d in report['diagnostics'])
probes = result['network']['link_probes']
assert len(probes) == 4
assert {probe['direction'] for probe in probes} == {
    'host -> namespace', 'namespace -> host'
}
assert all(probe['state'] in ('pass', 'skipped') for probe in probes)
assert not any(d['code'] == 'host_link' and d['state'] == 'warning'
               for d in result['network']['diagnostics'])
# Reading an ownership snapshot must never arm its namespace cleanup resources.
assert Path('/run/netns', namespace).exists()
assert context.status(namespace)['id'] == namespace
print('PASS: daemon doctor resolver/interface details, offline mode and inconclusive ICMP')


def service_report(name, *flags):
    output = context.client('doctor', '--namespace', name, '--timeout-ms', '150',
                            '--json', *flags, check=False)
    return json.loads(output.stdout)['namespaces'][0]['network']


# Verify enabled services independently of the synthetic VPN peer. No default
# Internet route or application payload is required for these local checks.
for firewall in ('nftables', 'iptables'):
    name = context.namespace('doctor_services')
    context.client('exec', '--provider', 'none', '--custom-netns-name', 'doctor_services',
                   '--interface', 'uplink', '--firewall', firewall, '--dns', '10.66.0.1',
                   '--allow-host-access', '--forward', '43140', '--forward', '43142', '--open-ports', '43141',
                   '--create-netns-only', '')
    server = None
    try:
        server = subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-c',
            'import socket,time\n'
            'a=socket.socket(socket.AF_INET6); a.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); a.bind(("::",43140)); a.listen(128)\n'
            'b=socket.socket(); b.bind(("127.0.0.1",43142)); b.listen(128)\n'
            'u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind(("0.0.0.0",43141))\n'
            'time.sleep(120)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        def listeners_ready():
            out = command('ip', 'netns', 'exec', name, 'ss', '-H', '-lntu').stdout
            return all(port in out for port in (':43140', ':43142', ':43141'))
        wait_for(listeners_ready)
        def addresses_ready():
            # IPv6 DAD can still be in progress just after namespace creation.
            for args in [('ip', '-j', '-6', 'address', 'show'),
                         ('ip', '-j', '-6', '-n', name, 'address', 'show')]:
                for interface in json.loads(command(*args).stdout):
                    if any(address.get('tentative') or 'tentative' in address.get('flags', [])
                           for address in interface.get('addr_info', [])):
                        return False
            return True
        wait_for(addresses_ready)
        network = service_report(name)
        diagnostics = network['diagnostics']
        access = [d for d in diagnostics if '--allow-host-access namespace -> host' in d['message']]
        assert len(access) == 2 and all(d['state'] == 'pass' for d in access), access
        backend = [d for d in diagnostics if 'host -> IPv4 namespace port 43140' in d['message']]
        assert len(backend) == 1 and backend[0]['state'] == 'pass', backend
        assert any('--forward 43142' in d['message'] and d['state'] == 'warning'
                   and 'no backend' in d['message'] for d in diagnostics), diagnostics
        assert any('UDP 0.0.0.0:43141' in d['message'] and d['state'] == 'skipped'
                   for d in diagnostics), diagnostics
        # A real host input drop must produce a service warning, even though
        # the veth remains UP. Inspection must leave that policy in place.
        command('nft', 'add', 'table', 'inet', 'doctor_services')
        try:
            command('nft', 'add', 'chain', 'inet', 'doctor_services', 'input',
                    '{ type filter hook input priority -200; policy accept; }')
            command('nft', 'add', 'rule', 'inet', 'doctor_services', 'input',
                    'iifname', network['host_veth'], 'meta', 'l4proto', 'tcp', 'drop')
            access = [d for d in service_report(name)['diagnostics']
                      if '--allow-host-access namespace -> host' in d['message']]
            assert len(access) == 2 and all(d['state'] == 'warning' for d in access), access
            command('nft', 'list', 'table', 'inet', 'doctor_services')
        finally:
            command('nft', 'delete', 'table', 'inet', 'doctor_services')
        # An existing namespace listener behind a drop is a useful warning;
        # absence of a listener alone must not be blamed on the firewall.
        command('ip', 'netns', 'exec', name, 'nft', 'add', 'table', 'inet', 'doctor_backend')
        command('ip', 'netns', 'exec', name, 'nft', 'add', 'chain', 'inet', 'doctor_backend', 'input',
                '{ type filter hook input priority -200; policy accept; }')
        command('ip', 'netns', 'exec', name, 'nft', 'add', 'rule', 'inet', 'doctor_backend', 'input',
                'tcp', 'dport', '43140', 'drop')
        diagnostics = service_report(name)['diagnostics']
        assert any('host -> IPv4 namespace port 43140' in d['message']
                   and d['state'] == 'warning' for d in diagnostics), diagnostics
        offline = service_report(name, '--offline')
        assert not offline['link_probes']
        tcp_offline = [d for d in offline['diagnostics'] if 'TCP connect' in d['message']]
        assert len(tcp_offline) >= 3 and all(d['state'] == 'skipped' for d in tcp_offline), offline
    finally:
        try:
            if server is not None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
        finally:
            context.client('stop', 'namespace', name, '--json')

name = context.namespace('doctor_no_proxy')
context.client('exec', '--provider', 'none', '--custom-netns-name', 'doctor_no_proxy',
               '--interface', 'uplink', '--firewall', 'nftables', '--dns', '10.66.0.1',
               '--forward', '43144', '--no-proxy', '--create-netns-only', '')
try:
    diagnostics = service_report(name)['diagnostics']
    assert any('--forward 43144' in d['message'] and d['state'] == 'skipped'
               and '--no-proxy' in d['message'] for d in diagnostics), diagnostics
finally:
    context.client('stop', 'namespace', name, '--json')
print('PASS: enabled host access, dual-stack TCP backend, UDP, loopback-only relay, drops and no-proxy')
