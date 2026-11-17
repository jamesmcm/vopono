"""Topology inspection through the authenticated daemon in the isolated harness."""
import json
from pathlib import Path
import sys

from common import Context

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
assert all(probe['state'] in ('pass', 'warning') for probe in probes)
# Reading an ownership snapshot must never arm its namespace cleanup resources.
assert Path('/run/netns', namespace).exists()
assert context.status(namespace)['id'] == namespace
print('PASS: daemon doctor resolver/interface details, offline mode and both veth directions')
