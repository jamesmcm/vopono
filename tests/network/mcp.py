"""Real MCP stdio clients and daemon jobs in disposable host namespaces."""
import json
import os
from pathlib import Path
import selectors
import signal
import shlex
import shutil
import subprocess
import sys
import time
from common import Context, command, wait_for

ctx = Context(*sys.argv[1:])
invalid = ctx.user_file('mcp-invalid.conf', '[Interface]\nPrivateKey=NEVER_SHARE_MCP_KEY\n')
config = ctx.user_file('mcp-settings.toml', f'''
[profiles.fixed]
provider = "none"
interface = "uplink"
firewall = "nftables"
application = "sleep 120"
keep-alive = true
[profiles.vpn]
monitor = true
custom = "{ctx.scratch / 'client.conf'}"
protocol = "wireguard"
interface = "uplink"
firewall = "nftables"
application = "sleep 120"
working-directory = "{ctx.scratch}"
[profiles.broken]
custom = "{invalid}"
protocol = "wireguard"
interface = "uplink"
firewall = "nftables"
application = "true"
''')


class MCP:
    def __init__(self, *options):
        self.sequence = 0
        self.log = (ctx.scratch / f'mcp-{time.monotonic_ns()}.log').open('w')
        self.process = subprocess.Popen(ctx.base + ['mcp', 'serve', '--vopono-config', str(config),
            '--max-jobs', '2', '--max-job-seconds', '120', *options],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True)
        self.request('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'vopono-network-test', 'version': '1'}})
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + '\n')
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        self.send({'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params})
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(30), 'MCP request timed out'
        line = self.process.stdout.readline()
        assert line, f'MCP exited unexpectedly: {self.process.poll()}'
        result = json.loads(line)
        assert result['id'] == self.sequence and 'error' not in result, result
        return result['result']

    def call(self, name, **arguments):
        result = self.request('tools/call', {'name': name, 'arguments': arguments})
        assert not result['isError'], result
        return result['structuredContent']

    def finish(self, job):
        wait_for(lambda: self.call('job_status', job_id=job['job_id'])['finished'], seconds=15)
        result = self.call('job_status', job_id=job['job_id'])
        assert not result['cleanup_pending'], result
        assert not Path('/run/netns', job['namespace']).exists(), result
        return result

    def close(self, terminate=False):
        if terminate:
            # Signal the server, not the runuser wrapper.
            children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
            assert len(children) == 1, children
            os.kill(int(children[0]), signal.SIGTERM)
        else:
            self.process.stdin.close()
        self.process.wait(timeout=15)
        assert self.process.returncode == 0
        self.log.close()


# Default application only and explicit profile restrictions are enforced.
restricted = MCP('--allow-profile', 'fixed')
assert restricted.call('profiles_list')['profiles'] == ['fixed']
assert restricted.request('tools/call', {'name': 'run_profile', 'arguments': {
    'profile': 'fixed', 'argv': ['true']}})['isError']
assert restricted.request('tools/call', {'name': 'doctor', 'arguments': {'profile': 'vpn'}})['isError']
job = restricted.call('run_profile', profile='fixed')
restricted.call('job_cancel', job_id=job['job_id'])
cancelled = restricted.finish(job)
assert cancelled['state'] == 'cancelled', cancelled
restricted.close()

# A definite daemon admission refusal must not become an unresolved job.
admission_name = ctx.namespace('mcp_admission')
ctx.client('exec', '--provider', 'none', '--custom-netns-name', 'mcp_admission',
           '--interface', 'uplink', '--firewall', 'nftables', '--create-netns-only')
occupants = [ctx.spawn(['exec', '--existing-netns', admission_name, '--interface', 'uplink',
    'sleep 90'], f'mcp-admission-{index}.log') for index in range(8)]
wait_for(lambda: len(ctx.status(admission_name)['applications']) == 8)
refused_server = MCP('--allow-profile', 'fixed')
refused = refused_server.call('run_profile', profile='fixed')
refusal = refused_server.finish(refused)
assert refusal['state'] == 'failed', refusal
assert 'execution limit' in refusal['error']['message'], refusal
assert refusal['error']['message'] == refusal['error']['error']['message'], refusal
refused_server.close()
ctx.client('stop', 'namespace', admission_name, '--json')
for occupant in occupants:
    occupant.wait(timeout=15)
print('PASS: explicit daemon admission refusals remain definite, cleaned-up MCP failures', flush=True)

server = MCP('--allow-command')
assert any(d['code'] == 'provider_config' and d['state'] == 'pass'
           for d in server.call('doctor', profile='vpn')['diagnostics'])
bad = server.request('tools/call', {'name': 'doctor', 'arguments': {'profile': 'broken'}})
assert bad['isError'] and 'NEVER_SHARE_MCP_KEY' not in json.dumps(bad)
noisy = "import os,subprocess,sys,time; subprocess.Popen(['sleep','120']); sys.stdout.write('x'*200000+'\\nLITERAL:'+repr(sys.argv[1:])+'\\n'); sys.stdout.flush(); sys.stderr.write('stderr-marker:'+os.getcwd()+'\\n'); sys.stderr.flush(); time.sleep(120)"
vpn = server.call('run_profile', profile='vpn', argv=['python3', '-c', noisy, '', 'a b', "a'b", '$HOME'])
other = server.call('run_profile', profile='fixed')
assert server.request('tools/call', {'name': 'run_profile', 'arguments': {'profile': 'fixed'}})['isError']


def output_ready():
    result = server.call('job_output', job_id=vpn['job_id'], max_bytes=16384)
    return result['stdout']['total_bytes'] > 200000


wait_for(output_ready)


def vpn_connected():
    # Application output can precede the first WireGuard handshake. A failed
    # readiness probe is expected while that asynchronous setup completes.
    result = server.request('tools/call', {'name': 'check', 'arguments': {
        'namespace': vpn['namespace'], 'timeout_ms': 300,
        'skip_dns': True, 'skip_ipv6': True}})
    return not result['isError'] and result['structuredContent']['result']['connected']


wait_for(vpn_connected, seconds=10)


def monitored_health():
    snapshot = server.call('health', namespace=vpn['namespace'])
    sample = snapshot['namespaces'][0]['health']
    return sample if sample and sample['state'] == 'connected' and sample['diagnostics'] else None


sample = wait_for(monitored_health, seconds=20)
assert sample['checked_at'] and sample['daemon_pid'] and sample['diagnostics_checked_at']
assert any(d['code'] == 'host_firewall' for d in sample['diagnostics'])
all_health = server.call('health')['namespaces']
assert any(ns['id'] == vpn['namespace'] and ns['health'] for ns in all_health)
assert any(ns['id'] == other['namespace'] and ns['health'] is None for ns in all_health)
# Full doctor reports can exceed job log history once monitor evidence is included.
large_sidecar = ctx.scratch / 'config/vopono/locks' / vpn['namespace'] / 'health.json'
original_large = large_sidecar.read_bytes()
try:
    large = json.loads(original_large)
    large['last_error'] = 'large-cached-evidence-' + 'x' * max(0, 60000 - len(original_large))
    large_sidecar.write_text(json.dumps(large))
    response = server.request('tools/call', {'name': 'doctor', 'arguments': {'namespace': vpn['namespace']}})
    large_report = response['structuredContent']
    cached = large_report['namespaces'][0]['health']
    assert cached['last_error'] == large['last_error'], response
    assert len(json.dumps(large_report)) > 65536, 'Fixture did not exceed job log history'
finally:
    large_sidecar.write_bytes(original_large)
# Cached telemetry must retain the same staleness semantics as CLI status.
sidecar = ctx.scratch / 'config/vopono/locks' / vpn['namespace'] / 'health.json'
original = sidecar.read_bytes()
try:
    stale = json.loads(original)
    stale['checked_at'] = 1
    sidecar.write_text(json.dumps(stale))
    cached = server.call('health', namespace=vpn['namespace'])['namespaces'][0]['health']
    assert cached['state'] == 'degraded' and 'stale' in cached['last_error']
finally:
    sidecar.write_bytes(original)
for arguments in ({}, {'namespace': vpn['namespace']},
                  {'namespace': vpn['namespace'], 'offline': False, 'timeout_ms': 300,
                   'dns_host': 'one.one.one.one', 'skip_ipv6': True}):
    response = server.request('tools/call', {'name': 'doctor', 'arguments': arguments})
    report = response['structuredContent']
    diagnosed = next(ns for ns in report['namespaces'] if ns['id'] == vpn['namespace'])
    assert diagnosed['health']['checked_at'] and diagnosed['network']['dns']['nameservers']
    if arguments.get('offline') is False:
        assert diagnosed['connectivity']['connected'] and diagnosed['connectivity']['dns']['resolved_ips']
assert server.request('tools/call', {'name': 'health', 'arguments': {'namespace': 'not-owned'}})['isError']
print('PASS: MCP namespace doctor, live DNS probes, cached health, stale/unmonitored samples and diagnostic evidence', flush=True)
snapshot = server.call('job_output', job_id=vpn['job_id'], stdout_offset=200000, max_bytes=16384)
assert snapshot['stdout']['dropped_bytes'] == 0
assert 'LITERAL:' in snapshot['stdout']['text'] and '$HOME' in snapshot['stdout']['text']
snapshot = server.call('job_output', job_id=vpn['job_id'], max_bytes=16384)
assert snapshot['stdout']['dropped_bytes'] > 0
assert 'stderr-marker' in snapshot['stderr']['text']
assert str(ctx.scratch) in snapshot['stderr']['text']
assert server.call('job_status', job_id=vpn['job_id'])['state'] == 'running'
pids = command('ip', 'netns', 'pids', vpn['namespace']).stdout.split()
assert len(pids) >= 2, pids
server.call('job_cancel', job_id=vpn['job_id'])
server.call('job_cancel', job_id=other['job_id'])
assert server.finish(vpn)['state'] == 'cancelled'
for pid in pids:
    status = Path(f'/proc/{pid}/status')
    assert not status.exists() or 'State:\tZ' in status.read_text(), f'Cancelled job left PID {pid} running'
assert server.finish(other)['state'] == 'cancelled'

normal = server.call('run_profile', profile='fixed', argv=['true'])
assert server.finish(normal)['state'] == 'completed'
timed = server.call('run_profile', profile='fixed', timeout_seconds=1)
assert server.finish(timed)['state'] == 'cancelled'
failed = server.call('run_profile', profile='broken')
failure = server.finish(failed)
assert failure['state'] == 'failed' and failure['error']['error']['diagnostics']
assert 'NEVER_SHARE_MCP_KEY' not in json.dumps(failure)
# Job IDs from another live MCP session cannot be cancelled.
stranger = MCP()
assert stranger.request('tools/call', {'name': 'job_cancel', 'arguments': {'job_id': normal['job_id']}})['isError']
stranger.close()
# A daemon crash is an indeterminate result, never an implicit relaunch.
crashed = server.call('run_profile', profile='fixed')
wait_for(lambda: server.call('job_status', job_id=crashed['job_id'])['state'] == 'running')
ctx.restart(abrupt=True)
wait_for(lambda: server.call('job_status', job_id=crashed['job_id'])['finished'])
assert server.call('job_status', job_id=crashed['job_id'])['state'] == 'indeterminate'
if Path('/run/netns', crashed['namespace']).exists():
    retried = server.call('job_cancel', job_id=crashed['job_id'])
    assert not retried['cleanup_pending'], retried
    assert not Path('/run/netns', crashed['namespace']).exists()
server.close()

for terminate in (False, True):
    disconnected = MCP()
    pending = disconnected.call('run_profile', profile='fixed')
    wait_for(lambda: disconnected.call('job_status', job_id=pending['job_id'])['state'] == 'running')
    disconnected.close(terminate)
    wait_for(lambda: not Path('/run/netns', pending['namespace']).exists())

print('PASS: MCP stdio, profile policy, real VPN jobs, bounded output, quotas, argv, cancel/timeout, crash and disconnect cleanup', flush=True)

# Delay real VPN setup after dispatch, and cancel while the daemon holds the
# namespace transition. The application must never run in either case.
shim_dir = ctx.scratch / 'mcp-slow-setup-bin'
shim_dir.mkdir()
shim = shim_dir / 'wg'
entered = ctx.scratch / 'mcp-setconf-entered'
marker = ctx.scratch / 'config/mcp-late-application'
shim.write_text('#!/bin/sh\n'
                f'if [ "$1" = setconf ]; then touch {shlex.quote(str(entered))}; sleep 4; fi\n'
                f'exec {shlex.quote(shutil.which("wg"))} "$@"\n')
shim.chmod(0o755)
original_path = os.environ['PATH']
os.environ['PATH'] = f'{shim_dir}:{original_path}'
try:
    ctx.restart()
    slow = MCP('--allow-command')
    try:
        for timeout in (1, 60):
            entered.unlink(missing_ok=True)
            job = slow.call('run_profile', profile='vpn', argv=['touch', str(marker)],
                            timeout_seconds=timeout)
            wait_for(entered.exists)
            if timeout == 60:
                slow.call('job_cancel', job_id=job['job_id'])
            result = slow.finish(job)
            assert result['state'] == 'cancelled' and result['timed_out'] == (timeout == 1), result
            assert not marker.exists(), result
    finally:
        slow.close()
finally:
    os.environ['PATH'] = original_path
    ctx.restart()
print('PASS: MCP cancellation and timeout during tunnel setup prevent application launch', flush=True)
