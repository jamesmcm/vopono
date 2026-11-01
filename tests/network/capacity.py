"""Namespace quotas include pending setup and are reclaimed on failure/stop."""
from pathlib import Path
import sys
from common import Context, wait_for

ctx = Context(*sys.argv[1:])


def create(name, *flags, check=True):
    return ctx.client('exec', '--provider', 'none', '--custom-netns-name', name,
        '--interface', 'uplink', '--firewall', 'nftables', '--create-netns-only',
        *flags, check=check)


def stop(name):
    ctx.client('stop', 'namespace', ctx.namespace(name), '--json')
    # Stop must finish namespace teardown and release its persistent permit.
    wait_for(lambda: not Path('/run/netns/' + ctx.namespace(name)).exists())


for n in range(8):
    create(f'monitor{n}', '--monitor')
result = create('monitor_over', '--monitor', check=False)
assert result.returncode != 0 and 'monitor limit' in result.stderr
assert not Path('/run/netns/' + ctx.namespace('monitor_over')).exists()
for n in range(8):
    stop(f'monitor{n}')
for n in range(16):
    create(f'capacity{n}')
result = create('capacity_over', check=False)
assert result.returncode != 0 and 'controller limit' in result.stderr
assert not Path('/run/netns/' + ctx.namespace('capacity_over')).exists()
assert 'available' in ctx.client('daemon', 'status', '--json').stdout
stop('capacity0')
# A failed protocol setup must release the reservation rather than permanently
# consume the only remaining namespace slot.
invalid = ctx.user_file('invalid-capacity.conf', '[Interface]\nPrivateKey=INVALID_SECRET\n')
result = ctx.client('exec', '--custom', str(invalid), '--protocol', 'wireguard',
    '--custom-netns-name', 'failed_capacity', '--interface', 'uplink',
    '--firewall', 'nftables', '--json', 'true', check=False)
assert result.returncode != 0
assert 'INVALID_SECRET' not in result.stdout + result.stderr
create('capacity_reused')
stop('capacity_reused')
for n in range(1, 16):
    stop(f'capacity{n}')
print('PASS: namespace/monitor limits, control availability and failure/stop permit reclamation', flush=True)
