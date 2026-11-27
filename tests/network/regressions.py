"""Daemon regressions run inside wireguard.sh's disposable namespaces."""
import json
import os
from pathlib import Path
import pwd
import pty
import selectors
import shlex
import shutil
import socket
import subprocess
import sys
import time
from common import Context


binary, scratch_arg, user = sys.argv[1:]
scratch = Path(scratch_arg)
uid = pwd.getpwnam(user).pw_uid
base = [
    "runuser", "-u", user, "--", "env",
    f"XDG_CONFIG_HOME={scratch / 'config'}", binary,
]


def client(*args, check=True):
    # Capturing both streams also verifies EOF after the client exits, even
    # while a persistent controller is still retaining namespace resources.
    return subprocess.run(
        base + list(args), stdin=subprocess.DEVNULL, capture_output=True,
        text=True, timeout=15, check=check,
    )


def launch(name, application, *flags):
    return [
        "exec", "--provider", "none", "--custom-netns-name", name,
        "--interface", "uplink", "--firewall", "nftables", *flags, application,
    ]


def attach(name, application, *flags):
    return [
        "exec", "--existing-netns", name, "--interface", "uplink",
        *flags, application,
    ]


def wait_for(condition):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for daemon state")


# Safe launch failures must keep their specific category and explanation.
for args, code, message in [
    (['--provider', 'mullvad', '--protocol', 'openvpn', '--server', 'se', 'true'],
     'protocol_not_supported', 'Mullvad does not support'),
    (['--provider', 'mullvad', '--protocol', 'wireguard', '--server', 'se', 'true'],
     'provider_not_configured', 'vopono sync mullvad'),
    (['--provider', 'none'], 'internal_error', 'An application or --profile is required'),
]:
    result = client('exec', '--interface', 'uplink', '--json', *args, check=False)
    report = json.loads(result.stdout)['error']
    assert result.returncode != 0 and report['code'] == code, report
    assert message in report['message'], report
print('PASS: launch diagnostics preserve configuration/protocol reasons and error categories', flush=True)

# A synchronized provider can still have no config matching the requested prefix.
air_configs = scratch / "config/vopono/air/wireguard"
air_configs.mkdir(parents=True)
(air_configs / "se-fixture.conf").touch()
account = pwd.getpwnam(user)
for path in [air_configs.parent, air_configs, air_configs / "se-fixture.conf"]:
    os.chown(path, uid, account.pw_gid)
args = ['exec', '--provider', 'airvpn', '--protocol', 'wireguard', '--server', 'india',
        '--interface', 'uplink', '--firewall', 'nftables', 'true']
expected = 'Could not find config matching server prefix "india"'
result = client(*args, check=False)
assert result.returncode != 0 and f'Daemon execution failed: {expected}' in result.stderr, result.stderr
result = client(*args[:-1], '--json', args[-1], check=False)
report = json.loads(result.stdout)['error']
assert result.returncode != 0 and report['code'] == 'server_not_found', report
assert expected in report['message'], report
print('PASS: daemon reports a missing server prefix in terminal and JSON output', flush=True)

# Exercise both settings formats through the daemon and create-only profiles
# without requiring an application command.
yaml = scratch / 'fixture.yml'
yaml.write_text('provider: None\n')
os.chown(yaml, uid, account.pw_gid)
for settings in [yaml, yaml.with_suffix('')]:
    result = client('exec', '--vopono-config', str(settings), '--interface', 'uplink',
                    '--firewall', 'nftables', 'printf yaml-supported')
    assert result.stdout == 'yaml-supported', result
profile = scratch / 'attach-profile.toml'
profile.write_text('[profiles.attach]\nprovider="none"\ncreate-netns-only=true\n'
                   'custom-netns-name="late_relay"\n')
os.chown(profile, uid, account.pw_gid)
client('exec', '--vopono-config', str(profile), '--profile', 'attach',
       '--interface', 'uplink', '--firewall', 'nftables')
name = f'late_relay-u{uid}'
port = 43158
relay_app = Context(binary, scratch, user).user_file('late-relay.py', f"""
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
assert os.environ['VOPONO_HOST_FORWARDED_PORTS'] == '{port}'
HTTPServer(('0.0.0.0', {port}), SimpleHTTPRequestHandler).serve_forever()
""")
application = subprocess.Popen(
    base + attach(name, 'python3 ' + str(relay_app), '--monitor', '--forward', str(port)),
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)


def relay_responds():
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.25) as stream:
            stream.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            return b'200 OK' in stream.recv(4096)
    except OSError:
        return False


try:
    wait_for(relay_responds)
    def monitor_appears():
        status = json.loads(client('status', '--json').stdout)
        return next(ns.get('health') for ns in status['namespaces'] if ns['id'] == name)

    wait_for(monitor_appears)
    entry = Context(binary, scratch, user).status(name)
    assert entry['host_forwarded_ports'] == [port], entry
    active = client(*attach(name, 'printenv VOPONO_HOST_FORWARDED_PORTS',
                            '--forward', str(port), '--json')).stdout.splitlines()
    assert json.loads(active[0])['host_forwarded_ports'] == [port], active
    assert active[1:] == [str(port)], active
    assert relay_responds()
    with socket.socket(socket.AF_INET6) as reserved:
        reserved.bind(('::', 0))
        reserved.listen()
        busy_port = str(reserved.getsockname()[1])
        result = client('exec', '--existing-netns', name, '--interface', 'uplink',
                        '--forward', busy_port, '--json', 'true', check=False)
        error = json.loads(result.stdout)['error']
        assert result.returncode != 0 and f'Could not bind host TCP port {busy_port}' in error['message']
        assert any('Address already in use' in cause for cause in error['context']), error
        assert relay_responds(), 'Failed attach removed the running relay'
finally:
    client('stop', 'namespace', name, '--json')
    application.wait(timeout=15)
print('PASS: daemon YAML settings, create-only profile, late relay and monitor, and bind errors', flush=True)

# The JSON relay must finish after the application exits even when a detached
# descendant still holds its stdout open. Keep stderr separate from this test.
name = f'reg_json_relay-u{uid}'
try:
    command = "sh -c 'sleep 30 2>/dev/null & printf finished'"
    result = subprocess.run(base + launch('reg_json_relay', command, '--json'),
                            stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=4, check=True)
    event, output = result.stdout.splitlines()
    assert json.loads(event)['event'] == 'launched' and output == 'finished', result
finally:
    client('stop', 'namespace', name, '--json', check=False)
print('PASS: JSON exec publishes output and returns while a descendant holds stdout', flush=True)

# More completed persistent requests than the per-user execution limit must
# leave admission available. Each capture must finish before namespace stop.
names = [f"reg_slot{n}-u{uid}" for n in range(9)]
for n, name in enumerate(names):
    result = client(*launch(f"reg_slot{n}", "", "--create-netns-only"))
    assert name in result.stdout
client(*attach(names[1], "true"))
client(*launch("reg_keepalive", "true", "--keep-alive"))
client("stop", "namespace", f"reg_keepalive-u{uid}", "--json")

# Saturate active execution slots as well: status and explicit stop must still
# be admitted. These clients share a persistent namespace for inexpensive setup.
children = [
    subprocess.Popen(
        base + attach(names[0], "sleep 60"), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    for _ in range(8)
]


def all_clients_visible():
    status = json.loads(client("status", "--json").stdout)
    return any(
        ns["id"] == names[0] and len(ns["applications"]) == 8
        for ns in status["namespaces"]
    )


wait_for(all_clients_visible)
rejected = client(*attach(names[0], "true"), check=False)
assert rejected.returncode != 0
assert "execution limit" in rejected.stderr
rejected = client(*attach(names[0], "true", "--json"), check=False)
assert rejected.returncode != 0
assert "execution limit" in json.loads(rejected.stdout)["error"]["message"]
client("stop", "namespace", names[0], "--json")
for child in children:
    child.communicate(timeout=15)
for name in names[1:]:
    client("stop", "namespace", name, "--json")
print("PASS: persistent and saturated execution admission, control requests and output EOF", flush=True)

# An unknown file deliberately prevents implicit teardown. Wait until cleanup
# has tried (and removed its primary lock), then verify ownership and attach.
name = f"reg_preserved-u{uid}"
lock_dir = scratch / "config/vopono/locks" / name
owner = Path("/run/vopono/namespace-owners") / name
child = subprocess.Popen(
    base + launch("reg_preserved", "sleep 3"), stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
wait_for(lambda: lock_dir.exists() and any(lock_dir.glob("client-*")))
leftover = lock_dir / "leftover.tmp"
leftover.touch()
os.chown(leftover, uid, pwd.getpwnam(user).pw_gid)
child.communicate(timeout=15)
assert child.returncode == 0
wait_for(lambda: not any(p.name.isdecimal() for p in lock_dir.iterdir()))
assert (Path("/run/netns") / name).exists()
assert owner.exists(), "Skipped teardown discarded the ownership record"
# Persistence makes the explicit-stop retry deterministic after removing the
# obstacle, rather than racing the controller's next automatic cleanup pass.
client(*attach(name, "true", "--keep-alive"))
wait_for(lambda: any(p.name.isdecimal() for p in lock_dir.iterdir()))
leftover.unlink()
client("stop", "namespace", name, "--json")
assert not (Path("/run/netns") / name).exists()
assert not owner.exists()
print("PASS: skipped teardown preserves ownership and supports a later explicit stop", flush=True)

# A failed explicit stop keeps its intent and retries after a transient obstacle.
pending = f'reg_pending_stop-u{uid}'
pending_path = Path('/run/netns', pending)
client(*launch('reg_pending_stop', '', '--create-netns-only'))
blocker = scratch / 'config/vopono/locks' / pending / 'unexpected'
blocker.touch()
result = client('stop', 'namespace', pending, '--json', check=False)
assert result.returncode != 0 and pending_path.exists(), result.stdout
entry = next(ns for ns in json.loads(client('status', '--json').stdout)['namespaces']
             if ns['id'] == pending)
assert entry['stopping'], entry
assert client(*attach(pending, 'true'), check=False).returncode != 0
blocker.unlink()
wait_for(lambda: not pending_path.exists())
print('PASS: explicit stop is visible, blocks new attachments and retries automatically', flush=True)

# CLI profile directories must be resolved before forwarding supplies a default.
work = scratch / 'profile-work'
work.mkdir()
work.chmod(0o755)
for key in ('working-directory', 'working_directory'):
    config = scratch / 'profile-settings.toml'
    config.write_text(
        f"[profiles.directory]\nprovider='none'\ninterface='uplink'\n"
        f"firewall='nftables'\napplication='pwd'\n{key}='{work}'\n"
    )
    os.chown(config, uid, pwd.getpwnam(user).pw_gid)
    args = ['exec', '--profile', 'directory', '--vopono-config', str(config)]
    result = client(*args)
    assert result.stdout.strip() == str(work), result.stdout
    result = client(*args, '--working-directory', str(scratch))
    assert result.stdout.strip() == str(scratch), result.stdout
print('PASS: CLI profiles honor both working-directory spellings and explicit CLI overrides', flush=True)

# Distinct custom profiles get distinct namespaces even with a common path prefix.
contents = (scratch / 'client.conf').read_text()
custom_a = scratch / 'review-a.conf'
custom_b = scratch / 'review-b.conf'
profile_config = scratch / 'review-profiles.toml'
profile_config.write_text(f"""[profiles.first]
custom = "{custom_a}"
create_netns_only = true
[profiles.second]
custom = "{custom_b}"
create_netns_only = true
""")
custom_a.write_text(contents)
custom_b.write_text(contents.replace('192.0.2.2:51820', '192.0.2.3:51820'))
for path in (custom_a, custom_b, profile_config):
    os.chown(path, uid, account.pw_gid)
profile_args = ['exec', '--vopono-config', str(profile_config), '--firewall', 'nftables', '--json']
first = json.loads(client(*profile_args, '--profile', 'first').stdout)
second = json.loads(client(*profile_args, '--profile', 'second').stdout)
try:
    assert first['namespace'] != second['namespace'], (first, second)
    assert first['provider'] == 'custom' and first['protocol'] == 'wireguard', first
    assert first['server'] == '192.0.2.2' and not first['reused'], first
    assert second['server'] == '192.0.2.3' and not second['reused'], second
    repeated = json.loads(client(*profile_args, '--profile', 'first').stdout)
    assert repeated['reused'] and repeated['namespace'] == first['namespace'], repeated
    insecure = client(*profile_args, '--profile', 'first', '--no-killswitch', check=False)
    assert insecure.returncode != 0 and 'different or unverified connection' in insecure.stdout
    # Exercise interface autodetection and the explicit attachment report together.
    reused = json.loads(client('exec', '--existing-netns', first['namespace'],
                               '--json', 'true').stdout)
    assert reused['reused'] and reused['server'] == first['server'], reused
    collision = client('exec', '--custom', str(custom_b), '--interface', 'uplink',
                       '--custom-netns-name', first['namespace'].removesuffix(f'-u{uid}'),
                       '--firewall', 'nftables', '--json', 'true', check=False)
    assert collision.returncode != 0, collision.stdout
    assert 'different or unverified connection' in json.loads(collision.stdout)['error']['message']
finally:
    for report in (first, second):
        client('stop', 'namespace', report['namespace'], '--json')
print('PASS: profile identity, effective launch details, reuse checks and default veth selection', flush=True)

# Interactive requests take the terminal bridge path through the daemon.
master, slave = pty.openpty()
terminal_app = "python3 -c 'print(\"terminal-ready\", flush=True); print(\"answer-\" + input(), flush=True)'"
child = subprocess.Popen(base + launch('reg_terminal', terminal_app),
                         stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
with os.fdopen(master, 'r+b', buffering=0) as terminal:
    with selectors.DefaultSelector() as selector:
        selector.register(terminal, selectors.EVENT_READ)
        captured = bytearray()

        def read_until(marker):
            deadline = time.monotonic() + 10
            while marker not in captured:
                assert time.monotonic() < deadline, captured
                if selector.select(.1):
                    chunk = terminal.read(4096)
                    assert chunk, captured
                    captured.extend(chunk)

        read_until(b'terminal-ready')
        terminal.write(b'hello\n')
        read_until(b'answer-hello')
        assert child.wait(timeout=10) == 0
print('PASS: daemon terminal bridge carries interactive input/output and exits cleanly', flush=True)

for redirect_stderr in (False, True):
    master, slave = pty.openpty()
    terminal_app = """sh -c 'echo output; echo error >&2; echo prompt > /dev/tty'"""
    child = subprocess.Popen(base + launch('reg_redirected', terminal_app, '--json'),
                             stdin=slave, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE if redirect_stderr else slave)
    try:
        output, errors = child.communicate(timeout=10)
        assert child.returncode == 0 and b'output' in output.splitlines(), output
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            terminal_output = bytearray()
            deadline = time.monotonic() + 5
            while b'prompt' not in terminal_output:
                assert time.monotonic() < deadline, terminal_output
                if selector.select(.1):
                    terminal_output.extend(os.read(master, 4096))
            if redirect_stderr:
                assert errors == b'error\n' and b'error' not in terminal_output
            else:
                assert b'error' in terminal_output, terminal_output
    finally:
        os.close(slave)
        os.close(master)
print('PASS: output redirection keeps stderr separate and terminal prompts visible', flush=True)

# Exercise the parser disagreement through the real daemon and OpenVPN path.
# The hidden log option must never create a root-owned output file.
for index, suffix in enumerate([" trailing-content", "#comment", "\0"]):
    config = scratch / f"inline-{index}.ovpn"
    log = scratch / f"forbidden-{index}.log"
    config.write_text(
        "client\ndev tun\nproto udp\nremote 192.0.2.2 1194\n"
        f"<ca>\n</ca>{suffix}\nlog {log}\n<ca>\n</ca>\n"
    )
    os.chown(config, uid, pwd.getpwnam(user).pw_gid)
    preflight = client('doctor', '--custom', str(config), '--offline', '--json', check=False)
    assert preflight.returncode != 0
    assert any(d['code'] == 'provider_config' and d['state'] == 'fail'
               for d in json.loads(preflight.stdout)['diagnostics'])
    result = client(
        "exec", "--custom", str(config), "--protocol", "openvpn",
        "--custom-netns-name", f"reg_inline{index}", "--interface", "uplink",
        "--firewall", "nftables", "--json", "true", check=False,
    )
    assert result.returncode != 0
    assert json.loads(result.stdout)["error"]["diagnostics"]
    assert not log.exists(), "OpenVPN processed a directive hidden from the sanitizer"
print("PASS: ambiguous inline tags cannot bypass privileged OpenVPN option validation", flush=True)

# Early config-parser failures also use redacted automatic reports, in both
# terminal and JSON output, before any protocol helper is started.
invalid = scratch / 'invalid-settings.toml'
invalid.write_text('NEVER_SHARE_SETTINGS_SECRET = [broken\n')
os.chown(invalid, uid, pwd.getpwnam(user).pw_gid)
for direct in (False, True):
    for flags in [[], ['--json']]:
        args = ['exec', '--vopono-config', str(invalid), '--provider', 'none',
                '--interface', 'uplink', *flags, 'true']
        if direct:
            result = subprocess.run([binary, *args], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, timeout=15,
                env={**os.environ, 'XDG_CONFIG_HOME': str(scratch / 'config'),
                     'SUDO_USER': user, 'SUDO_UID': str(uid),
                     'SUDO_GID': str(pwd.getpwnam(user).pw_gid)})
        else:
            result = client(*args, check=False)
        assert result.returncode != 0
        assert 'NEVER_SHARE_SETTINGS_SECRET' not in result.stdout + result.stderr
        if flags:
            assert json.loads(result.stdout)['error']['diagnostics']
print('PASS: direct/daemon early launch failures include redacted terminal/JSON evidence', flush=True)

# Simulate NetworkManager and delay final namespace deletion so both stops
# hold their ownership records while cleaning up their interfaces.
ctx = Context(binary, scratch, user)
nm_bin = scratch / 'nm-test-bin'
nm_bin.mkdir()
nmcli = nm_bin / 'nmcli'
nmcli.write_text('#!/bin/sh\nexit 0\n')
ip = nm_bin / 'ip'
real_ip = shlex.quote(shutil.which('ip'))
ip.write_text(f'#!/bin/sh\nif [ "$1" = netns ] && [ "$2" = delete ]; then sleep 2; fi\n'
              f'exec {real_ip} "$@"\n')
for executable in (nmcli, ip):
    executable.chmod(0o755)
conf_dir = Path('/etc/NetworkManager/conf.d')
conf_dir.mkdir(parents=True, exist_ok=True)
admin_config = conf_dir / 'unmanaged.conf'
previous = admin_config.read_bytes() if admin_config.exists() else None
admin_contents = b'[keyfile]\nunmanaged-devices=interface-name:admin-example\n'
admin_config.write_bytes(admin_contents)
original_path = os.environ['PATH']
os.environ['PATH'] = f'{nm_bin}:{original_path}'
try:
    ctx.restart()
    names = ('nm_a', 'nm_b')
    for short in names:
        client(*launch(short, '', '--create-netns-only'))
    drop_ins = list(conf_dir.glob('90-vopono-nm_*.conf'))
    assert len(drop_ins) == 2, drop_ins
    stops = [
        subprocess.Popen(base + ['stop', 'namespace', ctx.namespace(short), '--json'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for short in names
    ]
    for stop in stops:
        stdout, stderr = stop.communicate(timeout=15)
        assert stop.returncode == 0 and json.loads(stdout)['namespace_removed'], stderr
    assert admin_config.read_bytes() == admin_contents
    assert all(not path.exists() for path in drop_ins), drop_ins
finally:
    os.environ['PATH'] = original_path
    ctx.restart()
    if previous is None:
        admin_config.unlink()
    else:
        admin_config.write_bytes(previous)
print('PASS: concurrent stops remove their NetworkManager drop-ins and preserve administrator config', flush=True)
