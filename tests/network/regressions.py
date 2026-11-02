"""Daemon regressions run inside wireguard.sh's disposable namespaces."""
import json
import os
from pathlib import Path
import pwd
import pty
import selectors
import subprocess
import sys
import time


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
leftover.unlink()
client("stop", "namespace", name, "--json")
assert not (Path("/run/netns") / name).exists()
assert not owner.exists()
print("PASS: skipped teardown preserves ownership and supports a later explicit stop", flush=True)

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
    assert json.loads(preflight.stdout)['diagnostics'][0]['state'] == 'fail'
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
