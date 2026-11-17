"""Observe plaintext on the host veth while ordinary applications send traffic."""
import json
import os
from pathlib import Path
import shlex
import socket
import sys
import threading
import time


def send_probes():
    uid, marker, stop, ready, endpoints = sys.argv[2:]
    assert os.getuid() == int(uid) and os.getuid() != 0
    status = Path('/proc/self/status').read_text()
    assert 'NoNewPrivs:\t1' in status
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        try:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 51820)
        except PermissionError:
            pass
        else:
            raise AssertionError('Application can forge the WireGuard transport mark')
    marker = marker.encode()
    endpoints = json.loads(endpoints)

    def stopped():
        return Path(stop).exists()

    def stream(family):
        target = '1.1.1.1' if family == socket.AF_INET else '2606:4700:4700::1111'
        count = 0
        while not stopped():
            try:
                with socket.socket(family) as connection:
                    connection.settimeout(.2)
                    assert connection.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0
                    connection.connect((target, 4444))
                    while not stopped():
                        connection.sendall(marker)
                        if not connection.recv(1):
                            break
                        count += 1
                        Path(ready + ('-v6' if family == socket.AF_INET6 else '')).write_text(str(count))
                        time.sleep(.02)
            except OSError:
                time.sleep(.02)

    def datagrams(family):
        target = '1.1.1.1' if family == socket.AF_INET else '2606:4700:4700::1111'
        while not stopped():
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as connection:
                    connection.settimeout(.02)
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # --open-ports must not authorize connections originated
                    # by an application merely because it binds this port.
                    connection.bind(('0.0.0.0' if family == socket.AF_INET else '::', 4446))
                    connection.connect((target, 4445))
                    while not stopped():
                        connection.send(marker)
                        try:
                            connection.recv(4096)
                        except socket.timeout:
                            pass
                        time.sleep(.02)
            except OSError:
                time.sleep(.02)

    def transports():
        while not stopped():
            for host, port in endpoints:
                family = socket.AF_INET6 if ':' in host else socket.AF_INET
                try:
                    with socket.socket(family, socket.SOCK_DGRAM) as connection:
                        connection.sendto(marker, (host, port))
                except OSError:
                    pass
            time.sleep(.02)

    def transport_streams():
        while not stopped():
            for host, port in endpoints:
                family = socket.AF_INET6 if ':' in host else socket.AF_INET
                try:
                    with socket.socket(family) as connection:
                        connection.settimeout(.05)
                        connection.connect((host, port))
                        connection.sendall(marker)
                except OSError:
                    pass
            time.sleep(.02)

    threading.Thread(target=transport_streams, daemon=True).start()
    for family in (socket.AF_INET, socket.AF_INET6):
        threading.Thread(target=stream, args=(family,), daemon=True).start()
        threading.Thread(target=datagrams, args=(family,), daemon=True).start()
    threading.Thread(target=transports, daemon=True).start()
    while not stopped():
        time.sleep(.02)


if __name__ == '__main__' and sys.argv[1:2] == ['--send']:
    send_probes()
    raise SystemExit(0)


class LeakProbe:
    """Capture the actual boundary before host routing/NAT can hide a leak."""

    def __init__(self, context, namespace, endpoints):
        import secrets
        from common import wait_for

        self.context = context
        self.namespace = namespace
        self.marker = ('leak-' + secrets.token_hex(12)).encode()
        identifier = namespace + self.marker.decode()
        self.stop_file = context.scratch / 'config' / (identifier + '.stop')
        self.ready = context.scratch / 'config' / (identifier + '.ready')
        record = json.loads((Path('/run/vopono/namespace-owners') / namespace).read_text())
        interface = record['namespace']['veth_pair']['dest']
        self.capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.capture.bind((interface, 0))
        self.capture.settimeout(.1)
        self.done = threading.Event()
        self.leaks = []
        self.observer_error = None

        def observe():
            while not self.done.is_set():
                try:
                    packet = self.capture.recv(65536)
                    if self.marker in packet and len(self.leaks) < 3:
                        self.leaks.append(packet.hex())
                except socket.timeout:
                    pass
                except OSError as error:
                    if not self.done.is_set():
                        self.observer_error = str(error)
                    return

        self.observer = threading.Thread(target=observe, daemon=True)
        self.observer.start()
        helper = context.user_file(namespace + '-probes.py', Path(__file__).read_text())
        argv = ['python3', str(helper), '--send', str(context.uid), self.marker.decode(),
                str(self.stop_file), str(self.ready), json.dumps(endpoints)]
        self.app = context.spawn(['exec', '--existing-netns', namespace, '--interface', 'uplink',
                                  shlex.join(argv)], namespace + '-probes.log')
        try:
            wait_for(self.ready.exists)
        except BaseException:
            self.close()
            raise

    def wait_for_tunnel(self, ipv6=False):
        from common import wait_for

        def count():
            return int(Path(str(self.ready) + ('-v6' if ipv6 else '')).read_text())

        before = wait_for(count)
        wait_for(lambda: count() > before)

    def assert_isolated(self):
        assert self.observer_error is None, self.observer_error
        assert not self.leaks, f'Unencrypted application payload crossed the host veth: {self.leaks}'

    def close(self):
        self.stop_file.touch()
        try:
            self.app.wait(timeout=10)
        finally:
            time.sleep(.1)
            self.done.set()
            self.observer.join(timeout=1)
            self.capture.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        self.assert_isolated()


def check_wireguard(context):
    from common import command

    for backend in ('nftables', 'iptables'):
        short = 'guard_' + backend
        namespace = context.namespace(short)
        context.client('exec', '--custom', str(context.scratch / 'client.conf'),
                       '--protocol', 'wireguard', '--custom-netns-name', short,
                       '--interface', 'uplink', '--firewall', backend,
                       '--open-ports', '4446', '--create-netns-only', '')
        try:
            with LeakProbe(context, namespace, [('192.0.2.2', 51820),
                                                 ('192.0.2.3', 51820)]) as probe:
                probe.wait_for_tunnel()
                probe.wait_for_tunnel(ipv6=True)
                record = json.loads((Path('/run/vopono/namespace-owners') / namespace).read_text())
                interface = record['namespace']['wireguard']['if_name']
                for family in ('-4', '-6'):
                    command('ip', family, '-n', namespace, 'route', 'delete',
                            'default', 'table', '51820')
                    time.sleep(.5)
                    probe.assert_isolated()
                    command('ip', family, '-n', namespace, 'route', 'add',
                            'default', 'dev', interface, 'table', '51820')
                probe.wait_for_tunnel()
                probe.wait_for_tunnel(ipv6=True)
                command('ip', '-n', namespace, 'link', 'delete', interface)
                time.sleep(.5)
                probe.assert_isolated()
        finally:
            context.client('stop', 'namespace', namespace, '--json', check=False)
        print(f'PASS: {backend} blocks plaintext endpoint UDP and established/new flows during route/device loss', flush=True)


def check_observer(context):
    namespace = context.namespace('guard_control')
    context.client('exec', '--provider', 'none', '--custom-netns-name', 'guard_control',
                   '--interface', 'uplink', '--firewall', 'nftables',
                   '--create-netns-only', '')
    try:
        probe = LeakProbe(context, namespace, [('192.0.2.2', 51820)])
        try:
            probe.wait_for_tunnel()
            assert probe.leaks, 'Leak detector missed intentionally unprotected application traffic'
        finally:
            probe.close()
    finally:
        context.client('stop', 'namespace', namespace, '--json')
    print('PASS: positive control detects unprotected application payloads on the host veth', flush=True)


def check_command_failure(context):
    import shutil

    namespace = context.namespace('guard_failure')
    tools = context.scratch / 'failed-tools'
    tools.mkdir()
    actual = shutil.which('nft')
    shim = tools / 'nft'
    shim.write_text(
        '#!/usr/bin/python3\nimport os,sys\n'
        f'if {namespace!r} in sys.argv and "reject" in sys.argv and "!=" in sys.argv: raise SystemExit(42)\n'
        f'os.execv({actual!r}, [{actual!r}, *sys.argv[1:]])\n')
    shim.chmod(0o755)
    original = os.environ['PATH']
    marker = context.scratch / 'config/forbidden-application'
    try:
        os.environ['PATH'] = str(tools) + os.pathsep + original
        context.restart()
        result = context.client(
            'exec', '--custom', str(context.scratch / 'client.conf'),
            '--protocol', 'wireguard', '--custom-netns-name', 'guard_failure',
            '--interface', 'uplink', '--firewall', 'nftables', '--json',
            shlex.join(['python3', '-c', f'from pathlib import Path; Path({str(marker)!r}).touch()']),
            check=False)
        assert result.returncode != 0, result.stdout
        assert json.loads(result.stdout)['error']
        assert not marker.exists(), 'Application started after a failed kill-switch command'
        assert not Path('/run/netns', namespace).exists()
    finally:
        os.environ['PATH'] = original
        context.restart()
    print('PASS: failed kill-switch installation prevents application launch', flush=True)


def check_privilege_boundary(context):
    import grp
    import shutil
    import struct
    import subprocess
    from common import command

    helpers = context.scratch / 'capability-helpers'
    helpers.mkdir()
    # /tmp can be nosuid. Use a private mount so the positive control really
    # gains its file capability before checking that applications cannot.
    command('mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', str(helpers))
    try:
        executable = helpers / 'python'
        shutil.copyfile(sys.executable, executable)
        executable.chmod(0o755)
        # A file-capability helper can otherwise forge socket marks on Linux.
        os.setxattr(executable, 'security.capability',
                    struct.pack('<5I', 0x02000001, 1 << 13, 0, 0, 0))
        capable = 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,51820)'
        control = command('runuser', '-u', context.user, '--', str(executable), '-c', capable, check=False)
        assert control.returncode == 0, control.stderr
        restricted = (
            'import os,socket; from pathlib import Path; '
            f'assert os.getuid()=={context.uid}; '
            'assert "NoNewPrivs:\t1" in Path("/proc/self/status").read_text(); '
            's=socket.socket()\n'
            'try: s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,51820)\n'
            'except PermissionError: pass\n'
            'else: raise AssertionError("Application gained transport-mark capability")\n')
        namespace = context.namespace('guard_caps')
        context.client('exec', '--provider', 'none', '--custom-netns-name', 'guard_caps',
                       '--interface', 'uplink', '--create-netns-only', '')
        try:
            context.client('exec', '--existing-netns', namespace, '--interface', 'uplink',
                           shlex.join([str(executable), '-c', restricted]))
        finally:
            context.client('stop', 'namespace', namespace, '--json')
        subprocess.run(
            [context.binary, 'exec', '--provider', 'none', '--custom-netns-name', 'guard_cli',
             '--interface', 'uplink', '--user', context.user, '--group', grp.getgrgid(context.gid).gr_name,
             shlex.join([str(executable), '-c', restricted])],
            check=True, capture_output=True, text=True, timeout=30,
            env={**os.environ, 'XDG_CONFIG_HOME': str(context.scratch / 'config'),
                 'SUDO_USER': context.user, 'SUDO_UID': str(context.uid), 'SUDO_GID': str(context.gid)})
        print('PASS: daemon and direct applications cannot gain file capabilities or forge transport marks', flush=True)
    finally:
        command('umount', str(helpers))


if __name__ == '__main__':
    from common import Context

    context = Context(*sys.argv[1:])
    check_privilege_boundary(context)
    check_observer(context)
    check_wireguard(context)
    check_command_failure(context)
