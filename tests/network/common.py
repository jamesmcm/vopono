"""Helpers for tests invoked by the isolated network harness."""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time


def command(*args, check=True, timeout=15):
    return subprocess.run(list(args), check=check, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def wait_for(condition, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if condition():
                return
        except (OSError, KeyError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(.1)
    raise AssertionError('Timed out waiting for isolated network state')


class Context:
    def __init__(self, binary, scratch, user):
        self.binary = binary
        self.scratch = Path(scratch)
        self.user = user
        account = pwd.getpwnam(user)
        self.uid, self.gid = account.pw_uid, account.pw_gid
        self.base = ['runuser', '-u', user, '--', 'env',
                     f'XDG_CONFIG_HOME={self.scratch / "config"}', binary]

    def client(self, *args, **kwargs):
        return command(*self.base, *args, **kwargs)

    def spawn(self, args, log):
        with (self.scratch / log).open('w') as stream:
            return subprocess.Popen(self.base + args, stdin=subprocess.DEVNULL,
                                    stdout=stream, stderr=subprocess.STDOUT)

    def namespace(self, name):
        return f'{name}-u{self.uid}'

    def status(self, name):
        namespaces = json.loads(self.client('status', '--json').stdout)['namespaces']
        result = next((ns for ns in namespaces if ns['id'] == name), None)
        if result is None:
            raise KeyError(name)
        return result

    def restart(self, abrupt=False):
        pid = json.loads(self.client('daemon', 'status', '--json').stdout)['pid']
        os.kill(pid, signal.SIGKILL if abrupt else signal.SIGTERM)

        def exited():
            path = Path(f'/proc/{pid}/status')
            return not path.exists() or 'State:\tZ' in path.read_text()

        wait_for(exited)
        with (self.scratch / 'daemon.log').open('a') as log:
            daemon = subprocess.Popen([self.binary, 'daemon'], stdout=log,
                                      stderr=subprocess.STDOUT,
                                      env={**os.environ, 'RUST_LOG': 'debug'})
        wait_for(lambda: json.loads(self.client('daemon', 'status', '--json').stdout)['pid'] == daemon.pid)
        return daemon

    def user_file(self, name, contents, mode=0o600):
        path = self.scratch / name
        path.write_text(contents)
        path.chmod(mode)
        os.chown(path, self.uid, self.gid)
        return path
