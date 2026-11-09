"""Fixture-only third process for simultaneous controller/watchdog loss.

This is not a production supervisor. It must run inside the dedicated synthetic
systemd unit, outside the fixed child cgroup, and has no recovery if it dies.
"""
import os
from pathlib import Path
import selectors
import sys


def parent_of(pid):
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('PPid:'):
            return int(line.split()[1])
    raise RuntimeError('synthetic process parent unavailable')


def main():
    directory = Path(sys.argv[1])
    controller_pid = int(sys.argv[2])
    watchdog_pid = int(sys.argv[3])
    owner_pid = os.getppid()
    main_owned = len(sys.argv) == 5 and sys.argv[4] == 'controller-child'
    if (owner_pid != controller_pid if main_owned else parent_of(controller_pid) != owner_pid) or parent_of(watchdog_pid) != controller_pid:
        raise RuntimeError('synthetic fixture process relationship mismatch')
    controller_fd = os.pidfd_open(controller_pid, 0)
    watchdog_fd = os.pidfd_open(watchdog_pid, 0)
    try:
        if (os.getppid() != controller_pid if main_owned else parent_of(controller_pid) != owner_pid) or parent_of(watchdog_pid) != controller_pid:
            raise RuntimeError('synthetic fixture process relationship changed')
        membership = Path('/proc/self/cgroup').read_text()
        if (Path(f'/proc/{controller_pid}/cgroup').read_text() != membership
                or Path(f'/proc/{watchdog_pid}/cgroup').read_text() != membership):
            raise RuntimeError('synthetic processes not in custodian unit')
        entries = [line[4:] for line in membership.splitlines() if line.startswith('0::/')]
        if len(entries) != 1:
            raise RuntimeError('unified fixture cgroup unavailable')
        relative = Path(entries[0])
        if (not relative.parts or any(part in ('.', '..') for part in relative.parts)
                or not relative.name.startswith(('tucupi-rust-owned-test-', 'tucupi-main-test-'))
                or not relative.name.endswith('.service')):
            raise RuntimeError('not a dedicated synthetic fixture unit')
        group = Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture'
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            kill_fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=group_fd)
            try:
                with (directory / 'custodian-ready').open('x') as ready:
                    ready.write(str(os.getpid()))
                with selectors.DefaultSelector() as selector:
                    selector.register(controller_fd, selectors.EVENT_READ)
                    selector.register(watchdog_fd, selectors.EVENT_READ)
                    while selector.get_map():
                        for key, _ in selector.select():
                            selector.unregister(key.fileobj)
                os.write(kill_fd, b'1')
                (directory / 'custodian-stop-requested').touch()
            finally:
                os.close(kill_fd)
        finally:
            os.close(group_fd)
    finally:
        os.close(watchdog_fd)
        os.close(controller_fd)


if __name__ == '__main__':
    main()
