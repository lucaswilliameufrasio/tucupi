"""Fixture-only watchdog; never use as a production process supervisor.

Runs in the delegated synthetic unit, outside its fixed child cgroup. The
The watchdog has no disarm channel: controller pidfd readiness requests a kill,
including after normal controller exit.
"""
import os
from pathlib import Path
import selectors
import sys


def main():
    directory = Path(sys.argv[1])
    controller_pid = int(sys.argv[2])
    if os.getppid() != controller_pid:
        raise RuntimeError('synthetic controller already gone')
    parent_fd = os.pidfd_open(controller_pid, 0)
    if os.getppid() != controller_pid:
        os.close(parent_fd)
        raise RuntimeError('synthetic controller already gone')
    lines = Path('/proc/self/cgroup').read_text().splitlines()
    entries = [line[4:] for line in lines if line.startswith('0::/')]
    if len(entries) != 1:
        raise RuntimeError('unified fixture cgroup unavailable')
    relative = Path(entries[0])
    if not relative.parts or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('invalid fixture cgroup')
    group = Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture'
    group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        kill_fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=group_fd)
        try:
            with (directory / 'watchdog-ready').open('x') as ready:
                ready.write(str(os.getpid()))
            with selectors.DefaultSelector() as selector:
                selector.register(parent_fd, selectors.EVENT_READ)
                selector.select()
            os.write(kill_fd, b'1')
            (directory / 'watchdog-stop-requested').touch()
        finally:
            os.close(kill_fd)
    finally:
        os.close(group_fd)
        os.close(parent_fd)


if __name__ == '__main__':
    main()
