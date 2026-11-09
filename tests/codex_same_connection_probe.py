"""Synthetic read-only D-Bus observation; does not authorize recovery."""
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import sys

import dbus


def main():
    record_path, runtime = map(Path, sys.argv[1:])
    raw = record_path.read_bytes()
    if len(raw) > 4096:
        raise RuntimeError('synthetic record too large')
    record = json.loads(raw)
    unit = record['unit']
    if not re.fullmatch(r'tucupi-review-[0-9a-f]{32}\.service', unit):
        raise RuntimeError('invalid synthetic unit')
    if runtime != Path('/run/user') / str(os.geteuid()):
        raise RuntimeError('invalid runtime')
    directory = runtime.lstat()
    socket_before = (runtime / 'bus').lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) & 0o077
            or not stat.S_ISSOCK(socket_before.st_mode) or socket_before.st_uid != os.geteuid()):
        raise RuntimeError('unexpected runtime or socket owner')

    # One private connection for every daemon, owner, and unit query below.
    bus = dbus.bus.BusConnection('unix:path=' + str(runtime / 'bus'))
    duplicate = socket.socket(fileno=os.dup(bus.get_unix_fd()))
    try:
        peer_pid, peer_uid, _ = struct.unpack('3i', duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    finally:
        duplicate.close()
    if peer_pid <= 1 or peer_uid != os.geteuid():
        raise RuntimeError('unexpected bus peer')
    daemon = dbus.Interface(bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
    bus_id = str(daemon.GetId(timeout=3))
    owner = str(daemon.GetNameOwner('org.freedesktop.systemd1', timeout=3))
    uid = int(daemon.GetConnectionUnixUser(owner, timeout=3))
    pid = int(daemon.GetConnectionUnixProcessID(owner, timeout=3))
    if uid != os.geteuid() or pid <= 1:
        raise RuntimeError('unexpected manager credentials')
    pidfd = os.pidfd_open(pid)
    try:
        if select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError('manager already exited')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if (bus_id != record['bus_id'] or owner != record['owner']
                or pid != record['manager_pid'] or boot != record['boot']):
            raise RuntimeError('synthetic manager identity mismatch')
        # Address the unique owner, not the well-known name, on this same bus.
        manager = dbus.Interface(bus.get_object(owner, '/org/freedesktop/systemd1'), 'org.freedesktop.systemd1.Manager')
        path = manager.GetUnit(unit, timeout=3)
        props = dbus.Interface(bus.get_object(owner, path), 'org.freedesktop.DBus.Properties')
        observed_id = str(props.Get('org.freedesktop.systemd1.Unit', 'Id', timeout=3))
        invocation = bytes(props.Get('org.freedesktop.systemd1.Unit', 'InvocationID', timeout=3)).hex()
        active = str(props.Get('org.freedesktop.systemd1.Unit', 'ActiveState', timeout=3))
        if observed_id != unit or invocation != record['invocation'] or active != 'active':
            raise RuntimeError('synthetic unit identity mismatch')
        if (str(daemon.GetId(timeout=3)) != bus_id
                or str(daemon.GetNameOwner('org.freedesktop.systemd1', timeout=3)) != owner
                or int(daemon.GetConnectionUnixProcessID(owner, timeout=3)) != pid
                or select.select([pidfd], [], [], 0)[0]):
            raise RuntimeError('synthetic manager changed during observation')
        socket_after = (runtime / 'bus').lstat()
        if (socket_before.st_dev, socket_before.st_ino) != (socket_after.st_dev, socket_after.st_ino):
            raise RuntimeError('bus socket changed during observation')
        print('one D-Bus connection: peer credentials and synthetic unit identity matched; recovery blocked')
    finally:
        os.close(pidfd)
        bus.close()


if __name__ == '__main__':
    main()
