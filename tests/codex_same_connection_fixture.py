"""Opt-in same-connection manager probe against one synthetic service."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

import dbus

from codex_systemd_escape_fixture import start, unchanged
from codex_systemd_main_fixture import show


def main():
    root = Path(__file__).resolve().parent.parent
    unit = 'tucupi-review-' + uuid.uuid4().hex + '.service'
    runtime = Path('/run/user') / str(os.getuid())
    info = None
    with tempfile.TemporaryDirectory(prefix='tucupi-same-bus-', dir=Path.home()) as directory:
        path = Path(directory) / 'identity.json'
        try:
            info = start(unit, ['/usr/bin/sleep', '25'])
            unchanged(unit, info)
            bus = dbus.bus.BusConnection('unix:path=' + str(runtime / 'bus'))
            try:
                daemon = dbus.Interface(bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
                owner = str(daemon.GetNameOwner('org.freedesktop.systemd1', timeout=3))
                record = {
                    'unit': unit, 'invocation': info['InvocationID'],
                    'bus_id': str(daemon.GetId(timeout=3)), 'owner': owner,
                    'manager_pid': int(daemon.GetConnectionUnixProcessID(owner, timeout=3)),
                    'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                }
            finally:
                bus.close()
            path.write_text(json.dumps(record))
            path.chmod(0o600)
            def probe(runtime_path):
                return subprocess.run(['/usr/bin/python3', str(root / 'tests/codex_same_connection_probe.py'), str(path), str(runtime_path)],
                                      env={}, capture_output=True, text=True, timeout=12)

            result = probe(runtime)
            expected = 'one D-Bus connection: peer credentials and synthetic unit identity matched; recovery blocked'
            if result.returncode != 0 or expected not in result.stdout:
                raise RuntimeError('same-connection fixture failed: ' + result.stderr[-1500:])
            for key, value in (
                ('owner', ':1.999999999'),
                ('bus_id', 'f' * 32),
                ('manager_pid', 1),
                ('invocation', 'f' * 32),
            ):
                altered = dict(record)
                altered[key] = value
                path.write_text(json.dumps(altered))
                if probe(runtime).returncode == 0:
                    raise RuntimeError('changed synthetic identity accepted: ' + key)
            if probe(Path(directory) / 'missing-runtime').returncode == 0:
                raise RuntimeError('unavailable synthetic runtime accepted')
            unchanged(unit, info)
            print(expected)
            print('changed manager, bus or unit identity and unavailable runtime rejected; no recovery promoted')
        finally:
            if info is not None:
                state = show(unit)
                if state['InvocationID'] == info['InvocationID'] and state['ActiveState'] not in ('inactive', 'failed'):
                    subprocess.run(['systemctl', '--user', 'stop', unit], check=True, timeout=10)


if __name__ == '__main__':
    main()
