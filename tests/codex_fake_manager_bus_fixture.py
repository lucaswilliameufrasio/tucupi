"""Opt-in private same-UID D-Bus impersonation probe; no real manager mutation."""
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import uuid

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib


def serve(address, unit, invocation):
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.bus.BusConnection(address)
    name = dbus.service.BusName('org.freedesktop.systemd1', bus=bus, do_not_queue=True)

    class Manager(dbus.service.Object):
        @dbus.service.method('org.freedesktop.systemd1.Manager', in_signature='s', out_signature='o')
        def GetUnit(self, requested):
            if requested != unit:
                raise dbus.exceptions.DBusException('unknown synthetic unit')
            return dbus.ObjectPath('/synthetic/unit')

    class Unit(dbus.service.Object):
        @dbus.service.method('org.freedesktop.DBus.Properties', in_signature='s', out_signature='a{sv}')
        def GetAll(self, interface):
            if interface != 'org.freedesktop.systemd1.Unit':
                raise dbus.exceptions.DBusException('unknown interface')
            return {'Id': dbus.String(unit, variant_level=1),
                    'InvocationID': dbus.ByteArray(bytes.fromhex(invocation), variant_level=1),
                    'ActiveState': dbus.String('active', variant_level=1)}

        @dbus.service.method('org.freedesktop.DBus.Properties', in_signature='ss', out_signature='v')
        def Get(self, interface, property_name):
            if interface != 'org.freedesktop.systemd1.Unit':
                raise dbus.exceptions.DBusException('unknown interface')
            if property_name == 'Id':
                return dbus.String(unit, variant_level=1)
            if property_name == 'InvocationID':
                return dbus.ByteArray(bytes.fromhex(invocation), variant_level=1)
            if property_name == 'ActiveState':
                return dbus.String('active', variant_level=1)
            raise dbus.exceptions.DBusException('unknown property')

    manager = Manager(bus, '/org/freedesktop/systemd1')
    fake_unit = Unit(bus, '/synthetic/unit')
    print('ready', flush=True)
    GLib.MainLoop().run()
    return name, manager, fake_unit


def ready(process):
    if not select.select([process.stdout], [], [], 5)[0] or process.stdout.readline().strip() != 'ready':
        raise RuntimeError('synthetic manager did not start')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'serve':
        serve(*sys.argv[2:])
        return
    root = Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    unit = 'tucupi-review-' + uuid.uuid4().hex + '.service'
    invocation = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='tucupi-fake-bus-', dir=Path.home()) as directory:
        runtime = Path(directory)
        address = 'unix:path=' + str(runtime / 'bus')
        daemon = subprocess.Popen(['/usr/bin/dbus-daemon', '--session', '--nofork', '--address=' + address,
                                   '--print-address=1'], env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        service = None
        try:
            if not select.select([daemon.stdout], [], [], 5)[0] or not daemon.stdout.readline().strip().startswith('unix:'):
                raise RuntimeError('synthetic bus did not start')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(runtime / 'bus'))
                pid, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if pid != daemon.pid or uid != os.geteuid():
                    raise RuntimeError('synthetic bus peer identity mismatch')
            service = subprocess.Popen(['/usr/bin/python3', __file__, 'serve', address, unit, invocation],
                                       env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready(service)
            connection = dbus.bus.BusConnection(address)
            try:
                bus = dbus.Interface(connection.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus'), 'org.freedesktop.DBus')
                credentials = bus.GetConnectionCredentials('org.freedesktop.systemd1', timeout=3)
                if 'ProcessFD' not in credentials:
                    print('private same-UID bus lacks ProcessFD; Rust diagnostic must reject it')
            finally:
                connection.close()
            result = subprocess.run([str(helper), 'same-connection-rust-fixture', unit, str(runtime)],
                                    env={}, capture_output=True, text=True, timeout=10)
            if 'ProcessFD' not in credentials:
                if result.returncode == 0:
                    raise RuntimeError('missing ProcessFD was accepted')
                print('private fake manager rejected; recovery remains blocked')
                return
            if result.returncode != 0 or result.stdout.strip() != unit + ' ' + invocation:
                raise RuntimeError('synthetic bus probe unavailable or failed: ' + result.stderr[-1000:])
            provision = subprocess.run([str(helper), 'state-provision-fixture', directory], env={}, capture_output=True, text=True, timeout=5)
            if provision.returncode != 0:
                raise RuntimeError('synthetic state provisioning failed')
            record = runtime / 'state' / 'pending-attempt'
            record.write_text('tucupi-recovery-attempt-v1\nattempt=' + unit[len('tucupi-review-'):-len('.service')]
                              + '\nunit=' + unit + '\ninvocation=' + invocation
                              + '\nboot=' + 'b' * 32 + '\nmanager_epoch=' + 'c' * 32 + '\n')
            record.chmod(0o600)
            before = record.read_bytes()
            inspection = subprocess.run([str(helper), 'inspect-persisted-fixture', str(runtime / 'state'), directory],
                                        env={}, capture_output=True, text=True, timeout=10)
            if inspection.returncode != 0 or inspection.stdout.strip() != 'fixture-recovery-observation:ManagerEpochUnknown':
                raise RuntimeError('synthetic fake manager did not remain inconclusive')
            if record.read_bytes() != before:
                raise RuntimeError('synthetic record was changed')
            project = runtime / 'project'
            project.mkdir()
            (project / 'tucupi.toml').write_text("[security]\nreview_provider = 'codex'\n")
            state_parent = runtime / 'xdg' / 'tucupi'
            state_parent.mkdir(parents=True, mode=0o700)
            os.chmod(state_parent, 0o700)
            provision = subprocess.run([str(helper), 'state-provision-fixture', str(state_parent), 'recovery'],
                                       env={}, capture_output=True, text=True, timeout=5)
            if provision.returncode != 0:
                raise RuntimeError('default-flow synthetic state provisioning failed')
            shared = state_parent / 'recovery' / 'pending-attempt'
            shared.write_bytes(before)
            shared.chmod(0o600)
            env = {'HOME': directory, 'XDG_STATE_HOME': str(runtime / 'xdg'),
                   'XDG_RUNTIME_DIR': directory, 'DBUS_SESSION_BUS_ADDRESS': address,
                   'LANG': 'en_US.UTF-8', 'PATH': '/usr/bin:/bin'}
            app = subprocess.run([str(helper), 'app-production-observation-fixture', str(project)],
                                 env=env, capture_output=True, text=True, timeout=10)
            if app.returncode != 0 or 'app-production-observation:Some(ManagerUnavailable)' not in app.stdout:
                raise RuntimeError('default App unexpectedly accepted fake runtime: ' + app.stdout[-500:] + app.stderr[-500:])
            batch = subprocess.run([str(root / 'target/debug/tucupi'), '-i', str(project)],
                                   env=env, capture_output=True, text=True, timeout=10)
            if batch.returncode == 0 or 'Review cleanup was not verified' not in batch.stderr:
                raise RuntimeError('real batch did not remain blocked')
            if shared.read_bytes() != before:
                raise RuntimeError('default flows changed synthetic record')
            print('private same-UID bus and fake manager produced matching Rust observation')
            print('matching persisted synthetic record remains blocked; record unchanged')
            print('default App ignores fake bus environment; real batch blocks; record unchanged')
        finally:
            for process in (service, daemon):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == '__main__':
    main()
