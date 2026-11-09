"""Opt-in Rust-owned synthetic child admission and cancellation experiment.

Requires a built codex-fixture example, Codex CLI, systemd user delegation,
network namespaces and bubblewrap. This is not a production supervisor.
"""
import pathlib
import shutil
import subprocess
import tempfile
import time
import uuid


WORKER = r'''
import os, pathlib, selectors, subprocess, sys, time
directory = pathlib.Path(sys.argv[1])
helper, codex_dir, bridge = sys.argv[2:5]
mode = sys.argv[5]
custodian_script = sys.argv[6]
command = [helper, 'owned-spawn-fixture', str(directory), codex_dir, bridge]
if mode in ('watchdog-controller-crash', 'watchdog-cancel', 'watchdog-no-disarm', 'watchdog-both-crash', 'custodian-both-crash', 'custodian-three-crash', 'watchdog-dies-after-release'):
    command.append('watchdog')
elif mode in ('watchdog-startup-crash', 'watchdog-dies-before-release'):
    command.append('watchdog-pause')
process = subprocess.Popen(command,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, env={})
try:
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        expected = 'watchdog-ready-before-release' if mode in ('watchdog-startup-crash', 'watchdog-dies-before-release') else 'rust-created-admitted-before-worker-exec'
        if not selector.select(timeout=5) or process.stdout.readline().strip() != expected:
            raise RuntimeError('Rust did not admit its child before releasing the gate')
    if mode == 'watchdog-dies-before-release':
        pid = int((directory / 'watchdog-ready').read_text())
        status = pathlib.Path(f'/proc/{pid}/status').read_text().splitlines()
        if f'PPid:\t{process.pid}' not in status:
            raise RuntimeError('watchdog is not the test controller child')
        os.kill(pid, 9)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = pathlib.Path(f'/proc/{pid}/stat').read_text()
            if stat[stat.rfind(')') + 2] == 'Z':
                break
            time.sleep(0.02)
        else:
            raise RuntimeError('synthetic watchdog did not exit')
        stdout, stderr = process.communicate('continue\n', timeout=8)
        if process.returncode != 0 or 'watchdog died before release; synthetic cgroup empty; worker not started' not in stdout:
            raise RuntimeError('dead watchdog was not rejected: ' + stderr[-1000:])
        print('watchdog died before release; synthetic cgroup empty; worker not started', flush=True)
        os._exit(0)
    if mode == 'watchdog-startup-crash':
        relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2].lstrip('/')
        events = pathlib.Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture/cgroup.events'
        if 'populated 1' not in events.read_text().splitlines() or (directory / 'bridge-root-pid').exists():
            raise RuntimeError('child was not blocked before watchdog startup crash')
        process.kill()
        process.wait(timeout=5)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if (directory / 'watchdog-stop-requested').exists() and 'populated 0' in events.read_text().splitlines():
                break
            time.sleep(0.02)
        else:
            raise RuntimeError('watchdog did not stop child after startup crash')
        if (directory / 'bridge-root-pid').exists():
            raise RuntimeError('synthetic worker started during startup crash')
        print('watchdog startup crash: child cgroup empty; worker not started; outer unit alive', flush=True)
        os._exit(0)
    marker = directory / 'request-in-flight'
    deadline = time.monotonic() + 20
    while not marker.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('synthetic CLI request did not start')
        time.sleep(0.02)
    pid = int((directory / 'bridge-root-pid').read_text())
    membership_before = pathlib.Path(f'/proc/{pid}/cgroup').read_text()
    collision = subprocess.run([helper, 'owned-spawn-fixture', str(directory), codex_dir, bridge, 'collision-cancel'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env={}, timeout=5)
    if collision.returncode != 0 or 'collision rejected; second attempt cancellation requested' not in collision.stdout:
        raise RuntimeError('second Rust attempt did not reject collision and cancel: ' + collision.stderr[-1000:])
    stat = pathlib.Path(f'/proc/{pid}/stat').read_text()
    if process.poll() is not None or stat[stat.rfind(')') + 2] == 'Z' or pathlib.Path(f'/proc/{pid}/cgroup').read_text() != membership_before:
        raise RuntimeError('collision cancellation disturbed the first synthetic attempt')
    print('second attempt rejected collision and cancelled; first child remains in cgroup', flush=True)
    if mode in ('custodian-both-crash', 'custodian-three-crash'):
        watchdog_pid = int((directory / 'watchdog-ready').read_text())
        custodian = subprocess.Popen(['/usr/bin/python3', custodian_script, str(directory), str(process.pid), str(watchdog_pid)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                     env={})
        deadline = time.monotonic() + 5
        while not (directory / 'custodian-ready').exists():
            if custodian.poll() is not None:
                raise RuntimeError('synthetic custodian failed to start: ' + custodian.stderr.read().decode()[-1000:])
            if time.monotonic() >= deadline:
                custodian.kill()
                custodian.wait(timeout=5)
                raise RuntimeError('synthetic custodian readiness timed out')
            time.sleep(0.02)
        relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2].lstrip('/')
        events = pathlib.Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture/cgroup.events'
        if 'populated 1' not in events.read_text().splitlines():
            raise RuntimeError('child group was not populated before both failures')
        if mode == 'custodian-three-crash':
            os.kill(custodian.pid, 19)
        os.kill(watchdog_pid, 19)
        os.kill(process.pid, 19)
        os.kill(process.pid, 9)
        os.kill(watchdog_pid, 9)
        if mode == 'custodian-three-crash':
            os.kill(custodian.pid, 9)
            process.wait(timeout=5)
            custodian.wait(timeout=5)
            time.sleep(8)
            if not (directory / 'survived').exists():
                raise RuntimeError('triple failure did not reproduce surviving descendant')
            print('custodian also killed: synthetic descendant survived while outer unit alive', flush=True)
            os._exit(0)
        process.wait(timeout=5)
        if custodian.wait(timeout=5) != 0 or not (directory / 'custodian-stop-requested').exists():
            raise RuntimeError('synthetic custodian did not request stop')
        deadline = time.monotonic() + 4
        while 'populated 0' not in events.read_text().splitlines():
            if time.monotonic() >= deadline:
                raise RuntimeError('synthetic child group did not empty')
            time.sleep(0.02)
        time.sleep(7)
        if (directory / 'survived').exists():
            raise RuntimeError('synthetic descendant survived custodian stop')
        print('custodian: both failures observed; child group empty; outer unit alive; marker absent', flush=True)
        os._exit(0)
    if mode == 'watchdog-dies-after-release':
        watchdog_pid = int((directory / 'watchdog-ready').read_text())
        status = pathlib.Path(f'/proc/{watchdog_pid}/status').read_text().splitlines()
        if f'PPid:\t{process.pid}' not in status:
            raise RuntimeError('watchdog is not the test controller child')
        os.kill(watchdog_pid, 9)
        stdout, stderr = process.communicate(timeout=8)
        if process.returncode == 0 or 'watchdog failure after release; synthetic group stopped; review rejected' not in stdout:
            raise RuntimeError('watchdog death was not rejected: ' + stderr[-1000:])
        relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2].lstrip('/')
        events = pathlib.Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture/cgroup.events'
        if 'populated 0' not in events.read_text().splitlines():
            raise RuntimeError('synthetic child group remains populated')
        time.sleep(7)
        if (directory / 'survived').exists():
            raise RuntimeError('synthetic descendant survived watchdog failure')
        print('watchdog death after release: group empty; review rejected; marker absent', flush=True)
        os._exit(0)
    if mode == 'watchdog-both-crash':
        watchdog_pid = int((directory / 'watchdog-ready').read_text())
        status = pathlib.Path(f'/proc/{watchdog_pid}/status').read_text().splitlines()
        if f'PPid:\t{process.pid}' not in status:
            raise RuntimeError('watchdog is not the test controller child')
        os.kill(watchdog_pid, 19)
        os.kill(process.pid, 19)
        os.kill(process.pid, 9)
        os.kill(watchdog_pid, 9)
        process.wait(timeout=5)
        time.sleep(8)
        if not (directory / 'survived').exists():
            raise RuntimeError('simultaneous failure did not reproduce surviving descendant')
        print('controller and watchdog killed: synthetic descendant survived while outer unit alive', flush=True)
        os._exit(0)
    if mode == 'watchdog-no-disarm':
        watchdog_pid = int((directory / 'watchdog-ready').read_text())
        if os.readlink(f'/proc/{watchdog_pid}/fd/0') != '/dev/null':
            raise RuntimeError('watchdog unexpectedly has a disarm input channel')
        retained = os.open(f'/proc/{watchdog_pid}/fd/0', os.O_WRONLY | os.O_CLOEXEC)
        try:
            os.write(retained, b'Q')
            relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2].lstrip('/')
            events = pathlib.Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture/cgroup.events'
            process.kill()
            process.wait(timeout=5)
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if (directory / 'watchdog-stop-requested').exists() and 'populated 0' in events.read_text().splitlines():
                    break
                time.sleep(0.02)
            else:
                raise RuntimeError('watchdog did not respond to controller death')
            os.fstat(retained)
            time.sleep(7)
            if (directory / 'survived').exists():
                raise RuntimeError('synthetic descendant survived no-disarm scenario')
            print('no disarm channel: attempted Q ignored; controller death stopped group', flush=True)
        finally:
            os.close(retained)
        os._exit(0)
    if mode == 'watchdog-controller-crash':
        relative = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2].lstrip('/')
        events = pathlib.Path('/sys/fs/cgroup') / relative / 'tucupi-child-fixture/cgroup.events'
        process.kill()
        process.wait(timeout=5)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if (directory / 'watchdog-stop-requested').exists() and 'populated 0' in events.read_text().splitlines():
                break
            time.sleep(0.02)
        else:
            raise RuntimeError('synthetic watchdog did not stop child cgroup while unit main lived')
        time.sleep(7)
        if (directory / 'survived').exists():
            raise RuntimeError('synthetic descendant survived watchdog cancellation')
        print('watchdog controller crash: stop requested; child cgroup empty while outer unit alive; marker absent', flush=True)
        os._exit(0)
    if mode == 'controller-only-crash':
        process.kill()
        process.wait(timeout=5)
        # Keep the unit main alive: only the controller was killed. The marker
        # is written by a detached synthetic descendant after a bounded delay.
        time.sleep(8)
        if not (directory / 'survived').exists():
            raise RuntimeError('synthetic descendant did not demonstrate controller-only survival')
        print('controller-only crash: synthetic descendant survived while outer unit remained alive', flush=True)
        os._exit(0)
    if mode == 'controller-crash':
        # Do not drain inherited pipes before the unit kills its descendants.
        process.kill()
        process.wait(timeout=5)
        (directory / 'rust-controller-killed').touch()
        os._exit(42)
    stdout, stderr = process.communicate('cancel-fixture\n', timeout=8)
    if process.returncode != 0 or 'rust-cancelled-empty-pending' not in stdout:
        raise RuntimeError('Rust cancellation failed: ' + stderr[-1000:])
    if mode == 'watchdog-cancel':
        deadline = time.monotonic() + 3
        while not (directory / 'watchdog-stop-requested').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('watchdog did not observe normal controller exit')
            time.sleep(0.02)
    time.sleep(7)
    if (directory / 'survived').exists():
        raise RuntimeError('detached fixture descendant survived')
    print('Rust created and admitted its gated child; cancellation observed empty cgroup')
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
'''


def run_case(mode):
    codex = shutil.which('codex')
    if codex is None:
        raise RuntimeError('Codex CLI unavailable')
    root = pathlib.Path(__file__).resolve().parent.parent
    helper = root / 'target/debug/examples/codex_protocol_fixture'
    bridge = root / 'tests/codex_private_bridge_fixture.py'
    custodian = root / 'tests/codex_fixture_custodian.py'
    unit = 'tucupi-rust-owned-test-' + uuid.uuid4().hex + '.service'
    with tempfile.TemporaryDirectory(prefix='tucupi-rust-owned-', dir=pathlib.Path.home()) as directory:
        try:
            command = [
                'systemd-run', '--user', '--quiet', '--pipe', '--wait', '--collect', '--unit', unit,
                '--property=Delegate=yes', '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=40', '--property=TimeoutStopSec=1',
                '--property=MemoryMax=512M', '--property=TasksMax=64', '--property=CPUQuota=50%',
            ]
            if mode in ('broken-gate', 'cancelled-gate', 'watchdog-fail'):
                command.extend([str(helper), 'owned-spawn-fixture', directory,
                                str(pathlib.Path(codex).parent), str(bridge), mode])
            else:
                command.extend(['/usr/bin/python3', '-c', WORKER, directory, str(helper),
                                str(pathlib.Path(codex).parent), str(bridge), mode, str(custodian)])
            result = subprocess.run(command, capture_output=True, text=True, timeout=50, check=False)
            if mode == 'cancelled-gate':
                if result.returncode != 0 or 'cancelled fixture gate rejected; cgroup not created; worker not started' not in result.stdout:
                    raise RuntimeError(f'cancelled gate cleanup failed: {result.stderr[-2000:]}')
                print(result.stdout.strip())
            elif mode == 'watchdog-fail':
                expected = 'watchdog startup failed; synthetic cgroup empty; worker not started'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'watchdog startup failure scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'watchdog-dies-before-release':
                expected = 'watchdog died before release; synthetic cgroup empty; worker not started'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'watchdog death scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'watchdog-startup-crash':
                expected = 'watchdog startup crash: child cgroup empty; worker not started; outer unit alive'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'watchdog startup crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'broken-gate':
                if result.returncode != 0 or 'broken fixture gate rejected; cgroup observed empty' not in result.stdout:
                    raise RuntimeError(f'broken gate cleanup failed: {result.stderr[-2000:]}')
                print(result.stdout.strip())
            elif mode == 'controller-crash':
                if result.returncode == 0 or not (pathlib.Path(directory) / 'rust-controller-killed').exists():
                    raise RuntimeError('synthetic Rust controller did not crash as expected')
                time.sleep(7)
                if (pathlib.Path(directory) / 'survived').exists():
                    raise RuntimeError('detached fixture descendant survived controller crash')
                print('Rust controller killed; outer unit stopped the detached synthetic descendant')
            elif mode == 'watchdog-no-disarm':
                expected = 'no disarm channel: attempted Q ignored; controller death stopped group'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'no-disarm scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'custodian-three-crash':
                expected = 'custodian also killed: synthetic descendant survived while outer unit alive'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'custodian triple crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'custodian-both-crash':
                expected = 'custodian: both failures observed; child group empty; outer unit alive; marker absent'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'custodian simultaneous crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'watchdog-both-crash':
                expected = 'controller and watchdog killed: synthetic descendant survived while outer unit alive'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'simultaneous crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'watchdog-dies-after-release':
                expected = 'watchdog death after release: group empty; review rejected; marker absent'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'watchdog death after release failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'watchdog-controller-crash':
                expected = 'watchdog controller crash: stop requested; child cgroup empty while outer unit alive; marker absent'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'watchdog controller crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            elif mode == 'controller-only-crash':
                expected = 'controller-only crash: synthetic descendant survived while outer unit remained alive'
                if result.returncode != 0 or expected not in result.stdout:
                    raise RuntimeError(f'controller-only crash scenario failed: {result.stderr[-2000:]}')
                print(expected)
            else:
                if result.returncode != 0 or 'Rust created and admitted' not in result.stdout:
                    raise RuntimeError(f'synthetic Rust supervision failed: {result.stderr[-2000:]}')
                print(result.stdout.strip())
        finally:
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True,
                           timeout=10, check=False)


if __name__ == '__main__':
    run_case('cancelled-gate')
    run_case('broken-gate')
    run_case('cancel')
    run_case('watchdog-cancel')
    run_case('watchdog-fail')
    run_case('watchdog-dies-before-release')
    run_case('watchdog-startup-crash')
    run_case('watchdog-dies-after-release')
    run_case('watchdog-no-disarm')
    run_case('watchdog-both-crash')
    run_case('custodian-both-crash')
    run_case('custodian-three-crash')
    run_case('watchdog-controller-crash')
    run_case('controller-only-crash')
    run_case('controller-crash')
