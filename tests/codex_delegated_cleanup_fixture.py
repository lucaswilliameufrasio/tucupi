"""Opt-in cgroup-v2 delegation experiment, never a production runner.

Tests only synthetic processes in a unique transient user unit. The parent
fetches a synthetic response from loopback with a synthetic credential, then
stays alive while killing its child cgroup and observing `populated 0`.
No real credentials, external services, or host privilege changes are used.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid


WORKER = r'''
import http.server, json, os, pathlib, selectors, signal, subprocess, sys, threading, time, urllib.request
marker = pathlib.Path(sys.argv[1])
binary = sys.argv[2]
response_path = marker.with_name('synthetic-response')
class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        if self.headers.get('Authorization') != 'Bearer synthetic-only':
            self.send_error(401)
            return
        event = {'type': 'response.completed', 'response': {'status': 'completed', 'output': [{
            'type': 'message', 'role': 'assistant', 'content': [{
                'type': 'output_text', 'text': 'VERDICT: review\nREASON: synthetic'
            }]
        }]}}
        body = b'invalid synthetic response' if sys.argv[3].startswith('invalid') else ('data: ' + json.dumps(event) + '\n\n').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
if sys.argv[3] != 'bridge':
    server = http.server.HTTPServer(('127.0.0.1', 0), Model)
    server.timeout = 3
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request('http://127.0.0.1:' + str(server.server_port),
                                         data=b'{}', headers={'Authorization': 'Bearer synthetic-only'})
        with opener.open(request, timeout=3) as response:
            response_path.write_bytes(response.read(128001))
    finally:
        thread.join(timeout=3)
        server.server_close()
        if thread.is_alive():
            raise RuntimeError('synthetic model did not stop')
entry = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
parent = pathlib.Path('/sys/fs/cgroup') / entry.lstrip('/')
group = parent / 'tucupi-child-fixture'
observer = None
if sys.argv[3] == 'bridge':
    observer = subprocess.Popen([binary, 'owned-fixture-attempt'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={})
    with selectors.DefaultSelector() as selector:
        selector.register(observer.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=3) or observer.stdout.readline().strip() != 'fixture-created':
            raise RuntimeError('Rust fixture did not create child cgroup')
    collision = subprocess.run([binary, 'owned-fixture-attempt'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
    if collision.returncode == 0 or b'fixture cgroup already exists' not in collision.stderr:
        raise RuntimeError('Rust fixture did not reject the existing cgroup explicitly')
    print('Rust fixture created child exclusively; duplicate creation rejected', flush=True)
else:
    group.mkdir()
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(write_fd)
    if os.read(read_fd, 1) != b'1':
        os._exit(1)
    os.close(read_fd)
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    actual = pathlib.Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
    if pathlib.Path(actual).name != group.name:
        os._exit(2)
    if sys.argv[3] == 'bridge':
        marker.write_text('bridge started')
        os.execve('/usr/bin/python3', ['/usr/bin/python3', sys.argv[4]], {
            'PATH': sys.argv[5] + ':/usr/bin:/bin', 'HOME': str(marker.parent),
            'TUCUPI_BRIDGE_CANCEL_FIXTURE': str(marker.parent),
            'TUCUPI_BRIDGE_TEST_DIR': str(marker.parent),
            'PYTHONUNBUFFERED': '1',
        })
    grandchild = os.fork()
    if grandchild == 0:
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        marker.with_name('grandchild-started').write_text('grandchild started')
        time.sleep(20)
        os._exit(0)
    marker.write_text('child started')
    time.sleep(20)
    os._exit(0)
os.close(read_fd)
try:
    (group / 'cgroup.procs').write_text(str(child))
    os.write(write_fd, b'1')
    os.close(write_fd)
    write_fd = None
    deadline = time.monotonic() + (20 if sys.argv[3] == 'bridge' else 4)
    child_ready = marker.with_name('request-in-flight') if sys.argv[3] == 'bridge' else marker.with_name('grandchild-started')
    while not (marker.exists() and child_ready.exists()):
        if time.monotonic() >= deadline:
            raise RuntimeError('synthetic child did not start')
        time.sleep(0.01)
    before = (group / 'cgroup.events').read_text().splitlines()
    if 'populated 1' not in before:
        raise RuntimeError('child group was not populated')
    if sys.argv[3] == 'bridge':
        observer.stdin.write('bind\n')
        observer.stdin.flush()
    else:
        operation = 'attempt-cgroup-drop' if sys.argv[3] == 'invalid-drop' else 'attempt-cgroup-watch'
        observer = subprocess.Popen([binary, operation, str(group), str(response_path)], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={})
    with selectors.DefaultSelector() as selector:
        selector.register(observer.stdout, selectors.EVENT_READ)
        expected = ('fixture-bound' if sys.argv[3] == 'bridge' else
                    'ready-invalid' if sys.argv[3].startswith('invalid') else 'ready-valid')
        if not selector.select(timeout=2) or observer.stdout.readline().strip() != expected:
            raise RuntimeError('Rust attempt did not report expected response status')
    if sys.argv[3] == 'invalid-drop':
        stdout, stderr = observer.communicate(timeout=3)
        if observer.returncode == 0 or 'invalid fixture response' not in stderr:
            raise RuntimeError('Rust fixture did not reject invalid response')
    else:
        stdout, stderr = observer.communicate('cancel-fixture\n', timeout=3)
        if observer.returncode != 0 or stdout.strip() != 'cancelled-empty-pending':
            raise RuntimeError('Rust fixture did not cancel and observe the child group')
    _, status = os.waitpid(child, 0)
    if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
        raise RuntimeError('synthetic child was not killed by cgroup')
    deadline = time.monotonic() + 2
    while 'populated 0' not in (group / 'cgroup.events').read_text().splitlines():
        if time.monotonic() >= deadline:
            raise RuntimeError('child cgroup remained populated')
        time.sleep(0.01)
    if sys.argv[3] == 'bridge':
        time.sleep(7)
        if marker.with_name('survived').exists():
            raise RuntimeError('detached bridge descendant survived cgroup cancellation')
    print('fixture ' + sys.argv[3] + '; delegated cgroup observed populated 1 -> 0', flush=True)
finally:
    # The transient unit's KillMode and RuntimeMaxSec remain the outer fallback.
    if write_fd is not None:
        os.close(write_fd)
    if observer is not None and observer.poll() is None:
        observer.kill()
        observer.communicate(timeout=3)
    try:
        group.rmdir()
    except OSError:
        pass
'''


def main():
    unit = "tucupi-delegation-test-" + uuid.uuid4().hex + ".service"
    binary = pathlib.Path(__file__).resolve().parent.parent / "target/debug/examples/codex_protocol_fixture"
    mode = 'bridge' if sys.argv[1:] == ['--bridge'] else 'invalid-drop'
    codex = shutil.which('codex') if mode == 'bridge' else None
    if mode == 'bridge' and codex is None:
        raise RuntimeError('Codex CLI unavailable')
    bridge_script = pathlib.Path(__file__).resolve().with_name('codex_private_bridge_fixture.py')
    with tempfile.TemporaryDirectory(prefix="tucupi-delegation-", dir=pathlib.Path.home()) as directory:
        marker = pathlib.Path(directory) / "child-started"
        fake_group = pathlib.Path(directory) / 'unowned'
        fake_group.mkdir()
        (fake_group / 'cgroup.events').write_text('populated 1\n')
        kill_file = fake_group / 'cgroup.kill'
        kill_file.write_text('untouched')
        response = pathlib.Path(directory) / 'response'
        event = {'type': 'response.completed', 'response': {'status': 'completed', 'output': [{
            'type': 'message', 'role': 'assistant', 'content': [{
                'type': 'output_text', 'text': 'VERDICT: review\nREASON: synthetic'
            }]
        }]}}
        response.write_text('data: ' + json.dumps(event) + '\n\n')
        rejected = subprocess.run([str(binary), 'review-cgroup-watch', str(fake_group), str(response)],
                                  input='cancel-fixture\n', capture_output=True, text=True, timeout=5)
        if rejected.returncode == 0 or kill_file.read_text() != 'untouched':
            raise RuntimeError('Rust fixture accepted an unrelated cgroup path')
        print('Rust fixture refused cancellation of an unrelated path')
        try:
            result = subprocess.run([
                "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
                "--unit", unit, "--property=Delegate=yes", "--property=KillMode=control-group",
                "--property=RuntimeMaxSec=35", "--property=TimeoutStopSec=1",
                "--property=MemoryMax=512M", "--property=TasksMax=64", "--property=CPUQuota=50%",
                "/usr/bin/python3", "-c", WORKER, str(marker), str(binary), mode,
                str(bridge_script), str(pathlib.Path(codex).parent) if codex else '/usr/bin',
            ], capture_output=True, text=True, timeout=45, check=False)
            if result.returncode != 0 or "populated 1 -> 0" not in result.stdout or not marker.is_file():
                raise RuntimeError(f"delegated cleanup unavailable: stdout={result.stdout!r}, stderr={result.stderr!r}")
            print(result.stdout.strip())
        finally:
            # Only this unique transient unit is targeted.
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)


if __name__ == "__main__":
    main()
