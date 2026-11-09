"""Opt-in synthetic network-boundary experiment, not a production runner.

Uses two private network namespaces and a test-only Unix-socket bridge. The
sandbox and Codex CLI can reach a filtered Rust fixture broker while a probe
cannot reach the fake upstream directly. No real credentials or providers are used.
Build the codex_transport_fixture example with feature codex-fixture first.
"""
import http.server
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import codex_broker_fixture as fixture
from codex_isolated_smoke import event_stream

LIMIT = 136_192


def read_request(connection):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = connection.recv(4096)
        if not chunk or len(data) + len(chunk) > 8192:
            raise RuntimeError('invalid synthetic request headers')
        data += chunk
    head, body = data.split(b'\r\n\r\n', 1)
    lengths = [line.split(b':', 1)[1].strip() for line in head.split(b'\r\n')[1:]
               if line.lower().startswith(b'content-length:')]
    if len(lengths) != 1:
        raise RuntimeError('invalid synthetic request length')
    length = int(lengths[0])
    if length > 128_000 or len(body) > length:
        raise RuntimeError('synthetic request exceeds limit')
    while len(body) < length:
        chunk = connection.recv(min(4096, length - len(body)))
        if not chunk:
            raise RuntimeError('truncated synthetic request')
        body += chunk
    return head + b'\r\n\r\n' + body


def relay_once(client, upstream):
    client.settimeout(5)
    upstream.settimeout(5)
    upstream.sendall(read_request(client))
    total = 0
    while True:
        chunk = upstream.recv(4096)
        if not chunk:
            break
        total += len(chunk)
        if total > LIMIT:
            raise RuntimeError('synthetic response exceeds limit')
        client.sendall(chunk)


WORKER = r'''
import http.client, json, os, socket, sys
proxy, upstream = map(int, sys.argv[1:3])
if 'TUCUPI_SYNTHETIC_PRIVATE' in os.environ:
    raise RuntimeError('synthetic outer environment leaked into sandbox')
try:
    with open(sys.argv[3], 'rb') as private_file:
        private_file.read(1)
except OSError:
    pass
else:
    raise RuntimeError('synthetic private file was readable inside sandbox')
try:
    s = socket.create_connection(('127.0.0.1', upstream), timeout=2)
except OSError:
    pass
else:
    s.close()
    raise RuntimeError('synthetic upstream was reachable directly')
c = http.client.HTTPConnection('127.0.0.1', proxy, timeout=4)
c.request('POST', '/v1/responses', json.dumps({'input':'synthetic','tools':[{'type':'function','name':'synthetic'}]}),
          {'Authorization':'Bearer synthetic-client', 'Content-Type':'application/json'})
r = c.getresponse()
body = r.read()
c.close()
if r.status != 200 or b'VERDICT: review' not in body:
    raise RuntimeError('filtered synthetic broker was unavailable')
print('worker: private file and environment blocked; direct upstream blocked; filtered broker reachable')
'''


def inner(socket_path, upstream_port, private_file):
    if os.environ.get('TUCUPI_SYNTHETIC_PRIVATE') != 'synthetic-only':
        raise RuntimeError('synthetic environment control unavailable')
    subprocess.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'], check=True, timeout=5)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    if listener.getsockname()[1] == int(upstream_port):
        raise RuntimeError('synthetic port collision')
    listener.listen(1)
    listener.settimeout(30)
    failures = []

    def bridge():
        try:
            for _ in range(2):
                with listener.accept()[0] as client, socket.socket(socket.AF_UNIX) as upstream:
                    upstream.connect(socket_path)
                    relay_once(client, upstream)
        except Exception as error:
            failures.append(str(error))

    thread = threading.Thread(target=bridge, daemon=True)
    thread.start()
    try:
        bubblewrap = shutil.which('bwrap')
        if bubblewrap is None:
            raise RuntimeError('bubblewrap unavailable')
        result = subprocess.run([
            bubblewrap, '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
            '--die-with-parent', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/work', '--chdir', '/work',
            '--clearenv', '--setenv', 'PATH', '/usr/bin', '--', '/usr/bin/python3', '-c',
            WORKER, str(listener.getsockname()[1]), upstream_port, private_file,
        ], text=True, capture_output=True, timeout=10, check=True)
        codex = shutil.which('codex')
        if codex is None:
            raise RuntimeError('Codex CLI unavailable')
        codex_result = subprocess.run([
            bubblewrap, '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
            '--die-with-parent', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib64', '/lib64',
            '--ro-bind', os.path.realpath(codex), '/codex', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--tmpfs', '/work', '--dir', '/work/.codex', '--chdir', '/work',
            '--clearenv', '--setenv', 'HOME', '/work', '--setenv', 'CODEX_HOME', '/work/.codex',
            '--setenv', 'PATH', '/usr/bin', '--setenv', 'FIXTURE_KEY', 'synthetic-client-token',
            '--setenv', 'TOKIO_WORKER_THREADS', '2', '--', '/codex', 'exec',
            '--skip-git-repo-check', '--ephemeral', '--ignore-user-config', '--ignore-rules',
            '--disable', 'hooks', '--disable', 'shell_tool', '-m', 'synthetic-model',
            '-c', 'model_provider="fixture"', '-c', 'model_providers.fixture.name="fixture"',
            '-c', f'model_providers.fixture.base_url="http://127.0.0.1:{listener.getsockname()[1]}/v1"',
            '-c', 'model_providers.fixture.env_key="FIXTURE_KEY"',
            '-c', 'model_providers.fixture.wire_api="responses"',
            '-c', 'model_providers.fixture.request_max_retries=0',
            '-c', 'model_providers.fixture.stream_max_retries=0',
            '-c', 'analytics.enabled=false', '-c', 'web_search="disabled"', 'synthetic prompt',
        ], text=True, capture_output=True, timeout=25, check=False)
        if codex_result.returncode != 0 or 'VERDICT: review' not in codex_result.stdout:
            raise RuntimeError(f'synthetic Codex CLI failed: {codex_result.stderr[-2000:]!r}')
        thread.join(timeout=6)
        if thread.is_alive() or failures:
            raise RuntimeError('synthetic inner bridge failed')
        print(result.stdout.strip())
        print('Codex CLI: synthetic review received through private bridge')
    finally:
        listener.close()


def outer():
    subprocess.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'], check=True, timeout=5)
    fixture.FakeModel.requests = []
    fixture.FakeModel.response_body = event_stream(False)
    class SyntheticModel(fixture.FakeModel):
        def do_POST(self):
            hold = os.environ.get('TUCUPI_BRIDGE_CANCEL_FIXTURE')
            if os.environ.get('TUCUPI_BRIDGE_BAD_RESPONSE') and len(fixture.FakeModel.requests) == 1:
                fixture.FakeModel.response_body = event_stream(True)
            if hold and len(fixture.FakeModel.requests) == 1:
                # Test-only detached descendant, started during the CLI request.
                code = ("import os,pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                        "p.joinpath('started').write_text(str(os.getpid())); time.sleep(6); "
                        "p.joinpath('survived').touch()")
                subprocess.Popen(['/usr/bin/python3', '-c', code, hold],
                                 start_new_session=True, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 3
                while not (Path(hold) / 'started').exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError('synthetic descendant did not start')
                    time.sleep(0.01)
                (Path(hold) / 'request-in-flight').touch()
                time.sleep(20)
            super().do_POST()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SyntheticModel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    broker = None
    bridge_thread = None
    unix_listener = None
    try:
        binary = Path(__file__).resolve().parent.parent / 'target/debug/examples/codex_transport_fixture'
        broker = subprocess.Popen([str(binary), str(server.server_port)], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, env={'TOKIO_WORKER_THREADS': '2'})
        with selectors.DefaultSelector() as selector:
            selector.register(broker.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                raise RuntimeError('synthetic broker did not start')
            broker_port = int(broker.stdout.readline().strip())
        fixture_root = os.environ.get('TUCUPI_BRIDGE_TEST_DIR') or Path.home()
        with tempfile.TemporaryDirectory(prefix='tucupi-bridge-', dir=fixture_root) as directory:
            socket_path = str(Path(directory) / 'broker.sock')
            private_file = Path(directory) / 'synthetic-private'
            private_file.write_text('synthetic-only')
            if private_file.read_text() != 'synthetic-only':
                raise RuntimeError('synthetic file control unavailable')
            unix_listener = socket.socket(socket.AF_UNIX)
            unix_listener.bind(socket_path)
            os.chmod(socket_path, 0o600)
            unix_listener.listen(1)
            unix_listener.settimeout(30)
            failures = []

            def bridge():
                try:
                    for _ in range(2):
                        with unix_listener.accept()[0] as client, socket.create_connection(('127.0.0.1', broker_port), timeout=5) as upstream:
                            relay_once(client, upstream)
                except Exception as error:
                    failures.append(str(error))

            bridge_thread = threading.Thread(target=bridge, daemon=True)
            bridge_thread.start()
            unshare = shutil.which('unshare')
            if unshare is None:
                raise RuntimeError('unshare unavailable')
            result = subprocess.run([
                unshare, '--user', '--map-root-user', '--net', '/usr/bin/python3',
                str(Path(__file__).resolve()), '--inner', socket_path, str(server.server_port), str(private_file),
            ], text=True, capture_output=True, timeout=35, check=False,
               env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'TUCUPI_SYNTHETIC_PRIVATE': 'synthetic-only'})
            bridge_thread.join(timeout=6)
            if result.returncode != 0 or bridge_thread.is_alive() or failures:
                raise RuntimeError(f'synthetic private bridge failed: {result.stderr[-2000:]!r}')
            if len(fixture.FakeModel.requests) != 2:
                raise RuntimeError('expected exactly two synthetic upstream requests')
            for _, credential, payload in fixture.FakeModel.requests:
                if credential != 'Bearer ' + fixture.SYNTHETIC_TOKEN or 'tools' in payload:
                    raise RuntimeError('synthetic broker filtering or credential boundary failed')
            print(result.stdout.strip())
            print('synthetic upstream: two filtered requests with broker credential')
    finally:
        if unix_listener is not None:
            unix_listener.close()
        if broker is not None and broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--inner':
        inner(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if len(sys.argv) == 2 and sys.argv[1] == '--outer':
        outer()
        return
    fixture_dir = os.environ.get('TUCUPI_BRIDGE_CANCEL_FIXTURE')
    if fixture_dir:
        (Path(fixture_dir) / 'bridge-root-pid').write_text(str(os.getpid()))
    unshare = shutil.which('unshare')
    if unshare is None:
        raise RuntimeError('unshare unavailable')
    subprocess.run([unshare, '--user', '--map-root-user', '--net', '/usr/bin/python3',
                    str(Path(__file__).resolve()), '--outer'], check=True, timeout=50)


if __name__ == '__main__':
    main()
