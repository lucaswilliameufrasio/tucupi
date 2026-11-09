"""Opt-in negative isolation probe; never contacts a real provider.

Recreates the network arrangement of codex_isolated_smoke.py and fails if an
untrusted process can contact the fake upstream without the fixture broker.
All addresses, credentials, requests and responses are synthetic.
"""
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import codex_broker_fixture as fixture


PROBE = r'''
import http.client, json, sys
connection = http.client.HTTPConnection('127.0.0.1', int(sys.argv[1]), timeout=2)
try:
    connection.request('POST', '/v1/responses', json.dumps({'tools': [{'type': 'function', 'name': 'synthetic'}]}),
                       {'Authorization': 'Bearer synthetic-untrusted', 'Content-Type': 'application/json'})
    response = connection.getresponse()
    response.read()
    print('DIRECT_REACHABLE' if response.status == 200 else 'DIRECT_REJECTED')
except OSError:
    print('DIRECT_BLOCKED')
finally:
    connection.close()
'''


def inside():
    subprocess.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'], check=True, timeout=5)
    fixture.FakeModel.requests = []
    fixture.FakeModel.response_body = b'data: {"type":"response.completed","response":{"status":"completed","output":[]}}\n\n'
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), fixture.FakeModel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
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
            PROBE, str(server.server_port),
        ], capture_output=True, text=True, timeout=10, check=True)
        outcome = result.stdout.strip()
        if outcome == 'DIRECT_REACHABLE':
            if len(fixture.FakeModel.requests) != 1 or 'tools' not in fixture.FakeModel.requests[0][2]:
                raise RuntimeError('direct request did not reach the synthetic upstream as expected')
            raise RuntimeError('UNSAFE: sandbox reached synthetic upstream directly; broker filtering was bypassed')
        if outcome != 'DIRECT_BLOCKED' or fixture.FakeModel.requests:
            raise RuntimeError('unexpected isolation probe result')
        print('synthetic upstream was unreachable from the sandbox')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError('synthetic service did not stop')


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--inside':
        inside()
        return
    unshare = shutil.which('unshare')
    if unshare is None:
        raise RuntimeError('unshare unavailable')
    subprocess.run([unshare, '--user', '--map-root-user', '--net', '/usr/bin/python3',
                    str(Path(__file__).resolve()), '--inside'], check=True, timeout=20)


if __name__ == '__main__':
    main()
