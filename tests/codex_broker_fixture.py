"""Local-only Codex broker experiment. Not connected to Tucupi or real credentials.

Run: cargo build --example codex_protocol_fixture
     python3 tests/codex_broker_fixture.py
This fixture does not provide authentication, a sandbox, or production HTTP handling.
"""

import http.client
import http.server
import json
from pathlib import Path
import subprocess
import threading
import unittest

LIMIT = 128_000
SYNTHETIC_TOKEN = "synthetic-broker-token"
PROTOCOL_FIXTURE = Path(__file__).resolve().parent.parent / "target/debug/examples/codex_protocol_fixture"


def validate_with_rust(mode, body):
    """Invoke the Rust validation code; helper errors always fail closed."""
    try:
        result = subprocess.run(
            [str(PROTOCOL_FIXTURE), mode], input=body, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={}, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or len(result.stdout) > LIMIT:
        return None
    return result.stdout


class FixtureBroker(http.server.BaseHTTPRequestHandler):
    """Restricted test intermediary: fixed loopback upstream and synthetic auth."""

    upstream_port = 0

    def log_message(self, *_args):
        pass

    def do_POST(self):
        if self.path != "/v1/responses" or self.headers.get("Transfer-Encoding"):
            self.send_error(400)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > LIMIT:
                self.send_error(413)
                return
            payload = validate_with_rust("request", self.rfile.read(length))
            if payload is None:
                self.send_error(400)
                return
            connection = http.client.HTTPConnection("127.0.0.1", self.upstream_port, timeout=2)
            try:
                connection.request("POST", "/v1/responses", payload, {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + SYNTHETIC_TOKEN,
                })
                response = connection.getresponse()
                body = response.read(LIMIT + 1)
                if response.status != 200 or len(body) > LIMIT or validate_with_rust("response", body) != body:
                    self.send_error(502)
                    return
            finally:
                connection.close()
        except (OSError, ValueError, UnicodeDecodeError):
            self.send_error(502)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeModel(http.server.BaseHTTPRequestHandler):
    requests = []
    response_body = b''

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        self.requests.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(length))))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)


class BrokerFixtureTests(unittest.TestCase):
    def setUp(self):
        FakeModel.requests = []
        FakeModel.response_body = b'data: {"type":"response.completed","response":{"status":"completed","output":[]}}\n\ndata: [DONE]\n\n'
        self.model = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeModel)
        FixtureBroker.upstream_port = self.model.server_port
        self.broker = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureBroker)
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (self.model, self.broker)]
        for thread in self.threads:
            thread.start()

    def tearDown(self):
        for server in (self.broker, self.model):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def request(self, body, path="/v1/responses"):
        conn = http.client.HTTPConnection("127.0.0.1", self.broker.server_port, timeout=3)
        try:
            conn.request("POST", path, json.dumps(body).encode(), {"Authorization": "Bearer untrusted-client"})
            response = conn.getresponse()
            data = response.read()
            return response.status, data
        finally:
            conn.close()

    def test_strips_tools_and_does_not_forward_client_credential(self):
        status, _ = self.request({"model": "fixture", "input": [{"role": "user", "content": "synthetic"}], "tools": [{"type": "function", "name": "shell"}], "tool_choice": "auto"})
        self.assertEqual(status, 200)
        path, credential, request = FakeModel.requests[0]
        self.assertEqual(path, "/v1/responses")
        self.assertEqual(credential, "Bearer " + SYNTHETIC_TOKEN)
        self.assertNotIn("tools", request)
        self.assertNotIn("tool_choice", request)

    def test_rejects_tool_calls_and_unexpected_paths(self):
        self.assertEqual(self.request({"input": [{"type": "function_call", "name": "shell"}]})[0], 400)
        self.assertEqual(self.request({}, "/other")[0], 400)
        self.assertEqual(FakeModel.requests, [])

    def test_rejects_model_tool_call_before_forwarding_response(self):
        for kind in ("function_call", "computer_call", "web_search_call", "mcp_call"):
            event = {"type": "response.output_item.done", "item": {"type": kind}}
            FakeModel.response_body = ("data: " + json.dumps(event) + '\n\ndata: {"type":"response.completed","response":{"status":"completed","output":[]}}\n\n').encode()
            status, body = self.request({"input": []})
            self.assertEqual(status, 502)
            self.assertNotIn(kind.encode(), body)

    def test_rejects_incomplete_and_oversized_model_responses(self):
        for body in (b'data: {"type":"response.created"}\n\n', b'x' * (LIMIT + 1)):
            FakeModel.response_body = body
            self.assertEqual(self.request({"input": []})[0], 502)

    def test_rejects_unknown_output_item_and_noncompleted_response(self):
        for event in (
            {"type": "response.completed", "response": {"status": "completed", "output": [{"type": "tool_use", "name": "shell"}]}},
            {"type": "response.completed", "response": {"status": "incomplete", "output": []}},
        ):
            FakeModel.response_body = ("data: " + json.dumps(event) + "\n\n").encode()
            self.assertEqual(self.request({"input": []})[0], 502)

    def test_missing_rust_validator_does_not_fall_back(self):
        global PROTOCOL_FIXTURE
        original = PROTOCOL_FIXTURE
        try:
            PROTOCOL_FIXTURE = original.parent / "missing-codex-fixture"
            self.assertEqual(self.request({"input": []})[0], 400)
            self.assertEqual(FakeModel.requests, [])
        finally:
            PROTOCOL_FIXTURE = original


if __name__ == "__main__":
    unittest.main()
