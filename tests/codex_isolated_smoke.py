"""Opt-in Linux smoke test for the Codex fixture, never a production runner.

Run manually: python3 tests/codex_isolated_smoke.py
Requires unprivileged user/network namespaces, ip, bubblewrap, and Codex CLI.
Only synthetic credentials and loopback services in a private namespace are used.
"""

import http.server
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import threading

import codex_broker_fixture as fixture


def event_stream(tool_call):
    if tool_call:
        item = {"type": "function_call", "name": "shell", "call_id": "synthetic"}
    else:
        item = {
            "type": "message", "id": "msg_fixture", "role": "assistant",
            "status": "completed", "content": [{"type": "output_text",
            "text": "VERDICT: review\nREASON: synthetic fixture", "annotations": []}],
        }
    response = {
        "id": "resp_fixture", "object": "response", "status": "completed",
        "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
    }
    events = [
        {"type": "response.created", "response": {"id": "resp_fixture", "object": "response", "status": "in_progress", "output": []}},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]
    return ("".join("data: " + json.dumps(event) + "\n\n" for event in events) + "data: [DONE]\n\n").encode()


def run_inside_namespace(binary):
    subprocess.run(["/usr/bin/ip", "link", "set", "lo", "up"], check=True, timeout=5)
    if os.environ.get("TUCUPI_VERIFY_CGROUP") == "1":
        entry = Path("/proc/self/cgroup").read_text().strip().split(":", 2)[2]
        group = Path("/sys/fs/cgroup") / entry.lstrip("/")
        quota, period = (group / "cpu.max").read_text().split()
        if (int((group / "memory.max").read_text()) != 512 * 1024 * 1024
                or int((group / "pids.max").read_text()) != 64
                or quota == "max" or int(quota) * 2 > int(period)):
            raise RuntimeError("fixture cgroup limits unavailable")
        observer = Path(__file__).resolve().parent.parent / "target/debug/examples/codex_protocol_fixture"
        observation = subprocess.run([str(observer), "cgroup-events", str(group)],
                                     capture_output=True, text=True, timeout=5, env={}, check=True)
        if observation.stdout.strip() != "populated":
            raise RuntimeError("Rust observer did not see the running fixture cgroup")
        print("supervised cgroup limits verified", flush=True)
    fixture.FakeModel.requests = []
    fixture.FakeModel.response_body = event_stream(False)
    probe_dir = os.environ.get("TUCUPI_CANCEL_PROBE_DIR")
    model = fixture.FakeModel
    if probe_dir:
        class SlowModel(fixture.FakeModel):
            def do_POST(self):
                (Path(probe_dir) / "request-started").write_text("synthetic")
                threading.Event().wait(20)
                super().do_POST()
        model = SlowModel
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), model)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    binary_path = Path(__file__).resolve().parent.parent / "target/debug/examples/codex_transport_fixture"
    if os.environ.get("TUCUPI_TEST_MISSING_LISTENER") == "1":
        # Test-only failure injection: an executable file cannot contain a child.
        binary_path = binary_path / "missing"
    broker = None
    try:
        broker_env = {"TOKIO_WORKER_THREADS": "2"}
        if os.environ.get("TUCUPI_VERIFY_CGROUP") == "1":
            broker_env["TUCUPI_FIXTURE_VERIFY_CGROUP"] = "1"
            broker_env["TUCUPI_FIXTURE_EXPECTED_CGROUP"] = entry
        broker = subprocess.Popen([str(binary_path), str(upstream.server_port)], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, env=broker_env)
        with selectors.DefaultSelector() as selector:
            selector.register(broker.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                raise RuntimeError("Rust fixture listener did not start")
            port = int(broker.stdout.readline().strip())
        run_codex_checks(binary, port)
        if broker.wait(timeout=5) != 0:
            raise RuntimeError("Rust fixture listener failed")
    finally:
        if broker is not None and broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("fixture server did not stop")


def run_codex_checks(binary, port):
    probe_dir = os.environ.get("TUCUPI_CANCEL_PROBE_DIR")
    executable_mounts = ["--ro-bind", binary, "/codex"]
    if probe_dir:
        executable_mounts = ["--ro-bind", binary, "/codex-real", "--ro-bind", str(Path(probe_dir) / "wrapper"), "/codex", "--bind", probe_dir, "/scratch"]
    command = [
        "bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent",
        "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib64", "/lib64", *executable_mounts,
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/work", "--dir", "/work/.codex",
        "--chdir", "/work", "--clearenv", "--setenv", "HOME", "/work", "--setenv", "CODEX_HOME", "/work/.codex",
        "--setenv", "PATH", "/usr/bin", "--setenv", "FIXTURE_KEY", "synthetic-client-token",
        "--setenv", "TOKIO_WORKER_THREADS", "2", "--", "/codex",
        "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--disable", "hooks",
        "--disable", "shell_tool", "-m", "synthetic-model", "-c", 'model_provider="fixture"',
        "-c", 'model_providers.fixture.name="fixture"', "-c", f'model_providers.fixture.base_url="http://127.0.0.1:{port}/v1"',
        "-c", 'model_providers.fixture.env_key="FIXTURE_KEY"', "-c", 'model_providers.fixture.wire_api="responses"',
        "-c", "model_providers.fixture.request_max_retries=0", "-c", "model_providers.fixture.stream_max_retries=0",
        "-c", "analytics.enabled=false", "-c", 'web_search="disabled"', "synthetic prompt",
    ]
    result = run_codex_process(command)
    if result.returncode != 0 or "VERDICT: review" not in result.stdout:
        raise AssertionError(f"Codex fixture response failed (exit {result.returncode}); stdout={result.stdout[-2000:]!r}; stderr={result.stderr[-2000:]!r}")
    if len(fixture.FakeModel.requests) != 1:
        raise AssertionError("expected one request to the synthetic service")
    path, credential, payload = fixture.FakeModel.requests[0]
    if path != "/v1/responses" or credential != "Bearer " + fixture.SYNTHETIC_TOKEN:
        raise AssertionError("wrong fixture route or synthetic authentication")
    if "tools" in payload or "tool_choice" in payload:
        raise AssertionError("tool declarations reached the synthetic service")
    print("Codex -> Rust fixture broker -> fake model: passed; tools removed; synthetic broker credential used")
    fixture.FakeModel.requests = []
    fixture.FakeModel.response_body = event_stream(True)
    rejected = run_codex_process(command)
    if rejected.returncode == 0 or not fixture.FakeModel.requests:
        raise AssertionError("synthetic tool-call response was not rejected by the Codex flow")
    if "VERDICT: safe" in rejected.stdout:
        raise AssertionError("failed synthetic review was accepted as safe")
    print("Codex -> Rust fixture broker: synthetic tool-call response rejected")


def run_codex_process(command):
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if os.environ.get("TUCUPI_VERIFY_CGROUP") == "1":
            if Path(f"/proc/{process.pid}/cgroup").read_text() != Path("/proc/self/cgroup").read_text():
                raise RuntimeError("sandbox process escaped fixture cgroup")
        stdout, stderr = process.communicate(timeout=25)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        raise


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        run_inside_namespace(sys.argv[2])
        return
    binary = os.environ.get("TUCUPI_CODEX_FIXTURE_BINARY") or shutil.which("codex")
    if binary is None or shutil.which("bwrap") is None or shutil.which("unshare") is None:
        raise RuntimeError("codex, bubblewrap and unshare are required")
    subprocess.run([
        "unshare", "--user", "--map-root-user", "--net", "/usr/bin/python3",
        os.path.abspath(__file__), "--inside", os.path.realpath(binary),
    ], check=True, timeout=40)


if __name__ == "__main__":
    main()
