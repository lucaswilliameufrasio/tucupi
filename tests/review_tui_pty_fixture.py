"""Run the opt-in fixture executable in isolated PTYs and a keyctl session."""
import errno
import fcntl
import http.server
import json
import multiprocessing
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import uuid

CTX = multiprocessing.get_context("fork")
PROVIDERS = ("openrouter", "openai", "anthropic", "deepseek", "zai", "kimi")


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.status = CTX.Value("i", 200)
        self.requests = CTX.Queue()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body)
        self.server.requests.put((self.headers.get("Authorization"), self.headers.get("x-api-key"), self.headers.get("anthropic-version"), request))
        provider = request["model"].removeprefix("synthetic-model-")
        text = "VERDICT: safe\nREASON: synthetic"
        if provider == "openai":
            answer = {"status": "completed", "output": [{"type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text}]}]}
        elif provider == "anthropic":
            answer = {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}
        else:
            answer = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": text}}]}
        data = json.dumps(answer).encode()
        self.send_response(self.server.status.value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def launch(binary, root, service, port, provider, setup, status, server):
    pid, master = os.forkpty()
    if pid == 0:
        env = {"HOME": str(root), "XDG_CACHE_HOME": str(root / "cache"), "PATH": "/usr/bin:/bin", "TERM": "xterm", "LANG": "en_US.UTF-8", "TUCUPI_REVIEW_PTY_SERVICE": service, "TUCUPI_REVIEW_PTY_PORT": str(port)}
        os.execve(str(binary), [str(binary), str(root)], env)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 150, 0, 0))
    output = bytearray()
    exited = False

    def wait_for(text, timeout=10, start=0):
        deadline = time.monotonic() + timeout
        while text not in output[start:]:
            if time.monotonic() > deadline:
                raise RuntimeError(f"missing {text!r}; terminal tail: {bytes(output[-1500:])!r}")
            if select.select([master], [], [], .05)[0]:
                output.extend(os.read(master, 32768))

    def send(data):
        os.write(master, data)
        time.sleep(.15)

    try:
        wait_for(b"tucupi-synthetic-package")
        if setup:
            send(b"a")
            wait_for(b"API review")
            for _ in range(PROVIDERS.index(provider)):
                send(b"\x1b[C")
            send(b"m")
            send(f"synthetic-model-{provider}".encode())
            send(b"\r")
            send(b"k")
            send(b"synthetic-key")
            send(b"\r")
            wait_for(b"Key saved")
            send(b"\r")
            wait_for(b"Provider selected")
        else:
            server.status.value = status
            send(b"a")
            wait_for(b"API review")
            wait_for(f"synthetic-model-{provider}".encode())
            send(b"\x1b")
            send(b"c")
            auth, api_key, version, request = server.requests.get(timeout=10)
            if provider == "anthropic":
                assert api_key == "synthetic-key" and version == "2023-06-01"
                assert auth is None
            else:
                assert auth == "Bearer synthetic-key" and api_key is None
            assert request["model"] == f"synthetic-model-{provider}"
            assert "tucupi-synthetic-package" in json.dumps(request)
            if status != 200:
                wait_for(b"Source review")
                wait_for(b"The model was unavailable")
                send(b"\x1b")
            else:
                time.sleep(.4)
                start = len(output)
                send(b"a")
                wait_for(b"API review", start=start)
                send(b"\x1b")
        if b"synthetic-key" in output:
            raise RuntimeError("key was displayed in terminal output")
        send(b"q")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if select.select([master], [], [], .05)[0]:
                try:
                    output.extend(os.read(master, 32768))
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
            done, result = os.waitpid(pid, os.WNOHANG)
            if done:
                exited = True
                assert os.WIFEXITED(result) and os.WEXITSTATUS(result) == 0
                return
        raise RuntimeError("TUI did not exit")
    finally:
        if not exited:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        os.close(master)


def clean_entry(service, account):
    description = f"keyring-rs:{account}@{service}"
    result = subprocess.run(["keyctl", "search", "@s", "user", description], text=True, capture_output=True, check=False)
    if result.returncode == 0:
        subprocess.run(["keyctl", "invalidate", result.stdout.strip()], check=True)
    result = subprocess.run(["keyctl", "search", "@s", "user", description], capture_output=True, check=False)
    if result.returncode == 0:
        raise RuntimeError("synthetic keyring entry remains")


def main():
    binary = Path(__file__).resolve().parent.parent / "target/debug/tucupi"
    services = []
    server = Server()
    server_process = CTX.Process(target=server.serve_forever, daemon=True)
    server_process.start()
    try:
        with tempfile.TemporaryDirectory(prefix="tucupi-review-pty-", dir=Path.home()) as directory:
            root = Path(directory)
            for provider in PROVIDERS:
                service = "tucupi-pty-" + uuid.uuid4().hex
                services.append((service, provider))
                launch(binary, root, service, server.server_port, provider, True, 0, server)
                for status in (200, 401, 500):
                    launch(binary, root, service, server.server_port, provider, False, status, server)
                    print(f"restarted TUI: {provider} HTTP {status} verified", flush=True)
    finally:
        server_process.terminate()
        server_process.join(timeout=5)
        server.server_close()
        for service, provider in services:
            clean_entry(service, f"review-{provider}-api-key")
            clean_entry(service, "review-provider-selection")


if __name__ == "__main__":
    main()
