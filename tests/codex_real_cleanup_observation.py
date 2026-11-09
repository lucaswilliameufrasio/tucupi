"""Opt-in probe of pinned cgroup observation during a synthetic unit stop.

Runs only a unique transient user service containing /usr/bin/sleep. This is
not a production supervisor and does not validate Codex, authentication, or
process ownership. Run after building example codex_protocol_fixture.
"""
import os
import pathlib
import selectors
import subprocess
import uuid


def main():
    unit = "tucupi-observation-test-" + uuid.uuid4().hex + ".service"
    observer = None
    events_fd = None
    binary = pathlib.Path(__file__).resolve().parent.parent / "target/debug/examples/codex_protocol_fixture"
    try:
        subprocess.run([
            "systemd-run", "--user", "--quiet", "--unit", unit,
            "--property=RuntimeMaxSec=15", "--property=KillMode=control-group",
            "--property=TimeoutStopSec=1", "/usr/bin/sleep", "12",
        ], check=True, capture_output=True, timeout=10)
        result = subprocess.run([
            "systemctl", "--user", "show", "--property=ControlGroup", "--value", unit,
        ], check=True, capture_output=True, text=True, timeout=5)
        relative = pathlib.PurePosixPath(result.stdout.strip())
        if not relative.is_absolute() or relative.name != unit or ".." in relative.parts:
            raise RuntimeError("unexpected synthetic service cgroup")
        group = pathlib.Path("/sys/fs/cgroup") / str(relative).lstrip("/")
        events_fd = os.open(group / "cgroup.events", os.O_RDONLY | os.O_CLOEXEC)
        if b"populated 1\n" not in os.pread(events_fd, 4096, 0):
            raise RuntimeError("pinned events descriptor did not observe population")
        observer = subprocess.Popen([str(binary), "cgroup-watch", str(group)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, env={})
        with selectors.DefaultSelector() as selector:
            selector.register(observer.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5) or observer.stdout.readline().strip() != "populated":
                raise RuntimeError("observer did not confirm the running cgroup")
        subprocess.run(["systemctl", "--user", "stop", unit], check=True, capture_output=True, timeout=10)
        stdout, stderr = observer.communicate("check\n", timeout=5)
        if observer.returncode != 0 or stdout.strip() not in ("empty", "unavailable"):
            raise RuntimeError(f"unexpected observer result: {stdout!r} {stderr!r}")
        print("running cgroup: populated; after stop:", stdout.strip())
        if stdout.strip() == "unavailable":
            print("cleanup remains unverified: cgroup events disappeared")
        try:
            pinned = os.pread(events_fd, 4096, 0)
        except OSError as error:
            print("pinned events descriptor after stop: unavailable (errno", error.errno, ")")
        else:
            values = [line for line in pinned.splitlines() if line.startswith(b"populated ")]
            if values not in ([b"populated 0"], [b"populated 1"]):
                raise RuntimeError("unexpected pinned events content")
            print("pinned events descriptor after stop:", values[0].decode("ascii"))
    finally:
        # Only the unique unit created by this test is targeted.
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, timeout=10, check=False)
        if observer is not None and observer.poll() is None:
            observer.kill()
            observer.communicate(timeout=5)
        if events_fd is not None:
            os.close(events_fd)


if __name__ == "__main__":
    main()
