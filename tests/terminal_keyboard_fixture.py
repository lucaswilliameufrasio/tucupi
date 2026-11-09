"""Exercise production App and batch keyboard input in isolated Linux PTYs."""
import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import struct
import tempfile
import termios
import time


def run_case(binary, root, batch):
    pid, master = os.forkpty()
    if pid == 0:
        os.chdir(root)
        env = {'HOME': str(root), 'XDG_STATE_HOME': str(root / 'state'),
               'PATH': str(root), 'TERM': 'xterm', 'LANG': 'en_US.UTF-8'}
        args = [str(binary)] + (['-i'] if batch else []) + [str(root)]
        os.execve(str(binary), args, env)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
    output = bytearray()
    status = None

    def wait_for(needle, timeout=8):
        deadline = time.monotonic() + timeout
        while needle not in output:
            if time.monotonic() >= deadline:
                raise RuntimeError('terminal text not observed: ' + repr(needle))
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 32768)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        raise RuntimeError('terminal closed prematurely') from exc
                    raise
                if not data:
                    raise RuntimeError('terminal closed prematurely')
                output.extend(data)

    try:
        if batch:
            wait_for(b'Navigate')
            os.write(master, b'\x1b[B')
            time.sleep(0.1)
            os.write(master, b'\x1b[A')
            time.sleep(0.1)
            os.write(master, b' ')
            time.sleep(0.2)
            os.write(master, b'\r')
            time.sleep(0.2)
        else:
            wait_for(b'TUCUPI')
            os.write(master, b'\t')
            time.sleep(0.1)
            os.write(master, b'\x1b[B')
            time.sleep(0.1)
            os.write(master, b'\t')
            time.sleep(0.1)
            os.write(master, b'?')
            wait_for(b'Commands')
            os.write(master, b'\x1b[B')
            time.sleep(0.1)
            os.write(master, b'\x1b')
            time.sleep(0.2)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 18, 75, 0, 0))
        time.sleep(0.2)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
        time.sleep(0.2)
        os.write(master, b'q')
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    output.extend(os.read(master, 32768))
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
            waited, candidate = os.waitpid(pid, os.WNOHANG)
            if waited:
                status = candidate
                break
        else:
            raise RuntimeError('terminal process did not exit')
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError('terminal process failed: ' + repr(bytes(output[-1500:])))
        if b'\x1b[?1049l' not in output:
            raise RuntimeError('terminal alternate screen was not restored')
        flags = termios.tcgetattr(master)[3]
        if flags & (termios.ICANON | termios.ECHO) != termios.ICANON | termios.ECHO:
            raise RuntimeError('terminal canonical input or echo was not restored')
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        os.close(master)


def main():
    binary = Path(__file__).resolve().parent.parent / 'target/debug/tucupi'
    with tempfile.TemporaryDirectory(prefix='tucupi-keyboard-', dir=Path.home()) as path:
        root = Path(path)
        run_case(binary, root, False)
        print('App: sent tab/arrows/resize; help opened, Escape and quit; terminal modes restored')
        run_case(binary, root, True)
        print('batch: sent arrows/space/Enter on empty selection and resize; quit; terminal modes restored')


if __name__ == '__main__':
    main()
