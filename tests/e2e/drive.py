#!/usr/bin/env python3
"""Drive `brd` through a real PTY so control bytes can be sent exactly."""

import fcntl
import getpass
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

BRD = os.environ.get("BRD_BIN") or shutil.which("brd") or os.path.expanduser(
    "~/.local/bin/brd"
)
DEST = os.environ.get("BRD_E2E_DEST") or f"{getpass.getuser()}@127.0.0.1"
SHELL_NAME = os.environ.get("BRD_E2E_SHELL") or os.path.basename(
    os.environ.get("SHELL", "/bin/sh")
)
# The daemon's socket, lock and capabilities moved out of `XDG_RUNTIME_DIR`:
# logind deletes that at last logout, which left sessions running with nothing
# left to name them. This must track `state_dir()` in `crates/server/src/state.rs`.
STATE_DIR = (
    os.environ.get("BRD_STATE_DIR")
    or os.path.join(
        os.environ.get("XDG_STATE_HOME")
        or os.path.join(os.path.expanduser("~"), ".local", "state"),
        "brd",
    )
)
MARK_PREFIX = os.path.join(tempfile.gettempdir(), "brd_mark")


class Session:
    def __init__(self, cols=80, rows=24, env=None, argv=None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.proc = subprocess.Popen(
            argv or [BRD, DEST],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=os.setsid,
            env=env,
        )
        os.close(slave)
        self.buf = b""

    def send(self, data: bytes):
        os.write(self.master, data)

    def read_until(self, needle: bytes, timeout=6.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.buf:
                return True
            remaining = deadline - time.monotonic()
            r, _, _ = select.select([self.master], [], [], max(0.05, min(0.4, remaining)))
            if r:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf += chunk
        return needle in self.buf

    def drain(self, seconds=0.6):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.master], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                self.buf += chunk

    def wait(self, timeout=6.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return self.proc.returncode
            self.drain(0.2)
        return None

    def kill(self):
        if self.proc.poll() is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            self.proc.wait()
        os.close(self.master)


# `-l`, not `-i`: the daemon starts a login shell, because that is what
# `ssh host` gives you and `-i` sources `~/.bashrc` without ever reading
# `~/.profile`.
SHELL_ARGV = f"{SHELL_NAME} -l"


def shells():
    out = subprocess.run(
        ["pgrep", "-c", "-f", SHELL_ARGV], capture_output=True, text=True
    ).stdout.strip()
    return int(out or 0)


def kill_shells():
    subprocess.run(["pkill", "-f", SHELL_ARGV])


def tickets():
    d = STATE_DIR
    return len([f for f in os.listdir(d) if f.endswith(".cap")]) if os.path.isdir(d) else 0


def clear_marks():
    d, stem = os.path.split(MARK_PREFIX)
    for f in os.listdir(d):
        if f.startswith(stem):
            os.unlink(os.path.join(d, f))


def cold_start():
    """No daemon, and no saved session for the client to resume.

    A client holding resume state opens a transport, is told the session is
    gone, kills it and opens a second one - so the daemon ends up spawned by a
    transport that no longer exists. Any test about the transport that owns the
    daemon has to start from here or it measures the wrong process.
    """
    subprocess.run(["pkill", "-f", f"{os.path.basename(BRD)} --daemon"])
    subprocess.run(["pkill", "-f", f"{os.path.basename(BRD)} --server"])
    kill_shells()
    root = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local/state"
    )
    state = os.path.join(root, "brd", "reconnect")
    if os.path.isdir(state):
        for f in os.listdir(state):
            if f.endswith(".state"):
                os.unlink(os.path.join(state, f))
    time.sleep(1.0)


def mark_appears(name, timeout=8.0):
    """A file can only be created by a shell that actually received the input."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(f"{MARK_PREFIX}_{name}"):
            return True
        time.sleep(0.1)
    return False


def check(name, ok):
    print(f"{'PASS' if ok else 'FAIL'}  {name}", flush=True)
    return ok


def missing_prerequisites():
    """Every reason this host cannot run the harness, in the order found."""
    if not os.access(BRD, os.X_OK):
        yield f"no executable brd at {BRD}: set BRD_BIN, or install one on PATH"
    if shutil.which("ssh") is None:
        yield "ssh is not on PATH"
        return
    probe = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", DEST, "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if probe.returncode != 0:
        reason = probe.stderr.decode(errors="replace").strip() or "no output"
        yield f"cannot ssh to {DEST} without a password: {reason}"


def require_gate():
    """The harness needs a real SSH loopback and an installed brd; opt in explicitly.

    Opting in and then finding a prerequisite missing is a failure, not a skip.
    A run that exits 0 because `BRD_E2E` never reached the suites reports the
    resilience contract as met without having tested a line of it.
    """
    if os.environ.get("BRD_E2E") != "1":
        print(
            "skipping: set BRD_E2E=1 to run the e2e harness "
            "(needs SSH loopback and brd on PATH)",
            file=sys.stderr,
        )
        sys.exit(0)

    missing = list(missing_prerequisites())
    if missing:
        for reason in missing:
            print(f"e2e: {reason}", file=sys.stderr)
        sys.exit(2)
