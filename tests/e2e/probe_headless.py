#!/usr/bin/env python3
"""Does `-N` carry a tunnel with no terminal, no shell and no PTY behind it?

It is the same tunnel with none of the cost: no eight megabytes of scrollback
for a process that prints nothing, and no controlling terminal to be started
from.

Three of these checks are the point and none of them can be made by a unit
test: the client runs as an ordinary background process with its standard
input closed, the far side has no shell for the session, and killing the
transport under a copy in flight still costs a pause rather than the
connection.
"""

import os
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import BRD, DEST, check, kill_shells, require_gate, shells  # noqa: E402

require_gate()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Echo:
    """The service on the far side of the tunnel."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.pump, args=(conn,), daemon=True).start()

    def pump(self, conn):
        with conn:
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                try:
                    conn.sendall(chunk)
                except OSError:
                    return

    def close(self):
        self.sock.close()


def connect(port: int, timeout=25.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=5.0)
            conn.settimeout(30.0)
            return conn
        except OSError as error:
            last = error
            time.sleep(0.2)
    raise SystemExit(f"nothing accepted on the forwarded port: {last!r}")


results = []
echo = Echo()
local = free_port()
spec = f"127.0.0.1:{local}:127.0.0.1:{echo.port}"
before = shells()

# No PTY anywhere: stdin closed, output to pipes, its own process group. This
# is the invocation `ssh -N -L` gets and the one the placeholder command could
# never be given.
tunnel = subprocess.Popen(
    [BRD, "-N", "-L", spec, DEST],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
time.sleep(4.0)
results.append(
    check(
        f"the client runs with no controlling terminal (pid {tunnel.pid})",
        tunnel.poll() is None,
    )
)

conn = connect(local)
conn.sendall(b"NO-TERMINAL-REQUIRED")
results.append(
    check("a headless forward carries a round trip", conn.recv(4096) == b"NO-TERMINAL-REQUIRED")
)

# The session exists but owns no shell: `-N` is not `-- sleep infinity` with
# the terminal hidden, it is a session with no terminal in it.
results.append(check(f"no shell was started for it ({shells()} vs {before})", shells() == before))

listed = subprocess.run([BRD, "ls", DEST], capture_output=True, text=True, timeout=30).stdout
results.append(check("`brd ls` names it as a forward session", "[forwards]" in listed))

# The claim, again, on a session that has no terminal to repaint: a byte
# stream that resumes where it stopped rather than a connection that resets.
sent = bytearray()
received = bytearray()
failure = []


def writer():
    counter = 0
    try:
        while len(sent) < 200_000:
            block = f"{counter:09d}".encode() * 32
            conn.sendall(block)
            sent.extend(block)
            counter += 1
            time.sleep(0.002)
    except OSError as error:
        failure.append(repr(error))


pump = threading.Thread(target=writer, daemon=True)
pump.start()
time.sleep(0.5)
subprocess.run(["pkill", "-f", "brd --server"])
print("transport killed mid-transfer; the tunnel must only pause", flush=True)
pump.join(120.0)

deadline = time.monotonic() + 120.0
while len(received) < len(sent) and time.monotonic() < deadline:
    try:
        chunk = conn.recv(65536)
    except socket.timeout:
        break
    if not chunk:
        break
    received += chunk

results.append(check("the socket survived the transport dying", not failure))
if failure:
    print("  ", failure[0])
results.append(
    check(
        f"the byte stream resumed with no gap ({len(received)}/{len(sent)} bytes)",
        bytes(received) == bytes(sent),
    )
)
conn.close()

# A signal is how this one ends, because there is no quit key to press.
tunnel.send_signal(signal.SIGTERM)
try:
    code = tunnel.wait(timeout=20)
except subprocess.TimeoutExpired:
    code = None
    tunnel.kill()
results.append(check(f"SIGTERM ends it cleanly (exit {code})", code == 0))

# The listener is the client's, so it goes when the client does.
still_bound = True
try:
    socket.create_connection(("127.0.0.1", local), timeout=2.0).close()
except OSError:
    still_bound = False
results.append(check("the forwarded port is released on exit", not still_bound))

# `-N` with nothing to forward is a command that would do nothing at all.
bare = subprocess.run([BRD, "-N", DEST], capture_output=True, text=True, timeout=30)
results.append(
    check(
        f"`-N` with no `-L` is refused (exit {bare.returncode})",
        bare.returncode == 2 and "-L" in (bare.stderr + bare.stdout),
    )
)

# `-N` and a command contradict each other; preferring one silently would run
# something the user asked not to have.
both = subprocess.run(
    [BRD, "-N", "-L", spec, DEST, "--", "echo", "hi"],
    capture_output=True,
    text=True,
    timeout=30,
)
results.append(
    check(f"`-N` with a command is refused (exit {both.returncode})", both.returncode == 2)
)

echo.close()
kill_shells()

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
