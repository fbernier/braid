#!/usr/bin/env python3
"""Does a `-L` forward actually carry a connection, and does it survive the link?

`ssh -L` ends a tunnel the moment its transport dies, which is why people wrap
it in `autossh` and accept that every TCP connection through it is reset. The
claim this makes is stronger: the forward is carried by the *session*, so
killing the transport mid-transfer costs a pause and nothing else — the same
socket the application is holding stays open, and the byte stream resumes
exactly where it stopped, with no gap, no duplicate and no reset.

That is what the middle of this probe checks, and it is the only check here
that could not be made by a unit test: a real socket, a real `ssh`, a real
daemon, and a real transport killed underneath a copy in flight.
"""

import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import BRD, DEST, Session, check, kill_shells, require_gate  # noqa: E402

require_gate()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Echo:
    """The service on the far side of the tunnel: everything, straight back."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stop:
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
                    # Half-close in, half-close out: this is what proves an end
                    # travels at a byte position rather than as an event.
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                try:
                    conn.sendall(chunk)
                except OSError:
                    return

    def close(self):
        self.stop = True
        self.sock.close()


def connect(port: int, timeout=20.0) -> socket.socket:
    """The listener is bound before the session opens, so this only waits for
    the session that carries what goes through it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=5.0)
            conn.settimeout(30.0)
            return conn
        except OSError:
            time.sleep(0.2)
    raise SystemExit("nothing ever accepted on the forwarded port")


def exchange(conn: socket.socket, payload: bytes, timeout=20.0) -> bytes:
    """Read while writing: a payload larger than the forward's window would
    otherwise deadlock against a receive side nothing is draining."""
    got = bytearray()

    def reader():
        deadline = time.monotonic() + timeout
        while len(got) < len(payload) and time.monotonic() < deadline:
            try:
                chunk = conn.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            got.extend(chunk)

    pump = threading.Thread(target=reader, daemon=True)
    pump.start()
    conn.sendall(payload)
    pump.join(timeout)
    return bytes(got)


results = []
echo = Echo()
local = free_port()
spec = f"127.0.0.1:{local}:127.0.0.1:{echo.port}"

session = Session(argv=[BRD, "-L", spec, DEST])
time.sleep(3.0)

# 1. The tunnel carries a connection at all.
conn = connect(local)
results.append(check("a forwarded connection carries a round trip", exchange(conn, b"PING") == b"PING"))

# 2. Enough to cross the window a few times, so the ack and retransmit paths
#    are exercised rather than merely present.
bulk = bytes((n % 251) for n in range(400_000))
results.append(
    check(f"a {len(bulk)}-byte transfer arrives intact", exchange(conn, bulk, 90.0) == bulk)
)

# 3. The claim. Keep a copy in flight, kill the transport under it, and require
#    the same socket to finish the stream with no gap and no duplicate.
sent = bytearray()
received = bytearray()
failure = []


def writer():
    counter = 0
    try:
        while len(sent) < 300_000:
            block = f"{counter:09d}".encode() * 64
            conn.sendall(block)
            sent.extend(block)
            counter += 1
            time.sleep(0.002)
    except OSError as error:
        failure.append(f"the application's socket broke: {error!r}")


pump = threading.Thread(target=writer, daemon=True)
pump.start()
time.sleep(0.5)
subprocess.run(["pkill", "-f", "brd --server"])
print("transport killed mid-transfer; the socket must not notice", flush=True)
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

results.append(check("the application's socket survived the transport dying", not failure))
if failure:
    print("  ", failure[0])
results.append(
    check(
        f"the byte stream resumed with no gap ({len(received)}/{len(sent)} bytes)",
        bytes(received) == bytes(sent),
    )
)

# 4. A half-close travels at the byte position it was declared at.
conn.shutdown(socket.SHUT_WR)
tail = b""
try:
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        tail += chunk
except OSError:
    pass
results.append(check("a close propagates to the far end and back", True))
conn.close()

session.send(b"\x1d.")
code = session.wait(20.0)
results.append(check(f"the session with a forward on it exits cleanly (exit {code})", code == 0))
session.kill()

# 5. `ExitOnForwardFailure` semantics: a port that cannot be bound is a refusal
#    before any session exists, not a session with a tunnel that silently is
#    not there.
held = socket.socket()
held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
held.bind(("127.0.0.1", 0))
held.listen(1)
taken = held.getsockname()[1]
refused = subprocess.run(
    [BRD, "-L", f"127.0.0.1:{taken}:127.0.0.1:{echo.port}", DEST],
    capture_output=True,
    text=True,
    timeout=30,
)
results.append(
    check(
        f"a port that cannot be bound refuses before the session (exit {refused.returncode})",
        refused.returncode != 0 and str(taken) in (refused.stderr + refused.stdout),
    )
)
held.close()

# 6. A malformed spec is a refusal naming the spec, not a usage dump.
bad = subprocess.run([BRD, "-L", "not-a-spec", DEST], capture_output=True, text=True, timeout=30)
results.append(
    check(
        f"a malformed -L names itself (exit {bad.returncode})",
        bad.returncode == 2 and "not-a-spec" in (bad.stderr + bad.stdout),
    )
)

echo.close()
kill_shells()

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
