#!/usr/bin/env python3
"""Searching history the client's own terminal no longer shows.

The daemon holds the only real scrollback in this system: a libghostty
terminal with a byte budget of history behind the viewport. mosh has none to
search and a dumb pipe has only whatever the local terminal kept. This probe
scrolls a line far out of the viewport and then asks the daemon to find it,
which is the whole claim.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive  # noqa: E402
from drive import BRD, DEST, Session, check  # noqa: E402

drive.require_gate()

DETACH = b"\x1d" + b"d"
NEEDLE = "brd_scrollback_needle_9f3a"
ROWS = 6
BURIED = 200


def grep(pattern):
    return subprocess.run(
        [BRD, "grep", DEST, pattern], capture_output=True, text=True, timeout=60
    ).stdout


results = []
drive.cold_start()

# A short terminal so the needle is buried by an amount no viewport could hold.
session = Session(rows=ROWS, argv=[BRD, DEST, "--", "sh"])
session.send(f"printf '%s\\n' {NEEDLE}\n".encode())
session.read_until(NEEDLE.encode(), timeout=8.0)
session.send(f"i=0; while [ $i -lt {BURIED} ]; do echo filler_$i; i=$((i+1)); done\n".encode())
session.read_until(f"filler_{BURIED - 1}".encode(), timeout=20.0)
# Let the daemon's emulator finish consuming the burst before it is asked.
time.sleep(1.0)

results.append(
    check(
        f"the needle is off screen ({BURIED} lines into a {ROWS}-row terminal)",
        NEEDLE.encode() not in session.buf.split(b"filler_0")[-1],
    )
)

found = grep(NEEDLE)
results.append(check("a line scrolled out of the viewport is found", NEEDLE in found))
results.append(
    check(
        "the match names the session it came from",
        bool(found.strip()) and len(found.strip().split()[0]) == 8,
    )
)

results.append(
    check("a pattern matching nothing says so", "no matches" in grep("brd_absent_pattern_zzz"))
)

# Detached is not gone: the daemon still holds the history.
session.send(DETACH)
session.wait(8.0)
results.append(
    check("a detached session is still searchable", NEEDLE in grep(NEEDLE))
)

for line in subprocess.run(
    [BRD, "ls", DEST], capture_output=True, text=True, timeout=30
).stdout.splitlines():
    if line[:8].strip() and all(c in "0123456789abcdef" for c in line[:8]):
        subprocess.run([BRD, "kill", DEST, line[:8]], capture_output=True, timeout=30)
results.append(check("a killed session takes its history with it", NEEDLE not in grep(NEEDLE)))

print(f"\n{sum(results)}/{len(results)} checks passed", flush=True)
sys.exit(0 if all(results) else 1)
