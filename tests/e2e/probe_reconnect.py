#!/usr/bin/env python3
"""Kill the transport mid-session: does the client reconnect to the same shell?"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    MARK_PREFIX,
    Session,
    check,
    clear_marks,
    kill_shells,
    mark_appears,
    require_gate,
    shells,
)

require_gate()

MARK = MARK_PREFIX
MARK_DIR, MARK_NAME = os.path.split(MARK)
clear_marks()

results = []
s = Session()
time.sleep(2.0)
s.send(b"cd %s\n" % MARK_DIR.encode())
s.send(b"printf '\\033[31mRED_TEXT\\033[0m\\n'\n")
s.drain(1.5)
results.append(check("pre-kill: colored output reached client", b"\x1b[31mRED_TEXT" in s.buf))

# Kill the transport, not the daemon.
subprocess.run(["pkill", "-f", "brd --server"])
print("transport killed; waiting for reconnect...")
s.buf = b""
s.send(b"touch %s_AFTER_KILL\n" % MARK.encode())
ok = mark_appears("AFTER_KILL", 20.0)
results.append(check("reconnect: client drives the same shell again", ok))
s.drain(1.0)
s.send(b"touch %s_TAG_SURVIVED\n" % MARK_NAME.encode())
results.append(check("reconnect: same shell (working directory intact)", mark_appears("TAG_SURVIVED", 15.0)))
results.append(check("reconnect: still exactly one shell", shells() == 1))
print("post-reconnect screen bytes:", len(s.buf))
print("sample:", repr(s.buf[:300]))
s.kill()
kill_shells()

# The other order: the transport dies *while* the session is closing. The user
# asked to end this attachment, so the loss that follows is the expected end of
# it - reporting the read that failed on the way out exits non-zero on a session
# quit on purpose. `BRD_NO_DATAGRAM` keeps it on `ssh`, or killing the relay
# leaves the UDP path carrying the session and nothing is lost at all; the flood
# and the paste are what make the daemon slow enough answering `Close` for the
# loss to arrive first.
q = Session(env=dict(os.environ, BRD_NO_DATAGRAM="1"))
time.sleep(2.0)
q.send(b"yes brd-quit-race\n")
q.read_until(b"brd-quit-race", 8.0)
q.send(b"x" * (512 * 1024))
time.sleep(1.0)
q.send(b"\x1d.")
subprocess.run(["pkill", "-f", "brd --server"])
code = q.wait(20.0)
results.append(check(f"quit: a link lost before `Exit` still exits 0 (exit {code})", code == 0))
q.kill()
kill_shells()
print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
