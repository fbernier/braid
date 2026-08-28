#!/usr/bin/env python3
"""Detach, reattach, sharing, flood interrupt and reaping over a real SSH loopback."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    MARK_PREFIX,
    Session,
    check,
    clear_marks,
    mark_appears,
    require_gate,
    shells,
    tickets,
)

require_gate()

MARK = MARK_PREFIX
MARK_DIR, MARK_NAME = os.path.split(MARK)

clear_marks()
results = []

# --- 1. detach leaves the shell running ---
a = Session()
a.send(b"cd %s\n" % MARK_DIR.encode())
time.sleep(1.0)
a.send(b"\x1dd")  # Ctrl-] d
code = a.wait(8.0)
results.append(check("detach: client exits 0", code == 0))
results.append(check("detach: told how to reattach", b"detached; reattach with" in a.buf))
a.kill()

# --- 2. reattaching lands in the same shell ---
b = Session()
b.send(b"touch %s_DETACH_OK\n" % MARK_NAME.encode())
results.append(check("reattach: same shell (working directory survived)", mark_appears("DETACH_OK")))
results.append(check("reattach: no extra shell spawned", shells() == 1))

# --- 3. a second client joins rather than evicting ---
#
# A session is shared, so both clients drive the same shell and both see what
# it prints.
c = Session()
c.send(b"touch %s_SECOND\n" % MARK.encode())
results.append(check("share: the joining client drives the shell", mark_appears("SECOND")))
results.append(check("share: the first client was not displaced", b.proc.poll() is None))
results.append(
    check("share: no eviction notice", b"another client took over" not in b.buf)
)

# One shell, two views of it: what either client types the other must see,
# because the bytes come from the one PTY they share.
shared = b"BOTH_SEE_THIS"
c.send(b"printf '%s\\n' " + shared + b"\n")
results.append(check("share: output reaches the first client", b.read_until(shared, 8.0)))
results.append(check("share: output reaches the second client", c.read_until(shared, 8.0)))
results.append(check("share: still one shell", shells() == 1))

b.send(b"\x1dd")
b.wait(8.0)
b.kill()
results.append(check("share: one client leaving keeps the shell", shells() == 1))

# --- 4. Ctrl-C survives a flood (no head-of-line blocking) ---
c.send(b"cat /dev/urandom | base64\n")
time.sleep(2.0)
start = time.monotonic()
c.send(b"\x03")
c.send(b"touch %s_INTR\n" % MARK.encode())
got = mark_appears("INTR", 12.0)
results.append(check(f"flood: Ctrl-C landed in {time.monotonic() - start:.1f}s", got))

# --- 5. session and ticket are reaped when the shell exits ---
before = tickets()
c.send(b"exit\n")
code_c = c.wait(10.0)
time.sleep(0.8)
after = tickets()
results.append(check(f"reap: client exits 0 (got {code_c})", code_c == 0))
results.append(check(f"reap: ticket unlinked ({before} -> {after})", after == before - 1))
results.append(check("reap: no leaked shell", shells() == 0))
c.kill()

clear_marks()
print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
