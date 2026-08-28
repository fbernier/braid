#!/usr/bin/env python3
"""A child that stops reading its input must not wedge the session.

`write_all` on a PTY master blocks once the child stops reading, so that write
must not happen on the session actor. Blocked there, the actor stops draining
its event channel; the PTY reader blocks handing it output, the PTY output
buffer fills, and the child blocks writing stdout - so it never reads its input
again. `Close` and `Detach` arrive through the same channel, so `Ctrl-] .`
cannot break it, and only killing the daemon can - taking every other session
on the machine with it.

The check: run a program that neither reads its input nor stops writing, push a
paste at it, and require the quit key to still work.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import Session, check, kill_shells, require_gate  # noqa: E402

require_gate()

PASTE = b"x" * (512 * 1024)

results = []
s = Session()
time.sleep(2.0)

# Writes forever, reads nothing. Its output is what fills the PTY buffer the
# wedge closed around.
s.send(b"yes brd-wedge\n")
results.append(check("wedge: the program is producing output", s.read_until(b"brd-wedge", 8.0)))

started = time.monotonic()
s.send(PASTE)
queued = time.monotonic() - started
results.append(
    check(f"wedge: a paste does not block the client ({queued:.2f}s)", queued < 5.0)
)

# Both of these travel the paths the wedge closed: the interrupt through the
# PTY the paste is queued on, the quit key through the event channel the
# session's own output arrives on.
time.sleep(1.0)
s.send(b"\x03")
time.sleep(1.0)
s.send(b"\x1d.")
code = s.wait(20.0)
ended = check(f"wedge: the quit key still ends the session (exit {code})", code == 0)
if not ended:
    # The client prints its error to stderr, which is this pty. Without it a
    # failure here is "exit 1" and nothing else, and the run that produced it
    # is gone — which is the whole reason this was hard to chase once.
    s.drain(1.0)
    tail = s.buf.decode("utf-8", "replace")
    print("  client output tail:", repr(tail[-600:]))
    # `[brd]` alone misses the one line that matters: the client reports a
    # failure as `brd: <error>`, and this filter answering "none" to exactly
    # that is what sent the last failure to the CI log for archaeology.
    brd_lines = [line for line in tail.splitlines() if "[brd]" in line or "brd:" in line]
    print("  client diagnostics:", brd_lines[-5:] if brd_lines else "none")
results.append(ended)

s.kill()
kill_shells()

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
