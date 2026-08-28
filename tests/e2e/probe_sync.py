#!/usr/bin/env python3
"""After a burst forces sync mode, does the session return to full-fidelity passthrough?"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    MARK_PREFIX,
    Session,
    check,
    mark_appears,
    require_gate,
)

require_gate()

results = []
s = Session()
time.sleep(2.0)

s.send(b"printf '\\033[31mBEFORE\\033[0m\\n'\n")
s.drain(1.5)
results.append(check("before burst: colors pass through", b"\x1b[31mBEFORE" in s.buf))

# Force backpressure: far more output than the client can drain promptly.
s.send(b"cat /dev/urandom | base64 | head -c 40000000\n")
time.sleep(3.0)
s.send(b"\x03")
time.sleep(2.0)
s.drain(3.0)

# Let the stream go quiet so the gate can return to passthrough.
time.sleep(1.0)
s.buf = b""
s.send(b"printf '\\033[32mAFTER_BURST\\033[0m\\n'\n")
s.drain(2.5)

has_text = b"AFTER_BURST" in s.buf
has_color = b"\x1b[32mAFTER_BURST" in s.buf
results.append(check("after burst: output still flows", has_text))
results.append(check("after burst: colors restored (passthrough resumed)", has_color))

if has_text and not has_color:
    print("   -> still in sync mode: repaint strips attributes")

# And the session must still be interactive.
s.send(b"touch %s_ALIVE\n" % MARK_PREFIX.encode())
alive = mark_appears("ALIVE", 8.0)
results.append(check("after burst: session still interactive", alive))
if os.path.exists(f"{MARK_PREFIX}_ALIVE"):
    os.unlink(f"{MARK_PREFIX}_ALIVE")
s.kill()

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
