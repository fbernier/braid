#!/usr/bin/env python3
"""Does the session actually leave `ssh`, and is `ssh` still there when it cannot?

The datagram transport is entered as an ordinary `Resume` over UDP, which is
what makes the daemon *replace* the ssh attachment rather than open a second
one. Two things follow, and they are what this checks: once the session has
migrated there is no `ssh` process under the client at all, and a client that
refuses the offer runs exactly as it did before, on the pipe.

The third is the one the unit suites cannot make. A datagram send never blocks,
so nothing underneath this transport tells the daemon that a client has stopped
keeping up; the receive window in `Pong` is what does, and a burst larger than
it is where its absence would show — as a session that never gets back to
passthrough, or one whose shell stops hearing its keyboard.
"""

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
)

require_gate()


def ssh_children(pid: int) -> int:
    """`ssh` processes under this client, which a migrated session has none of."""
    out = subprocess.run(
        ["pgrep", "-P", str(pid), "-f", "ssh"], capture_output=True, text=True
    ).stdout.split()
    return len(out)


def udp_sockets() -> int:
    out = subprocess.run(["ss", "-unap"], capture_output=True, text=True).stdout
    return len([line for line in out.splitlines() if '"brd"' in line])


# Every mark here is a file, and a file left by the last run is a check that
# passes before the session has done anything.
clear_marks()
results = []

session = Session()
time.sleep(3.0)
results.append(
    check(
        f"the session left ssh behind ({ssh_children(session.proc.pid)} children)",
        ssh_children(session.proc.pid) == 0,
    )
)
# The client's socket and the daemon's listener. Anything less means the
# session never migrated and the check above only saw a slow start.
sockets = udp_sockets()
results.append(check(f"a datagram path is open ({sockets} sockets)", sockets >= 2))

session.send(b"touch %s_DGRAM\r" % MARK_PREFIX.encode())
results.append(
    check("a keystroke crosses the datagram path", mark_appears("DGRAM", 8.0))
)

# More than the window in one go, so the daemon has to stop streaming and
# switch this client to whole screens, then find its way back.
session.send(b"seq 1 40000\r")
results.append(
    check("a burst larger than the window arrives", session.read_until(b"40000", 30.0))
)
session.send(b"touch %s_AFTERBURST\r" % MARK_PREFIX.encode())
results.append(
    check("the session still hears the keyboard", mark_appears("AFTERBURST", 15.0))
)

session.send(b"\x1d.")
code = session.wait(20.0)
results.append(check(f"the datagram session detaches cleanly (exit {code})", code == 0))
session.kill()

# The fallback, which is the whole reason `ssh` is still in this program.
refused = Session(env=dict(os.environ, BRD_NO_DATAGRAM="1"))
time.sleep(3.0)
results.append(
    check(
        f"a refused offer keeps ssh ({ssh_children(refused.proc.pid)} children)",
        ssh_children(refused.proc.pid) >= 1,
    )
)
refused.send(b"touch %s_FALLBACK\r" % MARK_PREFIX.encode())
results.append(check("the ssh path still carries a session", mark_appears("FALLBACK", 8.0)))
refused.send(b"\x1d.")
refused.wait(20.0)
refused.kill()

kill_shells()

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
