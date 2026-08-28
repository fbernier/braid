#!/usr/bin/env python3
"""Two daemons racing for the socket: one serves, the other stands down."""

import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    BRD,
    MARK_PREFIX,
    STATE_DIR,
    Session,
    check,
    clear_marks,
    cold_start,
    kill_shells,
    mark_appears,
    require_gate,
    shells,
)

require_gate()

BRD_NAME = os.path.basename(BRD)


def daemons():
    """Live `brd --daemon` processes, by pid."""
    listing = subprocess.run(
        ["pgrep", "-f", f"{BRD_NAME} --daemon"], capture_output=True, text=True
    ).stdout.split()
    pids = []
    for pid in listing:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if argv and os.path.basename(argv[0]) == BRD_NAME.encode() and b"--daemon" in argv:
            pids.append(int(pid))
    return pids


def sockets():
    # Deliberately wider than the one name `socket_name()` returns: a daemon
    # that reintroduced a per-version socket would show up here as two.
    return sorted(glob.glob(os.path.join(STATE_DIR, "brd*.sock")))


clear_marks()
cold_start()
for path in sockets():
    os.unlink(path)

results = []
# The race two `brd user@host` invocations run from a cold start: both fail to
# connect, both spawn a daemon. The loser must not be left listening on a path
# that no longer names it, or every session it goes on to own keeps a shell
# alive with nothing able to reach it again.
racers = [
    subprocess.Popen(
        [BRD, "--daemon"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(2)
]
time.sleep(1.5)

running = daemons()
results.append(check(f"race: exactly one daemon serves ({running})", len(running) == 1))
results.append(check(f"race: one socket exists ({sockets()})", len(sockets()) == 1))
stood_down = sum(1 for racer in racers if racer.poll() is not None)
results.append(check(f"race: the other exited ({stood_down} of 2)", stood_down == 1))

# The surviving daemon must be the one the socket names.
session = Session()
time.sleep(2.0)
session.send(b"touch %s_RACE\n" % MARK_PREFIX.encode())
results.append(check("race: a client reaches the surviving daemon", mark_appears("RACE", 20.0)))
results.append(check("race: exactly one shell", shells() == 1))
results.append(check(f"race: still one daemon ({daemons()})", len(daemons()) == 1))

session.kill()
kill_shells()
for racer in racers:
    if racer.poll() is None:
        racer.kill()
    racer.wait()
print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
