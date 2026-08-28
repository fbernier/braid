#!/usr/bin/env python3
"""Tear the transport down the way sshd does: SIGHUP the remote process group."""

import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    BRD,
    MARK_PREFIX,
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
TAG = "TEARDOWN_OK"
MARK_DIR, MARK_NAME = os.path.split(MARK_PREFIX)


def brd_pids(flag):
    """Processes actually running `brd <flag>`; the ssh client only carries it as an argument."""
    out = subprocess.run(
        ["pgrep", "-f", f"{BRD_NAME} {flag}"], capture_output=True, text=True
    ).stdout.split()
    pids = []
    for pid in out:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if argv and os.path.basename(argv[0]) == BRD_NAME.encode() and flag.encode() in argv:
            pids.append(int(pid))
    return pids


def pgid_of(pid):
    try:
        return os.getpgid(pid)
    except OSError:
        return None


def ppid_of(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return int(f.read().rsplit(b") ", 1)[-1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def alive(pid):
    """A reaped or zombie pid is not a surviving daemon."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            stat = f.read()
    except OSError:
        return False
    return stat.rsplit(b") ", 1)[-1][:1] != b"Z"


def finish():
    s.kill()
    kill_shells()
    print()
    print(f"{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


clear_marks()
# The daemon has to be the one this transport spawned. A client with saved
# resume state opens a transport, learns the session is gone, kills it and
# opens another - and the daemon is then left in a process group nothing here
# is about to signal, which makes every check below pass without meaning it.
cold_start()

results = []
# Pinned to the ssh path: what is under test is the process group of the relay
# `sshd` starts, and a session that migrated to datagrams has reaped that relay
# on purpose — there would be nothing left to hang up, and every check below
# would pass without meaning it.
s = Session(env=dict(os.environ, BRD_NO_DATAGRAM="1"))
time.sleep(2.0)
s.send(b"cd %s\n" % MARK_DIR.encode())
s.send(b"touch %s_LIVE\n" % MARK_PREFIX.encode())
results.append(check("pre-teardown: session is live", mark_appears("LIVE", 10.0)))

servers = brd_pids("--server")
daemons = brd_pids("--daemon")
owner = next(
    (
        (server, daemon)
        for server in servers
        for daemon in daemons
        if ppid_of(daemon) == server
    ),
    None,
)
results.append(
    check("pre-teardown: this transport spawned this daemon", owner is not None)
)
if owner is None:
    print(f"servers={servers} daemons={daemons}: no transport owns a daemon")
    finish()

server, daemon = owner
pgid = pgid_of(server)
# A daemon left in sshd's process group dies with the connection: that is the bug.
daemon_pgid = pgid_of(daemon)
results.append(
    check(
        "pre-teardown: daemon is outside its transport's process group",
        pgid is not None and daemon_pgid is not None and daemon_pgid != pgid,
    )
)

try:
    os.killpg(pgid, signal.SIGHUP)
    sent = True
except OSError as e:
    sent = False
    print("killpg failed:", e)
results.append(check("teardown: SIGHUP delivered to the transport process group", sent))
print(f"process group {pgid} hung up; waiting for reconnect...")
time.sleep(1.5)
results.append(check("teardown: daemon survived the process-group SIGHUP", alive(daemon)))

s.buf = b""
s.send(b"touch %s_TAG_%s\n" % (MARK_NAME.encode(), TAG.encode()))
results.append(
    check("reconnect: same shell (working directory intact)", mark_appears(f"TAG_{TAG}", 20.0))
)
results.append(check("reconnect: still exactly one shell", shells() == 1))
print("post-reconnect screen bytes:", len(s.buf))
finish()
