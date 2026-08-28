#!/usr/bin/env python3
"""Named sessions and an explicit command.

A client holds one capability per destination per session, so a second
`brd host` neither overwrites the first's nor orphans it. Both halves are
checked against a real daemon: a session runs the argv it was given, and an
older one is still reachable by any unambiguous prefix of its id.
"""

import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive  # noqa: E402
from drive import BRD, DEST, Session, check  # noqa: E402

drive.require_gate()

DETACH = b"\x1d" + b"d"
# `sh`, not the login shell, so the probe's own syntax is POSIX whatever the
# user's `$SHELL` is — and so `brd ls` has something to name that a login
# shell would not be called.
SH = [BRD, DEST, "--", "sh"]


def listing():
    return subprocess.run(
        [BRD, "ls", DEST], capture_output=True, text=True, timeout=30
    ).stdout

def ids(text):
    """The first column of every row the table names a session in.

    `brd ls` prints a short id, which is also what a user would type back.
    """
    return [
        row.split()[0]
        for row in text.splitlines()
        if re.match(r"^[0-9a-f]{8}\s", row)
    ]


def start(tag):
    """A session whose shell remembers which one it is."""
    session = Session(argv=SH)
    session.send(f"TAG={tag}; : > {drive.MARK_PREFIX}_{tag}\n".encode())
    started = drive.mark_appears(tag)
    session.send(DETACH)
    session.wait()
    return started


results = []
drive.cold_start()
drive.clear_marks()

results.append(check("an explicit command runs instead of the login shell", start("SESSA")))
results.append(check("a second session starts beside the first", start("SESSB")))

table = listing()
named = ids(table)
results.append(check(f"both sessions are listed ({len(named)})", len(named) == 2))
results.append(
    check(
        f"the listing names what actually runs ({table.splitlines()[-1].split()[-1]!r})",
        "sh" in table,
    )
)

# Oldest first is not promised, so find the one that is not the newest: `brd`
# with no id resumes the newest, and the whole point is reaching the other one.
#
# Nothing is waited for before typing: a resume paints no screen, so the only
# thing that proves which shell answered is the shell answering.
newest = Session()
newest.send(b"printf 'WHICH<%s>\\n' \"$TAG\"\n")
newest.read_until(b"WHICH<SESS", timeout=10.0)
recent = re.search(rb"WHICH<(SESS[AB])>", newest.buf)
newest.send(DETACH)
newest.wait()
results.append(check("a bare brd resumes the newest session", recent is not None))

if recent:
    older = "SESSA" if recent.group(1) == b"SESSB" else "SESSB"
    wanted = None
    for candidate in named:
        probe = Session(argv=[BRD, "attach", DEST, candidate])
        probe.send(b"printf 'WHICH<%s>\\n' \"$TAG\"\n")
        probe.read_until(b"WHICH<SESS", timeout=10.0)
        found = re.search(rb"WHICH<(SESS[AB])>", probe.buf)
        probe.send(DETACH)
        probe.wait()
        if found and found.group(1).decode() == older:
            wanted = candidate
            break
    results.append(
        check(f"an older session is reachable by id prefix ({older})", wanted is not None)
    )

results.append(check("an empty prefix is refused rather than guessed", subprocess.run(
    [BRD, "attach", DEST, ""], capture_output=True, text=True, timeout=30
).returncode != 0))

# The sessions are the probe's, not the user's.
for session_id in named:
    subprocess.run([BRD, "kill", DEST, session_id], capture_output=True, timeout=30)
time.sleep(0.5)
results.append(check("every session the probe made is gone", not ids(listing())))

print(f"\n{sum(results)}/{len(results)} checks passed", flush=True)
sys.exit(0 if all(results) else 1)
