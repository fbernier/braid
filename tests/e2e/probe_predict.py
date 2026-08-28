#!/usr/bin/env python3
"""Does a keystroke reach the screen without waiting for the link, and is the screen right?

The client draws a keystroke before the session has echoed it, so the two
things worth checking are the ones that trade off against each other: whether
typing actually costs less than a round trip, and whether the row still says
exactly what was typed once the echoes have landed.

What answers is deliberately `sh` and not the login shell. A prompt framework
redraws the whole row on every keystroke — an autosuggestion the shell's own
history decides, a right-aligned clock, a colour that changes as the word
becomes a command — so the same run measures something different on the second
machine, and on the second *run* on the first machine. None of that is the
contract. The line discipline's echo is, and it is the same everywhere.

A repaint is the failure this watches for, and two different events paint one:
a prediction the session contradicted, and a link the client had to rebuild.
Only the first is the contract, so the run carries `BRD_LOG` and starts over
when the client reports a reconnect under it.
"""

import os
import re
import select
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from drive import (  # noqa: E402
    BRD,
    DEST,
    MARK_PREFIX,
    Session,
    check,
    clear_marks,
    cold_start,
    mark_appears,
    require_gate,
)

require_gate()

ONE_WAY_MS = 100
ROUND_TRIP_MS = 2 * ONE_WAY_MS
# What a keystroke the client drew itself must come in under. A quarter of the
# link, so the two cases this separates - drawn here, or waited for over there -
# stay four times apart on a runner whose cores are shared and whose scheduler
# is what decides when this process reads its own terminal.
PREDICTED_MS = ROUND_TRIP_MS / 4
# Backspaces taken, enough that the median is one.
ERASES = 12
LINE = "touch %s_PREDICT" % MARK_PREFIX
# Escapes are the session's business, not the row's: strip them before asking
# what the terminal shows.
ESCAPES = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    rb"|\x1bP[^\x1b]*\x1b\\|\x1b[()][B0]|\x1b[=><]"
)

SHIM = """#!/usr/bin/env python3
"ssh(1) with a fixed one-way delay on each direction of its stdio."
import os, subprocess, sys, threading, time
from collections import deque

DELAY = %f


def pump(src, dst):
    queue, wake, done = deque(), threading.Condition(), threading.Event()

    def reader():
        while True:
            try:
                data = os.read(src, 65536)
            except OSError:
                data = b""
            with wake:
                if data:
                    queue.append((time.monotonic() + DELAY, data))
                else:
                    done.set()
                wake.notify()
            if not data:
                return

    def writer():
        while True:
            with wake:
                while not queue and not done.is_set():
                    wake.wait(0.01)
                if not queue:
                    break
                due, data = queue[0]
            time.sleep(max(0.0, due - time.monotonic()))
            with wake:
                queue.popleft()
            try:
                dst.write(data)
                dst.flush()
            except (BrokenPipeError, ValueError):
                return
        try:
            dst.close()
        except (BrokenPipeError, ValueError):
            pass

    threading.Thread(target=reader, daemon=True).start()
    return threading.Thread(target=writer, daemon=True)


child = subprocess.Popen(
    ["/usr/bin/ssh"] + sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE
)
for thread in (pump(sys.stdin.fileno(), child.stdin), pump(child.stdout.fileno(), sys.stdout.buffer)):
    thread.start()
sys.exit(child.wait())
"""


class Row:
    """The cursor's row, as carriage returns and overwrites leave it."""

    def __init__(self):
        self.cells = []
        self.col = 0

    def feed(self, data):
        for byte in data:
            char = bytes([byte])
            if char == b"\r":
                self.col = 0
            elif char == b"\n":
                self.cells, self.col = [], 0
            elif char == b"\b":
                self.col = max(0, self.col - 1)
            else:
                while len(self.cells) <= self.col:
                    self.cells.append(b" ")
                self.cells[self.col] = char
                self.col += 1

    def text(self):
        return b"".join(self.cells).decode("utf-8", "replace").rstrip()


def read_for(fd, quiet, limit):
    out = b""
    deadline = time.monotonic() + limit
    idle = time.monotonic() + quiet
    while time.monotonic() < min(deadline, idle):
        ready, _, _ = select.select([fd], [], [], 0.02)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            out += chunk
            idle = time.monotonic() + quiet
    return out


def time_to_appear(fd, key, limit=5.0):
    """Milliseconds until the typed byte shows up, and what arrived with it."""
    start = time.monotonic()
    out = b""
    while time.monotonic() - start < limit:
        ready, _, _ = select.select([fd], [], [], 0.01)
        if not ready:
            continue
        out += os.read(fd, 65536)
        if key in out:
            return (time.monotonic() - start) * 1000, out
    return None, out


shim_dir = tempfile.mkdtemp(prefix="brd-delay-")
shim = os.path.join(shim_dir, "ssh")
with open(shim, "w") as handle:
    handle.write(SHIM % (ONE_WAY_MS / 1000.0))
os.chmod(shim, os.stat(shim).st_mode | stat.S_IXUSR)
# The client names every reconnect in here, which is what separates a repaint
# a prediction caused from one a lost link paid for. Both are a `\x1b[2J` in
# this PTY and nothing else in the stream tells them apart.
LOG = os.path.join(shim_dir, "client.log")
# A stalled shim is a lost link: the client's patience is three of the
# server's probes, and this shim is a Python process moving every byte through
# two threads and a sleep. A runner that starves it for a second costs a
# reconnect, so the measurement is taken again rather than reported as
# something prediction did.
ATTEMPTS = 3


def link_losses():
    """Reconnects this client has logged so far."""
    if not os.path.exists(LOG):
        return 0
    with open(LOG, encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if "link lost" in line)


def took(value, places=2):
    return "no echo" if value is None else f"{value:.{places}f} ms"


def settle(session):
    """Wait until the shell answers, so the run starts against a live prompt.

    Not a timer: the client paints a screen when it attaches, and a run that
    starts before that screen has landed counts it as a repaint. The sentinel
    is split by quoting so the echo of the command cannot end the wait - only
    what `printf` wrote can, and that is the whole path being measured.
    """
    session.send(b"printf 'BRD_SET''TLED\\n'\n")
    if not session.read_until(b"BRD_SETTLED", timeout=20.0):
        return False
    # Start from a settled prompt: the run begins with nothing confirmed.
    session.send(b"\r")
    read_for(session.master, 0.6, 5.0)
    return True


def measure():
    """Every check, against one session, or `None` if the link died under it."""
    outcomes = []
    # Nothing left over to resume: a saved session is answered by whatever shell
    # it was opened with, so the `sh` below would be ignored and the measurement
    # would be back on someone's prompt.
    clear_marks()
    cold_start()
    reconnects = link_losses()
    # The delay this probe measures against lives in the `ssh` shim, so the
    # session has to stay on the ssh pipe. A datagram session does not go through
    # `ssh` at all, which would leave every timing here measuring loopback and
    # the first check asserting that a round trip costs a round trip on a link
    # that has none.
    session = Session(
        argv=[BRD, DEST, "--", "sh"],
        env=dict(
            os.environ,
            PATH=shim_dir + ":" + os.environ["PATH"],
            BRD_NO_DATAGRAM="1",
            BRD_LOG=LOG,
        ),
    )
    try:
        if not settle(session):
            return None

        typed = b""
        timings = []
        for key in LINE.encode():
            session.send(bytes([key]))
            milliseconds, seen = time_to_appear(session.master, bytes([key]))
            timings.append(milliseconds)
            typed += seen
        # One round trip of quiet: every echo has landed and the row is the session's.
        typed += read_for(session.master, 0.5, 3.0)
        if link_losses() > reconnects:
            return None

        first, rest = timings[0], [t for t in timings[1:] if t is not None]
        outcomes.append(
            (
                f"first keystroke waits for the session ({took(first, 0)} >= {ROUND_TRIP_MS} ms)",
                first is not None and first >= ROUND_TRIP_MS * 0.8,
            )
        )
        predicted = sorted(rest)[len(rest) // 2] if rest else None
        outcomes.append(
            (
                f"typing does not wait for the link (median {took(predicted, 1)})",
                predicted is not None and predicted < PREDICTED_MS,
            )
        )

        row = Row()
        row.feed(ESCAPES.sub(b"", typed))
        shown = row.text()
        outcomes.append((f"row says what was typed ({shown!r})", shown.endswith(LINE)))
        screens = typed.count(b"\x1b[2J")
        outcomes.append(
            (f"predictions cost no repaints ({screens} screens)", screens == 0)
        )

        # Backspace is the most-typed editing key on a command line and the worst
        # case of this feature: unless its echo matches something outstanding, the
        # run ends with characters still drawn and the client asks for a whole
        # screen - once per keystroke, on exactly the links prediction exists for.
        erased = b""
        erase_timings = []
        for _ in range(ERASES):
            session.send(b"\x7f")
            milliseconds, seen = time_to_appear(session.master, b"\x08")
            erase_timings.append(milliseconds)
            erased += seen
        erased += read_for(session.master, 0.5, 3.0)
        if link_losses() > reconnects:
            return None

        drawn = [t for t in erase_timings if t is not None]
        median_erase = sorted(drawn)[len(drawn) // 2] if drawn else None
        outcomes.append(
            (
                f"backspace does not wait for the link (median {took(median_erase)})",
                median_erase is not None and median_erase < PREDICTED_MS,
            )
        )
        repaints = erased.count(b"\x1b[2J")
        outcomes.append(
            (f"backspace costs no repaints ({repaints} screens)", repaints == 0)
        )

        # One round trip later the session has caught up with every erase, and the
        # row both halves have been writing to is the authority on what the line
        # holds: a prediction the session never confirmed is a character still
        # standing in it.
        erased += read_for(session.master, 0.8, 4.0)
        row.feed(ESCAPES.sub(b"", erased))
        settled = row.text()
        outcomes.append(
            (
                f"the session agrees with the erased row ({settled!r})",
                settled.endswith(LINE[:-ERASES]),
            )
        )

        # Retype what was erased, so the line the session runs is the whole one again.
        session.send(LINE[-ERASES:].encode())
        read_for(session.master, 0.6, 3.0)

        # What the session received has to be the line, not the prediction of it.
        session.send(b"\r")
        outcomes.append(
            ("the session ran what was drawn", mark_appears("PREDICT", 8.0))
        )
        if os.path.exists(f"{MARK_PREFIX}_PREDICT"):
            os.unlink(f"{MARK_PREFIX}_PREDICT")
        return outcomes
    finally:
        # The quit key, so nothing is left for the next suite to resume into.
        try:
            session.send(b"\x1d.")
        except OSError:
            pass
        session.wait(20.0)
        session.kill()


for attempt in range(1, ATTEMPTS + 1):
    outcomes = measure()
    if outcomes is not None:
        break
    print(
        f"note: the link dropped under attempt {attempt}, so nothing it measured is "
        "about prediction; starting over",
        file=sys.stderr,
    )
else:
    # Not a skip: a host that cannot hold a 100 ms link up for two seconds has
    # not answered the question this suite exists to ask.
    outcomes = [
        (
            f"the link held long enough to measure ({ATTEMPTS} attempts, "
            f"{link_losses()} reconnects)",
            False,
        )
    ]
    if os.path.exists(LOG):
        with open(LOG, encoding="utf-8", errors="replace") as handle:
            sys.stderr.write(handle.read())

results = [check(name, ok) for name, ok in outcomes]

os.unlink(shim)
if os.path.exists(LOG):
    os.unlink(LOG)
os.rmdir(shim_dir)

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
