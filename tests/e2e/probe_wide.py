#!/usr/bin/env python3
"""A wide, densely coloured row must not end the session.

Before row chunking, a screen whose widest row did not fit one datagram was
answered with `Reject { ScreenTooLarge }` — a *terminal* rejection, so the
client stopped its reconnect loop and the session was lost while the shell
kept running. A 400-column line with forty style runs is `ls --color` on an
ordinary wide terminal, and 200 columns of emoji is a chat log.

The screen path is only reached under backpressure, so this drives the same
overrun `probe_sync.py` uses: a burst large enough to fill the byte-stream
window, at a width no datagram can carry a row of.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive
from drive import Session, check, require_gate

# 400 columns of alternating SGR colour: ~40 style runs on every row, which is
# 1208 encoded bytes against a 1134-byte datagram row budget.
#
# Wrapped in `sh -c` because the login shell here is whatever the user's is,
# and `$BRD_E2E_SHELL` defaults to `fish`, which shares no loop syntax with
# the POSIX shell this generator is written in.
WIDE = (
    """sh -c 'for i in $(seq 1 80); do """
    """for c in $(seq 31 38); do printf "\\033[%sm%s\\033[0m" "$c" "##########"; done; """
    """printf "\\n"; done'"""
)

# Two columns per cluster, eleven bytes per cluster: the largest chunk shape
# the encoder has to cut.
FAMILY = (
    """sh -c 'for i in $(seq 1 60); do """
    """for j in $(seq 1 100); do printf "\\U0001F468\\u200D\\U0001F469\\u200D\\U0001F467"; done; """
    """printf "\\n"; done'"""
)


def burst(session, command, marker):
    """Run `command`, then prove the session still answers."""
    session.send(command.encode() + b"\n")
    session.drain(3.0)
    # Split so the echoed command line cannot itself contain the marker: the
    # shell joins the halves, and the terminal only ever shows them joined
    # when the session actually printed them.
    head, tail = marker[:4], marker[4:]
    session.send(f"""sh -c 'printf "{head}""{tail}\\n"'\n""".encode())
    return session.read_until(marker.encode(), timeout=20.0)


def main():
    require_gate()
    drive.kill_shells()
    ok = True

    session = Session(cols=400, rows=24)
    try:
        session.drain(2.0)
        ok &= check(
            "a 400-column coloured burst leaves the session alive",
            burst(session, WIDE, "BRD_WIDE_OK"),
        )
        ok &= check(
            "a 400-column emoji burst leaves the session alive",
            burst(session, FAMILY, "BRD_EMOJI_OK"),
        )
        ok &= check(
            "the session still answers after both",
            burst(session, "true", "BRD_ALIVE_OK"),
        )
        session.send(b"\x1d.")
        ok &= check("the quit key still ends it", session.wait(timeout=10.0) == 0)
    finally:
        session.kill()
        drive.kill_shells()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
