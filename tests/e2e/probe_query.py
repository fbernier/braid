#!/usr/bin/env python3
"""Does a terminal query reach whoever can answer it, and nobody else?

The daemon's emulator answers some of the questions an application asks of its
terminal and not others. One it answers must not also reach the user's terminal,
which would answer a second time and leave the reply sitting on the shell prompt.
One it does not answer must reach the user's terminal, which is the only thing
that will: cutting that one strands the application waiting for a reply nothing
will ever send.

Both halves are about what crosses the wire to the client, so neither is visible
to a unit test. This drives a real daemon over a real PTY.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive  # noqa: E402
from drive import BRD, DEST, Session, check  # noqa: E402

drive.require_gate()

# Asks the terminal who it is and prints the answer, from inside the session.
# A shell cannot read a raw reply portably, and the point of the check is that
# the reply arrives at the application at all.
ASK = os.path.join(tempfile.gettempdir(), "brd_probe_ask_da.py")
ASK_SOURCE = """import os, select, sys, termios, tty

fd = sys.stdin.fileno()
saved = termios.tcgetattr(fd)
tty.setraw(fd)
os.write(1, b"\\x1b[c")
reply = b""
while select.select([fd], [], [], 2.0)[0]:
    byte = os.read(fd, 1)
    reply += byte
    if byte == b"c":
        break
termios.tcsetattr(fd, termios.TCSADRAIN, saved)
os.write(1, b"DA1{" + reply.replace(b"\\x1b", b"E") + b"}\\r\\n")
"""

with open(ASK, "w", encoding="utf-8") as handle:
    handle.write(ASK_SOURCE)

results = []
drive.cold_start()

# `sh`, so the prompt and the rc files of whatever login shell this host uses
# cannot put an escape sequence anywhere near what is being measured.
s = Session(argv=[BRD, DEST, "--", "sh"])
s.send(b"printf 'READY\\n'\n")
s.read_until(b"READY", timeout=10.0)

# Passthrough has to be the state under test: in a sync episode the client is
# painted from whole screens and no escape byte reaches this PTY either way,
# which would make every assertion below pass for the wrong reason.
s.buf = b""
s.send(b"printf '\\033[31mPASSTHROUGH\\033[0m\\n'\n")
s.read_until(b"PASSTHROUGH", timeout=8.0)
s.drain(0.5)
results.append(check("passthrough is active", b"\x1b[31mPASSTHROUGH" in s.buf))

# A Device Attributes query. The daemon's emulator answers it, so the reply
# reaches the application and the user's terminal is never asked.
s.buf = b""
s.send(b"python3 %s\n" % ASK.encode())
s.read_until(b"DA1{", timeout=10.0)
s.drain(0.5)

answered = b"DA1{E[?62;" in s.buf
results.append(check("the daemon answers DA1 to the application", answered))
if not answered:
    print("   -> the application never received a reply to CSI c")

# The query itself, on the wire to the client. It is written to the terminal
# before the reply is printed, so a leak would land ahead of the marker - the
# region after it holds only the escaped reply and could never show one.
head = s.buf.split(b"DA1{")[0]
leaked = b"\x1b[c" in head
results.append(check("the DA1 query does not reach the user's terminal", not leaked))
if leaked:
    print("   -> a second terminal will answer it onto the prompt")

# A background-colour query. libghostty-vt exposes no callback to answer one,
# so the daemon has to let it through to the terminal that can.
s.buf = b""
s.send(b"printf '\\033]11;?\\007'; printf 'ASKED\\n'\n")
s.read_until(b"ASKED", timeout=8.0)
s.drain(0.5)

forwarded = b"\x1b]11;?" in s.buf
results.append(check("an unanswerable query reaches the user's terminal", forwarded))
if not forwarded:
    print("   -> background-colour detection is dead: nothing will answer it")

# Whatever the queries did, the session is still a terminal the user can type at.
s.buf = b""
s.send(b"printf 'STILL_HERE\\n'\n")
alive = s.read_until(b"STILL_HERE", timeout=8.0)
results.append(check("the session survives a probing application", alive))

s.kill()
if os.path.exists(ASK):
    os.unlink(ASK)

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
