# brd end-to-end correctness harness

Drives a real `brd` client through a real PTY against an SSH loopback and asserts the
resilience contract: detach leaves the remote shell running, reattach lands in the same
shell, a second client *joins* rather than evicting and both drive the one PTY, Ctrl-C
lands during a 40 MB flood (no head-of-line blocking), sessions and tickets are reaped on
exit, sync mode returns to full-fidelity passthrough after a burst, killing the transport
mid-session reconnects to the same shell with state intact, an sshd-style process-group
`SIGHUP` leaves the daemon and its session standing, two daemons racing for the socket
from a cold start settle on one that a client can still reach, a session leaves `ssh` for
the datagram transport and falls back to the pipe when it cannot, a 400-column screen of
dense colour and one of emoji leave the session alive on that transport, typing and
backspacing through a delayed link cost no round trip and no repaint, sessions can be
listed and reached by id prefix, a line scrolled out of the viewport is still found by
`brd grep`, and a program that neither reads its input nor stops writing does not wedge
the session against its own quit key.

Requires passwordless SSH (key auth) to `$BRD_E2E_DEST` and an installed `brd` on `PATH`.
Not part of `cargo test`: opt in with `BRD_E2E=1`, otherwise every script exits 0 with a
skip message on stderr. Opting in and *then* finding a prerequisite missing exits 2 — a
skip is indistinguishable from a pass in a log, and these suites are the only coverage
the resilience contract has. The `e2e` job in `.github/workflows/ci.yml` stands up a
loopback `sshd` and runs the whole set on every pull request.

    BRD_E2E=1 python3 tests/e2e/run.py

- `BRD_E2E` — must be `1`; anything else skips.
- `BRD_BIN` — client binary; default `which brd`, else `~/.local/bin/brd`.
- `BRD_E2E_DEST` — ssh destination; default `$USER@127.0.0.1`.
- `BRD_E2E_SHELL` — shell the daemon spawns, used for `pgrep`/`pkill`; default
  `basename($SHELL)`. Tag checks use `set -g`, so fish for those two to be meaningful.
- `BRD_STATE_DIR` / `XDG_STATE_HOME` — where the daemon's socket, lock and capabilities
  live; the harness reads the same chain the daemon does, defaulting to
  `~/.local/state/brd`. Not `XDG_RUNTIME_DIR`: logind deletes that at last logout.
- `BRD_NO_DATAGRAM` — set to anything to refuse the daemon's datagram offer and stay on
  the ssh pipe. Two probes set it themselves: `probe_predict.py` measures against a
  delayed `ssh` shim, and `probe_teardown.py` signals the process group of the relay
  `sshd` starts — neither of which a migrated session goes through.

Perf A/B harnesses (keystroke echo latency against plain `ssh`) are deliberately not
tracked here: they measure the network they run on, so a number from CI means nothing.
Only correctness harnesses live in this directory.
