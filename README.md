<h1 align="center">Braid</h1>

<p align="center">
  A remote shell that outlives its connection.
  <br />
  Shut the laptop, change networks, lose the train tunnel &mdash;
  <code>brd user@host</code> puts you back in the same shell.
  <br />
  <br />
  <a href="#about">About</a>
  &middot;
  <a href="#install">Install</a>
  &middot;
  <a href="#usage">Usage</a>
  &middot;
  <a href="#how-it-works">How it works</a>
  &middot;
  <a href="#status">Status</a>
  &middot;
  <a href="#how-it-compares">Compare</a>
</p>

## About

**A disclosure first.** Call it slopware if you like: I started this on 24 August 2026,
and the code was written end to end by LLMs, under review of varying depth by me. It is
as much an experiment in working with LLMs effectively as it is a terminal &mdash; but I
think what came out is decent software, and it might be useful to you.

`brd user@host` opens a shell the way `ssh user@host` does, and logs in exactly the
same way: through your own `ssh`, your own `~/.ssh/config`, your own keys. There is no
new daemon to expose, no port to open, no second set of credentials.

The difference is on the far side. The PTY belongs to a small per-user daemon rather
than to the connection, so when the connection dies the shell does not notice. Every
other property here falls out of that one change.

**The transport is disposable.** Killing the link costs a pause. `brd user@host` again
lands in the same shell, at the same working directory, with the same job running.
Reconnection is unbounded and backs off to thirty seconds, because "suspended for six
hours" is the case this exists for, not an edge case.

**It leaves SSH when it can, and stays when it can't.** Once a session is up the daemon
offers a UDP path; the client takes it if the network allows. On that path there is no
head-of-line blocking, `Ctrl-C` lands during a 40 MB flood, and changing networks costs
one round trip rather than a handshake. When UDP is blocked or mangled the session stays
on the `ssh` pipe and keeps working &mdash; the case that has no answer in mosh.

**Typing does not wait for the network.** A keystroke, and the backspace that takes it
back, are drawn immediately once the session has confirmed that this run of typing
echoes. Over a 200 ms link the first keystroke costs 201 ms and every one after it costs
0.0 ms, with no repaints. Nothing is ever drawn at a prompt that has not echoed, so a
password is never predicted onto your screen &mdash; not by recognising the prompt, but
because the rule that permits drawing cannot be satisfied there.

**A host remembers more than one session, and a session carries more than one client.**
Two terminals can attach to the same shell and watch each other type. `brd ls` lists
them, `brd attach` reaches one by any unambiguous prefix of its id, and `brd kill` ends
one.

**Scrollback lives where the history is.** `brd grep host <pattern>` searches every
session's scrollback on the far side and prints what matched, including lines that
scrolled out of the viewport hours ago.

**Port forwards belong to the session, not to the link.** `brd -L 8080:localhost:80 host`
is `ssh -L` with the property `ssh -L` cannot have: kill the transport mid-transfer and
the copy pauses and resumes at the byte it stopped on. The application's socket never
learns anything happened.

## Install

Requires a current stable Rust, Zig 0.16.x, and network access to github.com &mdash; the
terminal emulator is [libghostty](https://github.com/ghostty-org/ghostty), built from
source by a dependency's build script. `install.sh` will fetch and checksum a private Zig
toolchain if the host doesn't have a matching one.

```console
$ git clone https://github.com/fbernier/braid && cd braid
$ ./install.sh          # builds release, installs to ~/.local/bin/brd
```

`brd` must be installed on **both ends**, and on the remote host it has to be reachable
from the PATH an `ssh` login gets. There are no distribution packages yet; see
[Status](#status).

Linux and macOS. Both are first-class: CI builds and tests on each, because the daemon
reads `sun_path` bounds, umask, process groups and PTYs straight from the platform.

## Usage

```console
$ brd user@host                          # resume the newest session there, or start one
$ brd user@host -- tmux attach           # run something other than a login shell
$ brd ls user@host                       # what is running on that host
$ brd attach user@host 3f9c              # an older session, by id prefix
$ brd kill user@host 3f9c
$ brd grep user@host 'error:'            # search every session's scrollback, remotely
$ brd -L 8080:localhost:80 user@host     # a forward that survives reconnects
$ brd -N -L 8080:localhost:80 user@host  # forwards only: no shell, backgrounds with &
```

Inside a session:

| Key | Does |
| --- | --- |
| `Ctrl-] d` | detach, leaving the shell running |
| `Ctrl-] .` | quit, ending the shell |
| `Ctrl-] r` | repaint |
| `Ctrl-] z` | suspend |

Transport options belong in `ssh_config`. `brd` runs your `ssh`, so your existing
`ProxyJump`, `Port`, `IdentityFile` and `Match` blocks already apply, and there is no
second configuration language to learn.

| Environment | Does |
| --- | --- |
| `BRD_PREDICT` | `never`, `adaptive` (default) or `always` |
| `BRD_LOG` | append a line per reconnect, transport change and detach |
| `BRD_NO_DATAGRAM` | refuse the UDP path and stay on `ssh` |
| `BRD_STATE_DIR` | where the daemon's socket, lock and capabilities live |

## How it works

Three processes, and the interesting one outlives the other two.

```
  your terminal                              remote host
  ┌────────────┐                    ┌──────────────────────────┐
  │    brd     │ ──── ssh ────────▶ │ brd --server  (relay)    │
  │  (client)  │                    │        │ unix socket     │
  └────────────┘                    │        ▼                 │
         │                          │ brd --daemon             │
         │                          │   ├── session ── PTY     │
         │                          │   └── session ── PTY     │
         │                          └──────────────────────────┘
         └────── UDP, once the daemon offers a path ──────▲
```

The client runs `ssh host brd --server`, which relays framed messages to a per-user
daemon over a private unix socket, starting it if it isn't running. The daemon owns the
PTYs. When the relay dies, the sessions don't.

**The screen is a data structure, not a byte stream &mdash; but only when it has to be.**
In steady state output is byte-exact passthrough, so your local scrollback is real
scrollback. When a client falls behind or reconnects, the daemon switches that client to
synchronised mode and sends the screen: grid, style runs, cursor, modes, title, kitty
keyboard flags, and the OSC sequences a sync episode would otherwise swallow. Damage is
tracked per row and cleared only when a client confirms a screen, so a dropped update
costs a retransmit rather than a lost row. The diff unit is a style run, not a row: a
one-line `less` scroll on an 80x50 grid is 165 bytes rather than 4671.

**Nothing blocks on a peer.** Every write that can meet something which stopped reading
&mdash; the PTY master, the attachment socket, your terminal, the pipe to `ssh` &mdash;
happens off the thread that has to keep moving, behind a bounded buffer. That is why the
quit key still works against a program that neither reads its input nor stops writing.

**The transport is a state machine with no I/O in it.** `crates/dgram` owns no socket, no
thread and no clock: every input is an argument and every output a return value, so both
ends of a connection run inside one process against a simulated link that drops,
reorders, duplicates, corrupts, truncates, replays, spoofs and blackholes on purpose. It
does New Reno with a pacer, RFC 9002 loss detection, QUIC-style path validation and
anti-amplification, and a path-MTU search. It never retransmits: the layer above resends
idempotent state, and loss only moves the window.

The invariants behind all of this live in the tests that found them: `crates/sim` runs
both ends of a connection inside one process against a link that fails on purpose,
`crates/server`'s oracle replays real `vim`, `htop` and CJK captures through the wire and
asserts the far screen is indistinguishable, and `tests/e2e` drives a real client through
a real PTY over an SSH loopback. Comments in the tree explain *why* a thing is shaped the
way it is; the tests say what would break if it changed.

## Security

Authentication is SSH's, unchanged. The daemon listens only on a unix socket inside a
`0700` directory, and checks `SO_PEERCRED` against your own uid before reading a byte.

Resuming a session needs a 32-byte capability; only its BLAKE3 digest is ever written to
disk. The UDP path's root secret is minted per attachment and delivered **inside the ssh
channel** &mdash; never in an argv, never in an environment variable, which is strictly
better than handing a session key to a client through `MOSH_KEY`.

Datagrams are sealed with ChaCha20-Poly1305 (RFC 8439): one key per epoch per direction,
the packet number as the nonce, the cleartext header as associated data. What it replaced
was a BLAKE3 construction of our own &mdash; XOF keystream, keyed-BLAKE3 tag, independent
keys, encrypt-then-MAC. That was careful and it was tested, but "recognisable on sight to
a reviewer" is worth more than saving a dependency, and the RFC's own test vector is now
in the suite, which is not something a design of ours could ever have.

[SECURITY.md](SECURITY.md) states the trust model those properties add up to, and how to
report privately anything that breaks one.

## Status

**Alpha.** The resilience contract is covered by 642 unit and integration tests, 14
end-to-end suites driving a real client through a real PTY over an SSH loopback, a
deterministic fault-injecting simulator, and 11 fuzz targets, all gated in CI on every
pull request. What that buys is confidence that the invariants hold, not that the
corners are all found: the wire protocol still breaks between versions, and there are
known gaps below.

| # | | Status |
|:-:|---|:---:|
| 1 | A session survives its transport | ✅ |
| 2 | Datagram transport, with an `ssh` fallback that actually works | ✅ |
| 3 | Predictive local echo that never guesses at a password prompt | ✅ |
| 4 | Multi-session, multi-client, remote scrollback search | ✅ |
| 5 | Forwards that belong to the session | ✅ |
| 6 | Complete terminal state across a resume | 🚧 |
| 7 | Installable from a package manager | ❌ |
| 8 | One process per session | ❌ |

### Complete terminal state across a resume

The screen sent on reconnect carries grid, style, cursor, modes and sticky state, and an
oracle test replays real captures of `vim`, `htop`, CJK, combining marks and emoji
through the wire and asserts the result is indistinguishable. Three things are still
missing because the emulator does not expose them yet: the saved cursor (DECSC), charset
designation, and tab stops. A resumed screen can therefore look right while a later
escape sequence behaves differently. That is a correctness gap, not a cosmetic one.

The repaint oracle also has a blind spot worth naming: both ends of it are the same
emulator, so anything Ghostty and other terminals disagree about is invisible to it. A
second, independent emulator in that loop is wanted.

### Installable from a package manager

Today a build fetches Ghostty's source from github.com and needs an exact Zig minor
version, and the Rust binding is pinned to a git revision. No distribution can package
that. This is the single biggest thing standing between Braid and anyone else using it.

### One process per session

One daemon owns every PTY on the host. Panics are contained per session, locks are
poison-tolerant, and a session's thread dying takes only that session &mdash; but a
segfault, a stack overflow or a fault across the Zig FFI boundary takes all of them. The
honest fix is a session-owner process per session with attachment descriptors passed over
`SCM_RIGHTS`, leaving the daemon a registry with no PTYs in it.

## How it compares

**mosh** is where the good ideas came from: state synchronisation, predictive echo,
pacing the frame rate to the link. It is more mature, it predicts inside full-screen
applications where Braid deliberately does not, and it has years of terminal
compatibility behind it. But a running `mosh-server` cannot be reattached from a new
client &mdash; lose the client process and you lose the session &mdash; it has no
fallback when UDP is blocked, and it keeps no scrollback of its own.

**Eternal Terminal** reconnects a TCP session transparently and keeps up to 64 MiB of
exact bytes to replay, which is more than Braid replays before it gives up and sends a
screen. It also does reverse and unix-socket forwarding. But everything rides one
reliable stream, so a flood still queues ahead of your `Ctrl-C`, and it needs a daemon
listening on a real port.

**tmux over ssh** gets you persistence and nothing else: the round trip is still on every
keystroke, and a dead link is still a dead link until TCP notices. Braid is happy to run
`tmux` inside itself; the two solve different halves.

## Contributing

Issues and pull requests welcome, with the caveat that this is alpha and the protocol
still moves. A non-trivial change wants a test that fails without it &mdash; the suites
above are the argument for why the code is shaped the way it is, and most of them were
written by getting something wrong first. Security reports go through
[SECURITY.md](SECURITY.md) rather than the issue tracker.

```console
$ cargo fmt --all --check
$ cargo test --workspace --locked
$ cargo clippy --workspace --all-targets --locked -- -D warnings
$ BRD_E2E=1 python3 tests/e2e/run.py    # needs passwordless ssh to $BRD_E2E_DEST
```

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Contributions are accepted under the same terms.
