#![forbid(unsafe_code)]

//! The user's terminal. The panic hook goes on before `tcsetattr`, and every
//! way out of raw mode comes back through [`restore_terminal`].

use crate::ClientError;
use crate::predict::{Prediction, Predictor, Repair, Typing};
use crate::render::{
    ANSI_SYNC_END, Assembled, PartMismatch, Predictions, RESET_TAIL, Screen, StatusLine,
};
use braid_proto::{CmdSeq, GridSize, InputCue, ScreenPart};
use rustix::event::{PollFd, PollFlags};
use rustix::io::Errno;
use rustix::termios::{self, OptionalActions};
use std::cell::Cell;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Finite, because a descriptor nobody drains is indistinguishable from one
/// nobody ever will.
const WRITE_WAIT: Duration = Duration::from_secs(10);

/// Invisible to a user, and finite to the supervisor behind `systemctl stop`.
const TEARDOWN_WAIT: Duration = Duration::from_millis(50);

/// Waits out a full output queue: fd 1 is shared with whatever else the user's
/// shell handed it to, and a peer that sets `O_NONBLOCK` turns a full queue
/// into a refusal `std`'s `BufWriter` does not retry.
fn write_waiting(fd: BorrowedFd<'_>, buf: &[u8], deadline: Instant) -> io::Result<usize> {
    loop {
        match rustix::io::write(fd, buf) {
            Ok(written) => return Ok(written),
            Err(Errno::INTR) => {}
            Err(Errno::WOULDBLOCK) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let timeout = rustix::fs::Timespec {
                    tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                    tv_nsec: remaining.subsec_nanos().into(),
                };
                let mut watched = [PollFd::new(&fd, PollFlags::OUT)];
                match rustix::event::poll(&mut watched, Some(&timeout)) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// A short write leaves half an escape sequence — `\x1b[?10` — on the screen.
fn write_all_waiting(fd: BorrowedFd<'_>, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        match write_waiting(fd, buf, deadline) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => buf = &buf[written..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// `Stdout`'s lock cannot cross a thread boundary; this client has two writers.
pub(crate) struct TerminalOut;

impl Write for TerminalOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_waiting(rustix::stdio::stdout(), buf, Instant::now() + WRITE_WAIT)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One owner: the reader loop paints output while the input thread draws
/// predictions, and a keystroke inside an escape sequence corrupts the screen.
pub struct Display<W: Write> {
    pub(crate) out: W,
    screen: Screen,
    predictor: Predictor,
    status: StatusLine,
}

impl<W: Write> Display<W> {
    pub fn new(out: W, prediction: Prediction) -> Self {
        Self {
            out,
            screen: Screen::default(),
            predictor: Predictor::new(prediction),
            status: StatusLine::new(),
        }
    }

    /// Returns whether the terminal holds predictions only a whole screen can
    /// take back off.
    ///
    /// Not flushed here: one mebibyte in 1160-byte writes cost 904 syscalls and
    /// 280.8us against a draining pipe, in 9280-byte writes 113 and 128.6us.
    pub fn output(
        &mut self,
        bytes: &[u8],
        cue: InputCue,
        echo_ack: Option<CmdSeq>,
    ) -> io::Result<bool> {
        let absorbed = self.predictor.absorb(bytes, cue, echo_ack);
        let passthrough = &bytes[absorbed.skip..];
        // Bytes belonging to the stream never go inside a screen's frame.
        self.screen.end_frame(&mut self.out)?;
        // The only way this client learns which modes the stream turned on, and
        // so all `teardown` has to undo them from.
        self.screen.observe(passthrough);
        // Ahead of the output: the reclaimed cells stand between the cursor and
        // the column this output belongs in.
        if absorbed.repair == Repair::Local {
            self.out.write_all(self.predictor.undo())?;
        }
        self.out.write_all(passthrough)?;
        Ok(absorbed.repair == Repair::Repaint)
    }

    /// Ends the frame a screen still arriving left open. Called wherever the
    /// session loop stops, which is what keeps echo latency where it is.
    pub fn flush(&mut self) -> io::Result<()> {
        self.screen.end_frame(&mut self.out)?;
        self.out.flush()
    }

    /// Nothing here touches the cue: a `Ping` says nothing about echo.
    pub fn echo_ack(&mut self, echo_ack: Option<CmdSeq>) -> bool {
        self.predictor.echo_ack(echo_ack)
    }

    /// The only evidence that the output which follows *could* be their echo.
    pub fn acknowledged(&mut self, highest: CmdSeq) {
        self.predictor.acknowledged(highest);
    }

    /// SIGWINCH: the cached cue was measured against the old width.
    pub fn resized(&mut self) {
        self.predictor.resized();
    }

    pub fn observed_rtt(&mut self, srtt: Option<Duration>) {
        self.predictor.observed_rtt(srtt);
    }

    /// `since` is how the caller says earlier keystrokes went to the session
    /// without reaching here, which the predictor accounts for either way.
    pub fn predict(
        &mut self,
        typed: &[u8],
        sent_as: Option<CmdSeq>,
        since: Typing,
    ) -> io::Result<()> {
        let drawn = self.predictor.predict(typed, sent_as, since);
        if drawn.is_empty() {
            return Ok(());
        }
        // Otherwise this flush carries a half-assembled screen with no frame end.
        self.screen.end_frame(&mut self.out)?;
        self.out.write_all(drawn)?;
        self.out.flush()
    }

    /// The only screen entry point; one too big for a frame arrives in several.
    pub fn part(
        &mut self,
        part: ScreenPart,
        terminal_rows: u16,
    ) -> io::Result<Result<Option<Assembled>, PartMismatch>> {
        let predictions = if self.predictor.invalidate() {
            Predictions::Drawn
        } else {
            Predictions::Settled
        };
        self.screen
            .part(&mut self.out, part, terminal_rows, predictions)
    }

    /// The link is gone: the terminal will miss whatever happens next.
    pub fn invalidate(&mut self) {
        self.predictor.invalidate();
        self.screen.invalidate();
    }

    /// The cursor goes back where the confirmed screen says it was: there is no
    /// saved-cursor slot to borrow, the application owns the terminal's.
    pub fn status_show(
        &mut self,
        size: GridSize,
        elapsed: Duration,
        dropped: bool,
    ) -> io::Result<()> {
        let cursor = self.screen.confirmed().and_then(|screen| screen.cursor);
        self.screen.end_frame(&mut self.out)?;
        self.status
            .show(&mut self.out, size, cursor, elapsed, dropped)
    }

    pub fn status_clear(&mut self) -> io::Result<()> {
        let cursor = self.screen.confirmed().and_then(|screen| screen.cursor);
        self.screen.end_frame(&mut self.out)?;
        self.status.clear(&mut self.out, cursor)
    }

    pub fn teardown(&mut self) -> io::Result<()> {
        self.predictor.invalidate();
        self.screen.teardown(&mut self.out)?;
        self.out.flush()
    }
}

/// The display, and the facts a signal could not put into it.
///
/// A signal must neither wait on this lock — the reader loop holds it across a
/// write to a terminal that may have stopped draining — nor lose what it
/// learned, since SIGCONT's `invalidate` is what stops this client diffing
/// against rows the shell has scrolled away.
pub(crate) struct Shared<W: Write> {
    display: Mutex<Display<W>>,
    pending: Pending,
}

/// What a signal handed over without the lock.
#[derive(Default)]
struct Pending {
    resized: AtomicBool,
    /// SIGCONT: the user's shell has scrolled, cleared or drawn over the screen.
    untrusted: AtomicBool,
}

impl Pending {
    fn apply<W: Write>(&self, display: &mut Display<W>) {
        if self.resized.swap(false, Ordering::AcqRel) {
            display.resized();
        }
        if self.untrusted.swap(false, Ordering::AcqRel) {
            display.invalidate();
        }
    }
}

impl<W: Write> Shared<W> {
    pub(crate) fn new(display: Display<W>) -> Self {
        Self {
            display: Mutex::new(display),
            pending: Pending::default(),
        }
    }

    /// The display, with everything a signal deferred already applied.
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Display<W>>, ClientError> {
        let mut display = self
            .display
            .lock()
            .map_err(|_| ClientError::Io(io::Error::other("terminal lock poisoned")))?;
        self.pending.apply(&mut display);
        Ok(display)
    }

    /// For a caller that must not wait: a prediction is an optimisation.
    pub(crate) fn try_lock(&self) -> Option<MutexGuard<'_, Display<W>>> {
        let mut display = self.display.try_lock().ok()?;
        self.pending.apply(&mut display);
        Some(display)
    }

    /// SIGWINCH, from the thread that waited the burst out.
    pub(crate) fn resized(&self) {
        if let Some(mut display) = self.try_lock() {
            display.resized();
        } else {
            self.pending.resized.store(true, Ordering::Release);
        }
    }

    /// No row this client remembers can be diffed against any more.
    pub(crate) fn invalidate(&self) {
        if let Some(mut display) = self.try_lock() {
            display.invalidate();
        } else {
            self.pending.untrusted.store(true, Ordering::Release);
        }
    }
}

/// The order is the point: a panic between the two — or inside `tcsetattr` —
/// prints a backtrace with ONLCR off onto a terminal nothing restores.
pub(crate) fn guarded_raw_mode<F: AsFd>(fd: F) -> io::Result<RawMode> {
    install_panic_hook();
    RawMode::enter(fd)
}

pub(crate) fn terminal_size<F: AsFd>(fd: F) -> io::Result<GridSize> {
    let size = termios::tcgetwinsize(fd)?;
    GridSize::new(size.ws_col, size.ws_row).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "terminal size outside protocol bounds",
        )
    })
}

/// Here rather than in `RawMode`, so a signal handler can reach it.
static ORIGINAL_TERMIOS: OnceLock<termios::Termios> = OnceLock::new();

pub(crate) fn restore_terminal() {
    if let Some(original) = ORIGINAL_TERMIOS.get() {
        let _ = termios::tcsetattr(io::stdin().as_fd(), OptionalActions::Now, original);
    }
}

/// Every mode [`braid_proto::RESET_ON_EXIT`] names, plus the kitty keyboard
/// flags. A signal handler and a panic hook cannot take the display lock, so
/// they send all of them blind; every one is off in an untouched terminal.
/// `blind_reset_matches_the_mode_table` keeps this literal from drifting.
pub(crate) const BLIND_RESET: &[u8] =
    b"\x1b[?1l\x1b[?66l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\
\x1b[?1005l\x1b[?1006l\x1b[?1007l\x1b[?1015l\x1b[?1016l\x1b[?1036l\x1b[?1049l\x1b[?2004l\
\x1b[?5l\x1b[?9l\x1b[?45l\x1b[?67l\x1b[=0;1u";

/// Not a `dup` of fd 1: `dup` shares the open file description, so `O_NONBLOCK`
/// set on it would land on the user's shell too. `None` is a revoked terminal.
fn nonblocking_terminal() -> Option<OwnedFd> {
    rustix::fs::open(
        "/dev/tty",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .ok()
}

/// Callers owe [`restore_terminal`] first; every byte below is cosmetic. On
/// fd 1 this would make `systemctl stop` and a session-leader hangup no-ops.
pub(crate) fn blind_reset() {
    let Some(terminal) = nonblocking_terminal() else {
        return;
    };
    let _ = reset_through(terminal.as_fd(), Instant::now() + TEARDOWN_WAIT);
}

/// The frame ends first: an open one holds the display until the 2026 timeout.
fn reset_through(fd: BorrowedFd<'_>, deadline: Instant) -> io::Result<()> {
    for part in [ANSI_SYNC_END, BLIND_RESET, RESET_TAIL] {
        write_all_waiting(fd, part, deadline)?;
    }
    Ok(())
}

pub(crate) const INPUT_THREAD: &str = "brd-input";

/// Matching on a thread's *name* inside the panic hook answers for one thread
/// and silently mishandles every thread added beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stake {
    /// A live session nobody can type into is worse than no session.
    Session,
    /// A panic here loses a tunnel, not the shell.
    Tunnel,
}

thread_local! {
    /// [`Stake::Session`] by default, the safe answer for anything unclassified.
    static STAKE: Cell<Stake> = const { Cell::new(Stake::Session) };
}

/// Applied where the thread is named, which is the only place that knows.
pub(crate) fn staked<T, F>(stake: Stake, body: F) -> impl FnOnce() -> T + Send + 'static
where
    F: FnOnce() -> T + Send + 'static,
{
    move || {
        STAKE.set(stake);
        body()
    }
}

/// `try_with`: a panic during thread-local destruction finds this slot gone.
pub(crate) fn stake_here() -> Stake {
    STAKE.try_with(Cell::get).unwrap_or(Stake::Session)
}

/// The default hook prints at the panic site — before `RawMode::drop`, ONLCR
/// off — and a panicking thread never reaches `RawMode::drop` at all.
pub(crate) fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if stake_here() == Stake::Tunnel {
            default(info);
            return;
        }
        restore_terminal();
        blind_reset();
        default(info);
        std::process::exit(1);
    }));
}

/// Separate from [`RawMode`] because SIGCONT re-enters raw mode on a terminal
/// this process already owes a restore; a second guard would undo the first.
pub(crate) fn enter_raw<F: AsFd>(fd: F) -> io::Result<()> {
    let original = termios::tcgetattr(&fd)?;
    let mut raw = original.clone();
    raw.make_raw();
    termios::tcsetattr(&fd, OptionalActions::Now, &raw)?;
    let _ = ORIGINAL_TERMIOS.set(original);
    Ok(())
}

pub(crate) struct RawMode;

impl RawMode {
    fn enter<F: AsFd>(fd: F) -> io::Result<Self> {
        enter_raw(fd)?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore_terminal();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BLIND_RESET, RESET_TAIL, TEARDOWN_WAIT, reset_through, write_all_waiting, write_waiting,
    };
    use crate::render::ANSI_SYNC_END;
    use std::io::Read;
    use std::net::Shutdown;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    /// Everything the teardown owes a terminal, in the order it owes it.
    fn whole_teardown() -> Vec<u8> {
        [ANSI_SYNC_END, BLIND_RESET, RESET_TAIL].concat()
    }

    /// Refuses rather than parks, like a tty a neighbour put `O_NONBLOCK` on.
    fn refusing_terminal() -> (UnixStream, UnixStream) {
        let (read, write) = UnixStream::pair().expect("a socket pair");
        write
            .set_nonblocking(true)
            .expect("a socket takes O_NONBLOCK");
        (read, write)
    }

    /// Returns how much must come back out before it takes anything again.
    fn fill(write: &UnixStream) -> usize {
        let block = [b'x'; 4096];
        let mut queued = 0;
        while let Ok(written) = rustix::io::write(write, &block) {
            queued += written;
        }
        queued
    }

    /// A full output queue on a shared tty is `EAGAIN`, which `BufWriter` drops.
    #[test]
    fn a_refused_write_waits_for_the_terminal_instead_of_ending_the_session() {
        let (mut read, write) = refusing_terminal();
        let queued = fill(&write);
        let draining = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let mut drained = vec![0_u8; queued];
            read.read_exact(&mut drained).expect("the terminal drains");
            read
        });
        let written = write_waiting(
            write.as_fd(),
            b"echo",
            Instant::now() + Duration::from_secs(5),
        )
        .expect("a full output queue is not a broken terminal");
        assert_eq!(written, 4);
        drop(draining.join().expect("the draining thread finishes"));
    }

    /// A `dup` of fd 1 shares the open file description, so `O_NONBLOCK` set on
    /// it lands on the user's shell too. Silent where there is no tty to open.
    #[test]
    fn the_teardown_descriptor_is_this_process_s_own_and_cannot_park() {
        let Some(terminal) = super::nonblocking_terminal() else {
            return;
        };
        assert!(
            rustix::fs::fcntl_getfl(&terminal)
                .expect("the teardown descriptor's flags")
                .contains(rustix::fs::OFlags::NONBLOCK),
            "a teardown write can park, which is what makes SIGTERM a no-op"
        );
        assert!(
            !rustix::fs::fcntl_getfl(rustix::stdio::stdout())
                .expect("stdout's flags")
                .contains(rustix::fs::OFlags::NONBLOCK),
            "the teardown made the session's own output non-blocking, and the shell's with it"
        );
    }

    /// The retry is for backpressure alone. `shutdown` rather than `drop`: a
    /// sibling's fork leaves the peer alive in the child until its `execve`, a
    /// window in which the write is legitimately taken.
    #[test]
    fn a_terminal_that_is_really_gone_still_ends_the_session() {
        let (read, write) = refusing_terminal();
        read.shutdown(Shutdown::Both)
            .expect("a socket takes a shutdown");
        drop(read);
        let error = write_waiting(
            write.as_fd(),
            b"echo",
            Instant::now() + Duration::from_secs(5),
        )
        .expect_err("nothing is reading this");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// A reset written to a blocking fd 1 parks in the kernel and nothing below
    /// it runs, which is what would make `systemctl stop` a no-op.
    #[test]
    fn a_terminal_that_stopped_draining_cannot_hold_a_teardown_open() {
        let (_read, write) = refusing_terminal();
        fill(&write);
        let started = Instant::now();
        let refused = reset_through(write.as_fd(), started + TEARDOWN_WAIT);
        let waited = started.elapsed();
        assert_eq!(
            refused
                .expect_err("a full terminal took the whole teardown")
                .kind(),
            std::io::ErrorKind::WouldBlock,
            "the teardown ended on something other than its own deadline"
        );
        // The regressions this stands against are two orders of magnitude away,
        // so the bound is scheduler headroom rather than precision.
        assert!(
            waited < TEARDOWN_WAIT * 20,
            "a teardown against a terminal nobody drains took {waited:?}"
        );
    }

    /// Every byte of every literal, in order, to a terminal that must be waited on.
    #[test]
    fn a_teardown_leaves_no_half_written_escape_sequence() {
        let (mut read, write) = refusing_terminal();
        // What makes the teardown wait is that the queue is full, not its size.
        rustix::net::sockopt::set_socket_send_buffer_size(&write, 4096)
            .expect("a socket takes a send buffer size");
        fill(&write);
        let expected = whole_teardown();
        let wanted = expected.len();

        // A trickle, so the teardown must wait both to start and to finish.
        let reading = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut sip = [0_u8; 8];
            loop {
                match read.read(&mut sip) {
                    Ok(0) | Err(_) => break seen,
                    Ok(count) => seen.extend_from_slice(&sip[..count]),
                }
            }
        });
        reset_through(write.as_fd(), Instant::now() + Duration::from_secs(5))
            .expect("a terminal that drains takes the whole teardown");
        // EOF from the socket, not from this being its last reference.
        write
            .shutdown(Shutdown::Write)
            .expect("a socket takes a shutdown");
        drop(write);
        let seen = reading.join().expect("the reading thread finishes");
        assert_eq!(
            &seen[seen.len() - wanted..],
            &expected[..],
            "the terminal was left holding a truncated escape sequence"
        );
    }

    /// The teardown's literals never reach this path; the kernel never splits
    /// a write that small.
    #[test]
    fn a_write_the_terminal_takes_in_pieces_is_finished_by_the_loop() {
        let (mut read, write) = refusing_terminal();
        rustix::net::sockopt::set_socket_send_buffer_size(&write, 4096)
            .expect("a socket takes a send buffer size");
        let queued = fill(&write);
        let owed: Vec<u8> = (0..16_384_u32).flat_map(u32::to_le_bytes).collect();
        let reading = std::thread::spawn(move || {
            let mut seen = Vec::new();
            read.read_to_end(&mut seen).expect("the terminal drains");
            seen
        });
        write_all_waiting(
            write.as_fd(),
            &owed,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("a terminal that drains takes the whole write");
        write
            .shutdown(Shutdown::Write)
            .expect("a socket takes a shutdown");
        drop(write);
        let seen = reading.join().expect("the reading thread finishes");
        assert_eq!(
            &seen[queued..],
            &owed[..],
            "the terminal was left holding a partial write"
        );
    }
}
