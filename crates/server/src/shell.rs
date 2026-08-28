// `deny` rather than `forbid`: portable-pty names the terminal it opened only
// as a `RawFd`, and there is no safe way to borrow one.
#![deny(unsafe_code)]

//! The child a session runs, its terminal, and the two threads between them.

use crate::actor::{SessionActor, Terminal, guarded};
use crate::backlog::BacklogRing;
use crate::defer::DeferredOsc;
use crate::forward::Forwards;
use crate::mailbox::{ActorEvent, Chunk, MailboxReceiver, MailboxSender, mailbox};
use crate::ptyin::PtyInput;
use crate::query::QueryFilter;
use crate::registry::{
    DaemonState, KillNotice, SessionCleanup, SessionHandle, SessionInfo, SessionKind, registry,
};
use crate::state::{FORWARDED_ENV, printable, session_name};
use crate::{
    ACTOR_STACK, BACKLOG_BYTES, CHILD_UMASK, CONTINUATION_BYTES, DEFAULT_UMASK, IO_STACK,
    PTY_CHUNK, REAP_POLL, SCROLLBACK_BYTES, ServerError, SessionEffects, SharedSink,
    TERMINATE_GRACE, log::log, sessions,
};
use braid_proto::{ByteOff, Generation, GridSize, MAX_COMMAND, SessionEnv, SessionId};
use braid_vt::{ContinuationLimit, ScrollbackLimit, VtEngine};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use rustix::event::{PollFd, PollFlags};
use rustix::process::{Pid, Signal};
use std::env;
use std::io::{self, Write};
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Bracketed so a `brd ls` line cannot be confused with a real argv.
const FORWARD_COMMAND: &str = "[forwards]";

/// The smallest legal [`GridSize`]: a forward-only session is never painted.
const FORWARD_GRID: GridSize = GridSize { cols: 1, rows: 1 };

/// The wakeup two parked PTY threads share: closing a descriptor under a
/// blocked `read` is undefined, and a descendant that `setsid`s out of the
/// child's process group holds the slave open past every signal
/// [`Shell::shut_down`] can send. The hangup is level-triggered, so every
/// parked thread sees the same one.
pub(crate) struct Hangup {
    /// Held by [`Shell`]; dropping it retires both threads.
    pub(crate) close: OwnedFd,
    pub(crate) watch: Arc<OwnedFd>,
}

impl Hangup {
    pub(crate) fn new() -> Result<Self, ServerError> {
        let (watch, close) = cloexec_pipe()
            .map_err(|error| ServerError::Setup(format!("session wakeup: {error}")))?;
        Ok(Self {
            close,
            watch: Arc::new(watch),
        })
    }

    pub(crate) fn watching(&self, raw: RawFd) -> Result<PtyEnd, ServerError> {
        PtyEnd::new(dup_cloexec(raw)?, Arc::clone(&self.watch))
    }
}

/// Close-on-exec: a shell that inherits a copy of the write end retires nothing.
#[cfg(not(target_vendor = "apple"))]
fn cloexec_pipe() -> rustix::io::Result<(OwnedFd, OwnedFd)> {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
}

/// Darwin has no `pipe2`, so a shell spawned between these two calls inherits
/// the write end and delays this hangup until it exits.
#[cfg(target_vendor = "apple")]
fn cloexec_pipe() -> rustix::io::Result<(OwnedFd, OwnedFd)> {
    let (watch, close) = rustix::pipe::pipe()?;
    rustix::io::fcntl_setfd(&watch, rustix::io::FdFlags::CLOEXEC)?;
    rustix::io::fcntl_setfd(&close, rustix::io::FdFlags::CLOEXEC)?;
    Ok((watch, close))
}

pub(crate) struct PtyEnd {
    pub(crate) fd: OwnedFd,
    hangup: Arc<OwnedFd>,
}

impl PtyEnd {
    /// Nonblocking for the whole open file description, which the reader and
    /// the writer share through two dups of it: a read that finds nothing and
    /// a write that finds no room then fall through to [`PtyEnd::ready`],
    /// instead of parking in a kernel call the hangup cannot reach into.
    fn new(fd: OwnedFd, hangup: Arc<OwnedFd>) -> Result<Self, ServerError> {
        // Read back rather than assumed: `F_SETFL` replaces the status flags
        // rather than adding to them.
        rustix::fs::fcntl_getfl(&fd)
            .and_then(|flags| rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK))
            .map_err(|error| ServerError::Setup(format!("session terminal: {error}")))?;
        Ok(Self { fd, hangup })
    }

    /// `false` is the hangup.
    pub(crate) fn ready(&self, interest: PollFlags) -> bool {
        loop {
            let mut watched = [
                PollFd::new(&self.fd, interest),
                PollFd::new(&*self.hangup, PollFlags::IN),
            ];
            match rustix::event::poll(&mut watched, None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return false,
            }
            if !watched[1].revents().is_empty() {
                return false;
            }
            if !watched[0].revents().is_empty() {
                return true;
            }
        }
    }
}

/// The terminal's output side.
///
/// A `read` on a master crosses the line discipline, which hands over at most
/// its own buffer - 4 KiB on Linux, less on Darwin - however large a buffer it
/// is offered. One read per [`ActorEvent::PtyOutput`] therefore costs an actor
/// turn, a mailbox wakeup, a sink push and an `Output` frame per 4 KiB rather
/// than per [`PTY_CHUNK`], which is what that constant was sized to buy.
struct PtyReader(PtyEnd);

impl PtyReader {
    /// Take everything the master is holding, waiting only when it holds
    /// nothing at all. `Ok(0)` is the hangup or the last slave closing.
    ///
    /// Measured on a 5950X against a flooding shell: 22 frames and 272
    /// syscalls per MiB, against 267 and 533 for one read per frame.
    fn drain(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        loop {
            match rustix::io::read(&self.0.fd, &mut buf[filled..]) {
                // Darwin reports the last slave closing as an ordinary end of
                // stream; Linux reports it as `EIO`.
                Ok(0) | Err(rustix::io::Errno::IO) => return Ok(filled),
                Ok(read) => {
                    filled += read;
                    if filled == buf.len() {
                        return Ok(filled);
                    }
                }
                Err(rustix::io::Errno::INTR) => {}
                // `EWOULDBLOCK` is `EAGAIN` on both targets. Bytes already in
                // hand leave now: holding them for a fuller frame would charge
                // an idle session's echo the latency of a flood.
                Err(rustix::io::Errno::AGAIN) => {
                    if filled > 0 {
                        return Ok(filled);
                    }
                    // A hangup is this terminal's end of stream, retiring the
                    // reader through `PtyEnded` as an ordinary EOF does.
                    if !self.0.ready(PollFlags::IN) {
                        return Ok(0);
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

struct PtyWriter(PtyEnd);

impl Write for PtyWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match rustix::io::write(&self.0.fd, buf) {
                Ok(written) => return Ok(written),
                Err(rustix::io::Errno::INTR) => {}
                // Asked only once the terminal is genuinely full, which is
                // what makes a hangup observable *inside* a `write_all` — the
                // one place `PtyInput` never reads its own `closed`. A child
                // that has stopped reading is exactly the case that gets here.
                Err(rustix::io::Errno::AGAIN) => {
                    if !self.0.ready(PollFlags::OUT) {
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(
    unsafe_code,
    reason = "portable-pty exposes the master only as a RawFd"
)]
fn dup_cloexec(raw: RawFd) -> Result<OwnedFd, ServerError> {
    // SAFETY: `raw` names the master of a `MasterPty` the caller owns for the
    // whole call, and the descriptor is only borrowed for the duplication.
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    // Plain `dup` clears close-on-exec, and a master inherited by the next
    // session's shell is a terminal that never reaches EOF.
    rustix::io::fcntl_dupfd_cloexec(borrowed, 0)
        .map_err(|error| ServerError::Setup(format!("session terminal: {error}")))
}

/// A destructor, so an exit path nobody has written yet cannot skip the reap.
pub(crate) struct Shell {
    pub(crate) child: Box<dyn Child + Send>,
    /// Dropping it is half of what makes the kernel hang the session up.
    pub(crate) master: Option<Box<dyn MasterPty + Send>>,
    /// Its pid may be reused once set, so nothing may be signalled through it.
    pub(crate) status: Option<i32>,
    /// Dropped after everything above it, retiring PTY threads parked on a
    /// terminal a descendant outside the child's process group still holds.
    pub(crate) _hangup: OwnedFd,
}

impl Shell {
    pub(crate) fn resize(&self, size: GridSize) -> bool {
        self.master.as_ref().is_some_and(|master| {
            master
                .resize(PtySize {
                    rows: size.rows,
                    cols: size.cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .is_ok()
        })
    }

    /// The *group*, not the pid: a backgrounded `sleep` holding the terminal
    /// open outlives the shell. portable-pty puts the child in a session of
    /// its own, so its pid is its process group.
    pub(crate) fn signal(&self, signal: Signal) {
        if self.status.is_some() {
            return;
        }
        let Some(pid) = self
            .child
            .process_id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw)
        else {
            return;
        };
        let _ = rustix::process::kill_process_group(pid, signal);
    }

    pub(crate) fn record(&mut self, code: i32) -> i32 {
        self.status = Some(code);
        code
    }

    /// `read` on the master returns EOF only when the *last* slave descriptor
    /// closes, and with no `SIGCHLD` handler `PtyEnded` never arrives for a
    /// shell that exited behind a grandchild.
    pub(crate) fn try_wait(&mut self) -> Option<i32> {
        if let Some(code) = self.status {
            return Some(code);
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let code = i32::try_from(status.exit_code()).unwrap_or(1);
                Some(self.record(code))
            }
            Ok(None) => None,
            Err(_) => Some(self.record(1)),
        }
    }

    /// EOF on the master does not say the child exited, and a blocking wait
    /// here stops the actor for good.
    fn reap_within(&mut self, grace: Duration) -> Option<i32> {
        let deadline = Instant::now() + grace;
        loop {
            if let Some(code) = self.try_wait() {
                return Some(code);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(REAP_POLL);
        }
    }

    /// A shell that traps `SIGHUP` survives forever otherwise, with no ticket
    /// file or registry entry left to find it by.
    pub(crate) fn shut_down(&mut self) -> i32 {
        if let Some(code) = self.status {
            return code;
        }
        self.signal(Signal::HUP);
        if let Some(code) = self.reap_within(TERMINATE_GRACE) {
            return code;
        }
        self.signal(Signal::KILL);
        // Bounded by the kernel: `SIGKILL` cannot be trapped or slept through.
        self.reap()
    }

    fn reap(&mut self) -> i32 {
        if let Some(code) = self.status {
            return code;
        }
        let code = self
            .child
            .wait()
            .map_or(1, |status| i32::try_from(status.exit_code()).unwrap_or(1));
        self.record(code)
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        let _ = self.shut_down();
        // After the child is gone, so the kernel's hangup is not racing the
        // signal that caused it.
        self.master = None;
    }
}

pub(crate) struct SessionSetup {
    pub(crate) ticket: sessions::SessionTicket,
    pub(crate) shell: Shell,
    pub(crate) writer: Box<dyn Write + Send>,
    pub(crate) daemon: Arc<DaemonState>,
    pub(crate) effects: Arc<SessionEffects>,
    pub(crate) size: GridSize,
    pub(crate) info: Arc<SessionInfo>,
    pub(crate) spent: mpsc::SyncSender<Vec<u8>>,
    pub(crate) tx: MailboxSender,
    pub(crate) killed: KillNotice,
}

pub(crate) fn start_session(setup: SessionSetup) -> Result<SessionActor, ServerError> {
    let vt = VtEngine::new(
        setup.size,
        ScrollbackLimit(SCROLLBACK_BYTES),
        ContinuationLimit(CONTINUATION_BYTES),
        Rc::new(SharedSink(Arc::clone(&setup.effects))),
    )?;
    Ok(SessionActor {
        ticket: setup.ticket,
        daemon: setup.daemon,
        terminal: Some(Terminal {
            shell: setup.shell,
            pty_in: PtyInput::new(setup.writer)?,
            vt,
            effects: setup.effects,
            backlog: BacklogRing::new(BACKLOG_BYTES),
            deferred: DeferredOsc::new(),
            queries: QueryFilter::new(),
            forwarded: Vec::new(),
            last_output: None,
            spent: setup.spent,
        }),
        size: setup.size,
        info: setup.info,
        attachments: Vec::new(),
        retired: Vec::new(),
        offset: ByteOff::zero(),
        generation: Generation::initial(),
        killed: setup.killed,
        tx: setup.tx,
        forwards: Forwards::default(),
        // Read only by the forward-only reap in `tick`, which a session with a
        // shell can never reach.
        detached_since: None,
    })
}

/// `-l` rather than `-i`: `-i` sources `~/.bashrc` and never `~/.profile`.
fn session_command(argv: &[String]) -> (CommandBuilder, String) {
    if let Some((program, rest)) = argv.split_first() {
        let mut command = CommandBuilder::new(program);
        for word in rest {
            command.arg(word);
        }
        return (command, printable(&argv.join(" "), MAX_COMMAND));
    }
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let mut command = CommandBuilder::new(&shell);
    command.arg("-l");
    (command, printable(&format!("{shell} -l"), MAX_COMMAND))
}

pub(crate) fn spawn_session(
    size: GridSize,
    term: &str,
    env: &SessionEnv,
    argv: &[String],
    ticket: sessions::SessionTicket,
    daemon: &Arc<DaemonState>,
) -> Result<SessionHandle, ServerError> {
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| ServerError::Setup(error.to_string()))?;
    let (mut command, command_line) = session_command(argv);
    command.env(
        "TERM",
        if term.is_empty() {
            "xterm-256color"
        } else {
            term
        },
    );
    command.env("BRD_SESSION", session_name(ticket.session_id));
    // Filtered again here rather than trusted: a rule enforced only by the peer
    // that can be replaced is not a rule.
    for (name, value) in &env.0 {
        if FORWARDED_ENV.contains(&name.as_str()) {
            command.env(name, value);
        }
    }
    // The daemon chdirs to `/`, so without this every shell would start there.
    if let Some(home) = command.get_env("HOME").map(std::ffi::OsStr::to_owned) {
        command.cwd(home);
    }
    // The daemon's umask is `0o077`; a shell inheriting it would make every
    // file the user writes `0600`.
    command.umask(Some(*CHILD_UMASK.get().unwrap_or(&DEFAULT_UMASK)));
    let child = pty
        .slave
        .spawn_command(command)
        .map_err(|error| ServerError::Setup(error.to_string()))?;
    drop(pty.slave);
    // Descriptors this daemon owns rather than portable-pty's sealed clones: a
    // thread parked on a terminal a runaway grandchild holds open has no other
    // way back.
    let raw = pty
        .master
        .as_raw_fd()
        .ok_or_else(|| ServerError::Setup("the terminal has no descriptor".into()))?;
    let hangup = Hangup::new()?;
    let reader = PtyReader(hangup.watching(raw)?);
    let writer = PtyWriter(hangup.watching(raw)?);
    let shell_process = Shell {
        child,
        master: Some(pty.master),
        status: None,
        _hangup: hangup.close,
    };
    let effects = Arc::new(SessionEffects::default());
    let session_id = ticket.session_id;
    let (tx, rx) = mailbox();
    // Read buffers travel to the actor and come back, so a busy PTY costs no
    // allocation per read.
    let (spent_tx, spent_rx) = mpsc::sync_channel::<Vec<u8>>(128);
    let reader_tx = tx.clone();
    thread::Builder::new()
        .stack_size(IO_STACK)
        .name("brd-pty-reader".into())
        .spawn(move || read_actor_pty(reader, &reader_tx, &spent_rx))
        .map_err(|_| ServerError::Worker)?;
    let info = Arc::new(SessionInfo::new(command_line, size));
    let killed = KillNotice::default();
    let setup = SessionSetup {
        ticket,
        shell: shell_process,
        writer: Box::new(writer),
        daemon: Arc::clone(daemon),
        effects,
        size,
        info: Arc::clone(&info),
        spent: spent_tx,
        killed: killed.clone(),
        tx: tx.clone(),
    };
    spawn_actor(
        daemon,
        SessionKind::Terminal,
        session_id,
        &info,
        tx,
        rx,
        killed,
        move || start_session(setup),
    )
}

pub(crate) fn spawn_forward_session(
    ticket: sessions::SessionTicket,
    daemon: &Arc<DaemonState>,
) -> Result<SessionHandle, ServerError> {
    let session_id = ticket.session_id;
    let (tx, rx) = mailbox();
    let info = forward_info();
    let killed = KillNotice::default();
    let actor_tx = tx.clone();
    let actor_daemon = Arc::clone(daemon);
    let actor_info = Arc::clone(&info);
    let actor_killed = killed.clone();
    spawn_actor(
        daemon,
        SessionKind::Forward,
        session_id,
        &info,
        tx,
        rx,
        killed,
        // Built on the session's own thread: a `SessionActor` holds an `Rc`
        // and is not `Send`.
        move || {
            Ok(forward_actor(
                ticket,
                actor_daemon,
                actor_info,
                actor_killed,
                actor_tx,
            ))
        },
    )
}

pub(crate) fn forward_info() -> Arc<SessionInfo> {
    Arc::new(SessionInfo::new(
        printable(FORWARD_COMMAND, MAX_COMMAND),
        FORWARD_GRID,
    ))
}

pub(crate) fn forward_actor(
    ticket: sessions::SessionTicket,
    daemon: Arc<DaemonState>,
    info: Arc<SessionInfo>,
    killed: KillNotice,
    tx: MailboxSender,
) -> SessionActor {
    SessionActor {
        ticket,
        daemon,
        terminal: None,
        size: FORWARD_GRID,
        info,
        attachments: Vec::new(),
        retired: Vec::new(),
        offset: ByteOff::zero(),
        generation: Generation::initial(),
        killed,
        tx,
        forwards: Forwards::default(),
        // The client that asked for this session may never arrive on it, so the
        // grace clock starts here rather than at the first detach.
        detached_since: Some(Instant::now()),
    }
}

#[expect(clippy::too_many_arguments, reason = "one session's whole identity")]
fn spawn_actor(
    daemon: &Arc<DaemonState>,
    kind: SessionKind,
    session_id: SessionId,
    info: &Arc<SessionInfo>,
    tx: MailboxSender,
    rx: MailboxReceiver,
    killed: KillNotice,
    build: impl FnOnce() -> Result<SessionActor, ServerError> + Send + 'static,
) -> Result<SessionHandle, ServerError> {
    let handle = SessionHandle {
        tx,
        info: Arc::clone(info),
        kind,
    };
    // Installed before the thread that owns it starts, and in the same critical
    // section that gives up this session's reservation, so the two never both
    // count it.
    registry(daemon).install(session_id, handle.clone());
    let cleanup_daemon = Arc::clone(daemon);
    if thread::Builder::new()
        .stack_size(ACTOR_STACK)
        .name("brd-session".into())
        .spawn(move || {
            crate::log::attribute(session_id);
            // The guard is what drops the capability file and registry entry on
            // every way out of this thread.
            let _cleanup = SessionCleanup {
                session_id,
                daemon: cleanup_daemon,
                killed,
            };
            match build() {
                Ok(mut actor) => guarded(&mut actor, |actor| actor.run(&rx)),
                Err(error) => log!("session did not start: {error}"),
            }
        })
        .is_err()
    {
        registry(daemon).remove(session_id);
        return Err(ServerError::Worker);
    }
    Ok(handle)
}

/// `PtyReader` rather than a `dyn Read`: the coalescing invariant is
/// [`PtyReader::drain`]'s, and a reader that only answers `read` would put one
/// line-discipline buffer in every frame.
fn read_actor_pty(mut reader: PtyReader, tx: &MailboxSender, spent: &mpsc::Receiver<Vec<u8>>) {
    loop {
        let mut chunk = Chunk::take(spent, PTY_CHUNK);
        match reader.drain(chunk.room()) {
            Ok(len) if len > 0 => {
                if tx.send(ActorEvent::PtyOutput(chunk.filled(len))).is_err() {
                    return;
                }
            }
            // End of stream, and `drain` retries `EINTR` itself, so anything
            // left is the terminal going away under it.
            Ok(_) | Err(_) => break,
        }
    }
    let _ = tx.send(ActorEvent::PtyEnded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::NoEvent;
    use crate::registry::*;
    use crate::testing::*;
    use crate::*;
    use braid_proto::{ServerMessage, SessionEnv};
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use rustix::process::Pid;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn a_session_is_registered_before_its_thread_starts_and_gone_after_it_ends() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        let handle = daemon_session(&daemon, ticket, &[]);
        assert!(registry(&daemon).sessions.contains_key(&session_id));

        handle.tx.send(kill()).expect("end the test session");
        assert!(settles(Duration::from_secs(5), || {
            registry(&daemon).sessions.is_empty()
        }));
    }

    /// A terminal hands over at most its line discipline's buffer per `read` -
    /// 4 KiB on Linux - however large a buffer it is offered, so one read per
    /// frame put 4 KiB in a chunk sized for 64. A pipe rather than a terminal:
    /// what is being claimed is that `drain` reads until the descriptor is
    /// empty, and a pipe says so without depending on a tty's buffer size.
    #[test]
    fn a_drain_takes_everything_ready_rather_than_one_read_of_it() {
        const WRITES: usize = 4;
        const EACH: usize = 4096;

        let (read, write) = rustix::pipe::pipe().expect("a pipe");
        let hangup = Hangup::new().expect("a wakeup");
        let mut reader =
            PtyReader(PtyEnd::new(read, Arc::clone(&hangup.watch)).expect("a reader end"));

        for _ in 0..WRITES {
            rustix::io::write(&write, &[b'x'; EACH]).expect("the pipe takes a block");
        }

        let mut buf = vec![0; PTY_CHUNK];
        assert_eq!(
            reader.drain(&mut buf).expect("the pipe has bytes"),
            WRITES * EACH,
            "a drain that stopped at the first read would answer {EACH}"
        );
    }

    /// The wait is the whole reason `drain` may not spin: an empty descriptor
    /// with nothing coming must park until the hangup, not return `Ok(0)` as
    /// though the shell had ended.
    #[test]
    fn a_drain_with_nothing_ready_ends_only_on_the_hangup() {
        let (read, _write) = rustix::pipe::pipe().expect("a pipe");
        let hangup = Hangup::new().expect("a wakeup");
        let mut reader =
            PtyReader(PtyEnd::new(read, Arc::clone(&hangup.watch)).expect("a reader end"));

        let draining = thread::spawn(move || {
            let mut buf = vec![0; PTY_CHUNK];
            reader.drain(&mut buf)
        });
        thread::sleep(Duration::from_millis(100));
        assert!(
            !draining.is_finished(),
            "the drain span an empty descriptor instead of parking"
        );

        drop(hangup.close);
        assert_eq!(
            draining.join().expect("the drain thread").ok(),
            Some(0),
            "the hangup is this terminal's end of stream"
        );
    }

    /// Ending a shell that traps `SIGHUP` takes the process group and the
    /// escalation; an unreaped child is a permanent zombie.
    #[test]
    fn shutting_a_shell_down_kills_its_group_and_reaps_it() {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg("trap '' HUP; echo BRD_TRAPPED; while :; do sleep 1; done");
        let mut reader = pty.master.try_clone_reader().expect("reader");
        let child = pty.slave.spawn_command(command).expect("spawn shell");
        drop(pty.slave);
        let pid = Pid::from_raw(
            i32::try_from(child.process_id().expect("the child has a pid")).expect("pid fits"),
        )
        .expect("pid is valid");
        // Signalling before the trap is installed meets the default
        // disposition, which proves nothing.
        let mut seen = Vec::new();
        let mut buf = [0_u8; 256];
        while !seen
            .windows(b"BRD_TRAPPED".len())
            .any(|window| window == b"BRD_TRAPPED")
        {
            let count = reader
                .read(&mut buf)
                .expect("the shell writes to its terminal");
            assert!(count > 0, "the shell ended before it trapped anything");
            seen.extend_from_slice(&buf[..count]);
        }
        let mut shell = Shell {
            child,
            master: Some(pty.master),
            status: None,
            _hangup: Hangup::new().expect("a wakeup").close,
        };
        assert!(rustix::process::test_kill_process(pid).is_ok());

        let began = Instant::now();
        shell.shut_down();
        assert!(
            began.elapsed() >= TERMINATE_GRACE,
            "a shell that ignores SIGHUP only goes to the escalation behind it"
        );
        // A zombie still answers a signal probe, so this failing is what says
        // the child was waited for rather than merely signalled.
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "the shell was signalled but never reaped"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && rustix::process::test_kill_process_group(pid).is_ok() {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            rustix::process::test_kill_process_group(pid).is_err(),
            "the whole process group goes, not just the pid"
        );
    }

    /// The test holds the slave open in place of a `setsid` grandchild: the
    /// terminal never reaches EOF and no signal `Shell` sends reaches it.
    #[test]
    fn a_terminal_nothing_will_close_still_retires_the_threads_parked_on_it() {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg("exit 0");
        let child = pty.slave.spawn_command(command).expect("spawn shell");
        let raw = pty.master.as_raw_fd().expect("a master descriptor");
        // Echo would park the reader on a full mailbox, which has its own
        // wakeup, instead of on the terminal.
        let quiet = dup_cloexec(raw).expect("a descriptor for the line discipline");
        let mut settings = rustix::termios::tcgetattr(&quiet).expect("terminal settings");
        settings.local_modes -= rustix::termios::LocalModes::ECHO;
        rustix::termios::tcsetattr(&quiet, rustix::termios::OptionalActions::Now, &settings)
            .expect("quiet the line discipline");
        // Read back, so a platform that takes the request and applies nothing
        // fails here rather than five seconds later as a terminal that never
        // woke: with echo on, the flood below returns as output.
        assert!(
            !rustix::termios::tcgetattr(&quiet)
                .expect("terminal settings")
                .local_modes
                .contains(rustix::termios::LocalModes::ECHO),
            "the line discipline is still echoing"
        );
        drop(quiet);
        let hangup = Hangup::new().expect("a wakeup");
        let reader = PtyReader(hangup.watching(raw).expect("a reader end"));
        let mut writer = PtyWriter(hangup.watching(raw).expect("a writer end"));
        let shell = Shell {
            child,
            master: Some(pty.master),
            status: None,
            _hangup: hangup.close,
        };

        let (tx, rx) = mailbox();
        let (_spent_tx, spent_rx) = mpsc::sync_channel::<Vec<u8>>(1);
        let reading = thread::spawn(move || read_actor_pty(reader, &tx, &spent_rx));
        // The reader parks in `read` only while the mailbox has room: a full
        // one parks it on a condvar no hangup reaches, and its closing
        // `PtyEnded` is a blocking send. Draining leaves the terminal as the
        // only thing it can be waiting on, which is what this test claims.
        let draining = thread::spawn(move || {
            while !matches!(
                rx.recv_timeout(Duration::from_millis(50)),
                Err(NoEvent::Disconnected)
            ) {}
        });
        // Far past what a terminal's input buffer holds, so the writer parks
        // inside one `write_all` rather than between two.
        let writing = thread::spawn(move || {
            let block = vec![b'x'; ptyin::BACKLOG];
            while writer.write_all(&block).is_ok() {}
        });

        let parked = Instant::now() + Duration::from_millis(200);
        while Instant::now() < parked {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !reading.is_finished(),
            "the reader never parked, so this proves nothing"
        );
        assert!(
            !writing.is_finished(),
            "the writer never parked, so this proves nothing"
        );

        drop(shell);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !(reading.is_finished() && writing.is_finished()) {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            reading.is_finished(),
            "the reader parked in `read` was never woken"
        );
        assert!(
            writing.is_finished(),
            "the writer parked mid-`write_all` was never woken"
        );
        draining.join().expect("the mailbox drain");
        drop(pty.slave);
    }

    /// A shell that backgrounds something and exits leaves the grandchild
    /// holding the terminal open, so only the clocked `try_wait` ends this.
    #[test]
    fn a_shell_that_exits_behind_a_grandchild_still_ends_its_session() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        let handle = daemon_session(
            &daemon,
            ticket,
            // The second sleep is the test's own: the shell must still be
            // running when the attachment that puts its actor on the probe
            // clock arrives, or there is no clock for the reap to fall due on.
            &[
                "/bin/sh".into(),
                "-c".into(),
                "sleep 30 & sleep 1; exit 0".into(),
            ],
        );
        let output = attached_output(&handle, AttachKind::New);

        assert!(
            settles(Duration::from_secs(10), || {
                !registry(&daemon).sessions.contains_key(&session_id)
            }),
            "a session whose shell has been reaped is over"
        );
        // The registry entry goes with the actor thread while the farewell is
        // still queued, so the two have no ordering between them.
        await_frame(
            &output,
            |message| matches!(message, ServerMessage::Exit { .. }).then_some(()),
            "every client is told the shell is gone",
        );
    }

    /// A rule enforced only by the peer that can be replaced is not a rule.
    /// `DISPLAY` arrives with the file its cookie lives in or an X client on
    /// the far end is refused by the display it was just handed.
    #[test]
    fn a_variable_outside_the_whitelist_never_reaches_the_shell() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let handle = spawn_session(
            GRID,
            "xterm-256color",
            &SessionEnv(vec![
                ("SSH_TTY".into(), "/brd-allowed".into()),
                ("DISPLAY".into(), ":0".into()),
                ("XAUTHORITY".into(), "/brd-cookie".into()),
                ("LD_PRELOAD".into(), "/brd-denied".into()),
            ]),
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf '<%s><%s><%s><%s>' \"$SSH_TTY\" \"$DISPLAY\" \"$XAUTHORITY\" \"$LD_PRELOAD\"; exec sleep 30".into(),
            ],
            ticket,
            &daemon,
        )
        .expect("spawn PTY");
        // A resume rather than a fresh attach: the shell prints once, at
        // startup, and a new attachment is owed nothing from before it.
        let output = attached_output(&handle, joining());
        assert!(
            output.contains(
                b"</brd-allowed><:0></brd-cookie><>",
                Duration::from_secs(10)
            ),
            "the whitelisted variables arrive and nothing else does"
        );
    }
}
