// `deny` rather than `forbid`: neither `getpeereid` nor portable-pty's
// `RawFd` has a safe binding, and `forbid` here could not be lifted for them.
#![deny(unsafe_code)]
mod actor;
mod attachment;
pub mod backlog;
// `braid-fuzz` drives the deferred-OSC scanner directly.
#[cfg(feature = "fuzzing")]
pub mod defer;
#[cfg(not(feature = "fuzzing"))]
mod defer;
pub(crate) mod dgram;
mod forward;
pub mod gate;
mod link;
pub mod log;
mod mailbox;
mod peer;
mod proxy;
pub mod ptyin;
// `braid-fuzz` drives the query filter directly, for the same reason it drives
// the deferred-OSC scanner: a filter fuzzed through the daemon is one whose
// inputs the daemon decides.
#[cfg(feature = "fuzzing")]
pub mod query;
#[cfg(not(feature = "fuzzing"))]
mod query;
mod registry;
pub mod screen;
pub mod sessions;
mod shell;
pub mod sink;
mod state;
#[cfg(test)]
mod testing;
use crate::attachment::Framing;
use crate::log::{log, log_throttled};
use crate::mailbox::{ActorEvent, TrySendError};
pub use crate::proxy::run_server;
use crate::proxy::{daemon_socket_path, newest_first};
use crate::ptyin::PtyInput;
use crate::registry::{
    ConnectionSlot, DaemonState, HandshakeDeadline, SessionHandle, SessionKind, SessionSlot,
    registry,
};
use crate::shell::{spawn_forward_session, spawn_session};
use crate::sink::{AttachmentSink, SinkError};
use crate::state::{load_ticket, persist_ticket, private_dir, state_dir, ticket_path};
use braid_proto::{
    ByteOff, ClientMessage, ConfirmedOutput, DatagramOffer, MAX_CLIENT_FRAME, MAX_FORWARD_CHUNK,
    MAX_MATCHES, MAX_OUTPUT_CHUNK, MAX_SESSIONS, RejectReason, SearchMatch, ServerMessage,
    SessionId, SessionSummary, Version, VersionRange, read_frame, read_frame_into, write_message,
};
use braid_vt::EffectSink;
use rustix::fs::RawMode;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

static NEXT_ATTACHMENT: AtomicU64 = AtomicU64::new(1);

/// The umask a session's shell runs under: what the daemon replaced when it
/// narrowed its own to `0o077`, which no child may inherit.
static CHILD_UMASK: OnceLock<RawMode> = OnceLock::new();

/// What a child runs under when no daemon has recorded anything.
const DEFAULT_UMASK: RawMode = 0o022;

/// Bytes one PTY read takes off the master: exactly one `Output` frame's
/// payload, so a read never spills 24 bytes into a second frame.
const PTY_CHUNK: usize = MAX_OUTPUT_CHUNK - OUTPUT_OVERHEAD;
const SCROLLBACK_BYTES: usize = 8 * 1024 * 1024;
/// Bytes of raw output kept for replay to a client that reconnects. Bounds
/// how far back a resume may be served from, not how far a user can scroll.
const BACKLOG_BYTES: usize = 8 * 1024 * 1024;
const CONTINUATION_BYTES: usize = 64 * 1024;
const REPLY_BYTES: usize = 64 * 1024;
const RELAY_CHUNK: usize = 32 * 1024;

/// The wire's own width, not a number this crate picked: the daemon reframes
/// datagram pieces around it.
const FRAME_LENGTH_PREFIX: usize = braid_proto::LENGTH_PREFIX;

/// Bytes an `Output` message costs beside its payload: the tag, offset, cue,
/// echo acknowledgement and byte count `encode_output` reserves 24 bytes for.
const OUTPUT_MESSAGE: usize = 24;

const OUTPUT_OVERHEAD: usize = FRAME_LENGTH_PREFIX + OUTPUT_MESSAGE;

/// Bounds on the synchronized-repaint rate. The interval itself tracks half
/// the measured round trip, which is mosh's number and for mosh's reason.
const REPAINT_FLOOR: Duration = Duration::from_millis(16);
const REPAINT_CEILING: Duration = Duration::from_millis(250);

/// Bounds on how often an attachment is probed. Probing is also where the
/// round-trip estimate comes from, and it is shipped in every `Ping`.
const PING_FLOOR: Duration = Duration::from_millis(250);
const PING_CEILING: Duration = Duration::from_secs(2);

/// Unanswered probing that means the attachment is gone. Five intervals, so a
/// link that is merely slow is not mistaken for one that is over.
const PING_DEAD_INTERVALS: u32 = 5;
const PING_DEAD_FLOOR: Duration = Duration::from_secs(5);

/// Smoothing for the round-trip estimate: one eighth, as in TCP.
const RTT_SHIFT: u32 = 3;

/// How long a session with nothing to do sleeps between wakeups. Every event
/// that matters wakes the actor immediately, so this bounds nothing.
const IDLE_DEADLINE: Duration = Duration::from_secs(30);

/// How long a forward-only session survives with nothing to carry and nobody
/// watching. Sized against `brd`'s reconnect backoff, which tops out at
/// thirty seconds. A terminal session is never reaped for this.
const FORWARD_SESSION_GRACE: Duration = Duration::from_mins(5);

/// The idle wakeup is the only thing that notices the reap, so it has to fall
/// inside the grace.
const _: () = assert!(IDLE_DEADLINE.as_secs() < FORWARD_SESSION_GRACE.as_secs());

/// How long a command must sit in front of the application before its silence
/// means anything. mosh's `ECHO_TIMEOUT`, for mosh's reason.
const ECHO_TIMEOUT: Duration = Duration::from_millis(50);

/// Commands whose echo may be outstanding at once, one per `Input` message.
const ECHO_HISTORY: usize = 64;

/// How long a shell has to answer `SIGHUP` before it is killed.
const TERMINATE_GRACE: Duration = Duration::from_millis(100);

/// How often a shell being reaped is polled while it goes.
const REAP_POLL: Duration = Duration::from_millis(5);

/// How long a `brd kill` may spend, from queueing the event to the session
/// being gone. One budget for both halves: the send can be what blocks.
const KILL_DEADLINE: Duration = Duration::from_secs(2);

/// How long one `brd search` may spend asking every session this daemon runs.
/// A whole-pass budget: each session is asked for an equal share of what is
/// left, and one whose share has run out is not asked at all.
const SEARCH_BUDGET: Duration = Duration::from_secs(1);

/// Sessions one daemon runs at once; each costs a PTY, a shell, four threads.
const SESSION_LIMIT: usize = 64;

/// Connections one daemon will serve at once, a thread and a descriptor
/// apiece. Well past what `SESSION_LIMIT` sessions of clients hold open.
const CONNECTION_LIMIT: usize = 512;

/// Descriptors one connection costs: the accepted socket, shared by the reader
/// and the sink writer through [`Half`]. One, because a dup names the same open
/// file description - which is why the handshake timeout armed on either side
/// is the one the reader sees.
const CONNECTION_DESCRIPTORS: u64 = 1;

/// How long a refusal a stranger can drive stays quiet after speaking once.
/// Milliseconds, which is what [`log::Throttle`] counts in.
const REFUSAL_WINDOW_MS: u64 = 60_000;

/// Bytes of one connection's inbound frames read at a time. `read_frame_into`
/// takes a 4-byte length and then a body, so unbuffered it is two `read(2)`
/// per keystroke on bytes that arrived in one segment. `BufReader` passes a
/// request at or past its capacity straight through, so a forward's bulk body
/// still lands in the caller's buffer with no extra copy.
const READ_BUFFER: usize = 8 * 1024;

/// How long one daemon has to answer a frozen management question: `brd ls`
/// asks every daemon on the host, so a wedged one costs only its own place.
const MANAGE_DEADLINE: Duration = Duration::from_secs(2);

/// What a screen header costs beside its title and deferred sequences.
/// Generous: a tight bound costs one clipboard, a loose one every screen.
const HEADER_SLOP: usize = 128;

/// How long a connection has to send its first frame. Only the first: an
/// attachment that has said `Hello` may legitimately be silent for hours.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// How long an attach may wait for room in a session's control lane. An
/// `Attach` has no reserved slot there and the socket read timeout is already
/// lifted, so without this the wait is unbounded.
const ATTACH_DEADLINE: Duration = Duration::from_secs(2);

/// Bytes of `sockaddr_un::sun_path`, one of which is the terminating NUL.
/// `bind` answers `ENAMETOOLONG` rather than truncating.
const SUN_PATH_MAX: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// Sessions one daemon will hold state for at once, measured in bytes:
/// [`SESSION_LIMIT`] bounds sessions and not memory, and sixty-four of
/// today's shape is a gigabyte before a single client has attached.
const MEMORY_BUDGET: usize = 512 * 1024 * 1024;

/// What one session is charged against [`MEMORY_BUDGET`]: the ceiling rather
/// than the resident size, because a busy session reaches it.
const SESSION_BYTES: usize =
    SCROLLBACK_BYTES + BACKLOG_BYTES + ptyin::BACKLOG + CONTINUATION_BYTES + REPLY_BYTES;

/// What one forward-only session is charged: no scrollback, replay backlog or
/// PTY queue, but `OUTPUT_LANE` mailbox slots a reader thread may each fill
/// with a whole chunk. Its window and socket buffers are [`FORWARD_BYTES`],
/// which this must not count a second time.
const FORWARD_SESSION_BYTES: usize = mailbox::OUTPUT_LANE * MAX_FORWARD_CHUNK;

/// The cheaper of the two, or the split is a second name for one charge.
const _: () = assert!(FORWARD_SESSION_BYTES < SESSION_BYTES);

/// What the ledger's two row snapshots are charged: a large ordinary terminal
/// rather than the largest grid a client may name and never paint.
const LEDGER_BYTES: usize = 2 * 200 * 50 * 4;

/// What one attachment is charged against [`MEMORY_BUDGET`]. Attachments are
/// the axis a *client* controls, which the per-session charge cannot see.
const ATTACHMENT_BYTES: usize = sink::CEILING + LEDGER_BYTES;

/// Forwarded connections one daemon will carry at once. Nothing else here
/// bounds descriptors: [`CONNECTION_LIMIT`] counts the sockets `accept`
/// produced, not the ones a session dialled out on.
const FORWARD_LIMIT: usize = 64;

/// What one forward is charged: both directions of the reliability layer's
/// window plus the socket writer's backlog.
const FORWARD_BYTES: usize = 2 * braid_forward::FORWARD_WINDOW + forward::BACKLOG;

/// Stack for a thread that does nothing but move bytes. Not smaller: the sink
/// thread builds a compressor, and 256 KiB here aborted the process - not the
/// thread - on the first 400-column screen that reached the datagram path.
const IO_STACK: usize = 1024 * 1024;

/// A thread that packs a datagram must be able to build the compressor.
const _: () = assert!(IO_STACK > braid_proto::wire::CODEC_STACK + 64 * 1024);

/// Stack for a session's actor: the one thread with real frames on it - a
/// repaint, a screen encode, a scrollback search across the Ghostty FFI.
const ACTOR_STACK: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("protocol: {0}")]
    Protocol(#[from] braid_proto::DecodeError),
    #[error("protocol encoding: {0}")]
    Encode(#[from] braid_proto::EncodeError),
    #[error("PTY: {0}")]
    Pty(#[from] io::Error),
    #[error("terminal: {0}")]
    Terminal(#[from] braid_vt::VtError),
    #[error("PTY setup failed: {0}")]
    Setup(String),
    #[error("worker thread failed")]
    Worker,
}

#[derive(Default)]
struct SessionEffects {
    replies: Mutex<Vec<u8>>,
    /// How many replies the emulator has produced. Counted rather than
    /// measured from `replies`, which is capped and drained: the query filter
    /// reads this to learn who a reply belonged to, and a count that stalled
    /// when the cap was reached would have it forward answered queries at
    /// exactly the moment an application is flooding the terminal with them.
    answers: AtomicU64,
}
impl SessionEffects {
    /// Hand the emulator's own replies to the PTY as input, through the same
    /// queue as the client's typing so a capability probe cannot wedge the
    /// actor. `false` means the queue refused them.
    fn flush_into(&self, pty_in: &PtyInput) -> Result<bool, ServerError> {
        let replies = self
            .replies
            .lock()
            .map(|mut replies| std::mem::take(&mut *replies))
            .map_err(|_| ServerError::Setup("effect buffer poisoned".into()))?;
        Ok(replies.is_empty() || pty_in.write(&replies))
    }

    /// Replies so far. Only ever compared against an earlier reading, on the
    /// one thread that feeds the emulator.
    fn answers(&self) -> u64 {
        self.answers.load(Ordering::Relaxed)
    }
}
impl EffectSink for SessionEffects {
    fn pty_write(&self, bytes: &[u8]) {
        self.answers.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut replies) = self.replies.lock()
            && replies.len().saturating_add(bytes.len()) <= REPLY_BYTES
        {
            replies.extend_from_slice(bytes);
        }
    }
}

/// Descriptors this daemon's own bounds can ask for at once. A session costs
/// its terminal and the two ends of the pipe that hangs its threads up; a
/// forward costs the socket it dialled. The slack covers the log, the lock,
/// the listener, the datagram socket and the capability files in flight.
const DESCRIPTOR_BUDGET: u64 = CONNECTION_LIMIT as u64 * CONNECTION_DESCRIPTORS
    + SESSION_LIMIT as u64 * 3
    + FORWARD_LIMIT as u64
    + 64;

/// Take the soft descriptor limit up to the hard one.
///
/// Without this the daemon's stated bounds are fiction: the soft limit is 1024
/// on most Linux and 256 under launchd, so `accept` answers `EMFILE` long
/// before [`CONNECTION_LIMIT`] refuses anything - and that `EMFILE` is sticky,
/// leaving the accept loop sleeping against a listen queue that only fills.
fn widen_descriptor_limit() {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    // `None` is `RLIM_INFINITY`: nothing to raise, and nothing to warn about.
    let Some(maximum) = limit.maximum else {
        return;
    };
    if limit.current.is_some_and(|current| current < maximum)
        && let Err(error) = rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
    {
        log!(
            "could not widen the descriptor limit past {:?}: {error}",
            limit.current
        );
        return;
    }
    if maximum < DESCRIPTOR_BUDGET {
        log!(
            "descriptors are capped at {maximum}, under the {DESCRIPTOR_BUDGET} this daemon's \
             own bounds can ask for: connections will be refused by the kernel rather than by \
             {CONNECTION_LIMIT}"
        );
    }
}

/// Own PTYs in the daemon and accept replaceable attachments over a private socket.
pub fn run_daemon() -> Result<(), ServerError> {
    // Every file this daemon creates is private at creation rather than at a
    // chmod one syscall later; the shell must not inherit that.
    let inherited = rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
    let _ = CHILD_UMASK.set(inherited.bits());
    let directory = state_dir();
    private_dir(directory)?;
    log::open(&directory.join("brd.log"));
    log::install_panic_hook();
    widen_descriptor_limit();
    // The daemon outlives the connection that started it, so its working
    // directory would pin a mount busy forever.
    env::set_current_dir("/")?;
    let Some(_lock) = DaemonLock::acquire()? else {
        log!("daemon: another process holds the lock");
        return Ok(());
    };
    let path = daemon_socket_path();
    let listener = match claim_socket(&path, directory)? {
        Claim::Listening(listener) => listener,
        // Live, and older than this lock file: it will answer the connection
        // this process was spawned for.
        Claim::Live => return Ok(()),
    };
    log!("daemon: listening on {}", path.display());
    // A failure to get a socket is not fatal: no offer is ever made and every
    // session runs over the transport that reached it.
    let daemon = Arc::new(DaemonState {
        sessions: Mutex::default(),
        connections: AtomicUsize::new(0),
        forwards: AtomicUsize::new(0),
        dgram: dgram::DatagramListener::bind(),
    });
    if let Some(datagrams) = daemon.dgram.clone() {
        datagrams.serve(&daemon);
    }
    // Edge-triggered: `EMFILE` in `accept` is sticky, and a line per failure
    // is ten a second onto the user's own disk for as long as it lasts.
    let mut failing: Option<io::ErrorKind> = None;
    for stream in listener.incoming() {
        // A transient accept failure must cost one connection rather than
        // every session on the machine, invisibly.
        let stream = match stream {
            Ok(stream) => {
                failing = None;
                stream
            }
            Err(error) => {
                if failing != Some(error.kind()) {
                    failing = Some(error.kind());
                    log!("accept failed: {error}");
                }
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if !peer::is_owner(&stream) {
            // A stranger can drive this as fast as it can `connect`, and one
            // line each is the operator's whole history inside a minute.
            static REFUSED_STRANGER: log::Throttle = log::Throttle::new(REFUSAL_WINDOW_MS);
            log_throttled!(REFUSED_STRANGER, "refused a connection from another user");
            continue;
        }
        let Some(slot) = ConnectionSlot::take(&daemon) else {
            // Closed rather than refused in the protocol: answering would
            // need one of the threads that are the scarce thing here.
            static SATURATED: log::Throttle = log::Throttle::new(REFUSAL_WINDOW_MS);
            log_throttled!(
                SATURATED,
                "refused a connection: {CONNECTION_LIMIT} are already being served"
            );
            continue;
        };
        let daemon = Arc::clone(&daemon);
        if thread::Builder::new()
            .stack_size(IO_STACK)
            .name("brd-attachment".into())
            .spawn(move || {
                let _slot = slot;
                let stream = Arc::new(stream);
                // The clock bounds the first frame, and this thread is where
                // one is read.
                let handshake = HandshakeDeadline::on(&stream, HANDSHAKE_DEADLINE);
                // Buffered before the handshake rather than after it: what a
                // refill pulls in past the first frame belongs to the reader
                // the attachment loop goes on to use.
                let input = io::BufReader::with_capacity(READ_BUFFER, Half(Arc::clone(&stream)));
                let output = Half(Arc::clone(&stream));
                if let Err(error) =
                    serve_attachment(Box::new(input), Box::new(output), &daemon, &handshake)
                {
                    log!("attachment ended: {error}");
                }
            })
            .is_err()
        {
            log!("could not start a thread for an attachment");
        }
    }
    Ok(())
}

/// What this process found on the daemon socket.
enum Claim {
    Listening(UnixListener),
    /// Something answered: a daemon of this protocol is already serving.
    Live,
}

/// Take the daemon socket, or find a daemon already answering on it.
///
/// The connect probe has to come before the sweep: holding the lock does not
/// prove nothing is live, because a daemon whose lock file was unlinked keeps
/// its `flock` on that inode. Sweeping a live daemon's `.cap` files leaves
/// every session on the machine permanently unresumable.
fn claim_socket(path: &std::path::Path, directory: &std::path::Path) -> Result<Claim, ServerError> {
    match UnixStream::connect(path) {
        Ok(_) => return Ok(Claim::Live),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        // Refused: nothing answered, which is what makes the inode stale.
        Err(_) => fs::remove_file(path)?,
    }
    // Nothing answers this socket, so every `.cap` beside it names a session
    // that is gone: only a session's own destructor unlinks one.
    sweep_tickets(directory);
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(Claim::Listening(listener))
}

/// Unlink the capability files in this directory, which here are all stale.
fn sweep_tickets(directory: &std::path::Path) {
    let prefix = "brd-";
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let named = path
            .file_stem()
            .is_some_and(|stem| stem.as_encoded_bytes().starts_with(prefix.as_bytes()));
        if named && path.extension().is_some_and(|extension| extension == "cap") {
            let _ = fs::remove_file(&path);
        }
    }
}

/// The exclusive right to serve the daemon socket, held for the process's
/// life: two `brd` invocations from a cold start both spawn a daemon, and a
/// loser that unlinked and rebound would be live but unreachable forever.
struct DaemonLock {
    /// The open descriptor is the lock; closing it releases it.
    _file: File,
}

impl DaemonLock {
    fn acquire() -> Result<Option<Self>, ServerError> {
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(state_dir().join("brd.lock"))?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
            Err(error) => Err(ServerError::Pty(error.into())),
        }
    }
}

/// Why buffered output could not be handed to a resuming client.
#[derive(Debug)]
enum ReplayError {
    /// The requested offset has already been overwritten in the ring.
    Evicted,
    /// The sink filled partway through: this is how far the replay actually got,
    /// so what the client is owed can be named exactly rather than estimated.
    Filled(ByteOff),
    Sink(SinkError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AttachmentId(u64);

#[derive(Clone, Copy)]
enum AttachKind {
    New,
    Resume(ConfirmedOutput),
}

/// One side of a connection, over the one descriptor both sides share.
///
/// `write_vectored` is forwarded rather than inherited: the default forwards
/// only the first non-empty slice, which would quietly turn every one of the
/// sink's batched `writev`s back into a syscall per frame.
struct Half(Arc<UnixStream>);

impl Read for Half {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for Half {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        (&*self.0).write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// Answer a connection in the protocol and end it, rather than closing the
/// socket and leaving the peer a dead transport it cannot read a reason from.
/// Written at this build's newest: a refusal is a handshake frame, so there
/// may be no negotiated version to write it at.
fn refuse(mut output: Box<dyn Write + Send>, reason: RejectReason) -> Result<(), ServerError> {
    write_message(
        &mut output,
        &ServerMessage::Reject { reason }.encode(Version::LOCAL)?,
    )?;
    Ok(())
}

/// Refuse a connection over the sink already built for it: by then the output
/// half is inside the sink, and a second writer would race it for the
/// descriptor.
fn refuse_sink(sink: &AttachmentSink) {
    let _ = sink.send(&ServerMessage::Reject {
        reason: RejectReason::Internal,
    });
    sink.close();
}

/// A datagram path for one attachment. Minted per attachment rather than per
/// daemon: the connection id and secret are what admit a client onto the UDP
/// path, and one pair shared between two would let either answer for the other.
fn datagram_offer(daemon: &DaemonState) -> Option<DatagramOffer> {
    daemon.dgram.as_ref().and_then(|listener| listener.offer())
}

/// Issue a session's identity and admit it against this daemon's bounds, or
/// answer that there is no room for it.
///
/// The count is held from the guard that reads the bound to the guard that
/// installs the handle, or every `Hello` racing this one sees the same room
/// and starts a shell in it. The slot travels out with the ticket, so a
/// failure between here and the registry entry gives the charge back.
fn admit_session(
    daemon: &Arc<DaemonState>,
    kind: SessionKind,
) -> Result<Option<(sessions::SessionTicket, SessionSlot)>, ServerError> {
    let ticket = sessions::SessionTicket::issue()
        .map_err(|error| ServerError::Setup(format!("session ticket: {error}")))?;
    let Some(slot) = SessionSlot::reserve(daemon, kind, ticket.session_id) else {
        log!("refused a session: this daemon is already running {SESSION_LIMIT}");
        return Ok(None);
    };
    persist_ticket(&ticket)?;
    Ok(Some((ticket, slot)))
}

#[expect(
    clippy::too_many_lines,
    reason = "one arm per establishment message and the negotiation that has to precede all of them: a split would put the version gate in a different function from the session it guards"
)]
fn serve_attachment(
    mut input: Box<dyn Read + Send>,
    output: Box<dyn Write + Send>,
    daemon: &Arc<DaemonState>,
    handshake: &HandshakeDeadline<'_>,
) -> Result<(), ServerError> {
    let payload = handshake.first_frame(&mut input)?;
    // Read at this build's newest: the first frame carries the range to
    // negotiate from, so there is nothing else to read it at.
    let first = ClientMessage::decode(&payload, Version::LOCAL)?;
    // Management carries no negotiated version: the daemon a user most needs
    // to enumerate is the one their upgraded binary cannot agree one with. Its
    // dialect is `Version::MANAGEMENT`, which is frozen and never the floor.
    if matches!(
        first,
        ClientMessage::ListSessions
            | ClientMessage::KillSession { .. }
            | ClientMessage::Search { .. }
    ) {
        return serve_management(input, output, daemon, first);
    }
    // Negotiated before the session is touched: an establishment message that
    // reaches a session this connection cannot then speak to evicts the
    // attachment that was working. The refusal names both ranges.
    let (ClientMessage::Hello {
        versions: stated, ..
    }
    | ClientMessage::HelloForward {
        versions: stated, ..
    }
    | ClientMessage::Resume {
        versions: stated, ..
    }) = first
    else {
        return Err(ServerError::Setup(
            "first message must be Hello, HelloForward or Resume".into(),
        ));
    };
    let version = match VersionRange::LOCAL.negotiate(stated) {
        Ok(version) => version,
        Err(reason) => return refuse(output, reason),
    };
    let (handle, kind, client, session_id) = match first {
        ClientMessage::Hello {
            size,
            term,
            env,
            command,
            client,
            ..
        } => {
            let Some((ticket, _slot)) = admit_session(daemon, SessionKind::Terminal)? else {
                return refuse(output, RejectReason::TooManySessions);
            };
            let session_id = ticket.session_id;
            // `spawn_session` installs the registry entry before the thread
            // that owns it starts; the capability file is this site's to take
            // back, because `/run/user/<uid>` is an inode-capped tmpfs.
            let handle =
                spawn_session(size, &term, &env, &command, ticket, daemon).inspect_err(|_| {
                    let _ = fs::remove_file(ticket_path(session_id));
                })?;
            (handle, AttachKind::New, client, session_id)
        }
        // Beside `Hello` rather than under it: only the session that gets
        // built differs.
        ClientMessage::HelloForward { client, .. } => {
            let Some((ticket, _slot)) = admit_session(daemon, SessionKind::Forward)? else {
                return refuse(output, RejectReason::TooManySessions);
            };
            let session_id = ticket.session_id;
            let handle = spawn_forward_session(ticket, daemon).inspect_err(|_| {
                let _ = fs::remove_file(ticket_path(session_id));
            })?;
            (handle, AttachKind::New, client, session_id)
        }
        ClientMessage::Resume { request, .. } => {
            // Refused in the protocol: a dropped connection looks like a dead
            // transport, and the client cannot tell that a fresh session is
            // the right recovery.
            let existing = match load_ticket(request.session_id, request.capability) {
                Ok(ticket) => registry(daemon)
                    .sessions
                    .get(&ticket.session_id)
                    .cloned()
                    .map(|handle| (ticket.session_id, handle)),
                Err(_) => None,
            };
            let Some((session_id, handle)) = existing else {
                return refuse(output, RejectReason::UnknownSession);
            };
            (
                handle,
                AttachKind::Resume(request.confirmed_output),
                request.client,
                session_id,
            )
        }
        _ => {
            return Err(ServerError::Setup(
                "first message must be Hello, HelloForward or Resume".into(),
            ));
        }
    };
    let id = AttachmentId(NEXT_ATTACHMENT.fetch_add(1, Ordering::Relaxed));
    let sink = AttachmentSink::new(output, version)?;
    if let Err(refused) = handle.tx.send_timeout(
        ActorEvent::Attach {
            id,
            client,
            sink: sink.clone(),
            kind,
            framing: Framing::Stream,
            offer: datagram_offer(daemon),
        },
        ATTACH_DEADLINE,
    ) {
        // The registry entry outlives its actor by one destructor, so a
        // closed mailbox leaves one this thread has to take back.
        if matches!(refused, TrySendError::Closed) {
            registry(daemon).remove(session_id);
        }
        refuse_sink(&sink);
        return Ok(());
    }
    attachment_loop(input, &handle, id, version);
    Ok(())
}

/// Answer management messages, and nothing else, on this connection. A
/// connection that opened with `brd ls` stays one until it hangs up, which is
/// what lets `brd kill` resolve an identifier and act on it over one link.
fn serve_management(
    mut input: Box<dyn Read + Send>,
    mut output: Box<dyn Write + Send>,
    daemon: &Arc<DaemonState>,
    first: ClientMessage,
) -> Result<(), ServerError> {
    let mut message = first;
    loop {
        let answer = match message {
            ClientMessage::ListSessions => ServerMessage::SessionList {
                sessions: session_list(daemon),
            },
            ClientMessage::KillSession { session_id } => {
                kill_session(daemon, session_id);
                ServerMessage::SessionList {
                    sessions: session_list(daemon),
                }
            }
            ClientMessage::Search { pattern, limit } => ServerMessage::SearchResults {
                matches: search_sessions(daemon, &pattern, usize::from(limit)),
            },
            _ => return Ok(()),
        };
        write_message(&mut output, &answer.encode(Version::MANAGEMENT)?)?;
        let Ok(payload) = read_frame(&mut input, MAX_CLIENT_FRAME) else {
            return Ok(());
        };
        let Ok(next) = ClientMessage::decode(&payload, Version::MANAGEMENT) else {
            return Ok(());
        };
        message = next;
    }
}

/// Every session this daemon owns, newest activity first.
fn session_list(daemon: &DaemonState) -> Vec<SessionSummary> {
    let mut summaries: Vec<SessionSummary> = registry(daemon)
        .sessions
        .iter()
        .map(|(id, handle)| handle.info.summarize(*id))
        .collect();
    summaries.sort_by(newest_first);
    summaries.truncate(MAX_SESSIONS);
    summaries
}

/// End one session and its shell, through the path `Close` takes.
fn kill_session(daemon: &DaemonState, session_id: SessionId) {
    let Some(handle) = registry(daemon).sessions.get(&session_id).cloned() else {
        return;
    };
    let expires = Instant::now() + KILL_DEADLINE;
    let (reply, answered) = mpsc::sync_channel(1);
    // `Kill` draws on the one slot of headroom past the control lane: a
    // blocking send parks this connection with no deadline at all, and the
    // sessions users reach for `brd kill` are disproportionately wedged ones.
    match handle
        .tx
        .send_timeout(ActorEvent::Kill { reply }, KILL_DEADLINE)
    {
        Ok(()) => {}
        // The actor is gone, so its own cleanup will never run: the entry it
        // left behind is this connection's to remove.
        Err(TrySendError::Closed) => {
            registry(daemon).remove(session_id);
            return;
        }
        // A lane full for the whole deadline is an actor that is not reading
        // it, and the list this answers with is about to say the session is
        // still running, which is the truth.
        Err(TrySendError::Full) => return,
    }
    // The sender travels with the event and is dropped by the session
    // thread's own cleanup, so this wakes on the session being gone. Polling
    // the registry instead takes its daemon-wide mutex four hundred times per
    // kill, and every attach, resume and `brd ls` waits behind that mutex.
    let _ = answered.recv_timeout(expires.saturating_duration_since(Instant::now()));
}

/// Search every session's scrollback where that scrollback lives. Each
/// session is asked only for what is still missing from the answer, and one
/// that does not reply inside the deadline contributes nothing.
fn search_sessions(daemon: &DaemonState, pattern: &str, limit: usize) -> Vec<SearchMatch> {
    let limit = limit.min(MAX_MATCHES);
    let mut sessions: Vec<(SessionId, SessionHandle)> = registry(daemon)
        .sessions
        .iter()
        .map(|(id, handle)| (*id, handle.clone()))
        .collect();
    // Newest activity first, as `brd ls` prints them: the truncation below is
    // what makes that order a decision.
    sessions.sort_by(|(left, left_handle), (right, right_handle)| {
        right_handle
            .info
            .active_unix
            .load(Ordering::Relaxed)
            .cmp(&left_handle.info.active_unix.load(Ordering::Relaxed))
            .then_with(|| left.as_bytes().cmp(&right.as_bytes()))
    });
    let pattern: Arc<str> = Arc::from(pattern);
    let deadline = Instant::now() + SEARCH_BUDGET;
    let mut matches: Vec<SearchMatch> = Vec::new();
    let asked = sessions.len();
    for (index, (_, handle)) in sessions.into_iter().enumerate() {
        if matches.len() >= limit {
            break;
        }
        // An equal share of what is left, recomputed per session: a head that
        // spends less than its share hands the rest to the tail.
        let left = u32::try_from(asked - index).unwrap_or(u32::MAX);
        let now = Instant::now();
        let share = deadline.saturating_duration_since(now) / left;
        // A session that will not be waited for must not be asked: answering
        // costs that actor a whole-scrollback search on the thread its client
        // is typing at.
        if share.is_zero() {
            break;
        }
        let (reply, answered) = mpsc::sync_channel(1);
        // The same instant travels with the event: what bounds the wait here
        // has to bound the work there, or a queue of searches is a queue of
        // whole-scrollback renders nobody is left to read.
        let expires = now + share;
        if handle
            .tx
            .try_send(ActorEvent::Search {
                pattern: Arc::clone(&pattern),
                limit: limit - matches.len(),
                deadline: expires,
                reply,
            })
            .is_err()
        {
            continue;
        }
        if let Ok(found) = answered.recv_timeout(share) {
            matches.extend(found);
        }
    }
    matches.truncate(limit);
    matches
}

/// Feed one attachment's frames to the actor until the transport or the peer
/// stops making sense, then tell the actor it is gone.
fn attachment_loop(
    mut input: Box<dyn Read + Send>,
    handle: &SessionHandle,
    id: AttachmentId,
    spoken: Version,
) {
    // One buffer for the attachment's life: this loop runs once per keystroke.
    let mut payload = Vec::new();
    while read_frame_into(&mut input, &mut payload, MAX_CLIENT_FRAME).is_ok() {
        // Breaking rather than returning: the `Detached` below has to be sent
        // however this loop ends, or the actor keeps this attachment installed
        // on a socket whose reader is gone.
        let Ok(message) = ClientMessage::decode(&payload, spoken) else {
            break;
        };
        if handle.tx.send(ActorEvent::Command { id, message }).is_err() {
            break;
        }
    }
    let _ = handle.tx.send(ActorEvent::Detached(id));
}

struct SharedSink(Arc<SessionEffects>);
impl EffectSink for SharedSink {
    fn pty_write(&self, bytes: &[u8]) {
        self.0.pty_write(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::*;
    use crate::registry::*;
    use crate::shell::*;
    use crate::state::*;
    use crate::testing::*;
    use braid_proto::{
        ByteOff, Capability, ClientId, CmdSeq, ForwardTarget, MIN_PROTOCOL_VERSION,
        PROTOCOL_VERSION, SessionEnv, StreamId,
    };
    use std::net::TcpListener;

    /// A connection with no socket under it, which is every test's.
    const fn no_deadline() -> HandshakeDeadline<'static> {
        HandshakeDeadline(None)
    }

    /// A range with nothing in common with this build's.
    fn unspeakable_range() -> VersionRange {
        VersionRange::new(PROTOCOL_VERSION + 1, PROTOCOL_VERSION + 3).expect("a range")
    }

    fn hello(versions: VersionRange, command: Vec<String>) -> Vec<u8> {
        ClientMessage::Hello {
            versions,
            size: GRID,
            term: "xterm".to_owned(),
            env: SessionEnv::default(),
            command,
            client: ClientId::from_bytes([3; 16]),
        }
        .encode(Version::LOCAL)
        .expect("a hello encodes")
    }

    /// A `Hello` stating a range this build cannot meet.
    fn mismatched_hello() -> Vec<u8> {
        hello(unspeakable_range(), Vec::new())
    }

    fn resume_frame(session_id: SessionId, capability: Capability) -> Vec<u8> {
        resume(session_id, capability, client(9))
            .encode(Version::LOCAL)
            .expect("a resume encodes")
    }

    /// Serve one first frame to completion, and answer with what the
    /// connection was told.
    fn served(daemon: &Arc<DaemonState>, frame: Vec<u8>) -> TestOutput {
        let output = TestOutput::new();
        serve_attachment(
            Box::new(io::Cursor::new(frame)),
            Box::new(output.clone()),
            daemon,
            &no_deadline(),
        )
        .expect("an answered connection is not a server failure");
        output
    }

    /// Dropping the connection instead of refusing it is indistinguishable
    /// from a dead transport: the client cannot tell that a fresh session, an
    /// upgrade or a retry later is the recovery.
    #[test]
    fn a_first_frame_that_cannot_be_served_is_refused_in_the_protocol() {
        let full = Arc::new(DaemonState::default());
        fill_registry(&full, SESSION_LIMIT);
        let mismatch = || RejectReason::Version {
            server: VersionRange::LOCAL,
            client: unspeakable_range(),
        };
        let cases: [(&str, Arc<DaemonState>, Vec<u8>, RejectReason); 3] = [
            (
                "a resume naming a session this daemon does not have",
                Arc::new(DaemonState::default()),
                resume_frame(
                    SessionId::from_bytes([0xAB; 16]),
                    Capability::from_bytes([0; 32]),
                ),
                RejectReason::UnknownSession,
            ),
            (
                "a peer speaking another protocol",
                Arc::new(DaemonState::default()),
                mismatched_hello(),
                mismatch(),
            ),
            (
                "a daemon already running every session it will",
                Arc::clone(&full),
                hello(VersionRange::LOCAL, Vec::new()),
                RejectReason::TooManySessions,
            ),
        ];
        for (what, daemon, frame, expected) in cases {
            let refused = served(&daemon, frame)
                .frames()
                .into_iter()
                .find_map(|message| match message {
                    ServerMessage::Reject { reason } => Some(reason),
                    _ => None,
                });
            assert_eq!(refused, Some(expected), "{what}");
        }
        assert_eq!(
            registry(&full).admitted(),
            SESSION_LIMIT,
            "a refused `Hello` left a reservation behind"
        );
        // "upgrade one end" is not actionable without knowing which end is
        // behind, and the daemon is the only side that saw both numbers.
        let named = mismatch().to_string();
        assert!(mismatch().is_terminal());
        assert!(
            named.contains(&VersionRange::LOCAL.to_string())
                && named.contains(&unspeakable_range().to_string()),
            "the refusal has to name both ends: {named}"
        );
    }

    /// The negotiation exists so a session survives an upgrade of either end,
    /// not merely so `brd ls` still finds it.
    #[test]
    fn a_client_of_another_version_attaches_rather_than_being_turned_away() {
        let daemon = Arc::new(DaemonState::default());
        let older = VersionRange::new(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION).expect("a range");
        let output = served(&daemon, hello(older, vec!["/bin/cat".to_owned()]));
        let greeting = await_frame(
            &output,
            |message| match message {
                ServerMessage::Hello { version, .. } => Some(*version),
                _ => None,
            },
            "an attach is answered with a greeting, not a refusal",
        );
        assert_eq!(
            greeting,
            VersionRange::LOCAL.negotiate(older).expect("they overlap"),
            "the greeting names the version the two ends settled on"
        );
    }

    /// The daemon a user most needs to enumerate is exactly the one their
    /// upgraded binary cannot agree a version with.
    #[test]
    fn list_sessions_is_answered_before_the_version_gate() {
        let daemon = Arc::new(DaemonState::default());
        assert!(
            served(&daemon, mismatched_hello())
                .frames()
                .iter()
                .any(|message| matches!(message, ServerMessage::Reject { .. })),
            "the version gate refuses this peer's Hello"
        );

        let frames = served(
            &daemon,
            ClientMessage::ListSessions
                .encode(Version::LOCAL)
                .expect("encode list"),
        )
        .frames();
        assert!(
            frames
                .iter()
                .any(|message| matches!(message, ServerMessage::SessionList { .. })),
            "the same peer is still answered about its sessions, got {frames:?}"
        );
        assert!(
            !frames
                .iter()
                .any(|message| matches!(message, ServerMessage::Reject { .. })),
            "nothing about a version is consulted on the way, got {frames:?}"
        );
    }

    /// `brd ls` has to name a session while its actor is busy, and `brd kill`
    /// has to end one through the path `Close` takes - answered by the session
    /// going, since polling the registry for it would take the mutex that
    /// serialises every attach, resume and `brd ls` every five milliseconds.
    #[test]
    fn a_session_is_listed_and_killed_over_a_management_connection() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        daemon_session(&daemon, ticket, &[]);

        let summary = session_list(&daemon)
            .into_iter()
            .find(|summary| summary.session_id == session_id)
            .expect("the session is named");
        assert_eq!(summary.size, GRID);
        assert_eq!(summary.attachments, 0);
        assert!(summary.command.contains("-l"), "{:?}", summary.command);

        let started = Instant::now();
        let killed = served(
            &daemon,
            ClientMessage::KillSession { session_id }
                .encode(Version::LOCAL)
                .expect("encode kill"),
        );
        assert!(
            started.elapsed() < KILL_DEADLINE,
            "the answer is the session going, not the deadline expiring"
        );
        let Some(ServerMessage::SessionList { sessions }) = killed
            .frames()
            .into_iter()
            .find(|message| matches!(message, ServerMessage::SessionList { .. }))
        else {
            panic!("a kill is answered with the list it leaves behind");
        };
        assert!(
            !sessions
                .iter()
                .any(|summary| summary.session_id == session_id),
            "the list a kill answers with must not still name what it killed"
        );
        assert!(!registry(&daemon).sessions.contains_key(&session_id));
        assert!(!ticket_path(session_id).exists());
    }

    /// `brd ls` has to name what actually runs, or the list a user kills from
    /// is fiction.
    #[test]
    fn an_explicit_command_replaces_the_login_shell_and_is_what_ls_names() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        let handle = daemon_session(
            &daemon,
            ticket,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "read x; printf BRD_ARGV".into(),
            ],
        );

        let summary = session_list(&daemon)
            .into_iter()
            .find(|summary| summary.session_id == session_id)
            .expect("the session is named");
        assert_eq!(summary.command, "/bin/sh -c read x; printf BRD_ARGV");

        let id = next_attachment();
        let output = TestOutput::new();
        let sink =
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment");
        handle
            .tx
            .send(attach_event(id, sink, AttachKind::New))
            .expect("attach transport");
        assert!(output.contains(&[hello_tag()], Duration::from_secs(2)));
        handle
            .tx
            .send(ActorEvent::Command {
                id,
                message: ClientMessage::Input {
                    seq: CmdSeq::first(),
                    bytes: b"go\n".to_vec(),
                },
            })
            .expect("send a line for the child to read");
        // A login shell handed this answers "go: not found".
        assert!(
            output.contains(b"BRD_ARGV", Duration::from_secs(3)),
            "the argv the client named is what ran"
        );

        // The child exits the moment it has printed, so this is teardown
        // rather than the property under test.
        let _ = handle.tx.send(kill());
    }

    /// A frame this attachment's reader cannot decode still ends in
    /// `Detached`, or output keeps flowing over the sink's own dup of the
    /// socket while every keystroke vanishes into a session that reads none.
    #[test]
    fn an_undecodable_frame_detaches_instead_of_stranding_the_attachment() {
        let handle = test_session();
        let id = next_attachment();
        let output = TestOutput::new();
        let sink =
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment");
        handle
            .tx
            .send(attach_event(id, sink.clone(), AttachKind::New))
            .expect("attach transport");
        assert!(output.contains(&[hello_tag()], Duration::from_secs(2)));

        // A well-formed frame carrying a tag no client message has: the
        // transport is fine and the message is not.
        let mut frame = 1_u32.to_be_bytes().to_vec();
        frame.push(0x7F);
        attachment_loop(
            Box::new(io::Cursor::new(frame)),
            &handle,
            id,
            Version::LOCAL,
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !sink.is_closed() {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            sink.is_closed(),
            "the actor still holds an attachment nobody is reading"
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// `brd -N` end to end over the establishment path a real client uses: a
    /// session that never had a terminal, answered by kind, carrying bytes
    /// both ways, named by `brd ls` and ended by `brd kill`.
    #[test]
    fn a_helloforward_session_is_answered_by_kind_and_carries_a_tunnel() {
        let daemon = Arc::new(DaemonState::default());
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        // A real socket rather than a cursor: the connection has to stay open
        // past the first frame, because the far end answers on its own clock.
        let (mut client_end, server_end) = UnixStream::pair().expect("a connection");
        let output = TestOutput::new();
        let served = {
            let daemon = Arc::clone(&daemon);
            let output = output.clone();
            thread::spawn(move || {
                serve_attachment(
                    Box::new(server_end),
                    Box::new(output),
                    &daemon,
                    &no_deadline(),
                )
            })
        };
        let say = |connection: &mut UnixStream, message: &ClientMessage| {
            write_message(connection, &message.encode(Version::LOCAL).expect("encode"))
                .expect("send");
        };

        say(
            &mut client_end,
            &ClientMessage::HelloForward {
                versions: VersionRange::LOCAL,
                client: client(1),
            },
        );
        let session_id = await_frame(
            &output,
            |message| match message {
                ServerMessage::HelloForward { session_id, .. } => Some(*session_id),
                ServerMessage::Hello { .. } => {
                    panic!("a forward-only session answered with a terminal's greeting")
                }
                _ => None,
            },
            "the session never greeted the client that asked for it",
        );
        assert_eq!(
            session_list(&daemon)
                .into_iter()
                .find(|summary| summary.session_id == session_id)
                .expect("`brd ls` never named the session")
                .command,
            "[forwards]"
        );

        let stream = StreamId::first();
        say(
            &mut client_end,
            &ClientMessage::ForwardOpen {
                seq: CmdSeq::first(),
                stream,
                target: ForwardTarget {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
            },
        );
        let (mut far, _) = listener.accept().expect("the forward dialled");
        say(
            &mut client_end,
            &ClientMessage::ForwardData {
                stream,
                off: ByteOff::zero(),
                fin: false,
                bytes: b"request".to_vec(),
            },
        );
        far.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a deadline on the far end");
        let mut seen = [0; 7];
        far.read_exact(&mut seen)
            .expect("the tunnel never wrote what its client sent");
        assert_eq!(&seen, b"request");

        far.write_all(b"answer").expect("write into the tunnel");
        let carried = await_frame(
            &output,
            |message| match message {
                ServerMessage::ForwardData { bytes, .. } if !bytes.is_empty() => {
                    Some(bytes.clone())
                }
                _ => None,
            },
            "the tunnel never carried what the far end answered",
        );
        assert_eq!(carried, b"answer");

        kill_session(&daemon, session_id);
        assert!(
            !registry(&daemon).sessions.contains_key(&session_id),
            "`brd kill` left a forward-only session running"
        );
        drop(client_end);
        served
            .join()
            .expect("the connection thread panicked")
            .expect("serving a forward-only client is not a server failure");
    }

    /// `brd kill` must not block inside `tx.send`: a mailbox full of another
    /// client's commands and queued output would hold the request on a
    /// management thread before the deadline it then measures has started.
    #[test]
    fn a_kill_request_does_not_wait_for_the_event_queue_to_drain() {
        let daemon = Arc::new(DaemonState::default());
        let session_id = SessionId::from_bytes([0x11; 16]);
        let (tx, rx) = mailbox();
        // Nothing reads this mailbox and both lanes are full.
        for _ in 0..OUTPUT_LANE {
            tx.try_send(pty_output(b"y")).expect("a free output slot");
        }
        for _ in 0..CONTROL_LANE {
            tx.try_send(ActorEvent::Detached(next_attachment()))
                .expect("a free control slot");
        }
        assert!(
            matches!(tx.try_send(pty_output(b"y")), Err(TrySendError::Full)),
            "an unbounded lane is not the backlog this test is about"
        );
        registry(&daemon)
            .sessions
            .insert(session_id, detached_handle(tx));

        let (finished, waited) = mpsc::channel();
        let killer_daemon = Arc::clone(&daemon);
        thread::spawn(move || {
            kill_session(&killer_daemon, session_id);
            let _ = finished.send(());
        });
        // Nothing here ever drains, so a request that waited for room waits
        // for good.
        assert!(
            waited.recv_timeout(KILL_DEADLINE * 2).is_ok(),
            "the request waited on a mailbox full of queued output"
        );

        let mut queued = Vec::new();
        while let Ok(event) = rx.recv_timeout(Duration::ZERO) {
            queued.push(event);
        }
        assert_eq!(
            queued.len(),
            CONTROL_LANE + OUTPUT_LANE + 1,
            "the kill was dropped by a mailbox that had no room reserved for it"
        );
        assert!(
            matches!(queued[CONTROL_LANE], ActorEvent::Kill { .. }),
            "the kill was queued behind the output it has nothing to do with"
        );
    }

    /// The daemon holds the only real scrollback in this system, so a search
    /// runs where that history lives - including the part of it the viewport
    /// has already scrolled past.
    #[test]
    fn a_scrollback_search_finds_a_line_the_viewport_no_longer_shows() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        let handle = daemon_session(&daemon, ticket, &[]);

        handle
            .tx
            .send(pty_output(b"BRD_NEEDLE in the haystack\r\n"))
            .expect("feed the needle");
        for line in 0..60 {
            handle
                .tx
                .send(pty_output(format!("filler {line}\r\n").as_bytes()))
                .expect("scroll the needle off the screen");
        }

        // The events above are queued ahead of the search on the same channel,
        // so the emulator has them by the time the actor answers.
        let found = search_sessions(&daemon, "BRD_NEEDLE", 8);
        let hit = found
            .iter()
            .find(|found| found.line.contains("BRD_NEEDLE"))
            .expect("the search finds a line the screen no longer shows");
        assert_eq!(hit.session_id, session_id);
        assert!(
            hit.distance >= u32::from(GRID.rows),
            "the match is still on the visible screen, so this proves nothing: {}",
            hit.distance
        );

        // The same answer over the connection a `brd grep` actually opens.
        let asked = served(
            &daemon,
            ClientMessage::Search {
                pattern: "BRD_NEEDLE".into(),
                limit: 8,
            }
            .encode(Version::LOCAL)
            .expect("encode search"),
        );
        let Some(ServerMessage::SearchResults { matches }) = asked
            .frames()
            .into_iter()
            .find(|message| matches!(message, ServerMessage::SearchResults { .. }))
        else {
            panic!("a search is answered in the protocol");
        };
        assert!(
            matches
                .iter()
                .any(|found| found.line.contains("BRD_NEEDLE")),
            "the management path answered without the match the actor found"
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// The offer is per attachment and rides in the greeting, which is the
    /// only frame a client that has not attached yet is going to read.
    #[test]
    fn a_greeting_carries_the_path_this_daemon_offers() {
        let listener = dgram::DatagramListener::bind().expect("a datagram socket");
        let daemon = Arc::new(DaemonState {
            sessions: Mutex::default(),
            connections: AtomicUsize::new(0),
            forwards: AtomicUsize::new(0),
            dgram: Some(listener),
        });
        let (ticket, session_id, capability) = persisted_ticket();
        let handle = daemon_session(&daemon, ticket, &[]);

        let output = served(&daemon, resume_frame(session_id, capability));
        assert!(
            output.contains(&[hello_tag()], Duration::from_secs(2)),
            "the session greets every attachment"
        );
        let Some(ServerMessage::Hello { offer, .. }) = output
            .frames()
            .into_iter()
            .find(|message| matches!(message, ServerMessage::Hello { .. }))
        else {
            panic!("the greeting is a `Hello`");
        };
        let offer = offer.expect("a daemon with a socket offers a path");
        assert_eq!(
            offer.port,
            datagram_offer(&daemon).expect("a second offer").port,
            "every attachment is offered the daemon's one socket"
        );
        assert_eq!(
            offer.ip, [0; 16],
            "the daemon cannot know which of its addresses was reached"
        );
        assert_ne!(offer.cid, [0; 8], "an offer names a connection");

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// Holding the lock does not prove no daemon is live: one whose lock file
    /// was unlinked keeps its `flock` on that inode. The probe is what proves
    /// it, and a `.cap` file is a resume's only authenticator - while only a
    /// session's own destructor unlinks one, so a `SIGKILL`ed daemon leaves
    /// every one of them on an inode-capped tmpfs.
    #[test]
    fn capabilities_are_swept_only_once_the_probe_finds_nothing_answering() {
        for live in [true, false] {
            let directory = scratch(if live { "claim-live" } else { "claim-dead" });
            let socket = directory.join(socket_name());
            let listening = live.then(|| UnixListener::bind(&socket).expect("a daemon listening"));
            let ticket = directory.join(session_name(SessionId::from_bytes([0x22; 16])) + ".cap");
            fs::write(&ticket, b"hash").expect("a session's capability");
            let log = directory.join("brd.log");
            fs::write(&log, b"lines").expect("daemon log");

            let claim = claim_socket(&socket, &directory).expect("probing is not a failure");

            assert_eq!(
                matches!(claim, Claim::Live),
                live,
                "a socket something is answering was taken anyway"
            );
            assert_eq!(
                ticket.exists(),
                live,
                "the sweep did not follow what the probe found"
            );
            assert!(log.exists(), "the sweep is capabilities and nothing else");
            drop(claim);
            drop(listening);
            let _ = fs::remove_dir_all(&directory);
        }
    }

    /// `Kill` has one slot of headroom past the control lane, and a second
    /// `brd kill` arriving while the first is queued finds none: a blocking
    /// send would park that connection forever.
    #[test]
    fn a_second_kill_gives_up_rather_than_parking_its_connection_forever() {
        let daemon = Arc::new(DaemonState::default());
        let session_id = SessionId::from_bytes([0x44; 16]);
        let (tx, _rx) = mailbox();
        for _ in 0..=CONTROL_LANE {
            tx.try_send(kill()).expect("room past the bound, once");
        }
        registry(&daemon).install(
            session_id,
            SessionHandle {
                tx,
                info: forward_info(),
                kind: SessionKind::Forward,
            },
        );

        let started = Instant::now();
        kill_session(&daemon, session_id);

        assert!(
            started.elapsed() < KILL_DEADLINE * 3,
            "a kill onto a full control lane never came back"
        );
    }
}
