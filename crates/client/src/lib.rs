#![forbid(unsafe_code)]

pub mod forward;
pub mod manage;
pub mod predict;
pub mod render;
pub mod transport;

mod dgram;
mod headless;
mod inbound;
mod journal;
mod log;
mod outbound;
mod state;
mod terminal;

use braid_proto::{
    ClientMessage, CmdSeq, DatagramOffer, DetachReason, GridSize, MAX_ENV, MAX_FRAME,
    MAX_OUTPUT_CHUNK, MAX_TERM, RejectReason, ServerMessage, SessionEnv, SessionId, Version,
    VersionRange, read_frame, write_message,
};
use forward::{ForwardSpec, Forwards, Listeners};
use inbound::{
    CONSUMED_STRIDE, Deadline, DeadlineReader, Inbound, LINK_TIMEOUT, RESUME_TIMEOUT, Reorder,
    datagrams_wanted, next_frame, place_output, reorder_deadline, silence_deadline, take_offer,
};
use log::log;
use outbound::{Accepted, Checkpoint, ClientWriter, FrameSink, Link, MIN_RESEND};
use predict::{Prediction, Typing};
use state::{CLIENT_ID, ReconnectState, reconnect_path};
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::process::{ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use terminal::{
    INPUT_THREAD, Shared, Stake, TerminalOut, blind_reset, enter_raw, guarded_raw_mode,
    restore_terminal, staked, terminal_size,
};
use thiserror::Error;
use transport::{Auth, Outbox, SshTransport, TransportError};

pub use headless::forward_only;
pub use terminal::Display;

/// Bounds messages, not keystrokes; unsent typing waits in a byte buffer.
const JOURNAL_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).expect("constant is non-zero");

const MAX_PENDING_INPUT: usize = 256 * 1024;

/// Split by whose words the text is: an `ssh` failure folded into `Io` reads as a local one.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("remote: {0}")]
    Remote(RejectReason),
    #[error("{0}")]
    Management(String),
    /// The one failure that must abort before anything else is attempted.
    #[error("{0}")]
    Forward(String),
    #[error("protocol: {0}")]
    Protocol(#[from] braid_proto::DecodeError),
    #[error("protocol encoding: {0}")]
    Encode(#[from] braid_proto::EncodeError),
    #[error("local I/O: {0}")]
    Io(#[from] io::Error),
    #[error("server exited with status {0}")]
    RemoteExit(i32),
}

enum ResumeFailure {
    Transport,
    /// Terminal rather than retried: every attempt meets the same key material.
    Credentials(String),
    Rejected(RejectReason),
    Protocol(braid_proto::DecodeError),
}

/// 250 ms doubling to a 30 s ceiling, unbounded: the bounded property is the spawn rate.
fn reconnect_backoff(attempt: u32) -> Duration {
    Duration::from_millis(250)
        .saturating_mul(1_u32 << attempt.min(20))
        .min(Duration::from_secs(30))
}

/// The offer is per-attachment: the handshake's names an address behind an `sshd` now gone.
struct Resumed {
    transport: SshTransport,
    input: ChildStdin,
    output: ChildStdout,
    offer: Option<DatagramOffer>,
    version: Version,
    /// Read only by a caller that asked for a *new* session; a resume keeps the state it holds.
    opened: ReconnectState,
}

/// `Auth::Batch`: an attached client's terminal is raw with `brd-input` blocked in `read`.
fn resume_transport(destination: &str, opening: &[u8]) -> Result<Resumed, ResumeFailure> {
    let mut transport =
        SshTransport::connect(destination, Auth::Batch).map_err(|_| ResumeFailure::Transport)?;
    let (mut input, output) = transport.take_io().ok_or(ResumeFailure::Transport)?;
    write_message(&mut input, opening).map_err(|_| ResumeFailure::Transport)?;
    // `ConnectTimeout` bounds the SYN alone, and the quit key is polled only between attempts.
    let mut output = DeadlineReader::new(output, Deadline::new(RESUME_TIMEOUT))
        .map_err(|_| ResumeFailure::Transport)?;
    let payload = read_frame(&mut output, MAX_FRAME).map_err(|error| {
        if error.is_transport_loss() {
            let diagnostics = transport.diagnostics();
            if transport::needs_credentials(&diagnostics) {
                ResumeFailure::Credentials(diagnostics)
            } else {
                ResumeFailure::Transport
            }
        } else {
            ResumeFailure::Protocol(error)
        }
    })?;
    // Either establishment answer: the kind matches the session, not the request. Decoded at
    // this build's newest, which is the version everything after it is read at.
    let (version, session_id, capability, offer) =
        match ServerMessage::decode(&payload, Version::LOCAL).map_err(ResumeFailure::Protocol)? {
            ServerMessage::Hello {
                version,
                session_id,
                capability,
                offer,
                ..
            }
            | ServerMessage::HelloForward {
                version,
                session_id,
                capability,
                offer,
            } => (version, session_id, capability, offer),
            ServerMessage::Reject { reason } => return Err(ResumeFailure::Rejected(reason)),
            _ => {
                return Err(ResumeFailure::Protocol(
                    braid_proto::DecodeError::InvalidField,
                ));
            }
        };
    Ok(Resumed {
        transport,
        input,
        output: output.into_inner(),
        offer,
        version,
        opened: ReconnectState::new(session_id, capability),
    })
}

/// A whitelist, never a copy: the daemon outlives the SSH session, so its own environment
/// holds a dead `SSH_AUTH_SOCK` and an `SSH_TTY` naming a pty that is gone.
const FORWARDED_ENV: [&str; 8] = [
    "SSH_AUTH_SOCK",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
    "DISPLAY",
    // A display forwarded without its cookie file is refused by every X client.
    "XAUTHORITY",
    "XDG_SESSION_ID",
    "XDG_SESSION_TYPE",
];

fn session_env() -> SessionEnv {
    session_env_from(|name| std::env::var(name).ok())
}

fn session_env_from(lookup: impl Fn(&str) -> Option<String>) -> SessionEnv {
    let mut forwarded = Vec::new();
    let mut total = 0_usize;
    for name in FORWARDED_ENV {
        let Some(value) = lookup(name) else { continue };
        // A hostile `DISPLAY` must cost its own variable, never the attach.
        let cost = name.len() + value.len() + 3;
        if value.chars().any(char::is_control) || total + cost > MAX_ENV {
            continue;
        }
        total += cost;
        forwarded.push((name.to_owned(), value));
    }
    SessionEnv(forwarded)
}

/// A `TERM` the wire refuses is a session that never opens.
fn valid_term(term: &str) -> bool {
    !term.is_empty()
        && term.len() <= MAX_TERM
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.' | b'_'))
}

struct Handshake {
    transport: SshTransport,
    input: ChildStdin,
    output: ChildStdout,
    state: ReconnectState,
    /// On a resume, past the highest command the server says it applied.
    resumed: Option<CmdSeq>,
    offer: Option<DatagramOffer>,
    version: Version,
}

fn hello(size: GridSize, term: &str, command: &[String]) -> ClientMessage {
    ClientMessage::Hello {
        versions: VersionRange::LOCAL,
        size,
        term: term.to_owned(),
        env: session_env(),
        command: command.to_vec(),
        client: *CLIENT_ID,
    }
}

/// A session the server no longer knows is not a launch failure: a fresh one is requested.
fn open_session(
    destination: &str,
    size: GridSize,
    term: &str,
    command: &[String],
    mut previous: Option<ReconnectState>,
) -> Result<Handshake, ClientError> {
    loop {
        let first = previous.as_ref().map_or_else(
            || hello(size, term, command),
            |state| state.resume_message(CmdSeq::first()),
        );
        // Before raw mode and the input thread, so a passphrase prompt is the user's own.
        let mut transport = SshTransport::connect(destination, Auth::Interactive)?;
        let (mut input, mut output) = transport
            .take_io()
            .ok_or(ClientError::Transport(TransportError::MissingPipe))?;
        write_message(&mut input, &first.encode(Version::LOCAL)?)?;
        let opening = match read_frame(&mut output, MAX_FRAME) {
            Ok(payload) => ServerMessage::decode(&payload, Version::LOCAL)?,
            // Falling back to a fresh session is the recovery; failing here strands the user.
            Err(error) if error.is_transport_loss() && previous.is_some() => {
                previous = None;
                continue;
            }
            // `ssh`'s diagnostics went to a pipe rather than the user's screen.
            Err(error) if error.is_transport_loss() => {
                let diagnostics = transport.diagnostics();
                return Err(if diagnostics.is_empty() {
                    ClientError::Protocol(error)
                } else {
                    ClientError::Ssh(diagnostics)
                });
            }
            Err(error) => return Err(ClientError::Protocol(error)),
        };
        match opening {
            ServerMessage::Hello {
                version,
                session_id,
                capability,
                offer,
                ..
            } => {
                // The server acks its highest applied command before any replayed output.
                let resumed = if previous.is_some() {
                    Some(
                        read_resume_ack(&mut output, version)?
                            .map_or_else(CmdSeq::first, CmdSeq::next),
                    )
                } else {
                    None
                };
                let state = previous.unwrap_or_else(|| ReconnectState::new(session_id, capability));
                return Ok(Handshake {
                    transport,
                    input,
                    output,
                    state,
                    resumed,
                    offer,
                    version,
                });
            }
            // Every other refusal describes something a second `Hello` would meet again.
            ServerMessage::Reject { reason } => {
                if reason != RejectReason::UnknownSession || previous.take().is_none() {
                    return Err(ClientError::Remote(reason));
                }
            }
            _ => {
                return Err(ClientError::Protocol(
                    braid_proto::DecodeError::InvalidField,
                ));
            }
        }
    }
}

fn read_resume_ack<R: Read>(
    output: &mut R,
    spoken: Version,
) -> Result<Option<CmdSeq>, ClientError> {
    match ServerMessage::decode(&read_frame(output, MAX_FRAME)?, spoken)? {
        ServerMessage::CommandAck { highest } => Ok(highest),
        _ => Err(ClientError::Protocol(
            braid_proto::DecodeError::InvalidField,
        )),
    }
}

const STATUS_TICK: Duration = Duration::from_secs(1);

/// An attached client owns the bottom row of a raw-mode terminal; a forward-only one
/// writes ordinary lines.
pub(crate) trait Indicator {
    fn waiting(&self, since: Duration, dropped: bool) -> Result<(), ClientError>;
    fn clear(&self) -> Result<(), ClientError>;
}

struct StatusLine<'a, O: Write>(&'a Shared<O>);

impl<O: Write> Indicator for StatusLine<'_, O> {
    fn waiting(&self, since: Duration, dropped: bool) -> Result<(), ClientError> {
        self.0.lock()?.status_show(status_size(), since, dropped)?;
        Ok(())
    }

    fn clear(&self) -> Result<(), ClientError> {
        self.0.lock()?.status_clear()?;
        Ok(())
    }
}

enum Reopen<'a> {
    Session(&'a ReconnectState),
    Forwards,
}

impl Reopen<'_> {
    fn frame(&self) -> Result<Vec<u8>, ClientError> {
        Ok(match self {
            Self::Session(state) => state
                .resume_message(CmdSeq::first())
                .encode(Version::LOCAL)?,
            Self::Forwards => ClientMessage::HelloForward {
                versions: VersionRange::LOCAL,
                client: *CLIENT_ID,
            }
            .encode(Version::LOCAL)?,
        })
    }
}

enum Reconnected {
    Link(Resumed),
    Closed,
    /// A variant, not an error: opening a replacement session loses nothing only for forwards.
    Gone,
}

fn reconnect<W: FrameSink>(
    destination: &str,
    reopen: &Reopen<'_>,
    input: &ClientWriter<W>,
    indicator: &dyn Indicator,
) -> Result<Reconnected, ClientError> {
    let since = Instant::now();
    let mut attempt = 0_u32;
    let opening = reopen.frame()?;
    loop {
        if input.close_requested.load(Ordering::Acquire) {
            indicator.clear()?;
            return Ok(Reconnected::Closed);
        }
        match resume_transport(destination, &opening) {
            Ok(replacement) => {
                log!("reconnect attempt {attempt} to {destination}: link back");
                indicator.clear()?;
                return Ok(Reconnected::Link(replacement));
            }
            // Retrying is the same refusal on the same key material forever.
            Err(ResumeFailure::Credentials(message)) => {
                log!("reconnect attempt {attempt} to {destination}: ssh needs credentials");
                indicator.clear()?;
                return Err(ClientError::Ssh(message));
            }
            // The one refusal whose answer is not the same for both clients.
            Err(ResumeFailure::Rejected(RejectReason::UnknownSession)) => {
                log!("reconnect attempt {attempt} to {destination}: session is gone");
                indicator.clear()?;
                return Ok(Reconnected::Gone);
            }
            // A client that cannot tell this from a dropped attachment spins on a corpse.
            Err(ResumeFailure::Rejected(reason)) if reason.is_terminal() => {
                log!("reconnect attempt {attempt} to {destination}: refused, {reason}");
                indicator.clear()?;
                return Err(ClientError::Remote(reason));
            }
            // Nothing answered, or an attachment was dropped whose session is still there.
            Err(ResumeFailure::Transport | ResumeFailure::Rejected(_)) => {
                log!("reconnect attempt {attempt} to {destination}: nothing yet");
            }
            Err(ResumeFailure::Protocol(error)) => {
                log!("reconnect attempt {attempt} to {destination}: {error}");
                indicator.clear()?;
                return Err(ClientError::Protocol(error));
            }
        }
        let deadline = Instant::now() + reconnect_backoff(attempt);
        attempt = attempt.saturating_add(1);
        loop {
            if input.close_requested.load(Ordering::Acquire) {
                indicator.clear()?;
                return Ok(Reconnected::Closed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let dropped = input.dropped_input.load(Ordering::Acquire);
            indicator.waiting(since.elapsed(), dropped)?;
            thread::sleep(remaining.min(STATUS_TICK));
        }
    }
}

/// A drag emits one signal per pixel, and each is a journalled `Resize` costing the server
/// a generation and every attachment a full screen.
const RESIZE_SETTLE: Duration = Duration::from_millis(20);

/// Not on the signal thread: SIGTERM, SIGHUP and SIGTSTP must reach `restore_terminal`.
#[derive(Default)]
struct PendingResize {
    settles_at: Mutex<Option<Instant>>,
    woken: Condvar,
}

impl PendingResize {
    fn note(&self) {
        if let Ok(mut settles_at) = self.settles_at.lock() {
            *settles_at = Some(Instant::now() + RESIZE_SETTLE);
            self.woken.notify_one();
        }
    }

    /// `None` once the lock is poisoned and no size will ever be read again.
    fn settled(&self) -> Option<()> {
        let mut settles_at = self.settles_at.lock().ok()?;
        loop {
            let Some(deadline) = *settles_at else {
                settles_at = self.woken.wait(settles_at).ok()?;
                continue;
            };
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                *settles_at = None;
                return Some(());
            };
            settles_at = self.woken.wait_timeout(settles_at, remaining).ok()?.0;
        }
    }
}

/// Columns high, rows low: an atomic keeps a `tcgetwinsize` off the display thread.
static TERMINAL_SIZE: AtomicU32 = AtomicU32::new(0);

fn note_terminal_size(size: GridSize) {
    TERMINAL_SIZE.store(
        (u32::from(size.cols) << 16) | u32::from(size.rows),
        Ordering::Release,
    );
}

fn status_size() -> GridSize {
    let packed = TERMINAL_SIZE.load(Ordering::Acquire);
    GridSize::new(
        u16::try_from(packed >> 16).unwrap_or(u16::MAX),
        u16::try_from(packed & 0xffff).unwrap_or(u16::MAX),
    )
    .or_else(|| {
        // Every path before the first SIGWINCH: ask the terminal once.
        let size = terminal_size(io::stdin().as_fd()).ok()?;
        note_terminal_size(size);
        Some(size)
    })
    .unwrap_or(GridSize { cols: 80, rows: 24 })
}

/// `None` takes the newest; a prefix resolves as `brd kill` does, empty refused.
fn take_session(
    sessions: &mut Vec<ReconnectState>,
    selector: Option<&str>,
) -> Result<Option<ReconnectState>, ClientError> {
    let Some(prefix) = selector else {
        return Ok((!sessions.is_empty()).then(|| sessions.remove(0)));
    };
    let ids: Vec<SessionId> = sessions.iter().map(|state| state.session_id).collect();
    let wanted = manage::resolve(&ids, prefix)?;
    Ok(sessions
        .iter()
        .position(|state| state.session_id == wanted)
        .map(|index| sessions.remove(index)))
}

/// A refusal is not an error and is never retried for this attachment. The caller drops its
/// `SshTransport` on `Some`: the resume carries the same `ClientId`, so the daemon has
/// already replaced the attachment.
fn upgrade(
    offer: Option<DatagramOffer>,
    state: &ReconnectState,
    deadline: &Deadline,
    input: &Arc<ClientWriter<Link>>,
) -> Result<Option<(Inbound, Version)>, ClientError> {
    let Some(offer) = offer.filter(|_| datagrams_wanted()) else {
        log!("transport: staying on ssh, no datagram offer this attachment can take");
        return Ok(None);
    };
    let Some((sink, reader, version)) = take_offer(&offer, state, deadline) else {
        log!("transport: datagram offer declined, falling back to ssh");
        return Ok(None);
    };
    input.reconnect(Link::Datagram(sink), version)?;
    let resending = Arc::clone(input);
    // This is the link the thread below retransmits for; a later upgrade retires it.
    let epoch = resending.epoch();
    thread::Builder::new()
        .name("brd-resend".into())
        .spawn(staked(Stake::Session, move || {
            // `retransmit` answers `None` for a transport that retransmits for itself.
            while let Ok(Some(wait)) = resending.retransmit(Instant::now(), epoch) {
                thread::sleep(wait.max(MIN_RESEND));
            }
        }))
        .map_err(|_| io::Error::other("resend thread failed"))?;
    log!("transport: migrated to datagrams, epoch {epoch}");
    Ok(Some((Inbound::Datagram(reader), version)))
}

/// Say once, after the terminal is back, how much output this session never handed over.
///
/// Printed here rather than during the session because every byte written while the
/// display is live belongs to the application: a notice painted mid-screen is corruption
/// nothing then repaints. The far side still has the history, which is what makes this
/// actionable rather than merely sad.
fn report_skipped(bytes: u64, destination: &str) {
    if bytes == 0 {
        return;
    }
    eprintln!(
        "[brd] {bytes} bytes of output were skipped to catch up after a reconnect; \
         the session still has them: brd grep {destination} <pattern>"
    );
}

/// Attach to `destination`, running `command` instead of a login shell when it
/// is not empty and resuming the stored session `session` names.
#[expect(clippy::too_many_lines, reason = "one session lifecycle")]
pub fn run(
    destination: &str,
    command: &[String],
    session: Option<&str>,
    prediction: Prediction,
    forwards: &[ForwardSpec],
) -> Result<(), ClientError> {
    // `ExitOnForwardFailure=yes`: a port the user asked for and did not get aborts here.
    let listeners = Listeners::bind(forwards)?;
    log!("attaching to {destination}");
    let stdin = io::stdin();
    let size = terminal_size(stdin.as_fd()).unwrap_or(GridSize { cols: 80, rows: 24 });
    // A `TERM` the wire refuses is a session that never opens.
    let term = std::env::var("TERM")
        .ok()
        .filter(|term| valid_term(term))
        .unwrap_or_else(|| "xterm-256color".into());
    let mut checkpoint = Checkpoint::new(reconnect_path(destination));
    let mut remembered = checkpoint.load()?;
    // Resuming would drop the command the user typed and hand back a shell instead.
    let previous_state = if command.is_empty() {
        take_session(&mut remembered, session)?
    } else {
        None
    };
    checkpoint.others = remembered;

    let handshake = open_session(destination, size, &term, command, previous_state)?;
    // Dropping this reaps `ssh`; every path out of this function drops it exactly once.
    let mut transport = Some(handshake.transport);
    let deadline = Deadline::new(LINK_TIMEOUT);
    let mut inbound = Inbound::ssh(handshake.output, deadline.clone())?;
    // A reconnect onto a daemon of another vintage replaces this.
    let mut version = handshake.version;
    let mut state = handshake.state;
    checkpoint.force(&state);

    let raw = guarded_raw_mode(stdin.as_fd())?;
    let input = Arc::new(ClientWriter::new(
        Link::Ssh(Outbox::new(handshake.input)),
        handshake.resumed.unwrap_or_else(CmdSeq::first),
        handshake.version,
    ));
    if handshake.resumed.is_some() {
        input.resize(size)?;
    }
    // After the writer connections are numbered against; the ports were bound before the
    // handshake, so a connection made meanwhile waits in the backlog.
    let forwards = if listeners.is_empty() {
        None
    } else {
        Some(Forwards::start(listeners, &input)?)
    };
    // Before the session loop, so a migrating client never reconciles two transports.
    if let Some((datagrams, spoken)) = upgrade(handshake.offer, &state, &deadline, &input)? {
        inbound = datagrams;
        version = spoken;
        transport = None;
    }
    // A whole frame: the default eight kibibytes would cut every full-size `Output` in eight.
    let display = Arc::new(Shared::new(Display::new(
        io::BufWriter::with_capacity(MAX_OUTPUT_CHUNK, TerminalOut),
        prediction,
    )));
    // Set when a keystroke reached the session without the predictor accounting for it.
    let interrupted = Arc::new(AtomicBool::new(false));
    let input_for_thread = Arc::clone(&input);
    let display_for_thread = Arc::clone(&display);
    let interrupted_for_thread = Arc::clone(&interrupted);
    thread::Builder::new()
        .name(INPUT_THREAD.into())
        .spawn(staked(Stake::Session, move || {
            let end = input_loop(
                io::stdin(),
                &input_for_thread,
                &display_for_thread,
                &interrupted_for_thread,
            );
            log!("input: {end}");
            let _ = farewell(&end, &input_for_thread);
        }))
        .map_err(|_| io::Error::other("input thread failed"))?;
    let resize_burst = Arc::new(PendingResize::default());
    let settling = Arc::clone(&resize_burst);
    let settle_writer = Arc::clone(&input);
    let settle_display = Arc::clone(&display);
    thread::Builder::new()
        .name("brd-resize".into())
        .spawn(staked(Stake::Session, move || {
            while settling.settled().is_some() {
                if let Ok(size) = terminal_size(io::stdin().as_fd()) {
                    note_terminal_size(size);
                    let _ = settle_writer.resize(size);
                }
                // Telling the server alone leaves the predictor drawing against the old
                // `room`: shrink 200 columns to 40 and the next keystrokes wrap.
                settle_display.resized();
            }
        }))
        .map_err(|_| io::Error::other("resize thread failed"))?;
    let resize_writer = Arc::clone(&input);
    let signal_display = Arc::clone(&display);
    thread::Builder::new()
        .name("brd-signals".into())
        .spawn(staked(Stake::Session, move || {
            let Ok(mut signals) = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGWINCH,
                signal_hook::consts::SIGCONT,
                signal_hook::consts::SIGTSTP,
                // Raw mode clears ISIG, but `kill -INT` and a process-group Ctrl-C still
                // deliver this and would leave the terminal raw.
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGQUIT,
                signal_hook::consts::SIGHUP,
            ]) else {
                return;
            };
            for signal in signals.forever() {
                if signal == signal_hook::consts::SIGWINCH {
                    resize_burst.note();
                    continue;
                }
                // `emulate_default_handler` re-raises, which is what makes a handled
                // SIGTSTP stop anything at all.
                if signal == signal_hook::consts::SIGTSTP {
                    restore_terminal();
                    blind_reset();
                    let _ = signal_hook::low_level::emulate_default_handler(
                        signal_hook::consts::SIGTSTP,
                    );
                    continue;
                }
                // `kill -STOP` then `fg`: the shell has nothing saved to restore for a job
                // it never stopped, and left the terminal cooked.
                if signal == signal_hook::consts::SIGCONT {
                    let _ = enter_raw(io::stdin().as_fd());
                    // `kill -STOP` is uncatchable, so this is the only place the model is
                    // told the shell drew over its rows.
                    signal_display.invalidate();
                    log!("resumed: prediction and screen model reset");
                    let _ = resize_writer.request_repaint();
                    continue;
                }
                // SIGSEGV and SIGBUS are deliberately not here: a handler that returns
                // re-runs the faulting instruction forever, and one that does not needs
                // `unsafe` this crate forbids.
                //
                // Termios first and no lock: the reader loop holds the display across its
                // write, and a terminal that stopped draining blocks it forever — which is
                // exactly when SIGTERM has to work.
                log!("terminated by signal {signal}");
                restore_terminal();
                blind_reset();
                std::process::exit(128 + signal);
            }
        }))
        .map_err(|_| io::Error::other("signal thread failed"))?;

    let mut expected = state.next_output_offset();
    // A screen makes the next `Output` a resume point no earlier checkpoint names.
    let mut painted = false;
    let mut reorder = Reorder::default();
    let mut window = expected.checked_add(CONSUMED_STRIDE).unwrap_or(expected);
    // Read from the last `Ping` rather than from under the writer's lock per held chunk.
    let mut srtt = None;
    // Reused: a frame per keystroke echo otherwise costs a fresh zeroed allocation.
    let mut payload = Vec::new();
    // Output the session says this client will never be handed, summed over every
    // resume this process makes. Reported on the way out rather than mid-session:
    // this thread is in raw mode and owns no row it could print a notice on.
    let mut skipped = 0_u64;
    loop {
        match next_frame(&mut inbound, &mut payload, &display) {
            Ok(()) => {}
            Err(error) if error.is_transport_loss() => {
                // No short circuit for a close already asked for: the daemon drops
                // the attachment as it ends the session, so the loss racing the
                // `Exit` that answers a `Close` is the ordinary way a quit lands
                // under load. `reconnect` reads the same flag and answers
                // `Reconnected::Closed` without dialling, which is the exit this
                // path wants — reporting an `EAGAIN` on the way out is not.
                // The terminal misses whatever the application does meanwhile, so the next
                // screen restates every mode rather than diffing.
                log!("link lost ({error}); prediction and screen model reset");
                input.disconnect()?;
                display.lock()?.invalidate();
                drop(transport.take());
                let resumed = match reconnect(
                    destination,
                    &Reopen::Session(&state),
                    &input,
                    &StatusLine(&display),
                ) {
                    Ok(Reconnected::Link(resumed)) => resumed,
                    Ok(Reconnected::Closed) => {
                        checkpoint.force(&state);
                        display.lock()?.teardown()?;
                        drop(raw);
                        eprintln!("[brd] detached; reattach with: brd {destination}");
                        return Ok(());
                    }
                    // Terminal here, unlike the forward-only client: a fresh session in
                    // place of this user's shell is an empty screen where their work was.
                    Ok(Reconnected::Gone) => {
                        let _ = display.lock().map(|mut display| display.teardown());
                        drop(raw);
                        return Err(ClientError::Remote(RejectReason::UnknownSession));
                    }
                    // The indicator owns the bottom row of a raw-mode screen.
                    Err(error) => {
                        let _ = display.lock().map(|mut display| display.teardown());
                        drop(raw);
                        return Err(error);
                    }
                };
                transport = Some(resumed.transport);
                // A replacement transport has measured nothing yet.
                deadline.set(LINK_TIMEOUT);
                inbound = Inbound::ssh(resumed.output, deadline.clone())?;
                version = resumed.version;
                input.reconnect(Link::Ssh(Outbox::new(resumed.input)), resumed.version)?;
                // Before the repaint, so the screen is owed on the attachment that survives.
                if let Some((datagrams, spoken)) =
                    upgrade(resumed.offer, &state, &deadline, &input)?
                {
                    inbound = datagrams;
                    version = spoken;
                    transport = None;
                }
                // Every forward held bytes against a sink that refused them, and the pump
                // thread cannot see this event for itself.
                if let Some(forwards) = forwards.as_ref() {
                    forwards.link_restored();
                }
                // Chunks held against the old stream position describe replayed bytes.
                reorder.clear();
                // The window may have been resized while the link was down.
                if let Ok(size) = terminal_size(io::stdin().as_fd()) {
                    note_terminal_size(size);
                    input.resize(size)?;
                }
                // Erasing the indicator leaves the bottom row blank, and a replay repaints
                // everything except the row it was written over.
                input.repaint_arrived();
                input.request_repaint()?;
                continue;
            }
            Err(error) => return Err(ClientError::Protocol(error)),
        }
        match ServerMessage::decode(&payload, version)? {
            ServerMessage::Output {
                off,
                bytes,
                cue,
                echo_ack,
            } => {
                // On a datagram link a chunk out of place is far more often the one behind
                // it overtaking than the one behind it lost, so only a gap too wide or too
                // old to be a reorder asks for a screen, and then exactly once.
                if place_output(expected, off, bytes.len()).is_none() {
                    let now = Instant::now();
                    if off.get() >= expected.get() {
                        reorder.hold(off, bytes, cue, echo_ack, now);
                    }
                    if reorder.lost(now, reorder_deadline(srtt)) {
                        reorder.clear();
                        input.request_repaint()?;
                    }
                    continue;
                }
                let mut chunk = Some((bytes, cue, echo_ack));
                while let Some((bytes, cue, echo_ack)) = chunk.take() {
                    let Some(next) = expected.checked_add(bytes.len()) else {
                        break;
                    };
                    let repair = display.lock()?.output(&bytes, cue, echo_ack)?;
                    if repair {
                        input.request_repaint()?;
                    }
                    expected = next;
                    state.note_output(expected);
                    chunk = reorder.take(expected);
                }
                // Opened as the terminal drains rather than when the server next probes.
                if expected.get() >= window.get() {
                    input.consumed(expected)?;
                    window = expected.checked_add(CONSUMED_STRIDE).unwrap_or(expected);
                }
                // A checkpoint is an `fsync`, so the terminal is drained before one.
                if painted || checkpoint.due() {
                    display.lock()?.flush()?;
                }
                if painted {
                    // Once per burst, not once per frame — the write is an fsync, and doing
                    // it per screen stalls this loop badly enough that a session under
                    // backpressure stops draining (`e2e.py`'s flood check).
                    painted = false;
                    checkpoint.force(&state);
                } else {
                    checkpoint.note(&state);
                }
            }
            ServerMessage::Screen { part } => {
                // Bound to a statement, not left as a match scrutinee: a temporary there
                // lives to the end of the match, so the arms below would take the outbound
                // lock while still holding the display. The grid is the smallest attached
                // terminal, so a scroll is the session's only at equal height.
                let assembled = display.lock()?.part(part, status_size().rows)?;
                match assembled {
                    Ok(Some(screen)) => {
                        input.repaint_arrived();
                        input.screen_ack(screen.generation, screen.version)?;
                        // The screen restates the position, so held chunks describe bytes
                        // it has already painted over.
                        reorder.clear();
                        expected = screen.next_off;
                        window = expected.checked_add(CONSUMED_STRIDE).unwrap_or(expected);
                        state.confirm(screen.generation, screen.next_off);
                        painted = true;
                        if checkpoint.due() {
                            display.lock()?.flush()?;
                        }
                        checkpoint.note(&state);
                    }
                    // The server still carries the damage, so the next screen names it again.
                    Ok(None) => {}
                    // The piece builds on a screen this client is not showing.
                    Err(_) => input.request_repaint()?,
                }
            }
            ServerMessage::Ping {
                token,
                echo_ack,
                interval_ms,
            } => {
                input.pong(token, expected)?;
                // The latency gate reads this: predicting on a link that answers inside a
                // keypress can only add risk.
                srtt = input.srtt()?;
                display.lock()?.observed_rtt(srtt);
                // The server paces its probes against the link it is measuring.
                deadline.set(silence_deadline(interval_ms));
                // The only clock this loop has once output stops: a datagram lost at the end
                // of a burst leaves the chunks behind it held with nothing to age the gap out.
                if reorder.lost(Instant::now(), reorder_deadline(srtt)) {
                    reorder.clear();
                    input.request_repaint()?;
                }
                // A silent application still owes an answer for the keystrokes drawn at it.
                if display.lock()?.echo_ack(echo_ack) {
                    input.request_repaint()?;
                }
            }
            // The session converged this terminal with a screen instead of the history
            // it asked for. Nothing is repairable: those bytes are gone from this
            // terminal's scrollback, and only the far side still has them.
            ServerMessage::OutputSkipped { bytes } => {
                skipped = skipped.saturating_add(bytes);
                log!("session skipped {bytes} bytes of output on resume ({skipped} total)");
            }
            ServerMessage::Detached { reason } => {
                // The session outlives this attachment, so the checkpoint must name it again.
                checkpoint.force(&state);
                display.lock()?.teardown()?;
                drop(raw);
                drop(transport);
                match reason {
                    DetachReason::Requested => {
                        eprintln!("[brd] detached; reattach with: brd {destination}");
                    }
                    DetachReason::Replaced => {
                        eprintln!("[brd] another client took over this session");
                    }
                }
                report_skipped(skipped, destination);
                return Ok(());
            }
            ServerMessage::CommandAck { highest } => {
                if let Some(highest) = highest {
                    input.acknowledge(highest)?;
                    // The ack shares the ordered stream with the output, so output after it
                    // could be that keystroke's echo and output before it cannot.
                    display.lock()?.acknowledged(highest);
                }
            }
            ServerMessage::Exit { code } => {
                checkpoint.force(&state);
                display.lock()?.teardown()?;
                drop(raw);
                // The daemon keeps its half of the attachment socket open while the reader
                // thread parks, so waiting on the transport would never return.
                drop(transport);
                report_skipped(skipped, destination);
                return if input.close_requested.load(Ordering::Acquire) || code == 0 {
                    Ok(())
                } else {
                    Err(ClientError::RemoteExit(code))
                };
            }
            // The rest describe an attachment the daemon just dropped, and the transport
            // loss behind this frame is what resumes the session.
            ServerMessage::Reject { reason } => {
                if reason.is_terminal() {
                    display.lock()?.teardown()?;
                    return Err(ClientError::Remote(reason));
                }
            }
            // A copy into the stream's receive buffer and nothing else: this thread also
            // holds the display lock for every terminal write, and a forward moving a
            // gigabyte must not stall a keystroke echo. A frame naming a stream this client
            // is not carrying is ignored: ending the session would lose a shell to a tunnel.
            ServerMessage::ForwardData {
                stream,
                off,
                fin,
                bytes,
            } => {
                if let Some(forwards) = forwards.as_ref() {
                    forwards.on_data(stream, off, fin, &bytes);
                }
            }
            ServerMessage::ForwardAck {
                stream,
                off,
                window,
                held,
            } => {
                if let Some(forwards) = forwards.as_ref() {
                    forwards.on_ack(stream, off, window, &held);
                }
            }
            ServerMessage::ForwardReset { stream, .. } => {
                if let Some(forwards) = forwards.as_ref() {
                    forwards.on_reset(stream);
                }
            }
            // `Hello` is answered before this loop; lists and searches get their own
            // management connection.
            ServerMessage::Hello { .. }
            | ServerMessage::HelloForward { .. }
            | ServerMessage::SessionList { .. }
            | ServerMessage::SearchResults { .. } => {
                return Err(ClientError::Protocol(
                    braid_proto::DecodeError::InvalidField,
                ));
            }
        }
    }
}

/// A `read` that *failed* means this attachment is over and nothing else: `EIO` is what a
/// revoked controlling terminal and a background read with `SIGTTIN` ignored both return,
/// and only `Closed` ends the remote shell.
enum InputEnd {
    Closed,
    Detached,
    Silent,
}

impl std::fmt::Display for InputEnd {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Closed => "end of input, closing the session",
            Self::Detached => "terminal unreadable or detach requested, leaving the session up",
            Self::Silent => "the transport is gone",
        })
    }
}

/// `Close` ends the user's shell and everything in it, and no reattachment brings it back.
fn farewell<W: FrameSink>(end: &InputEnd, output: &ClientWriter<W>) -> Result<(), ClientError> {
    match end {
        InputEnd::Closed => output.close(),
        InputEnd::Detached => output.detach(),
        InputEnd::Silent => Ok(()),
    }
}

fn input_loop<R: Read, W: FrameSink, D: Write>(
    mut input: R,
    output: &ClientWriter<W>,
    display: &Shared<D>,
    interrupted: &AtomicBool,
) -> InputEnd {
    let mut bytes = [0_u8; 4096];
    let mut pending = Vec::with_capacity(bytes.len());
    let mut detach_prefix = false;
    let end = loop {
        let count = match input.read(&mut bytes) {
            Ok(0) => break InputEnd::Closed,
            // Not the user asking to be finished: this costs the attachment, not the session.
            Err(error) => {
                log!("input: read failed, {error}");
                break InputEnd::Detached;
            }
            Ok(count) => count,
        };
        pending.clear();
        for &byte in &bytes[..count] {
            if detach_prefix {
                detach_prefix = false;
                match byte {
                    b'r' => {
                        let _ = output.request_repaint();
                    }
                    b'd' | b'.' => {
                        // Typing ahead of the binding is still input, not part of it.
                        if !pending.is_empty() && output.input(&pending).is_err() {
                            return InputEnd::Silent;
                        }
                        return if byte == b'd' {
                            InputEnd::Detached
                        } else {
                            InputEnd::Closed
                        };
                    }
                    // Suspend, as job control would if raw mode had left the driver a key
                    // for it. The signal thread owns the teardown.
                    b'z' => {
                        if !pending.is_empty() && output.input(&pending).is_err() {
                            return InputEnd::Silent;
                        }
                        pending.clear();
                        // Those bytes went to the session without reaching the predictor.
                        interrupted.store(true, Ordering::Release);
                        let _ = signal_hook::low_level::raise(signal_hook::consts::SIGTSTP);
                    }
                    // The prefix escapes itself: two presses send one 0x1d.
                    0x1d => pending.push(0x1d),
                    other => {
                        pending.push(0x1d);
                        pending.push(other);
                    }
                }
            } else if byte == 0x1d {
                detach_prefix = true;
            } else {
                pending.push(byte);
            }
        }
        if !pending.is_empty() {
            let (queued, sent_as) = match output.input(&pending) {
                Ok(Accepted::All(seq)) => (pending.len(), seq),
                // The rest was refused, so the terminal must not show it.
                Ok(Accepted::Partial { queued, seq }) => (queued, seq),
                Err(_) => return InputEnd::Silent,
            };
            // `try_lock`, because a prediction is an optimisation and transmission is not:
            // the reader loop holds this lock across its write to the terminal, so waiting
            // here puts local backpressure in front of the *next* keystroke, which is how a
            // Ctrl-C ends up queued behind a flood.
            if let Some(mut display) = display.try_lock() {
                let since = if interrupted.swap(false, Ordering::AcqRel) {
                    Typing::Interrupted
                } else {
                    Typing::Continuous
                };
                let _ = display.predict(&pending[..queued], sent_as, since);
            } else {
                // `predict` is the only place a run ends, so a Return that fails to end one
                // stays confirmed into the password prompt the Return reached.
                interrupted.store(true, Ordering::Release);
            }
        }
    };
    // A prefix key typed with nothing after it is still a keystroke.
    if detach_prefix {
        let _ = output.input(&[0x1d]);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use braid_proto::{
        ByteOff, CAPABILITY_BYTES, Capability, ClientId, ConfirmedOutput, CursorShape,
        ForwardResetReason, ForwardTarget, Generation, InputCue, MIN_DATAGRAM_FRAME, ModeSet,
        RowFrame, RowSpan, SackRuns, ScreenHeader, ScreenPart, ScreenVersion, StickyState,
        StreamId,
    };
    use inbound::{MAX_LINK_TIMEOUT, MAX_REORDER_WAIT, MIN_LINK_TIMEOUT, MIN_REORDER_WAIT};
    use journal::{CommandJournal, JournalError};
    use outbound::{Carriage, INITIAL_RESEND, Progress, Resend};
    use state::{REMEMBERED_SESSIONS, load_sessions, save_sessions, state_root, sweep_staging};
    use std::fmt::Write as _;
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;
    use terminal::{BLIND_RESET, install_panic_hook};

    /// Three of these carry text this process did not write.
    #[test]
    fn an_error_names_whose_words_it_carries() {
        for (error, text) in [
            (
                ClientError::Ssh("unix_listener: path too long".into()),
                "ssh: unix_listener: path too long",
            ),
            (
                ClientError::Remote(RejectReason::UnknownSession),
                "remote: session is no longer available",
            ),
            (
                ClientError::Io(io::Error::other("terminal lock poisoned")),
                "local I/O: terminal lock poisoned",
            ),
            (ClientError::RemoteExit(3), "server exited with status 3"),
        ] {
            assert_eq!(error.to_string(), text);
        }
    }

    /// That thread also answers SIGTERM, SIGHUP and SIGTSTP, each of which must reach the
    /// termios restore promptly.
    #[test]
    fn a_resize_burst_is_waited_out_off_the_thread_that_noticed_it() {
        let pending = Arc::new(PendingResize::default());
        let waiting = Arc::clone(&pending);
        let settling = thread::spawn(move || {
            waiting.settled().expect("a burst settles");
            Instant::now()
        });
        let burst = Instant::now();
        for _ in 0..20 {
            pending.note();
        }
        let noting = burst.elapsed();
        assert!(
            noting < RESIZE_SETTLE,
            "a whole drag was noted on the signal thread in {noting:?}"
        );
        let settled = settling.join().expect("the settle thread finishes");
        assert!(
            settled.duration_since(burst) >= RESIZE_SETTLE,
            "the terminal was read before the burst had settled"
        );
    }

    fn messages(bytes: &[u8]) -> Vec<ClientMessage> {
        let mut input = bytes;
        let mut result = Vec::new();
        while !input.is_empty() {
            let payload = read_frame(&mut input, MAX_FRAME).expect("test output should be framed");
            result.push(
                ClientMessage::decode(&payload, Version::LOCAL).expect("test output should decode"),
            );
        }
        result
    }

    struct Recorder {
        queued: Mutex<Vec<u8>>,
        carriage: Carriage,
    }

    impl Default for Recorder {
        fn default() -> Self {
            Self {
                queued: Mutex::new(Vec::new()),
                carriage: Carriage::Stream,
            }
        }
    }

    impl Recorder {
        fn datagram() -> Self {
            Self {
                carriage: Carriage::Datagram,
                ..Self::default()
            }
        }
    }

    impl FrameSink for Recorder {
        fn carriage(&self) -> Carriage {
            self.carriage
        }

        fn send(&self, frame: Vec<u8>) -> bool {
            self.queued
                .lock()
                .map(|mut queued| queued.extend_from_slice(&frame))
                .is_ok()
        }
    }

    #[derive(Default)]
    struct Backpressured {
        queued: Mutex<Vec<u8>>,
        full: AtomicBool,
    }

    impl FrameSink for Backpressured {
        fn carriage(&self) -> Carriage {
            Carriage::Stream
        }

        fn send(&self, frame: Vec<u8>) -> bool {
            !self.full.load(Ordering::Acquire) && self.send_reserved(frame)
        }

        fn send_reserved(&self, frame: Vec<u8>) -> bool {
            self.queued
                .lock()
                .map(|mut queued| queued.extend_from_slice(&frame))
                .is_ok()
        }
    }

    fn capability(byte: u8) -> Capability {
        Capability::from_bytes([byte; CAPABILITY_BYTES])
    }

    fn seq(value: u64) -> CmdSeq {
        CmdSeq::from_u64(value).expect("a test sequence is non-zero")
    }

    fn stream_writer() -> ClientWriter<Recorder> {
        ClientWriter::new(Recorder::default(), CmdSeq::first(), Version::LOCAL)
    }

    fn datagram_writer() -> ClientWriter<Recorder> {
        ClientWriter::new(Recorder::datagram(), CmdSeq::first(), Version::LOCAL)
    }

    fn input_of(value: u64, bytes: &[u8]) -> ClientMessage {
        ClientMessage::Input {
            seq: seq(value),
            bytes: bytes.to_vec(),
        }
    }

    fn written(writer: &ClientWriter<Recorder>) -> Vec<u8> {
        writer
            .state
            .lock()
            .expect("writer lock")
            .output
            .as_ref()
            .map(|recorder| recorder.queued.lock().expect("recorder lock").clone())
            .unwrap_or_default()
    }

    fn terminal() -> Shared<Vec<u8>> {
        Shared::new(Display::new(Vec::new(), Prediction::Always))
    }

    fn shown(display: &Shared<Vec<u8>>) -> Vec<u8> {
        display.lock().expect("display lock").out.clone()
    }

    #[derive(Clone, Default)]
    struct CountedWrites(Arc<std::sync::atomic::AtomicUsize>);

    impl Write for CountedWrites {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn counted_terminal() -> (
        Shared<io::BufWriter<CountedWrites>>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let sink = CountedWrites::default();
        let writes = Arc::clone(&sink.0);
        (
            Shared::new(Display::new(
                io::BufWriter::with_capacity(MAX_OUTPUT_CHUNK, sink),
                Prediction::Never,
            )),
            writes,
        )
    }

    fn output_burst(count: u64) -> Vec<u8> {
        (0..count)
            .flat_map(|index| {
                ServerMessage::Output {
                    off: ByteOff::from_u64(index),
                    bytes: vec![b'x'],
                    cue: InputCue::Opaque,
                    echo_ack: None,
                }
                .encode(Version::LOCAL)
                .expect("an output frame encodes")
            })
            .collect()
    }

    /// `cat` rather than a pipe: [`Inbound::ssh`] is typed by the descriptor `ssh` hands over.
    fn relay(timeout: Duration) -> (std::process::Child, ChildStdin, Inbound) {
        let mut child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("cat stands in for the transport");
        let into = child.stdin.take().expect("the relay takes frames");
        let from = child.stdout.take().expect("the relay gives them back");
        let inbound = Inbound::ssh(from, Deadline::new(timeout)).expect("a pipe takes O_NONBLOCK");
        (child, into, inbound)
    }

    fn paint<W: Write>(payload: &[u8], display: &Shared<W>) {
        let ServerMessage::Output {
            bytes,
            cue,
            echo_ack,
            ..
        } = ServerMessage::decode(payload, Version::LOCAL).expect("an output frame decodes")
        else {
            panic!("the relay carried something other than output");
        };
        display
            .lock()
            .expect("display lock")
            .output(&bytes, cue, echo_ack)
            .expect("the terminal takes the bytes");
    }

    /// A flush per frame would defeat the buffer under it: a mebibyte in 1160-byte writes
    /// costs 904 syscalls and 280.8us against a draining pipe, where the same bytes in
    /// 9280-byte writes cost 113 and 128.6us. The lone frame is a keystroke echo.
    #[test]
    fn frames_in_hand_coalesce_and_the_last_one_is_flushed_before_the_park() {
        for burst in [1_u64, 8] {
            let (mut child, mut into, mut inbound) = relay(Duration::from_millis(250));
            let (display, writes) = counted_terminal();
            into.write_all(&output_burst(burst)).expect("the burst");
            into.flush().expect("the burst");

            let mut payload = Vec::new();
            for _ in 0..burst {
                next_frame(&mut inbound, &mut payload, &display).expect("a queued frame arrives");
                paint(&payload, &display);
            }
            let coalesced = writes.load(Ordering::Relaxed);
            assert!(
                u64::try_from(coalesced).expect("a write count fits") < burst,
                "{burst} frames already in hand cost the terminal {coalesced} writes"
            );

            // Nothing else is coming, so the bytes are handed over rather than left behind.
            let parked = next_frame(&mut inbound, &mut payload, &display)
                .expect_err("silence past the deadline");
            assert!(
                parked.is_transport_loss(),
                "a park that gave up: {parked:?}"
            );
            assert_eq!(
                writes.load(Ordering::Relaxed),
                coalesced + 1,
                "the whole burst reached the terminal in one write, before the park"
            );

            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn drive<R: Read>(
        input: R,
        writer: &ClientWriter<Recorder>,
        display: &Shared<Vec<u8>>,
    ) -> InputEnd {
        let end = input_loop(input, writer, display, &AtomicBool::new(false));
        let _ = farewell(&end, writer);
        end
    }

    fn typed(bytes: &[u8], writer: &ClientWriter<Recorder>, display: &Shared<Vec<u8>>) -> InputEnd {
        drive(Cursor::new(bytes.to_vec()), writer, display)
    }

    struct Unreadable(io::ErrorKind);

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
    }

    /// `EIO` is what a revoked controlling terminal and a background read with `SIGTTIN`
    /// ignored both return; `Close` would end the shell on the far side and all in it.
    #[test]
    fn a_terminal_that_cannot_be_read_costs_the_attachment_and_not_the_session() {
        let writer = stream_writer();
        let end = drive(Unreadable(io::ErrorKind::Other), &writer, &terminal());
        assert!(
            matches!(end, InputEnd::Detached),
            "a read error is a detach"
        );
        assert_eq!(
            messages(&written(&writer)),
            vec![ClientMessage::Detach {
                seq: CmdSeq::first()
            }],
            "a broken keyboard ended the user's shell"
        );
    }

    /// The type is what keeps a later edit from folding the three back together.
    #[test]
    fn each_way_the_keyboard_ends_says_what_it_means() {
        let close = ClientMessage::Close {
            seq: CmdSeq::first(),
        };
        for (keys, end, sent) in [
            (&b""[..], InputEnd::Closed, vec![close.clone()]),
            (
                &b"\x1dd"[..],
                InputEnd::Detached,
                vec![ClientMessage::Detach {
                    seq: CmdSeq::first(),
                }],
            ),
            (&b"\x1d."[..], InputEnd::Closed, vec![close.clone()]),
            (
                &b"\x1dr"[..],
                InputEnd::Closed,
                vec![
                    ClientMessage::RequestRepaint {
                        seq: CmdSeq::first(),
                    },
                    ClientMessage::Close { seq: seq(2) },
                ],
            ),
            // The prefix escapes itself: two presses send one 0x1d, not two.
            (
                &b"\x1d\x1d"[..],
                InputEnd::Closed,
                vec![input_of(1, &[0x1d]), ClientMessage::Close { seq: seq(2) }],
            ),
        ] {
            let writer = stream_writer();
            let ended = typed(keys, &writer, &terminal());
            assert_eq!(
                std::mem::discriminant(&ended),
                std::mem::discriminant(&end),
                "{keys:?} ended as {ended}"
            );
            assert_eq!(messages(&written(&writer)), sent, "{keys:?}");
        }
    }

    fn whole_screen(size: GridSize, version: ScreenVersion, rows: &[&str]) -> ScreenPart {
        ScreenPart::Head {
            header: ScreenHeader {
                generation: Generation::initial(),
                version,
                next_off: ByteOff::zero(),
                size,
                cursor: Some((0, 0)),
                cursor_visible: true,
                cursor_shape: CursorShape::Block,
                cursor_blinking: false,
                modes: ModeSet::empty(),
                sticky: StickyState::default(),
            },
            base: None,
            scroll: None,
            pieces: 1,
            rows: rows
                .iter()
                .enumerate()
                .map(|(row, text)| RowSpan {
                    row: u16::try_from(row).expect("a short screen"),
                    chunk: false,
                    col: 0,
                    byte: 0,
                    clear_tail: false,
                    frame: RowFrame {
                        cells: u16::try_from(text.chars().count()).expect("a short row"),
                        text: (*text).into(),
                        runs: Vec::new(),
                    },
                })
                .collect(),
        }
    }

    fn repaint_over(
        display: &Shared<Vec<u8>>,
        size: GridSize,
        interrupt: impl FnOnce(),
    ) -> Vec<u8> {
        display
            .lock()
            .expect("display lock")
            .part(
                whole_screen(size, ScreenVersion::initial(), &["aaaa", "bbbb"]),
                size.rows,
            )
            .expect("a whole screen applies")
            .expect("every piece of a one-piece screen arrived");
        interrupt();
        display.lock().expect("display lock").out.clear();
        display
            .lock()
            .expect("display lock")
            .part(
                whole_screen(size, ScreenVersion::initial().next(), &["aaaa", "cccc"]),
                size.rows,
            )
            .expect("a whole screen applies")
            .expect("every piece of a one-piece screen arrived");
        shown(display)
    }

    /// `kill -STOP` is uncatchable, so `invalidate` on the way out is all that ever tells
    /// this client its rows are a guess — and a missed `try_lock` must not discard it.
    #[test]
    fn a_resume_that_missed_the_display_lock_still_stops_the_client_trusting_its_rows() {
        const ERASE: &[u8] = b"\x1b[2J\x1b[H";
        let size = GridSize { cols: 4, rows: 2 };

        let trusted = terminal();
        let diffed = repaint_over(&trusted, size, || {});
        assert!(
            !diffed.windows(ERASE.len()).any(|seen| seen == ERASE),
            "a trusted model was repainted from scratch, so the test proves nothing"
        );

        let display = terminal();
        let repainted = repaint_over(&display, size, || {
            // SIGCONT, arriving while the reader loop is painting.
            let _painting = display.lock().expect("display lock");
            display.invalidate();
        });
        assert!(
            repainted.windows(ERASE.len()).any(|seen| seen == ERASE),
            "the resume was dropped and the terminal kept being diffed against stale rows"
        );
    }

    /// The reader loop holds the display across its write, so taking the lock here queues
    /// the next keystroke behind a stalled terminal (`e2e.py`, "flood: Ctrl-C landed").
    #[test]
    fn typing_is_transmitted_while_the_terminal_is_held() {
        let writer = stream_writer();
        let display = terminal();
        let held = display.lock().expect("display lock");
        typed(b"\x03", &writer, &display);
        drop(held);
        assert_eq!(
            messages(&written(&writer)),
            vec![input_of(1, &[0x03]), ClientMessage::Close { seq: seq(2) },]
        );
    }

    /// In the order the reader loop sees: the ack for the PTY write, then the output it
    /// produced. Without the ack the echo is output the application could have made itself.
    fn confirmed_run(display: &Shared<Vec<u8>>) {
        let mut terminal = display.lock().expect("display lock");
        terminal
            .output(b"$ ", InputCue::Echoing { room: 40 }, None)
            .expect("prompt");
        terminal
            .predict(b"l", Some(CmdSeq::first()), Typing::Continuous)
            .expect("tentative keystroke");
        terminal.acknowledged(CmdSeq::first());
        terminal
            .output(b"l", InputCue::Echoing { room: 39 }, None)
            .expect("echo");
    }

    #[test]
    fn a_confirmed_run_draws_typing_and_the_echo_it_predicted_is_suppressed() {
        let writer = stream_writer();
        let display = terminal();
        confirmed_run(&display);
        typed(b"s", &writer, &display);
        assert_eq!(
            messages(&written(&writer)),
            vec![input_of(1, b"s"), ClientMessage::Close { seq: seq(2) }]
        );
        assert_eq!(
            shown(&display),
            b"$ ls",
            "drawn without waiting for the echo"
        );
        let mut terminal = display.lock().expect("display lock");
        assert!(
            !terminal
                .output(b"s", InputCue::Echoing { room: 38 }, None)
                .expect("echo"),
            "a matched echo is not a repair"
        );
        assert_eq!(terminal.out, b"$ ls", "and is not written a second time");
    }

    /// The reader thread holds the display across `absorb`, the write and the flush of
    /// every output frame — exactly when a command line's echo and the `Password:` under it
    /// are painted — and `predict` is the only caller of the stall that ends a run.
    #[test]
    fn a_keystroke_the_display_lock_swallowed_still_ends_the_run() {
        let writer = stream_writer();
        let display = terminal();
        confirmed_run(&display);
        let interrupted = AtomicBool::new(false);
        {
            // Return, typed while the reader thread is painting the prompt.
            let _painting = display.lock().expect("display lock");
            input_loop(Cursor::new(b"\r".to_vec()), &writer, &display, &interrupted);
        }
        assert!(
            interrupted.load(Ordering::Acquire),
            "a keystroke the predictor never saw is recorded as one"
        );
        input_loop(Cursor::new(b"h".to_vec()), &writer, &display, &interrupted);
        assert_eq!(
            shown(&display),
            b"$ l",
            "the first byte of the password is not drawn"
        );
    }

    /// A cumulative ack cannot advance past the oldest thing the server is missing, so one
    /// that repeats on a link still carrying traffic says the front has not arrived.
    #[test]
    fn a_repeated_acknowledgement_resends_the_front_at_once() {
        let writer = datagram_writer();
        writer.input(b"a").expect("typing is queued");
        writer.input(b"b").expect("typing is queued");
        writer.acknowledge(seq(1)).expect("the ack lands");
        writer.acknowledge(seq(1)).expect("the same ack again");
        let front = input_of(2, b"b");
        assert_eq!(
            messages(&written(&writer)),
            vec![input_of(1, b"a"), front.clone(), front],
            "the front of the journal goes again without waiting for the timer"
        );
        let repeated = written(&writer).len();
        writer.acknowledge(seq(1)).expect("and again");
        assert_eq!(
            written(&writer).len(),
            repeated,
            "one fast retransmit per stalled acknowledgement, not one per ack"
        );
    }

    /// A server probing steadily would push the deadline out ahead of itself forever.
    #[test]
    fn a_repeated_acknowledgement_does_not_restart_the_resend_timer() {
        let mut resend = Resend::default();
        let start = Instant::now();
        assert_eq!(resend.acknowledged(seq(1), start), Progress::Advanced);
        resend.transmitted(None, start);
        assert_eq!(
            resend.acknowledged(seq(1), start + Duration::from_millis(200)),
            Progress::Stalled
        );
        assert!(
            resend.due(start + INITIAL_RESEND),
            "the wait runs from the transmission, not from the acknowledgement"
        );
    }

    /// One typed byte must not cost a heap allocation beside the one the frame needs.
    #[test]
    fn an_acknowledged_input_buffer_carries_the_next_keystroke() {
        let writer = stream_writer();
        writer.input(b"a").expect("typing is queued");
        assert_eq!(
            writer.state.lock().expect("writer lock").spare.capacity(),
            0,
            "nothing has been retired yet, so the first keystroke allocates"
        );
        writer.acknowledge(seq(1)).expect("the ack lands");
        assert!(
            writer.state.lock().expect("writer lock").spare.capacity() > 0,
            "the retired command handed its buffer back"
        );
        writer.input(b"b").expect("typing is queued");
        assert_eq!(
            writer.state.lock().expect("writer lock").spare.capacity(),
            0,
            "and the next keystroke took it rather than allocating again"
        );
    }

    /// Otherwise ~1024 keystrokes during a disconnect kill a recoverable session.
    #[test]
    fn input_typed_while_disconnected_costs_no_journal_entries() {
        let writer = stream_writer();
        writer.disconnect().unwrap();
        for _ in 0..4_000 {
            writer.input(b"x").unwrap();
        }
        {
            let state = writer.state.lock().unwrap();
            assert!(state.journal.is_empty());
            assert_eq!(state.next_seq, CmdSeq::first());
            assert_eq!(state.pending.len(), 4_000);
        }

        writer
            .reconnect(Recorder::default(), Version::LOCAL)
            .unwrap();
        assert_eq!(
            messages(&written(&writer)),
            vec![input_of(1, &vec![b'x'; 4_000])],
            "contiguous input must coalesce into one message"
        );
        assert!(writer.state.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn backoff_doubles_up_to_a_ceiling() {
        assert_eq!(reconnect_backoff(0), Duration::from_millis(250));
        assert_eq!(reconnect_backoff(1), Duration::from_millis(500));
        assert_eq!(reconnect_backoff(4), Duration::from_secs(4));
        assert_eq!(reconnect_backoff(20), Duration::from_secs(30));
        assert_eq!(reconnect_backoff(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn the_journal_retains_only_unacknowledged_commands() {
        let mut journal = CommandJournal::new(std::num::NonZeroUsize::new(2).unwrap());
        let first = input_of(1, b"a");
        let second = input_of(2, b"b");
        journal.push(CmdSeq::first(), first).unwrap();
        journal
            .push(CmdSeq::first().next(), second.clone())
            .unwrap();
        assert_eq!(
            journal.push(CmdSeq::first().next().next(), second.clone()),
            Err(JournalError::Full)
        );
        journal.acknowledge(CmdSeq::first());
        assert_eq!(journal.all(), vec![second]);
    }

    /// A `ForwardData` numbered into the command stream would stall the server's gate
    /// behind its own retransmission and hold every later keystroke there.
    #[test]
    fn forward_payload_stays_out_of_the_ordered_command_stream() {
        let writer = stream_writer();
        let stream = StreamId::first();
        writer
            .forward_open(
                stream,
                ForwardTarget {
                    host: "intranet".into(),
                    port: 80,
                },
            )
            .expect("an empty journal has room for an open");
        let numbered = {
            let state = writer.lock().expect("the writer");
            (state.next_seq, state.journal.all().len())
        };
        assert_eq!(numbered, (CmdSeq::first().next(), 1));

        for message in [
            ClientMessage::ForwardData {
                stream,
                off: ByteOff::zero(),
                fin: false,
                bytes: b"hello".to_vec(),
            },
            ClientMessage::ForwardAck {
                held: SackRuns::EMPTY,
                stream,
                off: ByteOff::zero(),
                window: 1024,
            },
            ClientMessage::ForwardReset {
                stream,
                reason: ForwardResetReason::Closed,
            },
        ] {
            assert!(
                writer.forward_frame(&message).expect("the sink takes it"),
                "a forward frame the link accepted must report so"
            );
        }
        let after = {
            let state = writer.lock().expect("the writer");
            (state.next_seq, state.journal.all().len())
        };
        assert_eq!(
            after, numbered,
            "forward payload took a sequence or a journal entry"
        );
        // All four are on the wire; only the open is replayable off it.
        assert_eq!(messages(&written(&writer)).len(), 4);
    }

    /// `ExitOnForwardFailure=yes`: the session that would have failed next never opens.
    #[test]
    fn a_forward_that_cannot_bind_aborts_before_a_session_is_opened() {
        let held =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("a held port");
        let taken = held.local_addr().expect("the held address");
        let spec = forward::ForwardSpec {
            bind: taken.ip(),
            port: taken.port(),
            target: ForwardTarget {
                host: "intranet".into(),
                port: 80,
            },
        };
        // A destination no `ssh` reaches: its refusal is what would come back instead.
        let refused = run(
            "brd.invalid",
            &[],
            None,
            Prediction::Never,
            std::slice::from_ref(&spec),
        )
        .expect_err("a port that cannot be bound must end the run");
        assert!(
            matches!(refused, ClientError::Forward(_)),
            "the bind is what must have failed: {refused}"
        );
        assert!(
            refused.to_string().contains(&taken.to_string()),
            "the message must name the address: {refused}"
        );
    }

    #[test]
    fn reconnect_state_resumes_from_the_confirmed_offset() {
        let mut state = ReconnectState::new(SessionId::from_bytes([9; 16]), capability(4));
        state.confirm(Generation::initial(), ByteOff::from_u64(4_096));
        let ClientMessage::Resume { seq, request, .. } =
            state.resume_message(CmdSeq::first().next())
        else {
            panic!("a resume message");
        };
        assert_eq!(seq, CmdSeq::first().next());
        assert_eq!(request.capability, capability(4));
        assert_eq!(
            request.confirmed_output,
            ConfirmedOutput {
                generation: Generation::initial(),
                next_off: ByteOff::from_u64(4_096),
            }
        );
    }

    fn resume_client(message: &ClientMessage) -> ClientId {
        match message {
            ClientMessage::Resume { request, .. } => request.client,
            _ => panic!("a resume message"),
        }
    }

    /// The server tells a client back on a new transport from a second client joining by
    /// this id alone, so an identity rolled per resume makes a dropped link an arrival.
    #[test]
    fn the_client_id_is_the_process_and_never_the_session() {
        let ClientMessage::Hello { client, .. } =
            hello(GridSize { cols: 80, rows: 24 }, "xterm-256color", &[])
        else {
            panic!("a hello message");
        };
        let first = ReconnectState::new(SessionId::from_bytes([1; 16]), capability(1));
        let second = ReconnectState::new(SessionId::from_bytes([2; 16]), capability(2));
        for message in [
            first.resume_message(CmdSeq::first()),
            first.resume_message(CmdSeq::first().next()),
            second.resume_message(CmdSeq::first()),
        ] {
            assert_eq!(resume_client(&message), client);
        }
        assert_ne!(
            client,
            ClientId::from_bytes([0; 16]),
            "entropy, not a default"
        );
    }

    fn fill_journal(writer: &ClientWriter<Recorder>) {
        let mut state = writer.state.lock().expect("writer lock");
        while !state.journal.is_full() {
            let _ = state.queue(|seq| ClientMessage::Input {
                seq,
                bytes: b"x".to_vec(),
            });
        }
    }

    /// A dropped resize leaves the remote grid wrong until the next reconnect, silently.
    #[test]
    fn a_control_message_a_full_journal_refused_is_sent_when_room_appears() {
        let writer = stream_writer();
        fill_journal(&writer);
        let size = GridSize {
            cols: 100,
            rows: 40,
        };
        writer.resize(size).expect("resize");
        assert_eq!(
            writer.state.lock().expect("writer lock").deferred.resize,
            Some(size),
            "the latest size waits for room rather than being dropped"
        );

        writer
            .acknowledge(seq(JOURNAL_CAPACITY.get() as u64))
            .expect("acknowledge");
        assert_eq!(
            writer.state.lock().expect("writer lock").deferred.resize,
            None
        );
        assert_eq!(
            messages(&written(&writer)).last(),
            Some(&ClientMessage::Resize {
                seq: seq(JOURNAL_CAPACITY.get() as u64 + 1),
                size,
            })
        );
    }

    /// Nothing is replayed after a close, so it may displace history — and it must.
    #[test]
    fn a_close_is_transmitted_even_against_a_full_journal() {
        let writer = stream_writer();
        fill_journal(&writer);
        writer.close().expect("close");
        assert!(writer.close_requested.load(Ordering::Acquire));
        assert_eq!(
            messages(&written(&writer)).last(),
            Some(&ClientMessage::Close {
                seq: seq(JOURNAL_CAPACITY.get() as u64 + 1),
            })
        );
    }

    fn state_file(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("brd-{tag}-{}", std::process::id()));
        let path = root.join("brd").join("reconnect").join("host.state");
        (root, path)
    }

    /// Created private rather than chmodded into it afterwards. Versions before
    /// 7 created this tree with `create_dir_all` and no mode; refusing that would
    /// end the run after the ssh passphrase prompt, naming no path and no remedy.
    #[test]
    fn a_checkpoint_round_trips_under_a_tree_only_this_user_can_reach() {
        use std::os::unix::fs::PermissionsExt;
        for (tag, v6_shaped) in [("state", false), ("upgrade", true)] {
            let (root, path) = state_file(tag);
            let _ = fs::remove_dir_all(&root);
            let reconnect = path.parent().expect("a directory").to_path_buf();
            if v6_shaped {
                fs::create_dir_all(&reconnect).expect("a v6-shaped tree");
                for dir in [root.join("brd"), reconnect.clone()] {
                    fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).expect("loosen it");
                }
            }

            let mut state = ReconnectState::new(SessionId::from_bytes([3; 16]), capability(7));
            state.confirm(Generation::initial(), ByteOff::from_u64(123));
            save_sessions(&path, &[state]).expect("an owned tree is repaired, not refused");
            let loaded = load_sessions(&path).unwrap();
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded[0].session_id, state.session_id);
            assert_eq!(loaded[0].capability, state.capability);
            assert_eq!(loaded[0].confirmed_output, state.confirmed_output);
            for dir in [root.join("brd"), reconnect] {
                let mode = fs::symlink_metadata(&dir).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700, "{}: {mode:o}", dir.display());
            }
            let file = fs::symlink_metadata(&path).unwrap().permissions().mode();
            assert_eq!(file & 0o777, 0o600, "the capability itself is owner-only");
            let _ = fs::remove_dir_all(&root);
        }
    }

    /// One state file per destination holds every session on it: one slot would let a
    /// second `brd host` overwrite the first's capability and orphan a live session.
    #[test]
    fn a_second_session_to_one_destination_does_not_orphan_the_first() {
        let (root, path) = state_file("two");
        let first = ReconnectState::new(SessionId::from_bytes([1; 16]), capability(1));
        let second = ReconnectState::new(SessionId::from_bytes([2; 16]), capability(2));

        let mut checkpoint = Checkpoint::new(Some(path.clone()));
        checkpoint.force(&first);
        let mut remembered = checkpoint.load().expect("readable");
        let resumed = take_session(&mut remembered, None)
            .expect("resolved")
            .expect("present");
        assert_eq!(resumed.session_id, first.session_id);

        let mut second_client = Checkpoint::new(Some(path.clone()));
        second_client.others = second_client.load().expect("readable");
        second_client.force(&second);
        let ids: Vec<SessionId> = load_sessions(&path)
            .expect("readable")
            .iter()
            .map(|state| state.session_id)
            .collect();
        assert_eq!(
            ids,
            vec![second.session_id, first.session_id],
            "newest first, and nothing forgotten"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A client killed between staging and renaming leaves the file behind for good, its
    /// name carrying a pid nothing will reuse. The e2e harness kills clients for a living.
    #[test]
    fn a_staging_file_from_a_dead_process_is_swept_and_a_live_one_is_not() {
        let (root, path) = state_file("sweep");
        fs::create_dir_all(path.parent().expect("a directory")).expect("test directory");

        // Pid 1 is always running and is not this process; a pid past the system max is not.
        let live = path.with_extension("tmp1");
        let dead = path.with_extension("tmp4294967");
        let unrelated = path.with_extension("tmpnotapid");
        for file in [&live, &dead, &unrelated] {
            fs::write(file, b"staged").expect("staging file");
        }

        sweep_staging(&path);

        assert!(!dead.exists(), "a pid that is gone cannot be mid-write");
        assert!(live.exists(), "a live process may be staging right now");
        assert!(
            unrelated.exists(),
            "the sweep is staging files and nothing else"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A convenience, not a registry: this file must not grow without bound.
    #[test]
    fn only_the_newest_sessions_are_remembered() {
        let (root, path) = state_file("cap");
        let sessions: Vec<ReconnectState> = (0..u8::try_from(REMEMBERED_SESSIONS + 4).unwrap())
            .map(|byte| ReconnectState::new(SessionId::from_bytes([byte; 16]), capability(byte)))
            .collect();
        save_sessions(&path, &sessions).expect("written");
        let loaded = load_sessions(&path).expect("readable");
        assert_eq!(loaded.len(), REMEMBERED_SESSIONS);
        assert_eq!(loaded[0].session_id, sessions[0].session_id);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stored_session_is_selected_by_unambiguous_prefix() {
        let mut sessions = vec![
            ReconnectState::new(SessionId::from_bytes([0xab; 16]), capability(1)),
            ReconnectState::new(SessionId::from_bytes([0xac; 16]), capability(2)),
        ];
        assert!(take_session(&mut sessions.clone(), Some("")).is_err());
        assert!(
            take_session(&mut sessions.clone(), Some("a")).is_err(),
            "both start with a"
        );
        let picked = take_session(&mut sessions, Some("ac"))
            .expect("resolved")
            .expect("present");
        assert_eq!(picked.session_id, SessionId::from_bytes([0xac; 16]));
        assert_eq!(sessions.len(), 1, "the chosen session leaves the list");

        let newest = take_session(&mut sessions, None)
            .expect("resolved")
            .expect("present");
        assert_eq!(newest.session_id, SessionId::from_bytes([0xab; 16]));
    }

    /// A `/tmp/brd/reconnect/<hash>.state` fallback with no `HOME` names a file holding a
    /// live session's bearer token, which another local user can pre-create the tree for.
    /// `force` reports once and stops trying: nowhere private to write costs the resume
    /// file, never the session.
    #[test]
    fn a_capability_with_nowhere_private_to_go_costs_the_checkpoint_alone() {
        assert_eq!(state_root(None, None), None, "no /tmp fallback");
        assert_eq!(
            state_root(None, Some(PathBuf::from("/home/u"))),
            Some(PathBuf::from("/home/u/.local/state"))
        );
        assert_eq!(
            state_root(Some(PathBuf::from("/s")), Some(PathBuf::from("/home/u"))),
            Some(PathBuf::from("/s")),
            "an explicit state home wins"
        );

        let (root, path) = state_file("blocked");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        // A plain file where `brd/` has to go: nothing can make this private.
        fs::write(root.join("brd"), b"not a directory").expect("blocker");

        let state = ReconnectState::new(SessionId::from_bytes([3; 16]), capability(4));
        for mut checkpoint in [Checkpoint::new(None), Checkpoint::new(Some(path))] {
            checkpoint.force(&state);
            assert!(checkpoint.path.is_none(), "the checkpoint gives itself up");
            checkpoint.force(&state);
            assert!(checkpoint.load().expect("nothing to load").is_empty());
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// `ConnectTimeout` covers the SYN, so authentication, a hung remote `brd --server` and
    /// an sshd that accepts and then stalls each block the loop that polls the quit key.
    #[test]
    fn a_silent_peer_is_a_deadline_rather_than_a_hang() {
        let (_writer, reader) =
            std::os::unix::net::UnixStream::pair().expect("a socket pair for the test");
        let mut reader = DeadlineReader::new(reader, Deadline::new(Duration::from_millis(50)))
            .expect("a socket pair takes O_NONBLOCK");
        let started = Instant::now();
        let error = read_frame(&mut reader, MAX_FRAME).expect_err("silence past the deadline");
        assert!(
            error.is_transport_loss(),
            "a deadline reads as transport loss, which is what a resume answers"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(RESUME_TIMEOUT > Duration::ZERO);
    }

    /// A sequence is what an echo ack releases a prediction against.
    #[test]
    fn accepted_carries_the_sequence_the_input_went_out_under() {
        let writer = stream_writer();
        assert_eq!(
            writer.input(b"ls").expect("queued"),
            Accepted::All(Some(CmdSeq::first()))
        );
        assert_eq!(
            writer.input(b"\r").expect("queued"),
            Accepted::All(Some(CmdSeq::first().next()))
        );

        let buffered = stream_writer();
        buffered.disconnect().expect("transport down");
        assert_eq!(
            buffered.input(b"ls").expect("buffered"),
            Accepted::All(None)
        );
        buffered
            .reconnect(Recorder::default(), Version::LOCAL)
            .expect("a replacement transport");
        assert_eq!(
            buffered.input(b"\r").expect("queued"),
            Accepted::All(Some(CmdSeq::first().next())),
            "the buffered run went out first, under a sequence of its own"
        );
    }

    /// Drawing a run `input` clamped would put characters no session was given on screen.
    #[test]
    fn only_the_prefix_that_was_queued_is_drawn() {
        let writer = stream_writer();
        writer.disconnect().expect("transport down");
        writer
            .input(&vec![b'q'; MAX_PENDING_INPUT - 1])
            .expect("fill the buffer to one byte short");

        let display = terminal();
        typed(b"xy", &writer, &display);
        assert_eq!(
            *writer
                .state
                .lock()
                .expect("writer lock")
                .pending
                .last()
                .expect("pending input"),
            b'x',
            "only the byte there was room for was queued"
        );
        assert!(
            !shown(&display).contains(&b'y'),
            "a refused keystroke must not reach the terminal"
        );
        assert!(writer.dropped_input.load(Ordering::Acquire));
    }

    /// This is what a shell on the far end inherits, and `PATH=x; rm -rf` inherited from a
    /// peer is whatever the peer wanted it to be.
    #[test]
    fn the_env_whitelist_carries_only_whitelisted_names() {
        let env = session_env_from(|name| Some(format!("value-of-{name}")));
        let names: Vec<&str> = env.0.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, FORWARDED_ENV);

        let env = session_env_from(|name| match name {
            "SSH_AUTH_SOCK" => Some("/run/agent.sock".into()),
            // Refused at encode, so a session would never open with it.
            "DISPLAY" => Some("bad\u{7}display".into()),
            "SSH_TTY" => Some("x".repeat(MAX_ENV)),
            _ => None,
        });
        assert_eq!(
            env.0,
            vec![("SSH_AUTH_SOCK".to_owned(), "/run/agent.sock".to_owned())]
        );
        ClientMessage::Hello {
            versions: VersionRange::LOCAL,
            size: GridSize { cols: 80, rows: 24 },
            term: "xterm-256color".into(),
            env,
            command: Vec::new(),
            client: *CLIENT_ID,
        }
        .encode(Version::LOCAL)
        .expect("a whitelist this client built always encodes");
    }

    #[test]
    fn an_unusable_term_is_replaced_rather_than_sent() {
        for (term, usable) in [
            ("xterm-256color", true),
            ("screen.linux", true),
            ("", false),
            ("xterm;rm -rf", false),
        ] {
            assert_eq!(valid_term(term), usable, "{term:?}");
        }
        assert!(!valid_term(&"x".repeat(MAX_TERM + 1)));
    }

    /// Both users of [`BLIND_RESET`] run without the display lock. `REPAINT_MODES` is
    /// append-only, so a literal beside it goes stale silently.
    #[test]
    fn blind_reset_matches_the_mode_table() {
        let mut expected = String::new();
        for (mode, on) in braid_proto::RESET_ON_EXIT.iter() {
            if on {
                let _ = write!(expected, "\x1b[?{mode}l");
            }
        }
        expected.push_str("\x1b[=0;1u");
        assert_eq!(BLIND_RESET, expected.as_bytes());
    }

    /// A screen restates the position; a session ended with a protocol error restates nothing.
    #[test]
    fn an_output_at_an_unexpected_offset_asks_for_a_screen() {
        let at = ByteOff::from_u64(4_096);
        for (expected, off, len, placed) in [
            (at, at, 8, Some(ByteOff::from_u64(4_104))),
            (at, ByteOff::from_u64(4_000), 8, None),
            (at, ByteOff::from_u64(8_192), 8, None),
            // An offset space that has run out is not a position either.
            (
                ByteOff::from_u64(u64::MAX),
                ByteOff::from_u64(u64::MAX),
                1,
                None,
            ),
        ] {
            assert_eq!(place_output(expected, off, len), placed, "{off:?}");
        }
    }

    fn hold(reorder: &mut Reorder, off: u64, at: Instant) {
        reorder.hold(
            ByteOff::from_u64(off),
            vec![b'x'],
            InputCue::Opaque,
            None,
            at,
        );
    }

    /// The piece and byte bounds can only decide while chunks keep arriving, and a datagram
    /// lost at the end of a burst produces none at all.
    #[test]
    fn a_gap_nothing_arrives_to_close_is_called_a_loss_by_the_clock() {
        let deadline = reorder_deadline(Some(Duration::from_millis(100)));
        let held_at = Instant::now();
        let mut reorder = Reorder::default();
        hold(&mut reorder, 64, held_at);
        assert!(
            !reorder.lost(held_at + Duration::from_millis(199), deadline),
            "one chunk overtaking another is a reorder, not a loss"
        );
        assert!(
            reorder.lost(held_at + deadline, deadline),
            "nothing below this layer retransmits: the chunk is not on its way"
        );
    }

    /// The stamp measures the gap in front of the client, not one it closed.
    #[test]
    fn a_gap_that_closes_stops_the_clock_it_started() {
        let held_at = Instant::now();
        let mut reorder = Reorder::default();
        hold(&mut reorder, 64, held_at);
        assert!(reorder.take(ByteOff::from_u64(64)).is_some());
        assert!(
            !reorder.lost(held_at + Duration::from_hours(1), MIN_REORDER_WAIT),
            "an hour of quiet with nothing held is not a loss"
        );
    }

    /// A link that keeps delivering has proved the missing chunk is not merely late; one
    /// chunk arriving repeatedly has proved nothing and must not age the gap out.
    #[test]
    fn a_run_of_held_chunks_is_a_loss_but_a_repeated_chunk_is_not() {
        let held_at = Instant::now();
        let mut run = Reorder::default();
        for piece in 1..=32 {
            hold(&mut run, piece * 64, held_at);
        }
        assert!(run.lost(held_at, MAX_REORDER_WAIT));

        let mut duplicated = Reorder::default();
        for _ in 0..64 {
            hold(&mut duplicated, 64, held_at);
        }
        assert!(!duplicated.lost(held_at, MAX_REORDER_WAIT));
    }

    /// Two round trips, floored and capped: the floor keeps a LAN from calling scheduling
    /// jitter a loss, the ceiling keeps a satellite link from freezing the terminal.
    #[test]
    fn the_reorder_deadline_follows_the_round_trip() {
        for (srtt, deadline) in [
            (Some(Duration::from_millis(120)), Duration::from_millis(240)),
            (Some(Duration::from_micros(200)), MIN_REORDER_WAIT),
            (Some(Duration::from_secs(4)), MAX_REORDER_WAIT),
            // A link that has measured nothing is given the ceiling.
            (None, MAX_REORDER_WAIT),
        ] {
            assert_eq!(reorder_deadline(srtt), deadline, "{srtt:?}");
        }
    }

    /// The bound is on bytes, not on how long the link has been down, and the flag must be
    /// cleared once the buffer drains or every later disconnect claims lost keystrokes.
    #[test]
    fn dropped_input_is_bounded_and_forgotten_once_the_buffer_drains() {
        let writer = stream_writer();
        writer.disconnect().expect("transport down");
        writer
            .input(&vec![b'x'; MAX_PENDING_INPUT + 1_000])
            .expect("more than the buffer holds");
        assert_eq!(
            writer.state.lock().unwrap().pending.len(),
            MAX_PENDING_INPUT
        );
        assert!(writer.dropped_input.load(Ordering::Acquire));

        writer
            .reconnect(Recorder::default(), Version::LOCAL)
            .expect("a replacement transport");
        assert!(
            !writer.dropped_input.load(Ordering::Acquire),
            "nothing is waiting, so nothing is still being claimed lost"
        );
    }

    /// The ordinary queue would drop the new transport as soon as it was installed.
    #[test]
    fn a_journal_replay_uses_the_room_kept_for_it() {
        let writer = ClientWriter::new(Backpressured::default(), CmdSeq::first(), Version::LOCAL);
        writer.input(b"ls").expect("queued");
        writer.disconnect().expect("transport down");

        let replacement = Backpressured::default();
        replacement.full.store(true, Ordering::Release);
        writer
            .reconnect(replacement, Version::LOCAL)
            .expect("a replacement transport");

        let state = writer.state.lock().expect("writer lock");
        let output = state
            .output
            .as_ref()
            .expect("the replacement transport survived its own replay");
        assert_eq!(
            messages(&output.queued.lock().expect("sink lock")),
            vec![ClientMessage::Input {
                seq: CmdSeq::first(),
                bytes: b"ls".to_vec(),
            }]
        );
    }

    /// Names the thread a re-executed test binary is to panic on.
    const CHILD: &str = "BRD_TEST_CHILD";

    /// A process that must not survive cannot be asserted on inside a harness that must.
    fn as_child(test: &str, thread_name: &str) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(["--exact", "--nocapture", test])
            .env(CHILD, thread_name)
            .output()
            .expect("re-execute this test binary")
    }

    fn child_thread() -> Option<String> {
        std::env::var(CHILD).ok()
    }

    fn panic_under_the_hook(name: &str, stake: Stake) {
        install_panic_hook();
        let died = thread::Builder::new()
            .name(name.to_owned())
            .spawn(staked(stake, || panic!("a thread the hook classifies")))
            .expect("the thread starts")
            .join();
        assert!(died.is_err(), "the thread panicked");
    }

    /// Entering raw mode is itself the statement that can fail. Read off the exit status:
    /// the reset goes to a controlling terminal a test harness may not have.
    #[test]
    fn the_panic_hook_is_installed_before_raw_mode_is_entered() {
        const TEST: &str = "tests::the_panic_hook_is_installed_before_raw_mode_is_entered";
        if child_thread().is_some() {
            let (socket, _peer) =
                std::os::unix::net::UnixStream::pair().expect("a socket pair for the test");
            assert!(
                guarded_raw_mode(&socket).is_err(),
                "a socket is not a terminal"
            );
            panic!("the hook owns the terminal even when raw mode never happened");
        }
        assert_eq!(
            as_child(TEST, INPUT_THREAD).status.code(),
            Some(1),
            "the hook was not in place when raw mode could still fail"
        );
    }

    /// A hook that only reset the terminal and printed would leave a live remote shell and
    /// nothing reading the keyboard. Seven threads reach it, so recognising `brd-input` by
    /// name would let the other six de-raw the terminal under a session still painting.
    #[test]
    fn a_panic_on_any_thread_the_session_needs_ends_the_session() {
        const TEST: &str = "tests::a_panic_on_any_thread_the_session_needs_ends_the_session";
        if let Some(name) = child_thread() {
            panic_under_the_hook(&name, Stake::Session);
            // Reached only if the hook let this process carry on without it.
            std::process::exit(0);
        }
        for name in [INPUT_THREAD, "brd-resize"] {
            assert_eq!(
                as_child(TEST, name).status.code(),
                Some(1),
                "{name} died and the session carried on"
            );
        }
    }

    /// A forward thread owns no part of the display, and a tunnel that died is not a shell
    /// that died: ending the process would cost the session for a `-L` nobody was using.
    #[test]
    fn a_panic_on_a_tunnel_thread_costs_the_tunnel_and_nothing_else() {
        const TEST: &str = "tests::a_panic_on_a_tunnel_thread_costs_the_tunnel_and_nothing_else";
        if let Some(name) = child_thread() {
            panic_under_the_hook(&name, Stake::Tunnel);
            // The point of the test: this line is reached.
            std::process::exit(7);
        }
        assert_eq!(
            as_child(TEST, "brd-forward-read").status.code(),
            Some(7),
            "a tunnel's death took the session with it"
        );
    }

    /// The hook branches on what the spawn site declared, never the thread's name, and a
    /// thread nobody classified counts as the session's — the answer that fails safe.
    #[test]
    fn a_thread_says_what_its_death_costs_where_it_is_named() {
        assert_eq!(
            terminal::stake_here(),
            Stake::Session,
            "the thread the session runs on"
        );
        assert_eq!(
            thread::Builder::new()
                .name("brd-forward-read".into())
                .spawn(staked(Stake::Tunnel, terminal::stake_here))
                .expect("a forward thread")
                .join()
                .expect("the thread finishes"),
            Stake::Tunnel
        );
        assert_eq!(
            thread::spawn(terminal::stake_here)
                .join()
                .expect("the thread finishes"),
            Stake::Session,
            "a thread nobody classified must not be treated as expendable"
        );
    }

    /// The server paces its probes against the link it measures and says so in every
    /// `Ping`; three unanswered ones is the client's whole share of the contract.
    #[test]
    fn the_silence_deadline_follows_the_server_pacing() {
        for (interval, deadline, note) in [
            (500, Duration::from_millis(1_500), "three probes"),
            (2_000, Duration::from_secs(6), "three probes"),
            (
                100,
                MIN_LINK_TIMEOUT,
                "a tight interval must not make ordinary jitter a reconnect",
            ),
            (
                u16::MAX,
                MAX_LINK_TIMEOUT,
                "and a slack one must not bring the old constant back",
            ),
        ] {
            assert_eq!(silence_deadline(interval), deadline, "{note}");
        }
        assert!(MAX_LINK_TIMEOUT > LINK_TIMEOUT);
    }

    /// No TCP under a datagram path: the journal is the retransmission buffer.
    #[test]
    fn the_resend_timer_repeats_a_command_until_it_is_acknowledged() {
        let writer = datagram_writer();
        let typed = input_of(1, b"ls");
        writer.input(b"ls").expect("typing is queued");
        let start = Instant::now();
        assert_eq!(messages(&written(&writer)), vec![typed.clone()]);

        writer
            .retransmit(start, writer.epoch())
            .expect("the timer runs");
        assert_eq!(
            messages(&written(&writer)),
            vec![typed.clone()],
            "nothing is owed before the interval is up"
        );
        writer
            .retransmit(start + INITIAL_RESEND, writer.epoch())
            .expect("the timer runs");
        assert_eq!(
            messages(&written(&writer)),
            vec![typed.clone(), typed.clone()],
            "the oldest unacknowledged command goes again"
        );

        writer.acknowledge(seq(1)).expect("the ack lands");
        writer
            .retransmit(start + INITIAL_RESEND * 8, writer.epoch())
            .expect("the timer runs");
        assert_eq!(
            messages(&written(&writer)),
            vec![typed.clone(), typed],
            "an acknowledged command is not sent a third time"
        );
    }

    /// A stream retransmits underneath this client already.
    #[test]
    fn a_stream_is_never_resent_from_the_journal() {
        let writer = stream_writer();
        writer.input(b"ls").expect("typing is queued");
        assert_eq!(
            writer
                .retransmit(Instant::now() + INITIAL_RESEND * 8, writer.epoch())
                .expect("the timer runs"),
            None,
            "the timer has nothing to do on a transport that retransmits"
        );
        assert_eq!(messages(&written(&writer)).len(), 1);
    }

    /// A resend thread sleeping out its backoff can wake after the next upgrade replaced
    /// the sink under it, and two against one journal double every unacknowledged command.
    #[test]
    fn a_resend_caller_retires_when_its_link_is_replaced() {
        let writer = datagram_writer();
        writer.input(b"ls").expect("typing is queued");
        let stale = writer.epoch();
        writer
            .reconnect(Recorder::datagram(), Version::LOCAL)
            .expect("a replacement transport");
        let due = Instant::now() + INITIAL_RESEND * 8;
        assert_eq!(
            writer.retransmit(due, stale).expect("the timer runs"),
            None,
            "the thread spawned for the old link is still resending against it"
        );
        assert!(
            writer
                .retransmit(due, writer.epoch())
                .expect("the timer runs")
                .is_some(),
            "and the one spawned for the link that is up has been retired with it"
        );
    }

    /// A sample from a message sent twice cannot say which copy the ack covered. Karn's.
    #[test]
    fn a_round_trip_is_not_measured_from_a_retransmitted_command() {
        let measured = datagram_writer();
        measured.input(b"a").expect("typing is queued");
        measured.acknowledge(seq(1)).expect("the ack lands");
        assert!(
            measured.lock().expect("writer lock").resend.srtt.is_some(),
            "an acknowledgement of a message sent once is a round trip"
        );

        let resent = datagram_writer();
        resent.input(b"a").expect("typing is queued");
        resent
            .retransmit(Instant::now() + INITIAL_RESEND, resent.epoch())
            .expect("the timer runs");
        resent.acknowledge(seq(1)).expect("the ack lands");
        assert!(
            resent.lock().expect("writer lock").resend.srtt.is_none(),
            "the same acknowledgement, after a resend, measures nothing"
        );
    }

    /// Nothing fragments on the datagram path.
    #[test]
    fn typing_longer_than_a_datagram_is_cut_to_fit_one() {
        let writer = datagram_writer();
        let paste = vec![b'x'; MIN_DATAGRAM_FRAME * 3];
        writer.input(&paste).expect("a paste is queued");
        let sent = messages(&written(&writer));
        let mut carried = 0;
        for message in &sent {
            let ClientMessage::Input { bytes, .. } = message else {
                panic!("a paste is input: {message:?}");
            };
            carried += bytes.len();
            assert!(
                message.encode(Version::LOCAL).expect("input encodes").len() <= MIN_DATAGRAM_FRAME,
                "a frame of {} bytes does not fit a datagram",
                bytes.len(),
            );
        }
        assert!(sent.len() > 3, "the paste was cut: {} messages", sent.len());
        assert_eq!(carried, paste.len(), "and nothing of it was dropped");
    }

    fn offer(port: u16) -> DatagramOffer {
        let mut ip = [0; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&[127, 0, 0, 1]);
        DatagramOffer {
            ip,
            port,
            cid: [3; 8],
            secret: [4; 32],
        }
    }

    /// The `Resume` over datagrams is the whole migration, and the `ClientId` in it is what
    /// makes the daemon's `Hello` a replacement of the ssh attachment, not a second client.
    #[test]
    fn an_offer_that_answers_is_taken_up() {
        let daemon =
            std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("a daemon socket");
        let port = daemon.local_addr().expect("a bound port").port();
        let answering = thread::spawn(move || {
            let mut buffer = vec![0; braid_dgram::MAX_DATAGRAM];
            let (len, from) = daemon.recv_from(&mut buffer).expect("a datagram arrives");
            let (accepted, received) = braid_dgram::Endpoint::accept(
                braid_dgram::ConnectionId::from_bytes([3; 8]),
                braid_dgram::RootSecret::new([4; 32]),
                from,
                Instant::now(),
                &mut buffer[..len],
                braid_dgram::Fragmentation::Refused,
            )
            .expect("the datagram authenticates");
            let mut endpoint = accepted.commit();
            let braid_dgram::Received::Frame(frame) = received else {
                panic!("the first datagram carries the resume");
            };
            // A datagram knows its own length, so the stream's four-byte prefix comes off.
            let mut resume = Vec::new();
            braid_proto::wire::unpack(&buffer[frame], MAX_FRAME as usize, &mut resume)
                .expect("a packed resume");
            assert!(
                matches!(
                    ClientMessage::decode(&resume, Version::LOCAL).expect("the resume decodes"),
                    ClientMessage::Resume { .. }
                ),
                "the datagram path is entered as an ordinary resume"
            );
            let hello = ServerMessage::Hello {
                version: Version::LOCAL,
                size: GridSize { cols: 80, rows: 24 },
                session_id: SessionId::from_bytes([5; 16]),
                capability: capability(6),
                offer: None,
            }
            .encode(Version::LOCAL)
            .expect("a hello encodes");
            let mut packed = Vec::new();
            braid_proto::wire::pack(&hello[4..], &mut packed);
            let mut out = Vec::new();
            let to = endpoint
                .send(&packed, Instant::now(), &mut out)
                .expect("the hello seals");
            daemon.send_to(&out, to).expect("the hello goes back");
        });

        let state = ReconnectState::new(SessionId::from_bytes([5; 16]), capability(6));
        assert!(
            take_offer(&offer(port), &state, &Deadline::new(LINK_TIMEOUT)).is_some(),
            "an offer that answers carries the session"
        );
        answering.join().expect("the daemon half finishes");
    }

    /// Never retried: the probes run out and the session stays on the transport carrying it.
    #[test]
    fn an_offer_nothing_answers_leaves_the_session_on_ssh() {
        // Bound and then dropped, which is what a firewalled datagram path looks like.
        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a bound port")
            .port();
        let state = ReconnectState::new(SessionId::from_bytes([5; 16]), capability(6));
        let deadline = Deadline::new(LINK_TIMEOUT);
        assert!(take_offer(&offer(port), &state, &deadline).is_none());
        assert_eq!(
            deadline.get(),
            LINK_TIMEOUT,
            "the session's own deadline is put back"
        );
    }
}
