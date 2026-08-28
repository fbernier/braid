//! Fixtures every module's tests draw on. Beside the modules rather than inside
//! one: a fixture in a module's own `mod tests` is reachable from no other.

use crate::actor::SessionActor;
use crate::attachment::Framing;
use crate::mailbox::Chunk;
use crate::mailbox::{ActorEvent, MailboxReceiver, MailboxSender, mailbox};
use crate::registry::{
    AttachmentSlot, DaemonState, KillNotice, SessionHandle, SessionInfo, SessionKind, registry,
};
use crate::shell::{forward_actor, forward_info, spawn_session};
use crate::sink::AttachmentSink;
use crate::state::persist_ticket;
use crate::{AttachKind, AttachmentId, FRAME_LENGTH_PREFIX, NEXT_ATTACHMENT, dgram, sessions};
use braid_proto::wire::{pack, unpack};
use braid_proto::{
    ByteOff, Capability, ClientId, ClientMessage, CmdSeq, ConfirmedOutput, Generation, GridSize,
    MAX_FRAME, MIN_DATAGRAM_FRAME, ResumeRequest, ScreenPart, ScreenVersion, ServerMessage,
    SessionEnv, SessionId, Version, VersionRange,
};
use std::io::{self, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

/// The grid a test that is not about the grid runs on.
pub(crate) const GRID: GridSize = GridSize { cols: 80, rows: 24 };

/// A PTY read carrying exactly `bytes`, as the reader thread would send it.
pub(crate) fn pty_output(bytes: &[u8]) -> ActorEvent {
    ActorEvent::PtyOutput(Chunk::owned(bytes.to_vec()))
}

/// `/bin/sh` rather than the empty argv that starts `$SHELL -l`: a login shell
/// runs the developer's configuration, and a prompt that redraws on `SIGWINCH`
/// puts PTY output between a test's resize and its assertion.
pub(crate) fn test_session() -> SessionHandle {
    daemon_session(
        &Arc::new(DaemonState::default()),
        sessions::SessionTicket::issue().expect("session ticket"),
        &["/bin/sh".into()],
    )
}

/// A session on `daemon`, started the way a `Hello` starts one.
pub(crate) fn daemon_session(
    daemon: &Arc<DaemonState>,
    ticket: sessions::SessionTicket,
    command: &[String],
) -> SessionHandle {
    spawn_session(
        GRID,
        "xterm-256color",
        &SessionEnv::default(),
        command,
        ticket,
        daemon,
    )
    .expect("spawn PTY")
}

/// A session identity whose capability is on disk, which is what a resume proves.
pub(crate) fn persisted_ticket() -> (sessions::SessionTicket, SessionId, Capability) {
    let ticket = sessions::SessionTicket::issue().expect("session ticket");
    persist_ticket(&ticket).expect("persist the capability a resume proves");
    let session_id = ticket.session_id;
    let capability = Capability::from_bytes(ticket.capability);
    (ticket, session_id, capability)
}

/// The frame a client returning to `session_id` opens with.
pub(crate) fn resume(
    session_id: SessionId,
    capability: Capability,
    client: ClientId,
) -> ClientMessage {
    ClientMessage::Resume {
        versions: VersionRange::LOCAL,
        seq: CmdSeq::first(),
        request: ResumeRequest {
            session_id,
            capability,
            confirmed_output: ConfirmedOutput {
                generation: Generation::initial(),
                next_off: ByteOff::zero(),
            },
            client,
        },
    }
}

/// A registry entry with no actor behind it: the bounds and `brd ls` read the
/// handle, and nothing they do looks past it.
pub(crate) fn detached_handle(tx: MailboxSender) -> SessionHandle {
    SessionHandle {
        tx,
        info: Arc::new(SessionInfo::new("/bin/sh -l".into(), GRID)),
        kind: SessionKind::Terminal,
    }
}

pub(crate) fn seq(number: u64) -> CmdSeq {
    CmdSeq::from_u64(number).expect("test sequences are non-zero")
}

pub(crate) fn next_attachment() -> AttachmentId {
    AttachmentId(NEXT_ATTACHMENT.fetch_add(1, Ordering::Relaxed))
}

pub(crate) fn kill() -> ActorEvent {
    ActorEvent::Kill {
        reply: mpsc::sync_channel(1).0,
    }
}

pub(crate) fn test_charge() -> AttachmentSlot {
    AttachmentSlot::reserve(&Arc::new(DaemonState::default())).expect("an empty daemon")
}

pub(crate) fn client(number: u8) -> ClientId {
    ClientId::from_bytes([number; 16])
}

/// A writer that says how big a batch it has taken and then blocks holding it.
pub(crate) struct Holding {
    taken: mpsc::Sender<usize>,
    release: mpsc::Receiver<()>,
}

/// One of those, the channel it reports batches on, and the one that frees it.
pub(crate) fn holding() -> (Holding, mpsc::Receiver<usize>, mpsc::Sender<()>) {
    let (taken, took) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    (
        Holding {
            taken,
            release: blocked,
        },
        took,
        release,
    )
}

impl Write for Holding {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let _ = self.taken.send(bytes.len());
        if self.release.recv().is_err() {
            return Err(io::Error::other("released"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The process holds one panic hook, so a test that installs one and a test
/// that silences one cannot be inside their windows at the same time.
pub(crate) static PANIC_HOOK: Mutex<()> = Mutex::new(());

/// That lock, whatever a failed test left behind.
pub(crate) fn panic_hook() -> std::sync::MutexGuard<'static, ()> {
    PANIC_HOOK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a client that already knows this session reaches it again.
pub(crate) fn joining() -> AttachKind {
    AttachKind::Resume(ConfirmedOutput {
        generation: Generation::initial(),
        next_off: ByteOff::zero(),
    })
}

/// The event one stream attachment arrives on.
pub(crate) fn attach_event(id: AttachmentId, sink: AttachmentSink, kind: AttachKind) -> ActorEvent {
    ActorEvent::Attach {
        id,
        client: client(1),
        sink,
        kind,
        framing: Framing::Stream,
        offer: None,
    }
}

/// One stream client on a live session, and the transcript it is written.
/// `kind` decides whether output from before it arrives is replayed to it.
pub(crate) fn attached_output(handle: &SessionHandle, kind: AttachKind) -> TestOutput {
    let output = TestOutput::new();
    let sink = AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment");
    handle
        .tx
        .send(attach_event(next_attachment(), sink, kind))
        .expect("attach transport");
    output
}

/// Hand `visit` every whole length-prefixed frame in `bytes`, payload only.
fn walk(bytes: &[u8], mut visit: impl FnMut(&[u8])) {
    let mut cursor = 0_usize;
    while cursor + FRAME_LENGTH_PREFIX <= bytes.len() {
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + FRAME_LENGTH_PREFIX]
                .try_into()
                .expect("four bytes"),
        ) as usize;
        let start = cursor + FRAME_LENGTH_PREFIX;
        let Some(payload) = bytes.get(start..start + length) else {
            break;
        };
        visit(payload);
        cursor = start + length;
    }
}

/// Whether this frame is a message rather than a packing of one. `wire`'s codec
/// tags are 0 and 1 and every server message tag is at or above
/// `SERVER_TAG_BASE`, so the high bit separates them. Decided per frame rather
/// than per transport because a datagram attachment's screens arrive packed and
/// its byte-stream output does not.
fn is_message(payload: &[u8]) -> bool {
    payload.first().is_some_and(|&tag| tag >= 0x80)
}

/// One frame's message, as the peer that receives it would read it.
fn carried(payload: &[u8], scratch: &mut Vec<u8>) -> Option<ServerMessage> {
    if is_message(payload) {
        return ServerMessage::decode(payload, Version::LOCAL).ok();
    }
    unpack(payload, MAX_FRAME as usize, scratch).ok()?;
    ServerMessage::decode(scratch, Version::LOCAL).ok()
}

#[derive(Clone)]
pub(crate) struct TestOutput(Arc<(Mutex<Vec<u8>>, Condvar)>);

impl TestOutput {
    pub(crate) fn new() -> Self {
        Self(Arc::new((Mutex::new(Vec::new()), Condvar::new())))
    }

    pub(crate) fn contains(&self, needle: &[u8], timeout: Duration) -> bool {
        let (bytes, wake) = &*self.0;
        let mut bytes = bytes.lock().expect("test output lock");
        let deadline = Instant::now() + timeout;
        loop {
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return true;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (next, result) = wake
                .wait_timeout(bytes, remaining)
                .expect("test output wait");
            bytes = next;
            if result.timed_out() {
                return bytes.windows(needle.len()).any(|window| window == needle);
            }
        }
    }

    pub(crate) fn latest_screen(&self, timeout: Duration) -> Option<(Generation, ScreenVersion)> {
        let (bytes, wake) = &*self.0;
        let mut bytes = bytes.lock().expect("test output lock");
        let deadline = Instant::now() + timeout;
        loop {
            let mut newest = None;
            let mut scratch = Vec::new();
            walk(&bytes, |payload| {
                if let Some(ServerMessage::Screen {
                    part: ScreenPart::Head { header, .. },
                }) = carried(payload, &mut scratch)
                {
                    newest = Some((header.generation, header.version));
                }
            });
            if newest.is_some() {
                return newest;
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (next, _) = wake
                .wait_timeout(bytes, remaining)
                .expect("test output wait");
            bytes = next;
        }
    }

    pub(crate) fn frames(&self) -> Vec<ServerMessage> {
        let bytes = self.0.0.lock().expect("test output lock");
        let mut messages = Vec::new();
        let mut scratch = Vec::new();
        walk(&bytes, |payload| {
            if let Some(message) = carried(payload, &mut scratch) {
                messages.push(message);
            }
        });
        messages
    }

    pub(crate) fn highest_version(&self) -> Option<ScreenVersion> {
        self.frames()
            .into_iter()
            .filter_map(|message| match message {
                ServerMessage::Screen {
                    part: ScreenPart::Head { header, .. },
                } => Some(header.version),
                ServerMessage::Screen {
                    part: ScreenPart::Tail { version, .. },
                } => Some(version),
                _ => None,
            })
            .max()
    }

    /// The bound a datagram imposes is on the frame rather than the message.
    pub(crate) fn frame_sizes(&self) -> Vec<usize> {
        let bytes = self.0.0.lock().expect("test output lock");
        let mut sizes = Vec::new();
        walk(&bytes, |payload| {
            sizes.push(FRAME_LENGTH_PREFIX + payload.len());
        });
        sizes
    }

    /// What each frame costs the datagram carrying it: the length prefix comes
    /// off, and `pack`'s codec tag takes its place. A screen arrives packed
    /// already, so packing it here would measure a second compression of bytes
    /// the path never sees.
    pub(crate) fn packed_sizes(&self) -> Vec<usize> {
        let bytes = self.0.0.lock().expect("test output lock");
        let mut sizes = Vec::new();
        let mut packed = Vec::new();
        walk(&bytes, |payload| {
            if is_message(payload) {
                pack(payload, &mut packed);
                sizes.push(packed.len());
            } else {
                sizes.push(payload.len());
            }
        });
        sizes
    }
}

impl Write for TestOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let (output, wake) = &*self.0;
        output
            .lock()
            .expect("test output lock")
            .extend_from_slice(bytes);
        wake.notify_all();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer that stays shut until the test releases it.
#[derive(Clone)]
pub(crate) struct StalledOutput {
    pub(crate) seen: TestOutput,
    pub(crate) open: Arc<(Mutex<bool>, Condvar)>,
}

impl StalledOutput {
    pub(crate) fn new() -> Self {
        Self {
            seen: TestOutput::new(),
            open: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub(crate) fn release(&self) {
        let (open, wake) = &*self.open;
        *open.lock().expect("stall lock") = true;
        wake.notify_all();
    }
}

impl Write for StalledOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let (open, wake) = &*self.open;
        let mut open = open.lock().expect("stall lock");
        while !*open {
            open = wake.wait(open).expect("stall wait");
        }
        drop(open);
        self.seen.clone().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn hello_tag() -> u8 {
    ServerMessage::Hello {
        version: Version::LOCAL,
        size: GRID,
        session_id: SessionId::from_bytes([0; 16]),
        capability: Capability::from_bytes([0; braid_proto::CAPABILITY_BYTES]),
        offer: None,
    }
    .encode(Version::LOCAL)
    .expect("a small message")[FRAME_LENGTH_PREFIX]
}

/// A daemon holding `count` sessions, none of which has an actor: the bound is
/// a count, and nothing that reads it looks past the entry.
pub(crate) fn fill_registry(daemon: &Arc<DaemonState>, count: usize) {
    for index in 0..count {
        let byte = u8::try_from(index % 256).expect("a byte");
        registry(daemon).sessions.insert(
            SessionId::from_bytes([byte; 16]),
            detached_handle(mailbox().0),
        );
    }
}

pub(crate) fn forward_only_actor() -> (SessionActor, MailboxReceiver) {
    let (tx, rx) = mailbox();
    let actor = forward_actor(
        sessions::SessionTicket::issue().expect("session ticket"),
        Arc::new(DaemonState::default()),
        forward_info(),
        KillNotice::default(),
        tx,
    );
    (actor, rx)
}

pub(crate) fn await_frame<T>(
    output: &TestOutput,
    want: impl Fn(&ServerMessage) -> Option<T>,
    missing: &str,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(found) = output.frames().iter().find_map(&want) {
            return found;
        }
        assert!(Instant::now() < deadline, "{missing}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Poll `settled` until it holds, which is how a test waits on the actor thread.
pub(crate) fn settles(timeout: Duration, mut settled: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && !settled() {
        thread::sleep(Duration::from_millis(10));
    }
    settled()
}

pub(crate) fn attachments_settle(handle: &SessionHandle, expected: u16) -> bool {
    settles(Duration::from_secs(2), || {
        handle.info.attachments.load(Ordering::Relaxed) == expected
    })
}

/// Not `contains`: a screen carries the same row text as plain bytes, so a
/// marker found anywhere in the frames says nothing about which mode put it
/// there.
pub(crate) fn passthrough(output: &TestOutput) -> Vec<u8> {
    output
        .frames()
        .into_iter()
        .filter_map(|message| match message {
            ServerMessage::Output { bytes, .. } => Some(bytes),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Fixed, because a piece can only be checked against the number it was cut to;
/// `a_raised_path_limit_is_used_by_the_next_screen` exercises a moving budget.
pub(crate) const DATAGRAM_BUDGET: usize = MIN_DATAGRAM_FRAME;

pub(crate) fn datagram(budget: usize) -> Framing {
    Framing::Datagram {
        budget: dgram::PayloadLimit::fixed(budget),
    }
}

pub(crate) fn scratch(name: &str) -> std::path::PathBuf {
    let directory = env::temp_dir().join(format!(
        "brd-{name}-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("test directory");
    directory
}
