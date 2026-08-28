#![forbid(unsafe_code)]

//! What one daemon is running. Every bound is a count *and* a quantity, taken
//! by a guard: everything between admission and the registry entry can fail.

use crate::mailbox::MailboxSender;
use crate::state::{now_unix, ticket_path};
use crate::{
    ATTACHMENT_BYTES, CONNECTION_LIMIT, FORWARD_BYTES, FORWARD_LIMIT, FORWARD_SESSION_BYTES,
    MEMORY_BUDGET, SESSION_BYTES, SESSION_LIMIT, dgram,
};
use braid_proto::{DecodeError, GridSize, MAX_CLIENT_FRAME, SessionId, SessionSummary, read_frame};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct DaemonState {
    pub(crate) sessions: Mutex<Registry>,
    pub(crate) connections: AtomicUsize,
    /// Daemon-wide rather than per session: sixty-four sessions each holding
    /// [`MAX_FORWARDS`] is a descriptor table nothing else here bounds.
    ///
    /// [`MAX_FORWARDS`]: braid_proto::MAX_FORWARDS
    pub(crate) forwards: AtomicUsize,
    /// `None` when the bind failed and every session stays on the transport
    /// that reached it.
    pub(crate) dgram: Option<Arc<dgram::DatagramListener>>,
}

/// A guard because `serve_attachment` has a dozen ways out.
pub(crate) struct ConnectionSlot(pub(crate) Arc<DaemonState>);

impl ConnectionSlot {
    pub(crate) fn take(daemon: &Arc<DaemonState>) -> Option<Self> {
        daemon
            .connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                (live < CONNECTION_LIMIT).then(|| live + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(daemon)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A deadline on the first frame, not a per-read timeout.
///
/// `SO_RCVTIMEO` restarts on every `read` syscall and [`read_frame`] is a
/// `read_exact` loop, so a peer dribbling one byte per timeout would hold a
/// thread, a descriptor and a [`CONNECTION_LIMIT`] slot for
/// [`MAX_CLIENT_FRAME`] timeouts — about eight days at ten seconds. Only the
/// first frame, because an attachment that has said `Hello` may legitimately
/// be silent for hours.
pub(crate) struct HandshakeDeadline<'a>(
    /// `None` is a reader with no socket under it, which is what a test driving
    /// `serve_attachment` over memory has.
    pub(crate) Option<(&'a UnixStream, Instant)>,
);

/// A zero `timeval` means *no* timeout, so the remainder never rounds to it.
const LEAST_TIMEOUT: Duration = Duration::from_millis(1);

impl<'a> HandshakeDeadline<'a> {
    pub(crate) fn on(stream: &'a UnixStream, within: Duration) -> Self {
        Self(Some((stream, Instant::now() + within)))
    }

    pub(crate) fn first_frame(&self, input: &mut impl Read) -> Result<Vec<u8>, DecodeError> {
        let frame = read_frame(
            &mut Bounded {
                inner: input,
                deadline: self,
            },
            MAX_CLIENT_FRAME,
        );
        if let Some((stream, _)) = self.0 {
            let _ = stream.set_read_timeout(None);
        }
        frame
    }

    fn arm(&self) -> io::Result<()> {
        let Some((stream, expires)) = self.0 else {
            return Ok(());
        };
        let left = expires.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        stream.set_read_timeout(Some(left.max(LEAST_TIMEOUT)))
    }
}

/// Both halves of a connection are dups of one socket, so this is the timeout
/// the frame reader observes.
struct Bounded<'a, R> {
    inner: &'a mut R,
    deadline: &'a HandshakeDeadline<'a>,
}

impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.deadline.arm()?;
        self.inner.read(buf)
    }
}

/// A `HashMap` has no invariant a panic can break, and mapping the poison to an
/// error would strand every running session, unreachable.
pub(crate) fn registry(daemon: &DaemonState) -> MutexGuard<'_, Registry> {
    daemon
        .sessions
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
pub(crate) struct Registry {
    pub(crate) sessions: HashMap<SessionId, SessionHandle>,
    /// Sessions admitted whose actor does not exist yet. Reading
    /// [`SESSION_LIMIT`] without a reservation is a check-then-act: every
    /// connection is served on its own thread, so N simultaneous `Hello`s all
    /// see the same free slot and all spawn.
    pub(crate) starting: HashMap<SessionId, SessionKind>,
    /// Bytes charged against [`MEMORY_BUDGET`] by the two maps above, carried
    /// rather than derived: what a session costs is a property of the session.
    pub(crate) bytes: usize,
}

impl Registry {
    pub(crate) fn admitted(&self) -> usize {
        self.sessions.len() + self.starting.len()
    }

    /// Both halves under one guard: released first and inserted second, the
    /// count dips for as long as it takes to retake the lock.
    pub(crate) fn install(&mut self, session_id: SessionId, handle: SessionHandle) {
        self.starting.remove(&session_id);
        self.sessions.insert(session_id, handle);
    }

    /// Released here only when the reservation was never traded; otherwise
    /// [`SessionCleanup`] does it, and doing both would admit the next `Hello`
    /// on memory still spoken for.
    fn release_reservation(&mut self, session_id: SessionId) {
        if let Some(kind) = self.starting.remove(&session_id) {
            self.bytes = self.bytes.saturating_sub(kind.bytes());
        }
    }

    /// The handle names what it was charged, so a forward-only session is not
    /// refunded at a terminal session's rate.
    pub(crate) fn remove(&mut self, session_id: SessionId) {
        if let Some(handle) = self.sessions.remove(&session_id) {
            self.bytes = self.bytes.saturating_sub(handle.kind.bytes());
        }
    }
}

/// `brd ls` is served on a second connection while the actor is busy with the
/// first — and a session worth killing is often one that is busy.
pub(crate) struct SessionInfo {
    pub(crate) command: String,
    pub(crate) cols: AtomicU16,
    pub(crate) rows: AtomicU16,
    /// A session is shared rather than owned, so this is a count not a flag.
    pub(crate) attachments: AtomicU16,
    /// Wall clock, because this is printed to a human.
    pub(crate) active_unix: AtomicU64,
}

impl SessionInfo {
    pub(crate) fn new(command: String, size: GridSize) -> Self {
        Self {
            command,
            cols: AtomicU16::new(size.cols),
            rows: AtomicU16::new(size.rows),
            attachments: AtomicU16::new(0),
            active_unix: AtomicU64::new(now_unix()),
        }
    }

    pub(crate) fn touch(&self) {
        self.active_unix.store(now_unix(), Ordering::Relaxed);
    }

    pub(crate) fn resized(&self, size: GridSize) {
        self.cols.store(size.cols, Ordering::Relaxed);
        self.rows.store(size.rows, Ordering::Relaxed);
    }

    pub(crate) fn summarize(&self, session_id: SessionId) -> SessionSummary {
        SessionSummary {
            session_id,
            size: GridSize {
                cols: self.cols.load(Ordering::Relaxed),
                rows: self.rows.load(Ordering::Relaxed),
            },
            attachments: self.attachments.load(Ordering::Relaxed),
            active_unix: self.active_unix.load(Ordering::Relaxed),
            command: self.command.clone(),
        }
    }
}

/// Not read off the actor: a session is charged before its actor exists and
/// refunded one destructor after it is gone.
#[derive(Clone, Copy)]
pub(crate) enum SessionKind {
    Terminal,
    Forward,
}

impl SessionKind {
    pub(crate) const fn bytes(self) -> usize {
        match self {
            Self::Terminal => SESSION_BYTES,
            Self::Forward => FORWARD_SESSION_BYTES,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SessionHandle {
    pub(crate) tx: MailboxSender,
    pub(crate) info: Arc<SessionInfo>,
    /// So the destructor that removes this entry gives back what it took.
    pub(crate) kind: SessionKind,
}

/// Where a `brd kill` waits for the session it asked to end.
///
/// Not a signal the actor sends: the registry entry outlives the actor by
/// exactly one destructor, so the sender is parked here and the guard that
/// removes the entry drops it.
#[derive(Clone, Default)]
pub(crate) struct KillNotice(pub(crate) Arc<Mutex<Option<mpsc::SyncSender<()>>>>);

impl KillNotice {
    /// A second `brd kill` replaces the first, which then falls back to its own
    /// deadline — and wakes anyway, because replacing the sender drops it.
    pub(crate) fn park(&self, reply: mpsc::SyncSender<()>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(reply);
        }
    }

    pub(crate) fn wake(&self) {
        if let Ok(mut slot) = self.0.lock() {
            slot.take();
        }
    }
}

/// Removes the session's capability file and registry entry however its thread
/// leaves, so an exit path nobody has written yet cannot skip it.
pub(crate) struct SessionCleanup {
    pub(crate) session_id: SessionId,
    pub(crate) daemon: Arc<DaemonState>,
    pub(crate) killed: KillNotice,
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(ticket_path(self.session_id));
        registry(&self.daemon).remove(self.session_id);
        // After the entry is gone, never before: the promise `brd kill` makes
        // is that the list it prints no longer names the session.
        self.killed.wake();
    }
}

/// One session admitted against [`SESSION_LIMIT`] and [`MEMORY_BUDGET`], held
/// until the registry names its actor. A guard because everything in between
/// can fail, and [`SessionCleanup`] covers none of it: that is built by the
/// session thread, which those paths never reach.
pub(crate) struct SessionSlot {
    pub(crate) session_id: SessionId,
    pub(crate) daemon: Arc<DaemonState>,
}

impl SessionSlot {
    /// The count is the same bound for either kind — a forward-only session is
    /// a session — while the charge is what the kind costs.
    pub(crate) fn reserve(
        daemon: &Arc<DaemonState>,
        kind: SessionKind,
        session_id: SessionId,
    ) -> Option<Self> {
        let bytes = kind.bytes();
        let mut registry = registry(daemon);
        if registry.admitted() >= SESSION_LIMIT
            || registry.bytes.saturating_add(bytes) > MEMORY_BUDGET
        {
            return None;
        }
        registry.starting.insert(session_id, kind);
        registry.bytes += bytes;
        drop(registry);
        Some(Self {
            session_id,
            daemon: Arc::clone(daemon),
        })
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        // A no-op once `Registry::install` has taken the reservation.
        registry(&self.daemon).release_reservation(self.session_id);
    }
}

/// One attachment admitted against [`MEMORY_BUDGET`]. A guard because an
/// attachment ends at thirteen different sites.
pub(crate) struct AttachmentSlot(pub(crate) Arc<DaemonState>);

impl AttachmentSlot {
    pub(crate) fn reserve(daemon: &Arc<DaemonState>) -> Option<Self> {
        let mut registry = registry(daemon);
        if registry.bytes.saturating_add(ATTACHMENT_BYTES) > MEMORY_BUDGET {
            return None;
        }
        registry.bytes += ATTACHMENT_BYTES;
        drop(registry);
        Some(Self(Arc::clone(daemon)))
    }
}

impl Drop for AttachmentSlot {
    fn drop(&mut self) {
        let mut registry = registry(&self.0);
        registry.bytes = registry.bytes.saturating_sub(ATTACHMENT_BYTES);
    }
}

/// Two bounds because a forward costs two unrelated things: [`FORWARD_LIMIT`]
/// bounds the sockets and threads, [`FORWARD_BYTES`] the buffers behind them.
pub(crate) struct ForwardSlot(pub(crate) Arc<DaemonState>);

impl ForwardSlot {
    pub(crate) fn reserve(daemon: &Arc<DaemonState>) -> Option<Self> {
        daemon
            .forwards
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                (live < FORWARD_LIMIT).then(|| live + 1)
            })
            .ok()?;
        let mut registry = registry(daemon);
        if registry.bytes.saturating_add(FORWARD_BYTES) > MEMORY_BUDGET {
            drop(registry);
            // By hand here because the guard that would give the count back
            // does not exist yet.
            daemon.forwards.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        registry.bytes += FORWARD_BYTES;
        drop(registry);
        Some(Self(Arc::clone(daemon)))
    }
}

impl Drop for ForwardSlot {
    fn drop(&mut self) {
        let mut registry = registry(&self.0);
        registry.bytes = registry.bytes.saturating_sub(FORWARD_BYTES);
        drop(registry);
        self.0.forwards.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::*;
    use crate::shell::*;
    use crate::state::*;
    use crate::testing::*;
    use crate::*;
    use braid_proto::SessionId;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A thread that returns without reaching the cleanup strands a `.cap` file
    /// and a registry entry naming an actor that is already gone.
    #[test]
    fn a_session_that_fails_to_start_leaves_no_ticket_and_no_registry_entry() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        persist_ticket(&ticket).expect("persist ticket");
        assert!(ticket_path(session_id).exists());

        let (tx, _rx) = mailbox();
        registry(&daemon)
            .sessions
            .insert(session_id, detached_handle(tx));

        drop(SessionCleanup {
            session_id,
            daemon: Arc::clone(&daemon),
            killed: KillNotice::default(),
        });

        assert!(!ticket_path(session_id).exists());
        assert!(registry(&daemon).sessions.is_empty());
    }

    /// A check that lets the lock go before the insert does not hold the bound:
    /// N `Hello`s arriving together all read the same free slot and all take it.
    #[test]
    fn concurrent_admissions_cannot_exceed_the_session_limit() {
        let daemon = Arc::new(DaemonState::default());
        fill_registry(&daemon, SESSION_LIMIT - 1);

        // One slot, and eight connections asking for it at the same instant.
        let racers = 8_u8;
        let start = Arc::new(std::sync::Barrier::new(usize::from(racers)));
        let threads: Vec<_> = (0..racers)
            .map(|index| {
                let daemon = Arc::clone(&daemon);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    let session_id = SessionId::from_bytes([0xF0 | index; 16]);
                    start.wait();
                    SessionSlot::reserve(&daemon, SessionKind::Terminal, session_id)
                })
            })
            .collect();
        let slots: Vec<Option<SessionSlot>> = threads
            .into_iter()
            .map(|thread| thread.join().expect("racing admission"))
            .collect();

        assert_eq!(
            slots.iter().filter(|slot| slot.is_some()).count(),
            1,
            "more sessions were admitted than this daemon has room for"
        );
        assert_eq!(registry(&daemon).admitted(), SESSION_LIMIT);

        // The one that was admitted never started.
        drop(slots);
        assert_eq!(
            registry(&daemon).admitted(),
            SESSION_LIMIT - 1,
            "a session that never started held its slot for the daemon's life"
        );
    }

    /// The charge travels with the handle and is refunded at the rate the kind
    /// actually costs: charged as a terminal one, a forward-only session would
    /// refuse a daemon thirty tunnels it has the memory for.
    #[test]
    fn a_session_is_charged_and_refunded_for_what_its_kind_holds() {
        for (kind, bytes) in [
            (SessionKind::Terminal, SESSION_BYTES),
            (SessionKind::Forward, FORWARD_SESSION_BYTES),
        ] {
            let daemon = Arc::new(DaemonState::default());
            let session_id = SessionId::from_bytes([9; 16]);
            let slot = SessionSlot::reserve(&daemon, kind, session_id)
                .expect("an empty daemon admits one");
            assert_eq!(registry(&daemon).bytes, bytes);

            let (tx, _rx) = mailbox();
            registry(&daemon).install(
                session_id,
                SessionHandle {
                    tx,
                    info: forward_info(),
                    kind,
                },
            );
            drop(slot);
            assert_eq!(
                registry(&daemon).bytes,
                bytes,
                "the charge travelled with the handle"
            );
            registry(&daemon).remove(session_id);
            assert_eq!(
                registry(&daemon).bytes,
                0,
                "the refund was at another kind's rate"
            );

            fill_registry(&daemon, SESSION_LIMIT);
            assert!(
                SessionSlot::reserve(&daemon, kind, SessionId::from_bytes([10; 16])).is_none(),
                "the count bound stopped applying"
            );
        }
    }

    /// The count bound says nothing about memory: sixty-four sessions of
    /// today's shape is a gigabyte before a single client has attached.
    #[test]
    fn a_session_is_refused_when_the_daemon_has_no_memory_left_for_it() {
        let daemon = Arc::new(DaemonState::default());
        let admitted: Vec<SessionSlot> = (0..u8::MAX)
            .filter_map(|n| {
                SessionSlot::reserve(
                    &daemon,
                    SessionKind::Terminal,
                    SessionId::from_bytes([n; 16]),
                )
            })
            .collect();
        assert!(
            admitted.len() < SESSION_LIMIT,
            "the byte budget binds before the count does: {} admitted",
            admitted.len()
        );
        assert_eq!(admitted.len(), MEMORY_BUDGET / SESSION_BYTES);
        assert!(registry(&daemon).bytes <= MEMORY_BUDGET);

        // A reservation that was never traded gives its charge back, or a
        // daemon that refused a hundred sessions could never run another.
        drop(admitted);
        assert_eq!(registry(&daemon).bytes, 0);
        assert!(
            SessionSlot::reserve(
                &daemon,
                SessionKind::Terminal,
                SessionId::from_bytes([0; 16])
            )
            .is_some()
        );
    }

    /// A wedged `brd --server` holds a thread and a descriptor with no read
    /// timeout under it, and the daemon never exits.
    #[test]
    fn connections_past_the_bound_are_refused_and_their_slots_come_back() {
        let daemon = Arc::new(DaemonState::default());
        let held: Vec<ConnectionSlot> = (0..CONNECTION_LIMIT)
            .filter_map(|_| ConnectionSlot::take(&daemon))
            .collect();
        assert_eq!(held.len(), CONNECTION_LIMIT);
        assert!(
            ConnectionSlot::take(&daemon).is_none(),
            "a daemon at its bound refuses rather than spawning another thread"
        );
        drop(held);
        assert!(ConnectionSlot::take(&daemon).is_some());
    }

    /// `SO_RCVTIMEO` restarts on every `read`, and the frame reader is a
    /// `read_exact` loop, so the deadline must bound the frame.
    #[test]
    fn a_first_frame_that_dribbles_is_bounded_by_the_frame_and_not_by_one_read() {
        let (mut peer, daemon) = UnixStream::pair().expect("a socket pair");
        // A length prefix promising a frame that never arrives, then one byte
        // per read for as long as anyone is listening.
        thread::spawn(move || {
            let _ = peer.write_all(&1024_u32.to_be_bytes());
            while peer.write_all(b"x").is_ok() {
                thread::sleep(Duration::from_millis(20));
            }
        });

        let handshake = HandshakeDeadline::on(&daemon, Duration::from_millis(150));
        let started = Instant::now();
        let refused = handshake.first_frame(&mut &daemon);

        assert!(
            refused.is_err(),
            "a frame that never completed was accepted"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the deadline bounded one read rather than the frame"
        );
    }
}
