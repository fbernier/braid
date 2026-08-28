#![forbid(unsafe_code)]

//! The session actor's mailbox: control ahead of output, always.
//!
//! `attachment_loop` blocks on send, so one channel carrying both would make a
//! `Ctrl-C` typed at `yes(1)` wait out every queued PTY read in front of it.

use crate::attachment::Framing;
use crate::forward::ForwardLink;
use crate::sink::AttachmentSink;
use crate::{AttachKind, AttachmentId};
use braid_proto::{
    ClientId, ClientMessage, DatagramOffer, ForwardResetReason, SearchMatch, StreamId,
};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

/// A buffer on loan from the thread that filled it. It keeps its full length
/// for life and travels back to that thread when the actor is done with it, so
/// a producer at speed allocates nothing and zeroes nothing per read.
pub(crate) struct Chunk {
    buf: Vec<u8>,
    len: usize,
}

impl Chunk {
    /// Drawn from `spare` when the round trip has kept up, and only otherwise
    /// allocated. A recycled buffer is already `size` long, so the `resize` it
    /// is handed back through costs no memset.
    pub(crate) fn take(spare: &mpsc::Receiver<Vec<u8>>, size: usize) -> Self {
        let mut buf = spare.try_recv().unwrap_or_default();
        buf.resize(size, 0);
        Self { buf, len: 0 }
    }

    /// Bytes already in hand rather than on loan from a pool.
    #[cfg(test)]
    pub(crate) fn owned(buf: Vec<u8>) -> Self {
        let len = buf.len();
        Self { buf, len }
    }

    /// The room the producer reads into, before it says how much it filled.
    pub(crate) fn room(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// How much of that room the producer used. Clamped, so no caller can name
    /// more bytes than the buffer holds.
    pub(crate) fn filled(mut self, len: usize) -> Self {
        self.len = len.min(self.buf.len());
        self
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Back to the thread that filled it; a receiver that has gone costs the
    /// one buffer rather than an actor turn spent retrying.
    pub(crate) fn release(self, spare: &mpsc::SyncSender<Vec<u8>>) {
        let _ = spare.try_send(self.buf);
    }
}

pub(crate) enum ActorEvent {
    Attach {
        id: AttachmentId,
        /// A resume replaces the attachment carrying the same one.
        client: ClientId,
        sink: AttachmentSink,
        kind: AttachKind,
        framing: Framing,
        offer: Option<DatagramOffer>,
    },
    Command {
        id: AttachmentId,
        message: ClientMessage,
    },
    Detached(AttachmentId),
    PtyOutput(Chunk),
    PtyEnded,
    /// The sender is never sent on: it is parked in [`KillNotice`] and dropped
    /// by the guard that removes the registry entry, so what wakes the asker is
    /// the session being gone rather than the actor having read this.
    Kill {
        reply: mpsc::SyncSender<()>,
    },
    /// Only this actor's thread may touch the scrollback. `deadline` is
    /// honoured rather than merely raced: a search costs a render across eight
    /// megabytes on the thread the client is typing at, and `Search` is
    /// unrated on the wire.
    Search {
        pattern: Arc<str>,
        limit: usize,
        deadline: Instant,
        reply: mpsc::SyncSender<Vec<SearchMatch>>,
    },
    ForwardConnected {
        client: ClientId,
        stream: StreamId,
        link: Result<ForwardLink, ForwardResetReason>,
    },
    ForwardBytes {
        client: ClientId,
        stream: StreamId,
        bytes: Chunk,
    },
    ForwardEof {
        client: ClientId,
        stream: StreamId,
        failed: bool,
    },
}

/// Control events one actor may have waiting. Generous on purpose: each is
/// small, and this is a bound rather than a pacing mechanism.
pub(crate) const CONTROL_LANE: usize = 256;

/// Bulk events one actor may have waiting, in frames rather than bytes. A
/// producer parking on a full lane is what stops `yes(1)` buffering the
/// daemon's memory away. Forward threads share these slots: a second bulk lane
/// would be a second producer with no bound relating it to the first.
pub(crate) const OUTPUT_LANE: usize = 32;

/// The end of a stream travels *in* that stream: `PtyEnded` on the control lane
/// would overtake the reads queued ahead of it, discarding the last output of
/// every shell that prints and then exits.
const fn is_bulk(event: &ActorEvent) -> bool {
    matches!(
        event,
        ActorEvent::PtyOutput(_)
            | ActorEvent::PtyEnded
            | ActorEvent::ForwardConnected { .. }
            | ActorEvent::ForwardBytes { .. }
            | ActorEvent::ForwardEof { .. }
    )
}

pub(crate) struct Mailbox {
    state: Mutex<MailboxState>,
    pub(crate) arrived: Condvar,
    pub(crate) room: Condvar,
}

#[derive(Default)]
struct MailboxState {
    pub(crate) control: VecDeque<ActorEvent>,
    pub(crate) output: VecDeque<ActorEvent>,
    /// Tells a mailbox nobody can write to from one that is merely idle.
    senders: usize,
    /// The actor is gone: nothing queued here will ever be read.
    pub(crate) closed: bool,
}

impl MailboxState {
    fn has_room(&self, event: &ActorEvent) -> bool {
        match event {
            // Reserved outright: it is the shell having ended already, it
            // happens once per session, and a session nobody is told has
            // finished is every client on it waiting on a dead PTY.
            ActorEvent::PtyEnded => true,
            // One slot past the bound, not an unbounded lane: nothing bounds
            // how often a management connection may ask.
            ActorEvent::Kill { .. } => self.control.len() < CONTROL_LANE + 1,
            event if is_bulk(event) => self.output.len() < OUTPUT_LANE,
            _ => self.control.len() < CONTROL_LANE,
        }
    }

    pub(crate) fn push(&mut self, event: ActorEvent) {
        if is_bulk(&event) {
            self.output.push_back(event);
        } else {
            self.control.push_back(event);
        }
    }

    pub(crate) fn take(&mut self) -> Option<ActorEvent> {
        self.control.pop_front().or_else(|| self.output.pop_front())
    }

    fn lanes_full(&self) -> bool {
        self.control.len() >= CONTROL_LANE || self.output.len() >= OUTPUT_LANE
    }
}

#[derive(Debug)]
pub(crate) struct MailboxClosed;

#[derive(Debug)]
pub(crate) enum TrySendError {
    Full,
    Closed,
}

pub(crate) enum NoEvent {
    Timeout,
    Disconnected,
}

pub(crate) struct MailboxSender(Arc<Mailbox>);

impl MailboxSender {
    /// Waits for room in its *own* lane: the PTY reader parking here is
    /// backpressure on the shell, and a keystroke that waited behind it would
    /// wait out the flood it interrupts.
    pub(crate) fn send(&self, event: ActorEvent) -> Result<(), MailboxClosed> {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.closed {
                // Released before the event it refused: see `try_send`.
                drop(state);
                return Err(MailboxClosed);
            }
            if state.has_room(&event) {
                state.push(event);
                drop(state);
                self.0.arrived.notify_one();
                return Ok(());
            }
            state = self
                .0
                .room
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// A per-keystroke `Command` deliberately uses [`Self::send`] — there the
    /// wait *is* the backpressure — but an `Attach` has no reserved slot and
    /// the socket read timeout is already lifted, so an untimed wait would park
    /// a connection thread and its descriptor for as long as the session likes.
    pub(crate) fn send_timeout(
        &self,
        event: ActorEvent,
        timeout: Duration,
    ) -> Result<(), TrySendError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.closed {
                drop(state);
                return Err(TrySendError::Closed);
            }
            if state.has_room(&event) {
                state.push(event);
                drop(state);
                self.0.arrived.notify_one();
                return Ok(());
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                // The guard goes before the refused event does: see
                // [`Self::try_send`].
                drop(state);
                return Err(TrySendError::Full);
            };
            let (next, _) = self
                .0
                .room
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
    }

    pub(crate) fn try_send(&self, event: ActorEvent) -> Result<(), TrySendError> {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            drop(state);
            return Err(TrySendError::Closed);
        }
        if !state.has_room(&event) {
            // The guard goes before the refused event does: dropping an
            // `Attach` drops its sink, and a datagram sink's destructor comes
            // back here with a `Detached` on a lock that is not reentrant.
            drop(state);
            return Err(TrySendError::Full);
        }
        state.push(event);
        drop(state);
        self.0.arrived.notify_one();
        Ok(())
    }
}

impl Clone for MailboxSender {
    fn clone(&self) -> Self {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .senders += 1;
        Self(Arc::clone(&self.0))
    }
}

impl Drop for MailboxSender {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.senders -= 1;
        let last = state.senders == 0;
        drop(state);
        if last {
            self.0.arrived.notify_one();
        }
    }
}

pub(crate) struct MailboxReceiver(Arc<Mailbox>);

impl MailboxReceiver {
    /// Take the next event, or give up after `timeout`.
    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<ActorEvent, NoEvent> {
        let deadline = Instant::now() + timeout;
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            // Read before the pop, and only then: a lane below its bound has
            // nobody parked on it, and this runs once per PTY read.
            let full = state.lanes_full();
            if let Some(event) = state.take() {
                drop(state);
                if full {
                    self.0.room.notify_all();
                }
                return Ok(event);
            }
            if state.senders == 0 {
                return Err(NoEvent::Disconnected);
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Err(NoEvent::Timeout);
            };
            let (next, _) = self
                .0
                .arrived
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
    }
}

impl Drop for MailboxReceiver {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
        // Everything parked on a lane that will never have room again.
        self.0.room.notify_all();
    }
}

pub(crate) fn mailbox() -> (MailboxSender, MailboxReceiver) {
    let mailbox = Arc::new(Mailbox {
        state: Mutex::new(MailboxState {
            senders: 1,
            ..MailboxState::default()
        }),
        arrived: Condvar::new(),
        room: Condvar::new(),
    });
    (
        MailboxSender(Arc::clone(&mailbox)),
        MailboxReceiver(mailbox),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;
    use crate::*;
    use braid_proto::{ClientMessage, CmdSeq};
    use std::time::Duration;

    /// A `Ctrl-C` typed at `yes(1)` must not wait for the actor to chew through
    /// megabytes of the very output it was typed to stop.
    #[test]
    fn a_command_overtakes_the_pty_output_already_queued() {
        let (tx, rx) = mailbox();
        for _ in 0..OUTPUT_LANE {
            tx.try_send(pty_output(b"yes\n"))
                .expect("a free output slot");
        }
        assert!(
            matches!(tx.try_send(pty_output(b"yes\n")), Err(TrySendError::Full)),
            "there is no backlog here to overtake"
        );

        tx.send(ActorEvent::Command {
            id: next_attachment(),
            message: ClientMessage::Input {
                seq: CmdSeq::first(),
                bytes: b"\x03".to_vec(),
            },
        })
        .expect("a control send never waits for output");
        assert!(
            matches!(
                rx.recv_timeout(Duration::ZERO),
                Ok(ActorEvent::Command { .. })
            ),
            "the keystroke waited out the flood it was typed to interrupt"
        );
        assert!(
            matches!(
                rx.recv_timeout(Duration::ZERO),
                Ok(ActorEvent::PtyOutput(_))
            ),
            "overtaking dropped the output it went past"
        );
    }

    /// A shell that prints and then exits must not have its last output
    /// discarded by its own teardown.
    #[test]
    fn the_end_of_the_pty_stream_arrives_behind_the_output_it_follows() {
        let (tx, rx) = mailbox();
        for _ in 0..OUTPUT_LANE {
            tx.try_send(pty_output(b"BRD_ARGV\r\n"))
                .expect("a free output slot");
        }
        // Reserved like `Kill`: a full lane must not lose the one event that
        // says the shell is gone.
        tx.try_send(ActorEvent::PtyEnded)
            .expect("a shell exiting is never refused");

        for _ in 0..OUTPUT_LANE {
            let Ok(ActorEvent::PtyOutput(read)) = rx.recv_timeout(Duration::ZERO) else {
                panic!("the teardown overtook the output it follows");
            };
            assert_eq!(read.bytes(), b"BRD_ARGV\r\n");
        }
        assert!(matches!(
            rx.recv_timeout(Duration::ZERO),
            Ok(ActorEvent::PtyEnded)
        ));
    }

    /// Splitting the lanes must not cost the backpressure: an unbounded output
    /// lane is a `yes(1)` the emulator never catches up with.
    #[test]
    fn a_full_output_lane_holds_the_pty_reader_until_the_actor_takes_one() {
        let (tx, rx) = mailbox();
        for _ in 0..OUTPUT_LANE {
            tx.try_send(pty_output(b"yes\n"))
                .expect("a free output slot");
        }
        let reader = tx.clone();
        let (finished, waited) = mpsc::channel();
        thread::spawn(move || {
            let _ = finished.send(reader.send(pty_output(b"yes\n")).is_ok());
        });
        assert!(
            waited.recv_timeout(REAP_POLL * 10).is_err(),
            "a full output lane took another read"
        );

        assert!(matches!(
            rx.recv_timeout(Duration::ZERO),
            Ok(ActorEvent::PtyOutput(_))
        ));
        assert_eq!(
            waited.recv_timeout(Duration::from_secs(2)),
            Ok(true),
            "the reader was never woken by the room it was waiting for"
        );
    }

    /// Reserved room past the bound is justified for `PtyEnded` — exactly one
    /// per session — and not for a message a management connection may loop on.
    #[test]
    fn a_kill_draws_on_one_reserved_slot_rather_than_an_unbounded_lane() {
        let mut state = MailboxState::default();
        for _ in 0..CONTROL_LANE {
            state.push(ActorEvent::Detached(AttachmentId(1)));
        }
        assert!(
            !state.has_room(&ActorEvent::Detached(AttachmentId(1))),
            "the ordinary lane is full"
        );
        assert!(state.has_room(&kill()), "a kill draws on reserved room");
        state.push(kill());
        assert!(
            !state.has_room(&kill()),
            "one slot of reserved room, not an unbounded lane"
        );
        // The shell having already ended is still told, exactly once.
        assert!(state.has_room(&ActorEvent::PtyEnded));
    }
}
