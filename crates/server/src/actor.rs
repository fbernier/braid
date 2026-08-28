#![forbid(unsafe_code)]

//! One session's thread: the emulator, the shell and every client watching.

use crate::attachment::{Admission, Attachment, ClientStream, Framing, Painted, Painting};
use crate::backlog::BacklogRing;
use crate::defer::{DeferMark, DeferredOsc};
use crate::forward::{FORWARD_OVERHEAD, Forward, ForwardLink, Forwards};
use crate::mailbox::{ActorEvent, Chunk, MailboxReceiver, MailboxSender, NoEvent};
use crate::ptyin::PtyInput;
use crate::query::{Answer, Emulator, QueryFilter};
use crate::registry::{AttachmentSlot, DaemonState, ForwardSlot, KillNotice, SessionInfo};
use crate::shell::Shell;
use crate::sink::{self, AttachmentSink, SinkError};
use crate::state::printable;
use crate::{
    AttachKind, AttachmentId, FORWARD_SESSION_GRACE, IDLE_DEADLINE, ReplayError, ServerError,
    SessionEffects, SharedSink, gate, log::log, sessions,
};
use braid_forward::Segment;
use braid_proto::{
    ByteOff, Capability, ClientId, ClientMessage, CmdSeq, DatagramOffer, DetachReason,
    ForwardResetReason, ForwardTarget, Generation, GridSize, InputCue, MAX_ATTACHMENTS,
    MAX_FORWARDS, MAX_MATCH_LINE, RejectReason, ScreenHeader, ScreenVersion, SearchMatch,
    ServerMessage, StreamId, encode_output_into,
};
use braid_vt::VtEngine;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) struct SessionActor {
    pub(crate) ticket: sessions::SessionTicket,
    pub(crate) daemon: Arc<DaemonState>,
    /// `None` is a session carrying forwards and nothing else.
    pub(crate) terminal: Option<Terminal>,
    /// The effective grid: the smallest attached terminal on both axes.
    pub(crate) size: GridSize,
    pub(crate) info: Arc<SessionInfo>,
    pub(crate) attachments: Vec<Attachment>,
    /// The command streams of clients whose transports are gone, newest last.
    pub(crate) retired: Vec<ClientStream>,
    pub(crate) offset: ByteOff,
    /// Only ever moves forward: reissued across a resize it would replay the
    /// byte stream onto a screen it was never written for.
    pub(crate) generation: Generation,
    /// Where a `brd kill` is waiting; the session's own cleanup wakes it.
    pub(crate) killed: KillNotice,
    pub(crate) tx: MailboxSender,
    /// Keyed by client, not attachment: a forward outlives the transport it
    /// was opened over, which is what `-L` promises across a roam.
    pub(crate) forwards: Forwards,
    /// When this session was last left with no attachment; only a
    /// forward-only session is ever ended for it.
    pub(crate) detached_since: Option<Instant>,
}

/// Everything a session has only because it is driving a terminal.
pub(crate) struct Terminal {
    pub(crate) shell: Shell,
    pub(crate) pty_in: PtyInput,
    pub(crate) vt: VtEngine<SharedSink>,
    pub(crate) effects: Arc<SessionEffects>,
    pub(crate) backlog: BacklogRing,
    /// OSC sequences carried past the sync episodes that would swallow them.
    pub(crate) deferred: DeferredOsc,
    /// Cuts the queries the emulator already answered from the output a client
    /// is sent, so the client's own terminal is not asked them a second time.
    pub(crate) queries: QueryFilter,
    /// The filtered output, held across calls so a burst allocates nothing.
    pub(crate) forwarded: Vec<u8>,
    /// When the PTY last produced bytes; drives the return to passthrough.
    pub(crate) last_output: Option<Instant>,
    /// Read buffers on their way back to the PTY reader.
    pub(crate) spent: mpsc::SyncSender<Vec<u8>>,
}

impl Terminal {
    /// What this session promises about the echo of the next keystroke.
    fn cue(&self, cols: u16) -> InputCue {
        self.vt
            .cursor_cue()
            .map_or(InputCue::Opaque, |cue| input_cue(cue, cols))
    }
}

/// [`Emulator`] over the session's own engine and reply counter.
///
/// The reply itself goes where every reply goes: into `effects`, and from
/// there to the PTY as input. All this reports is that one happened, which is
/// the whole of what decides whether a span of output was the application's or
/// a question the emulator has already dealt with.
struct Attribution<'a> {
    vt: &'a mut VtEngine<SharedSink>,
    effects: &'a SessionEffects,
}

impl Emulator for Attribution<'_> {
    type Error = braid_vt::VtError;

    fn consume(&mut self, bytes: &[u8]) -> Result<Answer, Self::Error> {
        let before = self.effects.answers();
        self.vt.feed(bytes)?;
        if self.effects.answers() == before {
            Ok(Answer::Silent)
        } else {
            Ok(Answer::Replied)
        }
    }
}

/// The soonest wakeup that can accomplish anything: taking the sooner of the
/// repaint *gates* instead turns `recv_timeout` into a busy loop.
pub(crate) fn next_deadline(ping: Duration, repaint_hold: Option<Duration>) -> Duration {
    match repaint_hold {
        Some(hold) => ping.min(hold),
        None => ping,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Turn {
    Continue,
    Stop,
}

/// Run one session's body, telling its clients if it panics: a socket that
/// merely closes is a dead transport rather than a session that is over.
pub(crate) fn guarded(actor: &mut SessionActor, body: impl FnOnce(&mut SessionActor)) {
    if catch_unwind(AssertUnwindSafe(|| body(actor))).is_err() {
        log!("session ended: its thread panicked");
        actor.dismiss(&ServerMessage::Reject {
            reason: RejectReason::Internal,
        });
    }
}

impl SessionActor {
    pub(crate) fn run(&mut self, rx: &MailboxReceiver) {
        // Edge-triggered: level-triggered this is a log line per PTY read.
        let mut refusing = false;
        loop {
            let refused = !self.regrid();
            if refused && !refusing {
                log!("the shell refused the grid its clients asked for");
            }
            refusing = refused;
            let event = match rx.recv_timeout(self.deadline()) {
                Ok(event) => event,
                // A tick that ends the session has already said why.
                Err(NoEvent::Timeout) if self.ticked() == Turn::Stop => break,
                Err(NoEvent::Timeout) => continue,
                Err(NoEvent::Disconnected) => break,
            };
            let stop = match event {
                ActorEvent::Attach {
                    id,
                    client,
                    sink,
                    kind,
                    framing,
                    offer,
                } => {
                    self.attach(id, client, sink, kind, framing, offer);
                    false
                }
                ActorEvent::Command { id, message } => self.command(id, message),
                ActorEvent::Detached(id) => {
                    if let Some(index) = self.index_of(id) {
                        self.drop_attachment(index);
                    }
                    false
                }
                ActorEvent::PtyOutput(read) => {
                    // Never crosses the wire: bytes the emulator consumed that
                    // never entered the ring leave both screens wrong forever.
                    let failed = self
                        .output(read.bytes())
                        .inspect_err(|error| log!("session output failed: {error}"))
                        .is_err();
                    if let Some(terminal) = self.terminal.as_ref() {
                        read.release(&terminal.spent);
                    }
                    if failed {
                        self.dismiss(&ServerMessage::Reject {
                            reason: RejectReason::Internal,
                        });
                    }
                    failed
                }
                ActorEvent::PtyEnded => match self.terminal.as_mut() {
                    Some(terminal) => {
                        let code = terminal.shell.shut_down();
                        self.end(code);
                        true
                    }
                    None => false,
                },
                ActorEvent::Kill { reply } => {
                    // Parked, not answered: `brd kill` waits for the registry
                    // entry, which outlives this actor by one destructor.
                    self.killed.park(reply);
                    self.end(0);
                    true
                }
                ActorEvent::Search {
                    pattern,
                    limit,
                    deadline,
                    reply,
                } => {
                    self.search(&pattern, limit, deadline, &reply);
                    false
                }
                ActorEvent::ForwardConnected {
                    client,
                    stream,
                    link,
                } => {
                    self.forward_connected(client, stream, link);
                    false
                }
                ActorEvent::ForwardBytes {
                    client,
                    stream,
                    bytes,
                } => {
                    self.forward_read(client, stream, bytes);
                    false
                }
                ActorEvent::ForwardEof {
                    client,
                    stream,
                    failed,
                } => {
                    self.forward_eof(client, stream, failed);
                    false
                }
            };
            if stop {
                break;
            }
            // On every turn: bytes queued into a forward arm no timer until
            // they have been transmitted once.
            self.pump_forwards(Instant::now());
        }
    }

    pub(crate) fn end(&mut self, code: i32) {
        self.dismiss(&ServerMessage::Exit { code });
    }

    /// End the session on a turn that failed, telling every client why.
    pub(crate) fn failed(&mut self, error: &ServerError) {
        log!("session ended: {error}");
        self.dismiss(&ServerMessage::Reject {
            reason: RejectReason::Internal,
        });
    }

    fn dismiss(&mut self, message: &ServerMessage) {
        for index in (0..self.attachments.len()).rev() {
            let _ = self.attachments[index].sink.send(message);
            self.drop_attachment(index);
        }
    }

    fn index_of(&self, id: AttachmentId) -> Option<usize> {
        self.attachments
            .iter()
            .position(|attachment| attachment.id == id)
    }

    /// Publish what `brd ls` reads, and start the clock a forward-only session
    /// is reaped on at the first call that leaves no attachment.
    fn note_attachments(&mut self) {
        self.info.attachments.store(
            u16::try_from(self.attachments.len()).unwrap_or(u16::MAX),
            Ordering::Relaxed,
        );
        self.info.touch();
        self.detached_since = if self.attachments.is_empty() {
            self.detached_since.or_else(|| Some(Instant::now()))
        } else {
            None
        };
    }

    /// Give up on one attachment. The only site that closes a sink: its writer
    /// parks on a condvar no peer disconnect wakes, leaking a thread and an fd.
    fn drop_attachment(&mut self, index: usize) {
        let attachment = self.attachments.remove(index);
        attachment.sink.close();
        self.retire(attachment.stream);
        self.note_attachments();
    }

    /// Keep this client's command stream for the resume that replays it. The
    /// eviction also drops the forwards ring nothing else would ever key out.
    pub(crate) fn retire(&mut self, stream: ClientStream) {
        self.retired.retain(|kept| kept.client != stream.client);
        self.retired.push(stream);
        if self.retired.len() > MAX_ATTACHMENTS {
            let gone = self.retired.remove(0);
            self.forwards.forget(gone.client);
        }
    }

    fn take_stream(&mut self, client: ClientId) -> ClientStream {
        match self.retired.iter().position(|kept| kept.client == client) {
            Some(index) => self.retired.remove(index),
            None => ClientStream::new(client),
        }
    }

    fn next_generation(&mut self) -> Generation {
        self.generation = self.generation.next();
        self.generation
    }

    /// Where an attachment entering a sync episode starts carrying from.
    fn deferred_mark(&self) -> DeferMark {
        self.terminal
            .as_ref()
            .map_or(DeferMark(0), |terminal| terminal.deferred.mark())
    }

    /// The largest grid every attached terminal can show.
    fn requested_grid(&self) -> Option<GridSize> {
        self.attachments
            .iter()
            .map(|attachment| attachment.size)
            .reduce(|grid, size| GridSize {
                cols: grid.cols.min(size.cols),
                rows: grid.rows.min(size.rows),
            })
    }

    /// Fit the shell and the emulator to the smallest attached terminal, and
    /// answer whether it took. A session nobody is watching keeps its grid.
    pub(crate) fn regrid(&mut self) -> bool {
        let Some(size) = self.requested_grid() else {
            return true;
        };
        if size == self.size {
            return true;
        }
        let Some(terminal) = self.terminal.as_mut() else {
            return true;
        };
        let previous = self.size;
        if !terminal.shell.resize(size) {
            return false;
        }
        // Committed only once every fallible step has taken it: ahead of the
        // emulator, the early return above makes a refused resize permanent.
        if terminal.vt.resize(size).is_err() {
            // Silent: a second log line here would fire per actor turn.
            let _ = terminal.shell.resize(previous);
            return false;
        }
        // Read while borrowed: the generation below borrows the whole session.
        let mark = terminal.deferred.mark();
        self.size = size;
        self.info.resized(size);
        // Every row moved, and passthrough says nothing about a grid change.
        let generation = self.next_generation();
        for attachment in &mut self.attachments {
            attachment.regrid(generation, size.rows);
            attachment.begin_sync(mark);
        }
        true
    }

    /// Install a new attachment. Nothing here may end the session: a client
    /// that fails to attach is dropped and the PTY keeps running.
    #[expect(
        clippy::too_many_lines,
        reason = "one attachment's whole admission, in the order it happens"
    )]
    pub(crate) fn attach(
        &mut self,
        id: AttachmentId,
        client: ClientId,
        sink: AttachmentSink,
        kind: AttachKind,
        framing: Framing,
        offer: Option<DatagramOffer>,
    ) {
        if let Some(index) = self
            .attachments
            .iter()
            .position(|attachment| attachment.stream.client == client)
        {
            // The same `brd` on a newer transport; a *different* client never
            // displaces anyone. Told why, or it types into a dead socket.
            let _ = self.attachments[index].sink.send(&ServerMessage::Detached {
                reason: DetachReason::Replaced,
            });
            self.drop_attachment(index);
        } else if self.attachments.len() >= MAX_ATTACHMENTS {
            // Never an attachment, so `drop_attachment` cannot close this sink.
            let _ = sink.send(&ServerMessage::Reject {
                reason: RejectReason::TooManyAttachments,
            });
            sink.close();
            return;
        }
        let Some(charge) = AttachmentSlot::reserve(&self.daemon) else {
            log!("refused an attachment: this daemon is already holding as much as it will");
            let _ = sink.send(&ServerMessage::Reject {
                reason: RejectReason::TooManyAttachments,
            });
            sink.close();
            return;
        };
        let stream = self.take_stream(client);
        let highest = stream.highest();
        // A resume carries no size: it starts fitting and states its own with
        // a `Resize` when it differs.
        let mut attachment = Attachment::new(
            id,
            stream,
            sink,
            framing,
            self.size,
            self.generation,
            charge,
        );
        // Nothing this client holds could be a delta base.
        attachment.ledger.invalidate(self.size.rows);
        self.attachments.push(attachment);
        self.note_attachments();
        let index = self.attachments.len() - 1;
        // The greeting names the kind of session, not the request that reached it.
        let session_id = self.ticket.session_id;
        let capability = Capability::from_bytes(self.ticket.capability);
        let version = self.attachments[index].sink.version();
        let greeting = if self.terminal.is_some() {
            ServerMessage::Hello {
                version,
                size: self.size,
                session_id,
                capability,
                offer,
            }
        } else {
            ServerMessage::HelloForward {
                version,
                session_id,
                capability,
                offer,
            }
        };
        if self.attachments[index].sink.send(&greeting).is_err() {
            self.drop_attachment(index);
            return;
        }
        let AttachKind::Resume(confirmed) = kind else {
            return;
        };
        // Before any replayed output: a resuming client seeds its sequence from it.
        if self.attachments[index]
            .sink
            .send(&ServerMessage::CommandAck { highest })
            .is_err()
        {
            self.drop_attachment(index);
            return;
        }
        // A repaint armed with no emulator can never fire, and one whose hold
        // has expired makes `deadline` zero: a core spun for the session.
        if self.terminal.is_none() {
            return;
        }
        let mark = self.deferred_mark();
        // What this client asked for and will not get if the resume is answered
        // with a screen. The screen converges the grid; these bytes never reach
        // the user's own scrollback, so they are named rather than dropped quietly.
        let behind = self.offset.get().saturating_sub(confirmed.next_off.get());
        // A generation that is not this session's names a pre-resize screen.
        if confirmed.generation != self.attachments[index].generation {
            self.report_skipped(index, behind);
            self.attachments[index].begin_sync(mark);
            return;
        }
        // Otherwise a quarter megabyte of history goes into the sink before
        // `Full` triggers a repaint that supersedes all of it.
        if behind > u64::try_from(sink::STREAM_LIMIT).unwrap_or(u64::MAX) {
            // Queued history the screen about to be armed already accounts for.
            self.attachments[index].sink.discard_stream();
            self.report_skipped(index, behind);
            self.attachments[index].begin_sync(mark);
            return;
        }
        let echo_ack = self.attachments[index].stream.echo_ack(Instant::now());
        let replayed = self.replay(
            &self.attachments[index].sink,
            self.attachments[index].framing.output_chunk(),
            confirmed.next_off,
            echo_ack,
        );
        match replayed {
            Ok(()) => self.attachments[index].resumed(),
            // Recoverable: paint rather than end a session with work in it.
            Err(ReplayError::Evicted) => {
                self.report_skipped(index, behind);
                self.attachments[index].begin_sync(mark);
            }
            // Whatever the sink did take is still queued ahead of the screen, so
            // only the tail past where it stopped is owed.
            Err(ReplayError::Filled(reached)) => {
                let unsent = self.offset.get().saturating_sub(reached.get());
                self.report_skipped(index, unsent);
                self.attachments[index].begin_sync(mark);
            }
            // The transport is gone or refusing frames it can never take, so
            // there is no client left to paint for. Named: this is the one
            // resume outcome that costs the attachment rather than the history.
            Err(ReplayError::Sink(error)) => {
                log!("attachment dropped while replaying: {error:?}");
                self.drop_attachment(index);
            }
        }
    }

    /// Tell one client how much of the stream it will never be handed.
    ///
    /// Gated on the negotiated version because a *message* the peer does not know
    /// is a hard decode error rather than a skipped field: an older client must
    /// never be sent one. A failure to queue it is ignored — the screen behind it
    /// is what the session actually owes, and the next send reports the same fault.
    fn report_skipped(&mut self, index: usize, bytes: u64) {
        if bytes == 0
            || !self.attachments[index]
                .sink
                .version()
                .carries_output_skipped()
        {
            return;
        }
        log!("attachment resumed {bytes} bytes past what it will be handed");
        let _ = self.attachments[index]
            .sink
            .send(&ServerMessage::OutputSkipped { bytes });
    }

    #[expect(clippy::too_many_lines, reason = "one admission ordering")]
    pub(crate) fn command(&mut self, id: AttachmentId, message: ClientMessage) -> bool {
        let Some(index) = self.index_of(id) else {
            return false;
        };
        self.info.touch();
        match message {
            ClientMessage::Input { seq, bytes } => {
                let Some(terminal) = self.terminal.as_ref() else {
                    return self.ignore(id, index, seq);
                };
                match self.attachments[index].stream.check(seq) {
                    Admission::Fresh => {
                        // After the write: ahead of it a failed write leaves
                        // the sequence consumed and its replay acked unapplied.
                        if terminal.pty_in.write(&bytes) {
                            self.attachments[index].stream.applied(seq, Instant::now());
                            self.ack(id, seq);
                        } else {
                            log!("input backlog full; dropping the attachment");
                            return self.reject(id, RejectReason::InputBacklog);
                        }
                    }
                    Admission::Duplicate => self.ack(id, seq),
                    Admission::Gap => return self.gap(id, index),
                }
            }
            ClientMessage::Resize { seq, size } => {
                match self.attachments[index].stream.admit(seq) {
                    Admission::Fresh => {
                        self.attachments[index].size = size;
                        if self.regrid() {
                            self.ack(id, seq);
                        } else {
                            // Charged to the attachment: ending the session
                            // drops `Shell` and the work in it.
                            let stop = self.reject(id, RejectReason::Internal);
                            // The size nothing could apply left with it.
                            if !self.regrid() {
                                log!("the grid was not restored after a refused resize");
                            }
                            return stop;
                        }
                    }
                    Admission::Duplicate => self.ack(id, seq),
                    Admission::Gap => return self.gap(id, index),
                }
            }
            ClientMessage::RequestRepaint { seq } => {
                let Some(terminal) = self.terminal.as_ref() else {
                    return self.ignore(id, index, seq);
                };
                let mark = terminal.deferred.mark();
                match self.attachments[index].stream.admit(seq) {
                    Admission::Fresh => {
                        let generation = self.next_generation();
                        let rows = self.size.rows;
                        let attachment = &mut self.attachments[index];
                        attachment.restart(generation, rows);
                        attachment.begin_sync(mark);
                        if self.repaint(Painted::One(id)).is_err() {
                            return self.reject(id, RejectReason::Internal);
                        }
                        self.ack(id, seq);
                    }
                    Admission::Duplicate => self.ack(id, seq),
                    Admission::Gap => return self.gap(id, index),
                }
            }
            // Unsequenced and outside the gate: idempotent state, not a command.
            // An ack that re-entered sync mode would make every repaint renew it.
            ClientMessage::ScreenAck {
                generation,
                version,
            } => self.attachments[index].confirm(generation, version),
            ClientMessage::Close { seq } => {
                if self.attachments[index].stream.admit(seq) == Admission::Fresh {
                    self.ack(id, seq);
                }
                self.end(0);
                return true;
            }
            ClientMessage::Detach { seq } => {
                if self.attachments[index].stream.admit(seq) == Admission::Fresh {
                    self.ack(id, seq);
                }
                let _ = self.attachments[index].sink.send(&ServerMessage::Detached {
                    reason: DetachReason::Requested,
                });
                self.drop_attachment(index);
            }
            ClientMessage::Pong { token, consumed } => {
                let attachment = &mut self.attachments[index];
                attachment.link.answered(token);
                attachment.consume(consumed);
            }
            // Unsequenced: a window update behind a journal measures the journal.
            ClientMessage::Consumed { off } => self.attachments[index].consume(off),
            ClientMessage::ForwardOpen {
                seq,
                stream,
                target,
            } => return self.forward_open(id, index, seq, stream, target),
            // Outside the gate beside `ScreenAck` and `Consumed`: a lost one
            // inside the ordered stream blocks every keystroke behind its resend.
            payload @ (ClientMessage::ForwardData { .. }
            | ClientMessage::ForwardAck { .. }
            | ClientMessage::ForwardReset { .. }) => self.forward_frame(index, &payload),
            // Answered before a session actor ever sees a frame.
            ClientMessage::Hello { .. }
            | ClientMessage::HelloForward { .. }
            | ClientMessage::Resume { .. }
            | ClientMessage::ListSessions
            | ClientMessage::KillSession { .. }
            | ClientMessage::Search { .. } => {}
        }
        false
    }

    /// Answer a scrollback search on the thread that owns the emulator, or drop
    /// it: the asker's deadline bounds the work rather than merely racing it.
    pub(crate) fn search(
        &mut self,
        pattern: &str,
        limit: usize,
        deadline: Instant,
        reply: &mpsc::SyncSender<Vec<SearchMatch>>,
    ) {
        if Instant::now() >= deadline {
            return;
        }
        let session_id = self.ticket.session_id;
        // No emulator is no scrollback, which is a search over nothing.
        let Some(terminal) = self.terminal.as_mut() else {
            let _ = reply.try_send(Vec::new());
            return;
        };
        let found = match terminal.vt.search(pattern, limit) {
            Ok(found) => found,
            Err(error) => {
                log!("scrollback search failed: {error}");
                Vec::new()
            }
        };
        let matches = found
            .into_iter()
            .filter_map(|hit| {
                // The wire refuses control bytes; a blank match shows nothing.
                let line = printable(&hit.line, MAX_MATCH_LINE);
                (!line.trim().is_empty()).then_some(SearchMatch {
                    session_id,
                    distance: hit.distance,
                    line,
                })
            })
            .collect();
        let _ = reply.try_send(matches);
    }

    pub(crate) fn output(&mut self, bytes: &[u8]) -> Result<(), ServerError> {
        let Some(terminal) = self.terminal.as_mut() else {
            return Ok(());
        };
        let now = Instant::now();
        let last_output = terminal.last_output.replace(now);
        self.info.touch();
        // The filter drives the emulator rather than running after it: which
        // sequence a reply belonged to is only knowable from where the reply
        // fell in the stream.
        //
        // Owned here so the attachment loop can borrow the result while
        // `terminal` is otherwise in use; the buffer is kept on `terminal` so
        // a burst allocates nothing.
        let mut forwarded = std::mem::take(&mut terminal.forwarded);
        let mut emulator = Attribution {
            vt: &mut terminal.vt,
            effects: &terminal.effects,
        };
        let result = match terminal
            .queries
            .filter(bytes, &mut forwarded, &mut emulator)
        {
            Ok(kept) => self.forward(kept, now, last_output),
            Err(error) => Err(error.into()),
        };
        // Back onto `terminal` whatever happened, so the next chunk reuses it.
        if let Some(terminal) = self.terminal.as_mut() {
            terminal.forwarded = forwarded;
        }
        result
    }

    /// Record the query-stripped output and hand it to every attached client.
    ///
    /// Split from [`output`](Self::output) so the filtered bytes are a plain
    /// borrow the attachment loop can hold while `self` is otherwise mutably in
    /// use. Everything past the emulator rides this one stream, so the offset,
    /// the ring and every client agree on the bytes a resume replays.
    fn forward(
        &mut self,
        bytes: &[u8],
        now: Instant,
        last_output: Option<Instant>,
    ) -> Result<(), ServerError> {
        let Some(terminal) = self.terminal.as_mut() else {
            return Ok(());
        };
        // The ring and the offset come before anything fallible: the emulator
        // has consumed these bytes and nothing heals a ring that missed them.
        terminal.backlog.push(bytes);
        let start_offset = self.offset;
        self.offset = self
            .offset
            .checked_add(bytes.len())
            .ok_or_else(|| ServerError::Setup("output offset exhausted".into()))?;
        // The emulator's own replies are input. Overrunning is a child that has
        // stopped reading; ending the session would take the user's work too.
        if !terminal.effects.flush_into(&terminal.pty_in)? {
            log!("reply backlog full; dropping every attachment");
            self.dismiss(&ServerMessage::Reject {
                reason: RejectReason::InputBacklog,
            });
            return Ok(());
        }
        if self.attachments.is_empty() {
            return Ok(());
        }
        let cue = terminal.cue(self.size.cols);
        let grid = self.size;
        let mark = terminal.deferred.mark();
        let mut gone: Vec<AttachmentId> = Vec::new();
        for attachment in &mut self.attachments {
            attachment.settle_before_output(start_offset, now, last_output, grid);
            if attachment.is_syncing() || !attachment.fits(grid) {
                attachment.begin_sync(mark);
                continue;
            }
            if attachment
                .push_output(start_offset, bytes, cue, now, mark)
                .is_err()
            {
                gone.push(attachment.id);
            }
        }
        // After the loop: a client that entered a sync episode on *this* chunk
        // still carries its sequences, its mark having been taken beforehand.
        if self.attachments.iter().any(Attachment::is_syncing) {
            terminal.deferred.feed(bytes);
        }
        self.forget_carried();
        self.drop_all(&gone);
        self.repaint(Painted::Due)
    }

    /// Drop the deferred sequences every attached client already holds.
    fn forget_carried(&mut self) {
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let carried = self
            .attachments
            .iter()
            .map(|attachment| attachment.deferred_from)
            .min()
            .unwrap_or_else(|| terminal.deferred.mark());
        terminal.deferred.forget_before(carried);
    }

    fn drop_all(&mut self, gone: &[AttachmentId]) {
        for &id in gone {
            if let Some(index) = self.index_of(id) {
                self.drop_attachment(index);
            }
        }
    }

    /// Push buffered output to a resuming client from `start`, cut to what one
    /// `Output` frame on its transport carries.
    pub(crate) fn replay(
        &self,
        sink: &AttachmentSink,
        chunk_budget: usize,
        start: ByteOff,
        echo_ack: Option<CmdSeq>,
    ) -> Result<(), ReplayError> {
        // No terminal owes this client no history, which is not an eviction.
        let Some(terminal) = self.terminal.as_ref() else {
            return Ok(());
        };
        let Some((first, second)) = terminal.backlog.replay_from(start) else {
            return Err(ReplayError::Evicted);
        };
        let mut offset = start;
        let mut spare: Vec<Vec<u8>> = Vec::new();
        for bytes in [first, second] {
            for chunk in bytes.chunks(chunk_budget) {
                if spare.is_empty() {
                    sink.reclaim(&mut spare);
                }
                let mut frame = spare.pop().unwrap_or_default();
                // Replayed bytes are history: their cursor has already moved on.
                encode_output_into(&mut frame, offset, InputCue::Opaque, echo_ack, chunk)
                    .map_err(|_| ReplayError::Sink(SinkError::Unusable))?;
                sink.send_output(frame).map_err(|error| match error {
                    // Not a failure of the attachment: the screen that follows
                    // repairs the grid, and `offset` is what is owed past here.
                    SinkError::Full => ReplayError::Filled(offset),
                    // Named, not a wildcard: a third sink failure must be a
                    // compile error here rather than silently costing the client.
                    error @ SinkError::Unusable => ReplayError::Sink(error),
                })?;
                offset = offset
                    .checked_add(chunk.len())
                    .ok_or(ReplayError::Evicted)?;
            }
        }
        Ok(())
    }

    /// What a turn from the clock does next; a failed render says so.
    fn ticked(&mut self) -> Turn {
        match self.tick() {
            Ok(turn) => turn,
            Err(error) => {
                self.failed(&error);
                Turn::Stop
            }
        }
    }

    /// How long the actor may sleep. [`IDLE_DEADLINE`] is far shorter than
    /// [`FORWARD_SESSION_GRACE`], so that reap needs no timer of its own.
    pub(crate) fn deadline(&self) -> Duration {
        let attachments = self
            .attachments
            .iter()
            .map(Attachment::deadline)
            .min()
            .unwrap_or(IDLE_DEADLINE);
        match self.forwards.deadline(Instant::now()) {
            Some(owed) => attachments.min(owed),
            None => attachments,
        }
    }

    /// Everything that falls due on a clock rather than on an event.
    pub(crate) fn tick(&mut self) -> Result<Turn, ServerError> {
        // `read` on the master returns EOF only when the last slave fd closes,
        // so `bash -c 'sleep 100000 & exit'` never reports `PtyEnded`.
        if let Some(terminal) = self.terminal.as_mut()
            && let Some(code) = terminal.shell.try_wait()
        {
            self.end(code);
            return Ok(Turn::Stop);
        }
        let now = Instant::now();
        // A forward-only session carrying nothing with nobody attached can
        // never produce another byte; mid-reconnect is what the grace covers.
        if self.terminal.is_none()
            && self.forwards.is_empty()
            && self
                .detached_since
                .is_some_and(|since| now.duration_since(since) >= FORWARD_SESSION_GRACE)
        {
            self.end(0);
            return Ok(Turn::Stop);
        }
        let mut gone: Vec<AttachmentId> = Vec::new();
        for attachment in &mut self.attachments {
            if attachment.sink.is_closed() {
                // Nothing else will wake this session about a dead writer.
                gone.push(attachment.id);
            } else if attachment.link.is_dead(now) {
                log!("attachment stopped answering; dropping it");
                gone.push(attachment.id);
            } else if let Some(token) = attachment.link.probe(now) {
                let echo_ack = attachment.stream.echo_ack(now);
                let interval_ms = attachment.link.interval_ms();
                if attachment
                    .sink
                    .send(&ServerMessage::Ping {
                        token,
                        echo_ack,
                        interval_ms,
                    })
                    .is_err()
                {
                    gone.push(attachment.id);
                }
            }
        }
        self.drop_all(&gone);
        self.pump_forwards(now);
        self.repaint(Painted::Due)?;
        Ok(Turn::Continue)
    }

    /// Render the screen once, per-client encodings from it. Every ledger takes
    /// this frame's damage sent or not: Ghostty clears dirty bits per render.
    pub(crate) fn repaint(&mut self, painted: Painted) -> Result<(), ServerError> {
        if !self
            .attachments
            .iter()
            .any(|attachment| painted.wants(attachment))
        {
            return Ok(());
        }
        let Some(terminal) = self.terminal.as_mut() else {
            return Ok(());
        };
        let now = Instant::now();
        let offset = self.offset;
        let grid = self.size;
        let last_output = terminal.last_output;
        // Read before the repaint, which borrows the emulator for the loop below.
        let pending_wrap = terminal.vt.cursor_cue().is_ok_and(|cue| cue.pending_wrap);
        let deferred = &terminal.deferred;
        let frame = terminal.vt.repaint()?;
        // One header for the pass: per attachment it clones the window title
        // and the whole deferred log at the repaint rate, per client watching.
        let mut header = ScreenHeader {
            generation: self.generation,
            version: ScreenVersion::initial(),
            next_off: offset,
            size: frame.size,
            cursor: frame.cursor,
            cursor_visible: frame.cursor_visible,
            cursor_shape: frame.cursor_shape,
            cursor_blinking: frame.cursor_blinking,
            modes: frame.modes,
            sticky: frame.sticky.clone(),
        };
        header.sticky.pending_wrap = pending_wrap;
        // libghostty exposes no accessor for the DECSC save slot.
        header.sticky.saved_cursor = None;
        let mut gone: Vec<AttachmentId> = Vec::new();
        for attachment in &mut self.attachments {
            attachment.ledger.note_damage(&frame.dirty);
            if !painted.wants(attachment) {
                continue;
            }
            let (generation, version) = attachment.painting(painted, now);
            header.generation = generation;
            header.version = version;
            header.sticky.deferred = attachment.owed_deferred(deferred);
            match attachment.push_screen(&header, frame) {
                Ok(Painting::Sent) => attachment.sent(deferred.mark(), now),
                // Nothing left. Sync mode stays: leaving it on a screen the
                // client never got would resume the stream from a state it lacks.
                Ok(Painting::Withheld) => continue,
                Err(_) => {
                    gone.push(attachment.id);
                    continue;
                }
            }
            if !attachment.is_syncing() {
                continue;
            }
            // An attachment pinned to screens by its own size arms nothing, or
            // it would repaint for as long as the sizes disagree.
            let caught_up = gate::may_return_to_passthrough(
                attachment.catch_up(offset),
                now,
                last_output,
                attachment.link.repaint_interval(),
            );
            attachment.settle(caught_up, grid);
        }
        self.drop_all(&gone);
        Ok(())
    }

    /// What an out-of-order command costs, which is the transport's business:
    /// on a datagram a gap is one lost packet the journal retransmits.
    pub(crate) fn gap(&mut self, id: AttachmentId, index: usize) -> bool {
        match self.attachments[index].framing {
            Framing::Stream => self.reject(id, RejectReason::SequenceGap),
            Framing::Datagram { .. } => false,
        }
    }

    /// Advance the gate over a command this session cannot carry out: a
    /// sequence never acknowledged stalls every command behind it.
    fn ignore(&mut self, id: AttachmentId, index: usize, seq: CmdSeq) -> bool {
        match self.attachments[index].stream.admit(seq) {
            Admission::Fresh | Admission::Duplicate => self.ack(id, seq),
            Admission::Gap => return self.gap(id, index),
        }
        false
    }

    /// Drop the attachment that cannot be served on; the session survives.
    pub(crate) fn reject(&mut self, id: AttachmentId, reason: RejectReason) -> bool {
        if let Some(index) = self.index_of(id) {
            let _ = self.attachments[index]
                .sink
                .send(&ServerMessage::Reject { reason });
            self.drop_attachment(index);
        }
        false
    }

    pub(crate) fn ack(&mut self, id: AttachmentId, seq: CmdSeq) {
        let Some(index) = self.index_of(id) else {
            return;
        };
        let attachment = &mut self.attachments[index];
        let highest = attachment.stream.acknowledged(seq);
        let _ = attachment.sink.send(&ServerMessage::CommandAck { highest });
    }

    /// A client asking for a forwarded connection, through the gate: a forward
    /// that opened twice would be two sockets for one stream id.
    fn forward_open(
        &mut self,
        id: AttachmentId,
        index: usize,
        seq: CmdSeq,
        stream: StreamId,
        target: ForwardTarget,
    ) -> bool {
        match self.attachments[index].stream.admit(seq) {
            Admission::Fresh => {
                self.start_forward(index, stream, target);
                // Whatever the outcome: a stalled sequence blocks every keystroke.
                self.ack(id, seq);
            }
            Admission::Duplicate => self.ack(id, seq),
            Admission::Gap => return self.gap(id, index),
        }
        false
    }

    /// Open one forwarded connection for the client at `index`. Nothing here
    /// may drop the attachment: a mistyped `-L` must not cost the session.
    fn start_forward(&mut self, index: usize, id: StreamId, target: ForwardTarget) {
        let client = self.attachments[index].stream.client;
        if self.forwards.was_closed(client, id) || self.forwards.contains(client, id) {
            // An id this client has already spent. Reused over a live stream
            // the two ends interleave two connections down one socket.
            self.forward_reset(index, id, ForwardResetReason::Internal);
            return;
        }
        if self.forwards.held_by(client) >= MAX_FORWARDS {
            self.forward_reset(index, id, ForwardResetReason::Limit);
            return;
        }
        let Some(charge) = ForwardSlot::reserve(&self.daemon) else {
            log!("refused a forward: this daemon is already carrying as many as it will");
            self.forward_reset(index, id, ForwardResetReason::Limit);
            return;
        };
        match Forward::open(target, client, id, self.tx.clone(), charge) {
            Ok(forward) => self.forwards.insert(client, id, forward),
            Err(error) => {
                log!("a forward did not start: {error}");
                self.forward_reset(index, id, ForwardResetReason::Internal);
            }
        }
    }

    /// Tell one client a stream of its own is over, and remember that it is.
    /// The frame is offered rather than insisted on; the attachment stays.
    fn forward_reset(&mut self, index: usize, id: StreamId, reason: ForwardResetReason) {
        let client = self.attachments[index].stream.client;
        let _ = queue_forward(
            &self.attachments[index].sink,
            &ServerMessage::ForwardReset { stream: id, reason },
        );
        self.forwards.retire(client, id);
    }

    /// Retire a forward and tell the client that owns it, wherever it is. A
    /// client mid-reconnect has none, and the entry would hold a descriptor.
    fn retire_forward(&mut self, client: ClientId, id: StreamId, reason: ForwardResetReason) {
        if let Some(index) = self.client_index(client) {
            self.forward_reset(index, id, reason);
            return;
        }
        self.forwards.retire(client, id);
    }

    /// The attachment this client is watching through, if it has one now.
    fn client_index(&self, client: ClientId) -> Option<usize> {
        self.attachments
            .iter()
            .position(|attachment| attachment.stream.client == client)
    }

    /// One unsequenced forward frame: payload, a window update, or an end.
    fn forward_frame(&mut self, index: usize, message: &ClientMessage) {
        let client = self.attachments[index].stream.client;
        let (ClientMessage::ForwardData { stream: id, .. }
        | ClientMessage::ForwardAck { stream: id, .. }
        | ClientMessage::ForwardReset { stream: id, .. }) = *message
        else {
            return;
        };
        if let ClientMessage::ForwardReset { .. } = message {
            // Never answered with a reset of our own: two ends resetting each
            // other loops forever on a transport that duplicates frames.
            self.forwards.retire(client, id);
            return;
        }
        let Some(forward) = self.forwards.get_mut(client, id) else {
            self.unknown_forward(index, id);
            return;
        };
        match message {
            ClientMessage::ForwardData {
                off, fin, bytes, ..
            } => {
                if forward.stream.on_data(off.get(), *fin, bytes).is_err() {
                    // The client contradicted its own stream. Nothing
                    // retransmits its way out of that.
                    self.forward_reset(index, id, ForwardResetReason::Internal);
                }
            }
            // Bytes this side never sent is the same contradiction.
            ClientMessage::ForwardAck {
                off, window, held, ..
            } if forward
                .stream
                .on_ack(off.get(), *window, held, Instant::now())
                .is_err() =>
            {
                self.forward_reset(index, id, ForwardResetReason::Internal);
            }
            // The pattern above admits nothing else.
            _ => {}
        }
    }

    /// Answer a frame naming a stream this side is not carrying. Silence fits
    /// an open still in the journal; a *closed* id would be resent forever.
    fn unknown_forward(&mut self, index: usize, id: StreamId) {
        let client = self.attachments[index].stream.client;
        if self.forwards.was_closed(client, id) {
            let _ = queue_forward(
                &self.attachments[index].sink,
                &ServerMessage::ForwardReset {
                    stream: id,
                    reason: ForwardResetReason::Closed,
                },
            );
        }
    }

    /// The connect thread has answered.
    fn forward_connected(
        &mut self,
        client: ClientId,
        id: StreamId,
        link: Result<ForwardLink, ForwardResetReason>,
    ) {
        match link {
            Ok(link) => {
                let Some(forward) = self.forwards.get_mut(client, id) else {
                    // Retired while dialling. Dropping the link closes the socket.
                    return;
                };
                forward.connected(link);
                forward.grant_credit();
            }
            Err(reason) => self.retire_forward(client, id, reason),
        }
    }

    /// Bytes one forwarded socket produced, on their way to its client.
    fn forward_read(&mut self, client: ClientId, id: StreamId, bytes: Chunk) {
        if let Some(forward) = self.forwards.get_mut(client, id) {
            forward.absorb(bytes, Instant::now());
        }
    }

    /// A forwarded socket will produce nothing more.
    fn forward_eof(&mut self, client: ClientId, id: StreamId, failed: bool) {
        if failed {
            self.retire_forward(client, id, ForwardResetReason::Internal);
            return;
        }
        if let Some(forward) = self.forwards.get_mut(client, id) {
            // Half a connection closing; the other half may still carry bytes.
            forward.finish(Instant::now());
        }
    }

    /// Move every forward one turn: acknowledge, transmit, deliver, refill. A
    /// forward whose client is mid-reconnect is skipped whole and kept.
    fn pump_forwards(&mut self, now: Instant) {
        if self.forwards.is_empty() {
            return;
        }
        let mut retired: Vec<(ClientId, StreamId, Option<ForwardResetReason>)> = Vec::new();
        {
            // Destructured so the two borrows are disjoint.
            let Self {
                forwards,
                attachments,
                ..
            } = self;
            let mut payload = Vec::new();
            for (&(client, id), forward) in forwards.iter_mut() {
                let Some(attachment) = attachments
                    .iter()
                    .find(|attachment| attachment.stream.client == client)
                else {
                    continue;
                };
                // Ahead of the payload: this is what opens the peer's window.
                if let Some(ack) = forward.owed_ack()
                    && queue_forward(
                        &attachment.sink,
                        &ServerMessage::ForwardAck {
                            stream: id,
                            off: ByteOff::from_u64(ack.off),
                            window: ack.window,
                            held: ack.held,
                        },
                    )
                    .is_ok()
                {
                    forward.acked();
                }
                let budget = forward_chunk(&attachment.framing);
                while let Some(segment) = forward.stream.poll_transmit(now, budget, &mut payload) {
                    if send_segment(&attachment.sink, id, segment, &mut payload).is_err() {
                        // Still owed: the stream sends these bytes again.
                        break;
                    }
                    forward.stream.transmitted(segment, now);
                }
                if !forward.drain_to_socket() {
                    retired.push((client, id, Some(ForwardResetReason::Internal)));
                    continue;
                }
                forward.grant_credit();
                if forward.is_done() {
                    retired.push((client, id, None));
                }
            }
        }
        for (client, id, reason) in retired {
            match reason {
                Some(reason) => self.retire_forward(client, id, reason),
                // Both halves closed with nothing owed: news to nobody.
                None => self.forwards.retire(client, id),
            }
        }
    }
}

/// Bytes of forwarded payload one frame may carry. Read where it is used: the
/// path MTU moves, and a cached limit pins a forward at the IPv6 floor.
fn forward_chunk(framing: &Framing) -> usize {
    framing
        .frame_budget()
        .saturating_sub(FORWARD_OVERHEAD)
        .min(braid_forward::MAX_FORWARD_CHUNK)
}

/// Encode one forward message and queue it on the sink's forward lane.
fn queue_forward(sink: &AttachmentSink, message: &ServerMessage) -> Result<(), SinkError> {
    let frame = message
        .encode(sink.version())
        .map_err(|_| SinkError::Unusable)?;
    sink.send_forward(frame)
}

/// Hand one polled segment to the sink, giving the payload buffer back rather
/// than allocating per segment: a forward at speed polls one per 32 KiB.
fn send_segment(
    sink: &AttachmentSink,
    stream: StreamId,
    segment: Segment,
    payload: &mut Vec<u8>,
) -> Result<(), SinkError> {
    let message = ServerMessage::ForwardData {
        stream,
        off: ByteOff::from_u64(segment.off),
        fin: segment.fin,
        bytes: std::mem::take(payload),
    };
    let queued = queue_forward(sink, &message);
    if let ServerMessage::ForwardData { bytes, .. } = message {
        *payload = bytes;
        payload.clear();
    }
    queued
}

/// Turn what the emulator knows into a budget: the client holds no emulator.
fn input_cue(cue: braid_vt::CursorCue, cols: u16) -> InputCue {
    if cue.alternate || cue.mouse_tracking || !cue.visible || cue.pending_wrap {
        return InputCue::Opaque;
    }
    // The last cell is never offered: a prediction there commits a wrap this
    // session has not made.
    InputCue::Echoing {
        room: cols.saturating_sub(cue.col).saturating_sub(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::*;
    use crate::mailbox::*;
    use crate::registry::*;
    use crate::shell::*;
    use crate::sink::*;
    use crate::testing::*;
    use crate::*;
    use braid_proto::{
        ByteOff, ClientId, CmdSeq, ConfirmedOutput, DetachReason, ForwardResetReason,
        ForwardTarget, Generation, GridSize, InputCue, MAX_ATTACHMENTS, MAX_FORWARDS, RejectReason,
        ScreenPart, StreamId, Version,
    };
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{self, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Taken from the encoder: a literal would restate the tag assignment.
    fn detach_tag() -> u8 {
        ServerMessage::Detached {
            reason: DetachReason::Requested,
        }
        .encode(Version::LOCAL)
        .expect("a small message")[FRAME_LENGTH_PREFIX]
    }

    fn newest_cue(output: &TestOutput) -> Option<InputCue> {
        output.frames().iter().rev().find_map(|message| {
            if let ServerMessage::Output { cue, .. } = message {
                Some(*cue)
            } else {
                None
            }
        })
    }

    /// A PTY whose child has stopped reading: writes park until the test lets go.
    struct WedgedPty(mpsc::Receiver<()>);

    impl Write for WedgedPty {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// One session actor over a real terminal with a PTY writer nothing drains.
    /// Keep the receiver: dropped, every forward retires on its first send.
    fn wedged_actor() -> (SessionActor, mpsc::Sender<()>, MailboxReceiver) {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: GRID.rows,
                cols: GRID.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let mut command = CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg("exec sleep 30");
        let child = pty.slave.spawn_command(command).expect("spawn shell");
        drop(pty.slave);
        let (release, wedged) = mpsc::channel();
        let (spent, _spent_rx) = mpsc::sync_channel(1);
        let (tx, rx) = mailbox();
        let actor = start_session(SessionSetup {
            ticket: sessions::SessionTicket::issue().expect("session ticket"),
            shell: Shell {
                child,
                master: Some(pty.master),
                status: None,
                _hangup: Hangup::new().expect("a wakeup").close,
            },
            writer: Box::new(WedgedPty(wedged)),
            daemon: Arc::new(DaemonState::default()),
            effects: Arc::new(SessionEffects::default()),
            size: GRID,
            info: Arc::new(SessionInfo::new("/bin/sh -c exec sleep 30".into(), GRID)),
            spent,
            killed: KillNotice::default(),
            tx,
        })
        .expect("start session");
        (actor, release, rx)
    }

    /// One attachment driven straight from a test, and its transcript.
    fn attach_to(actor: &mut SessionActor, client: ClientId) -> (AttachmentId, TestOutput) {
        let output = TestOutput::new();
        let id = next_attachment();
        actor.attach(
            id,
            client,
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            AttachKind::New,
            Framing::Stream,
            None,
        );
        (id, output)
    }

    /// An address nothing is listening on: the dial fails, but its answer lands
    /// on a mailbox these tests never drain.
    fn dead_target() -> ForwardTarget {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener);
        ForwardTarget {
            host: address.ip().to_string(),
            port: address.port(),
        }
    }

    /// An instant that far back, for a test that cannot wait out a real grace.
    fn long_ago(elapsed: Duration) -> Instant {
        Instant::now()
            .checked_sub(elapsed)
            .expect("the test clock started after this process did")
    }

    /// Which greeting a session opened an attachment with, waiting for the frame.
    fn greeted_by(output: &TestOutput) -> &'static str {
        await_frame(
            output,
            |message| match message {
                ServerMessage::Hello { .. } => Some("Hello"),
                ServerMessage::HelloForward { .. } => Some("HelloForward"),
                _ => None,
            },
            "the session never greeted its client",
        )
    }

    fn attach_with(
        handle: &SessionHandle,
        id: AttachmentId,
        client: ClientId,
        kind: AttachKind,
        framing: Framing,
        sink: AttachmentSink,
    ) {
        handle
            .tx
            .send(ActorEvent::Attach {
                id,
                client,
                sink,
                kind,
                framing,
                offer: None,
            })
            .expect("attach transport");
    }

    fn attach_client(
        handle: &SessionHandle,
        id: AttachmentId,
        client: ClientId,
        kind: AttachKind,
    ) -> TestOutput {
        attach_framed(handle, id, client, kind, Framing::Stream)
    }

    fn attach_framed(
        handle: &SessionHandle,
        id: AttachmentId,
        client: ClientId,
        kind: AttachKind,
        framing: Framing,
    ) -> TestOutput {
        let output = TestOutput::new();
        let sink =
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment");
        attach_with(handle, id, client, kind, framing, sink);
        assert!(
            output.contains(&[hello_tag()], Duration::from_secs(2)),
            "the session greets every attachment"
        );
        output
    }

    fn send(handle: &SessionHandle, id: AttachmentId, message: ClientMessage) {
        handle
            .tx
            .send(ActorEvent::Command { id, message })
            .expect("a live session mailbox");
    }

    fn typed(number: u64, bytes: &[u8]) -> ClientMessage {
        ClientMessage::Input {
            seq: seq(number),
            bytes: bytes.to_vec(),
        }
    }

    fn closes(sink: &AttachmentSink) -> bool {
        settles(Duration::from_secs(2), || sink.is_closed())
    }

    /// The grid `brd ls` reads without reaching the actor.
    fn grid(handle: &SessionHandle) -> GridSize {
        GridSize {
            cols: handle.info.cols.load(Ordering::Relaxed),
            rows: handle.info.rows.load(Ordering::Relaxed),
        }
    }

    fn grid_settles(handle: &SessionHandle, expected: GridSize) -> bool {
        settles(Duration::from_secs(2), || grid(handle) == expected)
    }

    /// Wait until this attachment has stopped being written to: a resize is
    /// answered by the shell's own redraw, which lands after it.
    fn writes_settle(output: &TestOutput) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut written = output.frames().len();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
            let now = output.frames().len();
            if now != written {
                written = now;
                since = Instant::now();
            } else if since.elapsed() >= REPAINT_CEILING * 2 {
                return true;
            }
        }
        false
    }

    /// The grid of the newest whole screen this attachment was sent.
    fn newest_screen_size(output: &TestOutput) -> Option<GridSize> {
        output
            .frames()
            .into_iter()
            .rev()
            .find_map(|message| match message {
                ServerMessage::Screen {
                    part:
                        ScreenPart::Head {
                            header, base: None, ..
                        },
                } => Some(header.size),
                _ => None,
            })
    }

    fn screened(output: &TestOutput) -> bool {
        output
            .frames()
            .iter()
            .any(|message| matches!(message, ServerMessage::Screen { part: _ }))
    }

    fn highest_ack(output: &TestOutput) -> Option<CmdSeq> {
        output
            .frames()
            .into_iter()
            .filter_map(|message| match message {
                ServerMessage::CommandAck { highest } => highest,
                _ => None,
            })
            .max()
    }

    /// Wait for exactly this message on a transcript, as the encoder writes it.
    fn told(output: &TestOutput, message: &ServerMessage) -> bool {
        let frame = message.encode(Version::LOCAL).expect("a small message");
        output.contains(&frame, Duration::from_secs(2))
    }

    /// Start a stoppable PTY output trickle and return after its first event is queued.
    fn trickle(handle: &SessionHandle) -> impl FnOnce() {
        let feeder = handle.tx.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let feeder_stop = Arc::clone(&stop);
        let (started, wait_started) = mpsc::sync_channel(0);
        let burst = thread::spawn(move || {
            let mut started = Some(started);
            while !feeder_stop.load(Ordering::Relaxed) {
                if feeder.send(pty_output(b".")).is_err() {
                    return;
                }
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        wait_started.recv().expect("trickle should start");
        move || {
            stop.store(true, Ordering::Relaxed);
            burst.join().expect("burst thread");
        }
    }

    /// An unclosed sink parks its writer on a condvar nothing notifies again:
    /// every detach then costs a thread and a descriptor until `EMFILE`.
    #[test]
    fn a_detach_closes_the_sink() {
        let handle = test_session();
        let id = next_attachment();
        let output = TestOutput::new();
        let sink =
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment");
        attach_with(
            &handle,
            id,
            client(1),
            AttachKind::New,
            Framing::Stream,
            sink.clone(),
        );
        assert!(output.contains(&[hello_tag()], Duration::from_secs(2)));
        assert!(!sink.is_closed());

        handle
            .tx
            .send(ActorEvent::Detached(id))
            .expect("transport died");

        assert!(
            closes(&sink),
            "the writer is parked forever unless the sink is closed"
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A deadline of `Duration::ZERO` under a held screen brings `recv_timeout`
    /// straight back and runs the loop flat out for up to two seconds.
    #[test]
    fn a_held_screen_is_slept_through_rather_than_spun_on() {
        let ping = Duration::from_secs(2);
        let hold = Duration::from_millis(250);
        let sooner = Duration::from_millis(5);
        for (ping, repaint_hold, expected) in [
            // Waking now can do nothing but re-arm the same hold.
            (ping, Some(hold), hold),
            // Nothing is holding it: the repaint goes out on this wakeup.
            (ping, Some(Duration::ZERO), Duration::ZERO),
            // A probe falling due sooner is its own reason to wake.
            (sooner, Some(hold), sooner),
            // Nothing owed on a clock at all.
            (ping, None, ping),
        ] {
            assert_eq!(next_deadline(ping, repaint_hold), expected);
        }
    }

    /// The visible half of that spin: every turn bumps a screen version, so a
    /// session held for one ack burns millions of them.
    #[test]
    fn an_unacknowledged_screen_does_not_burn_screen_versions() {
        let handle = test_session();
        let output = StalledOutput::new();
        attach_with(
            &handle,
            next_attachment(),
            client(1),
            AttachKind::New,
            Framing::Stream,
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
        );

        // Overrun the byte budget, which is how a session enters sync mode. The
        // writer never drains, so no screen is ever acknowledged.
        let chunk = vec![0_u8; 16 * 1024];
        for _ in 0..48 {
            handle.tx.send(pty_output(&chunk)).expect("feed pty output");
        }

        // A trickle keeps a repaint armed: something owed, nothing able to go.
        let stop_trickle = trickle(&handle);
        thread::sleep(Duration::from_millis(600));
        stop_trickle();
        output.release();
        thread::sleep(Duration::from_millis(100));

        let highest = output
            .seen
            .highest_version()
            .expect("the session sends a screen");
        // 250 ms of hold with no RTT estimate: 700 ms is a handful of screens.
        assert!(
            highest.get() < 64,
            "a held screen burned {} versions, which is a spin",
            highest.get()
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A transport dying takes neither the shell nor the client's place at it.
    #[test]
    fn detached_session_keeps_pty_for_replacement_attachment() {
        let handle = test_session();
        let first_id = next_attachment();
        let _first = attach_client(&handle, first_id, client(1), AttachKind::New);
        handle
            .tx
            .send(ActorEvent::Detached(first_id))
            .expect("detach first transport");

        let second_id = next_attachment();
        let second = attach_client(&handle, second_id, client(1), joining());
        send(
            &handle,
            second_id,
            typed(1, b"printf '\\033[31mBRD_REATTACHED\\033[0m\\n'\n"),
        );
        assert!(second.contains(b"\x1b[31mBRD_REATTACHED\x1b[0m", Duration::from_secs(3)));

        send(&handle, second_id, ClientMessage::Close { seq: seq(2) });
    }

    /// A client asking to leave must not take the shell with it.
    #[test]
    fn client_detach_keeps_the_session_running() {
        let handle = test_session();
        let first_id = next_attachment();
        let first = attach_client(&handle, first_id, client(1), AttachKind::New);
        send(
            &handle,
            first_id,
            ClientMessage::Detach {
                seq: CmdSeq::first(),
            },
        );
        // The detach tag carrying reason 0: the client asked to leave.
        assert!(first.contains(&[detach_tag(), 0], Duration::from_secs(2)));

        let second_id = next_attachment();
        let second = attach_client(&handle, second_id, client(2), AttachKind::New);
        // Its own sequence space: a new client numbers its first command one.
        send(
            &handle,
            second_id,
            typed(1, b"printf 'BRD_AFTER_DETACH\\n'\n"),
        );
        assert!(second.contains(b"BRD_AFTER_DETACH", Duration::from_secs(3)));

        send(&handle, second_id, ClientMessage::Close { seq: seq(2) });
    }

    /// A session that enters sync mode must be able to leave it: repaints carry
    /// plain text, so a surviving SGR sequence proves the byte stream resumed.
    #[test]
    fn a_synchronized_session_returns_to_passthrough_when_output_settles() {
        let handle = test_session();
        let id = next_attachment();
        let output = attach_client(&handle, id, client(1), AttachKind::New);

        send(
            &handle,
            id,
            ClientMessage::RequestRepaint {
                seq: CmdSeq::first(),
            },
        );
        // Settle back to passthrough first, so the ack is the only thing that
        // could re-enter sync mode.
        thread::sleep(Duration::from_millis(200));
        let (generation, version) = output
            .latest_screen(Duration::from_secs(2))
            .expect("session should send a screen");
        send(
            &handle,
            id,
            ClientMessage::ScreenAck {
                generation,
                version,
            },
        );
        send(
            &handle,
            id,
            typed(2, b"printf '\\033[31mBRD_STYLED\\033[0m\\n'\n"),
        );
        assert!(output.contains(b"\x1b[31mBRD_STYLED\x1b[0m", Duration::from_secs(3)));

        send(&handle, id, ClientMessage::Close { seq: seq(3) });
    }

    /// The first output after silence must use the silence that preceded it;
    /// recording the new output first loses that only chance to leave sync.
    #[test]
    fn output_after_quiescence_resumes_passthrough_before_it_is_coalesced() {
        let (mut actor, _release, _rx) = wedged_actor();
        let output = StalledOutput::new();
        let id = next_attachment();
        actor.attach(
            id,
            client(1),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            AttachKind::New,
            Framing::Stream,
            None,
        );
        actor.terminal.as_mut().expect("terminal").last_output = Some(Instant::now());
        assert!(!actor.command(
            id,
            ClientMessage::RequestRepaint {
                seq: CmdSeq::first(),
            },
        ));
        assert!(actor.attachments[0].is_syncing());

        actor.terminal.as_mut().expect("terminal").last_output =
            Some(long_ago(REPAINT_CEILING * 2));
        let styled = b"\x1b[32mAFTER_BURST\x1b[0m\n";
        actor.output(styled).expect("feed terminal output");
        assert!(
            !actor.attachments[0].is_syncing(),
            "the new output erased the preceding quiescence"
        );

        output.release();
        assert!(
            settles(Duration::from_secs(2), || passthrough(&output.seen)
                == styled),
            "the first post-quiescence output was repainted instead of passed through"
        );
    }

    /// A screen acknowledgement makes the next repaint a delta against that exact screen.
    #[test]
    fn a_client_that_confirms_a_screen_is_sent_deltas() {
        let (mut actor, _release, _rx) = wedged_actor();
        let (id, output) = attach_to(&mut actor, client(1));

        assert!(!actor.command(
            id,
            ClientMessage::RequestRepaint {
                seq: CmdSeq::first(),
            },
        ));
        let (generation, version) = output
            .latest_screen(Duration::from_secs(2))
            .expect("session should send a screen");
        assert!(!actor.command(
            id,
            ClientMessage::ScreenAck {
                generation,
                version,
            },
        ));

        let mark = actor.deferred_mark();
        actor.attachments[0].begin_sync(mark);
        thread::sleep(actor.attachments[0].repaint_hold());
        actor.output(b".").expect("feed terminal output");

        let (delta_generation, base, rows) = await_frame(
            &output,
            |message| match message {
                ServerMessage::Screen {
                    part:
                        ScreenPart::Head {
                            header,
                            base: Some(base),
                            rows,
                            ..
                        },
                } => Some((header.generation, *base, rows.len())),
                _ => None,
            },
            "a confirmed screen was never used as a delta base",
        );
        assert_eq!(
            (delta_generation, base),
            (generation, version),
            "a delta must name the screen the client confirmed"
        );
        assert!(
            rows < usize::from(GRID.rows),
            "a delta naming every row is larger than the screen it replaces"
        );
    }

    /// The budget keeps a predicted character off the last cell of a row, where
    /// the wrap it commits the terminal to is one this session has not made.
    #[test]
    fn the_cue_stops_one_cell_short_of_the_margin() {
        let open = braid_vt::CursorCue {
            col: 0,
            pending_wrap: false,
            visible: true,
            alternate: false,
            mouse_tracking: false,
        };
        for (cue, expected) in [
            (open, InputCue::Echoing { room: 79 }),
            (
                braid_vt::CursorCue { col: 78, ..open },
                InputCue::Echoing { room: 1 },
            ),
            // The cursor sits on the last cell: nothing may be drawn ahead.
            (
                braid_vt::CursorCue { col: 79, ..open },
                InputCue::Echoing { room: 0 },
            ),
            (
                braid_vt::CursorCue {
                    alternate: true,
                    ..open
                },
                InputCue::Opaque,
            ),
            (
                braid_vt::CursorCue {
                    mouse_tracking: true,
                    ..open
                },
                InputCue::Opaque,
            ),
            (
                braid_vt::CursorCue {
                    visible: false,
                    ..open
                },
                InputCue::Opaque,
            ),
            (
                braid_vt::CursorCue {
                    pending_wrap: true,
                    ..open
                },
                InputCue::Opaque,
            ),
        ] {
            assert_eq!(input_cue(cue, 80), expected);
        }
    }

    /// An application that takes the screen takes prediction with it.
    #[test]
    fn an_application_taking_the_screen_makes_the_cue_opaque() {
        let handle = test_session();
        let id = next_attachment();
        let output = attach_client(&handle, id, client(1), AttachKind::New);

        // The marker is assembled by `printf` so it never appears in the echo:
        // waiting for the echo would sample the cue before the command ran.
        send(&handle, id, typed(1, b"printf 'BRD_%s' PLAIN\n"));
        assert!(output.contains(b"BRD_PLAIN", Duration::from_secs(3)));
        assert!(
            matches!(newest_cue(&output), Some(InputCue::Echoing { .. })),
            "a shell at a prompt echoes what is typed"
        );

        send(&handle, id, typed(2, b"printf '\\033[?1049hBRD_%s' ALT\n"));
        assert!(output.contains(b"BRD_ALT", Duration::from_secs(3)));
        assert_eq!(newest_cue(&output), Some(InputCue::Opaque));

        send(&handle, id, ClientMessage::Close { seq: seq(3) });
    }

    /// A resize arrives whenever a window changes, so a failure in one must
    /// cost the attachment and not the shell the user has work in.
    #[test]
    fn a_resize_that_fails_costs_the_attachment_and_not_the_session() {
        let daemon = Arc::new(DaemonState::default());
        let ticket = sessions::SessionTicket::issue().expect("session ticket");
        let session_id = ticket.session_id;
        let handle = daemon_session(&daemon, ticket, &[]);

        let id = next_attachment();
        let _output = attach_client(&handle, id, client(1), AttachKind::New);

        // `TIOCSWINSZ` refuses this, so `Shell::resize` answers false.
        send(
            &handle,
            id,
            ClientMessage::Resize {
                seq: CmdSeq::first(),
                size: GridSize {
                    cols: 0,
                    rows: GridSize::MAX_ROWS,
                },
            },
        );

        // A session that ended over the resize greets nobody, so `attach_client`
        // is the assertion here.
        let _after = attach_client(&handle, next_attachment(), client(2), AttachKind::New);
        assert!(registry(&daemon).sessions.contains_key(&session_id));

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// Committed ahead of the emulator, a refused resize leaves `self.size`
    /// naming a grid the emulator is not on, and the early return makes it stick.
    #[test]
    fn a_grid_the_emulator_refuses_leaves_the_session_on_the_one_it_has() {
        let size = GRID;
        let (mut actor, _release, _mailbox) = wedged_actor();
        let output = TestOutput::new();
        let mut attachment = Attachment::new(
            next_attachment(),
            ClientStream::new(client(1)),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            Framing::Stream,
            size,
            Generation::initial(),
            test_charge(),
        );
        // A grid the terminal ioctl takes and the emulator does not: neither
        // half is checked against the other anywhere else.
        attachment.size = GridSize { cols: 0, rows: 24 };
        actor.attachments.push(attachment);
        assert!(
            actor
                .terminal
                .as_mut()
                .expect("a session over a terminal")
                .shell
                .resize(GridSize { cols: 0, rows: 24 }),
            "the terminal refuses this grid too, so it proves nothing about the order"
        );

        assert!(!actor.regrid(), "the emulator took a zero-column grid");
        assert_eq!(
            actor.size, size,
            "the grid was committed before the emulator had accepted it"
        );
        assert_eq!(
            actor
                .terminal
                .as_ref()
                .expect("a session over a terminal")
                .vt
                .size(),
            actor.size,
            "the emulator and the session name different grids"
        );
        // Not sticky: the early return only fires for a grid already in use.
        assert!(!actor.regrid(), "a refused grid was silently adopted");
        assert_eq!(actor.size, size);

        actor.attachments[0].size = size;
        assert!(actor.regrid(), "a grid every half accepts still applies");
        actor.dismiss(&ServerMessage::Exit { code: 0 });
    }

    /// A forward this daemon will not carry costs one stream and nothing else:
    /// the sequence is still acknowledged and the attachment stays.
    #[test]
    fn a_forward_past_the_limit_is_refused_without_costing_the_attachment() {
        let (mut actor, _release, _mailbox) = wedged_actor();
        let (id, output) = attach_to(&mut actor, client(1));
        let target = dead_target();

        let mut seq = CmdSeq::first();
        let mut stream = StreamId::first();
        for _ in 0..MAX_FORWARDS {
            actor.command(
                id,
                ClientMessage::ForwardOpen {
                    seq,
                    stream,
                    target: target.clone(),
                },
            );
            seq = seq.next();
            stream = stream.next();
        }
        assert_eq!(actor.forwards.held_by(client(1)), MAX_FORWARDS);

        assert!(
            !actor.command(
                id,
                ClientMessage::ForwardOpen {
                    seq,
                    stream,
                    target
                }
            ),
            "a forward past the limit ended the session"
        );
        assert_eq!(
            actor.attachments.len(),
            1,
            "a forward past the limit cost the attachment"
        );
        assert_eq!(
            actor.forwards.held_by(client(1)),
            MAX_FORWARDS,
            "the ninth forward was carried anyway"
        );

        assert!(
            told(
                &output,
                &ServerMessage::ForwardReset {
                    stream,
                    reason: ForwardResetReason::Limit,
                }
            ),
            "the client was never told which stream was refused"
        );
        assert!(
            told(&output, &ServerMessage::CommandAck { highest: Some(seq) }),
            "the gate never advanced past a refused forward"
        );
    }

    /// A client that contradicts its own stream loses that stream and nothing
    /// else: a panic here would hand a session to any client that sent two.
    #[test]
    fn a_contradicted_forward_is_reset_rather_than_fatal() {
        let (mut actor, _release, _mailbox) = wedged_actor();
        let (id, output) = attach_to(&mut actor, client(1));
        let stream = StreamId::first();
        actor.command(
            id,
            ClientMessage::ForwardOpen {
                seq: CmdSeq::first(),
                stream,
                target: dead_target(),
            },
        );

        // Three bytes and an end, then a fourth byte past it.
        actor.command(
            id,
            ClientMessage::ForwardData {
                stream,
                off: ByteOff::zero(),
                fin: true,
                bytes: b"abc".to_vec(),
            },
        );
        assert!(
            !actor.command(
                id,
                ClientMessage::ForwardData {
                    stream,
                    off: ByteOff::from_u64(3),
                    fin: false,
                    bytes: b"more".to_vec(),
                }
            ),
            "a contradiction ended the session"
        );
        assert_eq!(actor.attachments.len(), 1, "the attachment went with it");
        assert!(
            !actor.forwards.contains(client(1), stream),
            "the contradicted stream is still being carried"
        );
        assert!(told(
            &output,
            &ServerMessage::ForwardReset {
                stream,
                reason: ForwardResetReason::Internal,
            }
        ));

        // Answered rather than ignored: silence is for a stream whose open has
        // not arrived, never for one this side has closed.
        actor.command(
            id,
            ClientMessage::ForwardData {
                stream,
                off: ByteOff::zero(),
                fin: false,
                bytes: b"x".to_vec(),
            },
        );
        assert!(
            told(
                &output,
                &ServerMessage::ForwardReset {
                    stream,
                    reason: ForwardResetReason::Closed,
                }
            ),
            "a client retransmitting into a closed stream was left to do it forever"
        );
    }

    /// A forward belongs to the client, not the transport it arrived on - on a
    /// forward-only session past its grace too, which nothing else holds open.
    #[test]
    fn a_forward_survives_the_attachment_it_was_opened_on() {
        let (mut terminal, _release, terminal_mailbox) = wedged_actor();
        let (mut forward_only, forward_mailbox) = forward_only_actor();
        for (actor, mailbox, collectable) in [
            (&mut terminal, &terminal_mailbox, false),
            (&mut forward_only, &forward_mailbox, true),
        ] {
            let (first, _transcript) = attach_to(actor, client(1));
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
            let address = listener.local_addr().expect("address");
            let stream = StreamId::first();
            actor.command(
                first,
                ClientMessage::ForwardOpen {
                    seq: CmdSeq::first(),
                    stream,
                    target: ForwardTarget {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                },
            );
            let (mut far, _) = listener.accept().expect("the forward dialled");

            // The two events the run loop would take off its mailbox.
            let ActorEvent::ForwardConnected {
                client: dialled,
                stream: opened,
                link,
            } = mailbox
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("the connect thread never answered"))
            else {
                panic!("the first thing a forward reports is its connect");
            };
            actor.forward_connected(dialled, opened, link);
            far.write_all(b"tunnelled").expect("write into the forward");
            let ActorEvent::ForwardBytes {
                client: sender,
                stream: carrying,
                bytes,
            } = mailbox
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("nothing was read off the socket"))
            else {
                panic!("what follows a connect is payload");
            };
            actor.forward_read(sender, carrying, bytes);

            // The transport dies with none of it acknowledged.
            actor.dismiss(&ServerMessage::Detached {
                reason: DetachReason::Replaced,
            });
            if collectable {
                // Past the grace: only the live tunnel says this is a reconnect.
                actor.detached_since =
                    Some(long_ago(FORWARD_SESSION_GRACE + Duration::from_secs(1)));
                assert!(
                    matches!(actor.tick(), Ok(Turn::Continue)),
                    "a session carrying a live connection was collected out from under it"
                );
            } else {
                actor.pump_forwards(Instant::now());
            }
            assert!(
                !actor.forwards.is_empty(),
                "the forward left with the transport that happened to carry it"
            );

            let (second, resumed) = attach_to(actor, client(1));
            actor.pump_forwards(Instant::now());
            assert!(
                told(
                    &resumed,
                    &ServerMessage::ForwardData {
                        stream,
                        off: ByteOff::zero(),
                        fin: false,
                        bytes: b"tunnelled".to_vec(),
                    }
                ),
                "the bytes the forward was holding never reached the client that owns it"
            );

            // And the other direction, on the attachment that inherited it.
            actor.command(
                second,
                ClientMessage::ForwardData {
                    stream,
                    off: ByteOff::zero(),
                    fin: false,
                    bytes: b"request".to_vec(),
                },
            );
            actor.pump_forwards(Instant::now());
            far.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("a deadline on the far end");
            let mut seen = [0; 7];
            far.read_exact(&mut seen)
                .expect("the forward never wrote what its client sent");
            assert_eq!(&seen, b"request");
        }
    }

    /// `brd -N` burns no PTY, no shell and no byte-moving threads: [`Terminal`]
    /// owns all four, so its absence is the absence of every one of them. The
    /// greeting names the kind of session rather than the request that reached
    /// it: a `Hello` here would carry a grid this side does not have.
    #[test]
    fn a_forward_only_session_holds_no_terminal_and_greets_with_helloforward() {
        let (mut actor, _mailbox) = forward_only_actor();
        assert!(
            actor.terminal.is_none(),
            "a session asked to carry forwards opened a terminal anyway"
        );
        assert_eq!(
            actor.info.command, "[forwards]",
            "`brd ls` names a forward-only session by something else"
        );
        assert_eq!(
            actor.size,
            GridSize::new(1, 1).expect("the smallest legal grid"),
            "a session that is never painted reported a plausible terminal"
        );

        let (_new, greeted) = attach_to(&mut actor, client(1));
        assert_eq!(
            greeted_by(&greeted),
            "HelloForward",
            "a forward-only session answered a new client with a terminal's greeting"
        );

        // A resume against it: the same client on a newer transport.
        let output = TestOutput::new();
        actor.attach(
            next_attachment(),
            client(1),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            joining(),
            Framing::Stream,
            None,
        );
        assert_eq!(
            greeted_by(&output),
            "HelloForward",
            "a resume was answered as if this session had a terminal"
        );

        // And the terminal session beside it still answers with its grid.
        let (mut terminal, _release, _pty) = wedged_actor();
        let (_id, shell) = attach_to(&mut terminal, client(1));
        assert_eq!(
            greeted_by(&shell),
            "Hello",
            "a session with a terminal stopped describing it"
        );
    }

    /// A forward-only session has no screen to sync a resumed generation to. An
    /// armed repaint that can never fire makes `deadline` zero: a spun core.
    #[test]
    fn a_resume_against_a_forward_only_session_arms_no_repaint() {
        let (mut actor, _mailbox) = forward_only_actor();
        let output = TestOutput::new();
        actor.attach(
            next_attachment(),
            client(1),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            AttachKind::Resume(ConfirmedOutput {
                generation: Generation::initial().next().next(),
                next_off: ByteOff::from_u64(4096),
            }),
            Framing::Stream,
            None,
        );
        assert_eq!(greeted_by(&output), "HelloForward");
        assert!(
            !actor.attachments[0].repaint_pending,
            "a session with no screen owes one"
        );
        assert!(
            !actor.deadline().is_zero(),
            "the actor was left with no blocking syscall to make"
        );
    }

    /// A resume too far behind is answered with a screen rather than the history it
    /// asked for. The screen converges the grid, so nothing here is *broken* — but
    /// those bytes never reach the user's own terminal, and a client told nothing
    /// cannot tell that from having seen everything.
    #[test]
    fn a_resume_past_the_replay_bound_is_told_what_it_will_never_be_handed() {
        let (mut actor, _release, _pty) = wedged_actor();
        // Further behind than the sink would ever carry as a stream.
        let behind = sink::STREAM_LIMIT as u64 * 4;
        actor.offset = ByteOff::from_u64(behind);

        let output = TestOutput::new();
        actor.attach(
            next_attachment(),
            client(1),
            AttachmentSink::new(Box::new(output.clone()), Version::LOCAL).expect("attachment"),
            AttachKind::Resume(ConfirmedOutput {
                generation: actor.generation,
                next_off: ByteOff::zero(),
            }),
            Framing::Stream,
            None,
        );

        let reported = await_frame(
            &output,
            |message| match message {
                ServerMessage::OutputSkipped { bytes } => Some(*bytes),
                _ => None,
            },
            "the client was never told its history had been skipped",
        );
        assert_eq!(
            reported, behind,
            "the count must be the gap, not an estimate"
        );
        assert!(
            actor.attachments[0].repaint_pending,
            "the screen that replaces the history was never armed"
        );
    }

    /// The gate that keeps a tag out of a decoder too old to know it. A field would be
    /// skipped; an unknown *message* is a hard error that ends a working session.
    #[test]
    fn a_client_that_predates_the_notice_is_never_sent_one() {
        let (mut actor, _release, _pty) = wedged_actor();
        actor.offset = ByteOff::from_u64(sink::STREAM_LIMIT as u64 * 4);

        let output = TestOutput::new();
        actor.attach(
            next_attachment(),
            client(1),
            // The oldest peer this build still speaks to.
            AttachmentSink::new(Box::new(output.clone()), Version::FLOOR).expect("attachment"),
            AttachKind::Resume(ConfirmedOutput {
                generation: actor.generation,
                next_off: ByteOff::zero(),
            }),
            Framing::Stream,
            None,
        );

        // The screen still arrives: what is withheld is the diagnostic, not the repair.
        assert!(
            actor.attachments[0].repaint_pending,
            "the resume was not answered with a screen"
        );
        assert!(
            !actor.attachments[0].sink.version().carries_output_skipped(),
            "the fixture stopped being an older peer, so this proves nothing"
        );
        assert!(
            !output
                .frames()
                .iter()
                .any(|message| matches!(message, ServerMessage::OutputSkipped { .. })),
            "a tag this peer cannot decode was put on its wire"
        );
    }

    /// A client with no business typing here may still send a keystroke, and
    /// each arm must be a no-op rather than a panic or a disconnect.
    #[test]
    fn terminal_commands_against_a_forward_only_session_are_ignored() {
        let (mut actor, _mailbox) = forward_only_actor();
        let (id, _greeted) = attach_to(&mut actor, client(1));
        for message in [
            typed(1, b"ls\n"),
            ClientMessage::Resize {
                seq: seq(2),
                size: GRID,
            },
            ClientMessage::RequestRepaint { seq: seq(3) },
        ] {
            assert!(
                !actor.command(id, message),
                "a terminal command ended a forward-only session"
            );
        }
        assert_eq!(
            actor.attachments.len(),
            1,
            "a terminal command cost the attachment that sent it"
        );
    }

    /// A forward-only session holding nothing with nobody attached can never
    /// produce another byte, but a client mid-reconnect looks identical.
    #[test]
    fn a_forward_only_session_is_collected_once_the_grace_is_spent() {
        let (mut actor, _mailbox) = forward_only_actor();
        assert!(
            matches!(actor.tick(), Ok(Turn::Continue)),
            "a session was collected inside the grace its client reconnects in"
        );

        // The client attached and left; the clock runs from the moment it did.
        let (id, _transcript) = attach_to(&mut actor, client(1));
        assert!(
            actor.detached_since.is_none(),
            "the clock ran while a client was watching"
        );
        actor.command(id, ClientMessage::Detach { seq: seq(1) });
        assert!(
            actor.detached_since.is_some(),
            "the clock never started when the last client left"
        );
        assert!(
            matches!(actor.tick(), Ok(Turn::Continue)),
            "a session was collected inside the grace its client reconnects in"
        );

        actor.detached_since = Some(long_ago(FORWARD_SESSION_GRACE));
        assert!(
            matches!(actor.tick(), Ok(Turn::Stop)),
            "a session with nothing to carry and nobody to carry it for was kept for the daemon's life"
        );

        // A terminal session lives exactly as long as its shell, however long
        // it has been detached: the promise `brd` makes about closing a laptop.
        let (mut terminal, _release, _mailbox) = wedged_actor();
        terminal.detached_since = Some(long_ago(FORWARD_SESSION_GRACE * 10));
        assert!(
            matches!(terminal.tick(), Ok(Turn::Continue)),
            "a detached session with a live shell was collected"
        );
        assert!(terminal.terminal.is_some(), "the shell went with it");
    }

    /// An application that queries the terminal and stops reading must not end
    /// the session: the emulator owes a DA1 reply, and the reply is input.
    #[test]
    fn an_unread_reply_backlog_drops_the_attachment_rather_than_the_session() {
        let (mut actor, release, _mailbox) = wedged_actor();

        // Each query is three bytes in and thirteen back, so one pass over this
        // owes the PTY better than a hundred kilobytes of unread reply.
        let queries = b"\x1b[c".repeat(4096);
        for _ in 0..64 {
            actor
                .output(&queries)
                .expect("a child that will not read its replies is not a fatal error");
        }
        assert!(
            !actor
                .terminal
                .as_ref()
                .expect("a session over a terminal")
                .pty_in
                .write(&vec![0; REPLY_BYTES]),
            "the reply backlog never overflowed, so this proves nothing"
        );

        drop(release);
    }

    /// The only client a session displaces is the one that came back; anything
    /// else is a stolen session rather than a shared one.
    #[test]
    fn a_second_client_does_not_displace_the_first() {
        let handle = test_session();
        let first_id = next_attachment();
        let first = attach_client(&handle, first_id, client(1), AttachKind::New);
        let _second = attach_client(&handle, next_attachment(), client(2), joining());
        assert!(attachments_settle(&handle, 2));
        assert!(
            !first
                .frames()
                .iter()
                .any(|message| matches!(message, ServerMessage::Detached { .. })),
            "the first client was told it had been replaced"
        );

        // Still the session's, not merely connected: it types and the shell answers.
        send(&handle, first_id, typed(1, b"printf 'BRD_FIRST\\n'\n"));
        assert!(first.contains(b"BRD_FIRST", Duration::from_secs(3)));

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A resume carrying an identity the session holds replaces that attachment
    /// and nobody else's, and the command stream continues across it.
    #[test]
    fn the_same_client_returning_on_a_new_transport_replaces_its_own_attachment() {
        let handle = test_session();
        let first_id = next_attachment();
        let first = attach_client(&handle, first_id, client(1), AttachKind::New);
        let other = attach_client(&handle, next_attachment(), client(2), joining());
        send(&handle, first_id, typed(1, b"printf 'BRD_BEFORE\\n'\n"));
        assert!(first.contains(b"BRD_BEFORE", Duration::from_secs(3)));

        let returned_id = next_attachment();
        let returned = attach_client(&handle, returned_id, client(1), joining());
        // The detach tag carrying reason 1: back on a newer transport.
        assert!(first.contains(&[detach_tag(), 1], Duration::from_secs(2)));
        assert!(
            attachments_settle(&handle, 2),
            "the returning client joined beside its own attachment instead of replacing it"
        );

        send(&handle, returned_id, typed(2, b"printf 'BRD_AFTER\\n'\n"));
        assert!(returned.contains(b"BRD_AFTER", Duration::from_secs(3)));
        assert!(other.contains(b"BRD_AFTER", Duration::from_secs(3)));

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// Sharing stops somewhere: each attachment costs a thread, a sink and a
    /// ledger, and nothing else bounds how many a user may open.
    #[test]
    fn the_ninth_attachment_is_refused() {
        let handle = test_session();
        for number in 0..MAX_ATTACHMENTS {
            let kind = if number == 0 {
                AttachKind::New
            } else {
                joining()
            };
            let named = u8::try_from(number + 1).expect("eight clients fit a byte");
            attach_client(&handle, next_attachment(), client(named), kind);
        }
        let full = u16::try_from(MAX_ATTACHMENTS).expect("the bound fits the count");
        assert!(attachments_settle(&handle, full));

        let refused = TestOutput::new();
        let sink =
            AttachmentSink::new(Box::new(refused.clone()), Version::LOCAL).expect("attachment");
        attach_with(
            &handle,
            next_attachment(),
            client(200),
            joining(),
            Framing::Stream,
            sink.clone(),
        );
        assert!(told(
            &refused,
            &ServerMessage::Reject {
                reason: RejectReason::TooManyAttachments,
            }
        ));
        assert!(
            closes(&sink),
            "a refused attachment leaks its writer thread and its descriptor"
        );
        assert_eq!(handle.info.attachments.load(Ordering::Relaxed), full);

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// tmux's rule: a grid wider than someone's window is half a screen. A
    /// client in passthrough renders against a grid it believes in and the
    /// stream never says the grid moved, so every attachment is repainted.
    #[test]
    fn the_grid_is_the_smallest_attached_terminal() {
        let handle = test_session();
        let first_id = next_attachment();
        let first = attach_client(&handle, first_id, client(1), AttachKind::New);
        let second_id = next_attachment();
        let second = attach_client(&handle, second_id, client(2), joining());
        assert!(
            !screened(&first) && !screened(&second),
            "a client in passthrough has been sent no screen to confuse this with"
        );
        let smaller = GridSize::new(60, 20).expect("valid test size");
        send(
            &handle,
            second_id,
            ClientMessage::Resize {
                seq: CmdSeq::first(),
                size: smaller,
            },
        );

        assert!(
            grid_settles(&handle, smaller),
            "the session kept the larger grid"
        );
        assert!(
            first.latest_screen(Duration::from_secs(3)).is_some(),
            "the grid moved under a client that never asked for a screen"
        );
        assert!(second.latest_screen(Duration::from_secs(3)).is_some());
        assert_eq!(newest_screen_size(&first), Some(smaller));
        assert_eq!(newest_screen_size(&second), Some(smaller));

        // A larger window does not win by arriving later: the grid is the
        // minimum over the terminals watching.
        send(
            &handle,
            first_id,
            ClientMessage::Resize {
                seq: CmdSeq::first(),
                size: GridSize::new(100, 40).expect("valid test size"),
            },
        );
        assert!(
            told(
                &first,
                &ServerMessage::CommandAck {
                    highest: Some(CmdSeq::first()),
                }
            ),
            "the resize was never admitted, so what follows proves nothing"
        );
        assert_eq!(grid(&handle), smaller);

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A byte stream on a client larger than the grid autowraps a column early
    /// and scrolls on the last row. Screens place every row explicitly.
    #[test]
    fn a_client_larger_than_the_grid_is_served_screens_rather_than_output() {
        let handle = test_session();
        let larger = attach_client(&handle, next_attachment(), client(1), AttachKind::New);
        let fitting_id = next_attachment();
        let fitting = attach_client(&handle, fitting_id, client(2), joining());
        let smaller = GridSize::new(60, 20).expect("valid test size");
        send(
            &handle,
            fitting_id,
            ClientMessage::Resize {
                seq: CmdSeq::first(),
                size: smaller,
            },
        );
        assert!(grid_settles(&handle, smaller));
        assert!(fitting.latest_screen(Duration::from_secs(3)).is_some());
        assert!(
            writes_settle(&fitting),
            "the resize was still being answered, so what follows proves nothing"
        );

        handle
            .tx
            .send(pty_output(b"BRD_PINNED"))
            .expect("feed pty output");
        assert!(
            fitting.contains(b"BRD_PINNED", Duration::from_secs(3)),
            "the client whose window matches the grid lost the byte stream"
        );
        assert!(
            passthrough(&fitting)
                .windows(b"BRD_PINNED".len())
                .any(|window| window == b"BRD_PINNED"),
            "the matching client was served a screen instead of the stream"
        );
        assert!(
            larger.contains(b"BRD_PINNED", Duration::from_secs(3)),
            "the client larger than the grid was shown nothing at all"
        );
        assert!(
            !passthrough(&larger)
                .windows(b"BRD_PINNED".len())
                .any(|window| window == b"BRD_PINNED"),
            "a client larger than the grid was handed a byte stream it cannot lay out"
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A client leaving takes its own attachment and nothing else.
    #[test]
    fn one_client_detaching_leaves_the_others_attached() {
        let handle = test_session();
        let first = attach_client(&handle, next_attachment(), client(1), AttachKind::New);
        let second_id = next_attachment();
        let second = attach_client(&handle, second_id, client(2), joining());
        let third_id = next_attachment();
        let third = attach_client(&handle, third_id, client(3), joining());
        assert!(attachments_settle(&handle, 3));

        send(
            &handle,
            second_id,
            ClientMessage::Detach {
                seq: CmdSeq::first(),
            },
        );
        // The detach tag carrying reason 0: the client asked to leave.
        assert!(second.contains(&[detach_tag(), 0], Duration::from_secs(2)));
        assert!(attachments_settle(&handle, 2));

        send(&handle, third_id, typed(1, b"printf 'BRD_STILL_HERE\\n'\n"));
        assert!(third.contains(b"BRD_STILL_HERE", Duration::from_secs(3)));
        assert!(first.contains(b"BRD_STILL_HERE", Duration::from_secs(3)));

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// Sync mode is per attachment because the link is: the client beside a
    /// stalled one keeps the byte stream it can still absorb.
    #[test]
    fn a_slow_client_falls_into_sync_mode_without_dragging_a_fast_one_with_it() {
        let handle = test_session();
        let fast = attach_client(&handle, next_attachment(), client(1), AttachKind::New);
        let slow = StalledOutput::new();
        attach_with(
            &handle,
            next_attachment(),
            client(2),
            joining(),
            Framing::Stream,
            AttachmentSink::new(Box::new(slow.clone()), Version::LOCAL).expect("attachment"),
        );

        // Paced against the fast client's own draining: the stream lane charges
        // what its writer holds, so an unpaced burst overruns a healthy client.
        let chunk = vec![0_u8; 16 * 1024];
        for round in 0..6 {
            for _ in 0..4 {
                handle.tx.send(pty_output(&chunk)).expect("feed pty output");
            }
            let marker = format!("BRD_DRAINED_{round}");
            handle
                .tx
                .send(pty_output(marker.as_bytes()))
                .expect("feed a marker behind the burst");
            assert!(
                fast.contains(marker.as_bytes(), Duration::from_secs(5)),
                "the fast client stopped draining the byte stream it was given"
            );
        }
        handle
            .tx
            .send(pty_output(b"BRD_FAST_STREAM"))
            .expect("feed a marker behind the burst");

        assert!(
            fast.contains(b"BRD_FAST_STREAM", Duration::from_secs(5)),
            "the fast client stopped being streamed a byte stream it was draining"
        );
        assert!(
            !screened(&fast),
            "the fast client was dragged into sync mode by the slow one"
        );
        slow.release();
        assert!(
            slow.seen.latest_screen(Duration::from_secs(5)).is_some(),
            "the slow client was never given the screens the stream it could not drain became"
        );

        handle.tx.send(kill()).expect("close test PTY");
    }

    /// A gap on a stream means the stream cannot be reconstructed at all.
    #[test]
    fn a_sequence_gap_retires_a_stream_attachment() {
        let handle = test_session();
        let id = next_attachment();
        let output = attach_client(&handle, id, client(1), AttachKind::New);
        send(&handle, id, typed(3, b"a"));
        assert!(
            attachments_settle(&handle, 0),
            "a gap on a stream leaves nothing to reconstruct the stream from"
        );
        // The count drops when the actor retires it; the reason reaches the
        // client through a writer thread that has not necessarily run yet.
        assert!(
            told(
                &output,
                &ServerMessage::Reject {
                    reason: RejectReason::SequenceGap,
                }
            ),
            "the client is told why"
        );
        handle.tx.send(kill()).expect("close test PTY");
    }

    /// On a datagram a gap is one lost packet the client's journal retransmits.
    #[test]
    fn a_sequence_gap_does_not_retire_a_datagram_attachment() {
        let handle = test_session();
        let id = next_attachment();
        let output = attach_framed(
            &handle,
            id,
            client(1),
            AttachKind::New,
            datagram(DATAGRAM_BUDGET),
        );
        for number in [1, 3, 2, 3] {
            send(&handle, id, typed(number, b"a"));
        }
        assert!(
            attachments_settle(&handle, 1),
            "a lost datagram cost the attachment"
        );
        settles(Duration::from_secs(2), || {
            highest_ack(&output) == Some(seq(3))
        });
        assert_eq!(
            highest_ack(&output),
            Some(seq(3)),
            "the retransmission that repairs the gap was never applied"
        );
        handle.tx.send(kill()).expect("close test PTY");
    }

    /// Every fatal path announces itself: a silent one is a dead transport on
    /// the wire, and the `Resume` retried can only be `UnknownSession`.
    /// `panic = unwind` alone is not enough either, because the thread's
    /// stderr is `/dev/null` and every attachment's socket merely closes.
    #[test]
    fn a_session_that_fails_tells_its_clients_why_and_the_log_too() {
        let directory = scratch("panic-hook");
        let path = directory.join("brd-panic.log");
        let installed = panic_hook();
        log::open(&path);
        log::install_panic_hook();
        for panicking in [false, true] {
            let (mut actor, _release, _mailbox) = wedged_actor();
            let (_, output) = attach_to(&mut actor, client(1));

            if panicking {
                guarded(&mut actor, |_| panic!("the emulator gave up"));
            } else {
                actor.failed(&ServerError::Worker);
            }

            assert_eq!(
                await_frame(
                    &output,
                    |message| match message {
                        ServerMessage::Reject { reason } => Some(*reason),
                        _ => None,
                    },
                    "the session ended without telling anyone why",
                ),
                RejectReason::Internal
            );
            assert!(actor.attachments.is_empty(), "the attachment was kept");
        }
        drop(installed);
        let recorded = fs::read_to_string(&path).unwrap_or_default();
        let _ = fs::remove_dir_all(&directory);
        assert!(
            recorded.contains("the emulator gave up"),
            "the daemon's only voice said nothing about a panic: {recorded:?}"
        );
    }

    /// A search renders the whole scrollback on the thread its client types at,
    /// and `Search` is not rate limited: the deadline has to bound the work.
    #[test]
    fn a_search_whose_asker_has_given_up_is_dropped_rather_than_answered() {
        let (mut actor, _release, _mailbox) = wedged_actor();
        let (reply, answered) = mpsc::sync_channel(1);

        actor.search("anything", 8, long_ago(Duration::from_millis(1)), &reply);

        assert!(
            matches!(answered.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "a search past its deadline was carried out anyway"
        );

        // Inside the deadline it is still answered.
        actor.search(
            "anything",
            8,
            Instant::now() + Duration::from_secs(2),
            &reply,
        );
        assert!(
            answered.try_recv().is_ok(),
            "a search inside its deadline went unanswered"
        );
    }
}
