#![forbid(unsafe_code)]

//! One end of a datagram connection, free of sockets, threads and clocks:
//! every input is an argument and every output a return value, so both ends
//! run in one process against a link that misbehaves on purpose.

use crate::aead;
use crate::congestion::Congestion;
use crate::keys::{Direction, Epoch, KeySchedule, REKEY_AFTER, Reach, RootSecret};
use crate::loss::{Acknowledgement, Cause, InFlight, LossDetector, MAX_ACK_DELAY};
use crate::mtu::{Fragmentation, Mtu};
use crate::packet::{
    ACK_BODY_BYTES, Ack, BASE_DATAGRAM, ConnectionId, HEADER_BYTES, Header, Kind, MalformedPacket,
    TAG_BYTES,
};
use crate::path::{Answered, PathValidator};
use crate::window::{Admission, ReplayWindow};
use std::net::SocketAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("frame of {actual} bytes exceeds the {limit} a datagram carries")]
    TooLarge { actual: usize, limit: usize },
    /// Sealing anything now would reuse a keystream, so the connection ends.
    #[error("connection has exhausted its key schedule")]
    Exhausted,
    #[error("connection is closed")]
    Closed,
    /// Nothing is wrong: the caller keeps the frame and offers it again at
    /// [`poll_deadline`](Endpoint::poll_deadline).
    #[error("this frame may not go yet")]
    Blocked,
}

/// None of these ends a connection: an endpoint that died on a forged packet
/// would be a session anybody could end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecvError {
    #[error(transparent)]
    Malformed(#[from] MalformedPacket),
    #[error("datagram names another connection")]
    WrongConnection,
    #[error("datagram names an unreachable key epoch")]
    UnknownEpoch,
    #[error(transparent)]
    Auth(#[from] aead::AuthFailed),
    #[error("packet number {0} has already been accepted")]
    Replayed(u64),
}

/// An accepting endpoint that has opened one datagram and sealed nothing.
/// Holding the root secret makes the two ways out exclusive: two endpoints over
/// one root both restart at [`Epoch::first`] and packet zero.
pub struct Accepted {
    endpoint: Endpoint,
    root: RootSecret,
}

impl Accepted {
    #[must_use]
    pub fn commit(self) -> Endpoint {
        self.endpoint
    }

    #[must_use]
    pub fn release(self) -> RootSecret {
        self.root
    }
}

/// A datagram that did not open, and the offer it was tried against: nothing
/// was sealed under it, so a client whose first attempt failed may still use it.
#[derive(Debug)]
pub struct Rejected {
    pub root: RootSecret,
    pub error: RecvError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    /// One `braid` frame, at this range of the buffer that was passed in.
    Frame(Range<usize>),
    Nothing,
    Migrated(SocketAddr),
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub cwnd: usize,
    pub bytes_in_flight: usize,
    pub srtt: Option<Duration>,
    pub rttvar: Duration,
    pub plpmtu: usize,
    /// Packets the peer acknowledged around.
    pub lost: u64,
    /// Of those, the ones the peer acknowledged after all.
    pub spurious: u64,
}

/// Held until the caller next transmits; `recv` owns no socket.
struct Answer {
    to: SocketAddr,
    token: [u8; 8],
}

enum AckDebt {
    Settled,
    /// `since` is when the newest eliciting datagram arrived, which is what
    /// makes the reported delay an honest number rather than a zero.
    Owed {
        at: Instant,
        since: Instant,
        eliciting: u8,
    },
}

/// Ack-eliciting datagrams that may arrive before an acknowledgement stops
/// waiting for company. Two, as TCP and QUIC both settled on.
const ACK_EVERY: u8 = 2;

pub struct Endpoint {
    cid: ConnectionId,
    keys: KeySchedule,
    /// Never restarted by a rotation, so an acknowledgement that crosses one
    /// still names exactly one packet.
    next: u64,
    /// One window, not one per epoch: numbers do not restart.
    window: ReplayWindow,
    path: PathValidator,
    answer: Option<Answer>,
    closed: bool,
    /// Only the connecting side keeps a connection alive.
    role: Direction,
    /// A last-transmission clock that does not make `send` take the time.
    sealed_since_poll: bool,
    quiet_since: Option<Instant>,
    congestion: Congestion,
    loss: LossDetector,
    mtu: Mtu,
    debt: AckDebt,
    /// A field rather than [`REKEY_AFTER`] so a test can cross the rekey
    /// branch, which no finishing run reaches and which would repeat a nonce.
    rekey_every: u64,
    rekey_at: u64,
}

/// Under the shortest NAT mapping timeout worth designing for.
const KEEPALIVE: Duration = Duration::from_secs(1);

impl Endpoint {
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the move is the contract: a reference would let one offer build two endpoints"
    )]
    pub fn connect(
        cid: ConnectionId,
        root: RootSecret,
        peer: SocketAddr,
        fragmentation: Fragmentation,
    ) -> Self {
        Self::new(
            cid,
            &root,
            PathValidator::dialled(peer),
            Direction::ClientToServer,
            fragmentation,
        )
    }

    /// Told where its peer is rather than having dialled it — a claim, so it is
    /// sent nothing until traffic arrives and no more than
    /// [`crate::path::AMPLIFICATION_LIMIT`] times that until it answers.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the move is the contract: a reference would let one offer build two endpoints"
    )]
    pub fn listen(
        cid: ConnectionId,
        root: RootSecret,
        peer: SocketAddr,
        fragmentation: Fragmentation,
    ) -> Self {
        Self::new(
            cid,
            &root,
            PathValidator::claimed(peer),
            Direction::ServerToClient,
            fragmentation,
        )
    }

    /// Constructed and fed in one call, or an endpoint is something an attacker
    /// allocates by sending eight bytes. Nothing has sealed anything and the
    /// offer comes back either way, so a daemon can validate before committing.
    pub fn accept(
        cid: ConnectionId,
        root: RootSecret,
        from: SocketAddr,
        now: Instant,
        datagram: &mut [u8],
        fragmentation: Fragmentation,
    ) -> Result<(Accepted, Received), Rejected> {
        let mut endpoint = Self::new(
            cid,
            &root,
            PathValidator::claimed(from),
            Direction::ServerToClient,
            fragmentation,
        );
        match endpoint.recv(from, now, datagram) {
            Ok(received) => Ok((Accepted { endpoint, root }, received)),
            Err(error) => Err(Rejected { root, error }),
        }
    }

    fn new(
        cid: ConnectionId,
        root: &RootSecret,
        path: PathValidator,
        sending: Direction,
        fragmentation: Fragmentation,
    ) -> Self {
        Self {
            cid,
            keys: KeySchedule::new(root, sending),
            next: 0,
            window: ReplayWindow::new(),
            path,
            answer: None,
            closed: false,
            role: sending,
            sealed_since_poll: false,
            quiet_since: None,
            congestion: Congestion::new(BASE_DATAGRAM),
            loss: LossDetector::new(),
            mtu: Mtu::new(fragmentation),
            debt: AckDebt::Settled,
            rekey_every: REKEY_AFTER,
            rekey_at: REKEY_AFTER,
        }
    }

    pub const fn rekey_every(&mut self, packets: u64) {
        self.rekey_every = if packets == 0 { 1 } else { packets };
        self.rekey_at = self.next.saturating_add(self.rekey_every);
    }

    #[must_use]
    pub const fn connection(&self) -> ConnectionId {
        self.cid
    }

    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.path.current()
    }

    #[must_use]
    pub const fn send_epoch(&self) -> Epoch {
        self.keys.send_epoch()
    }

    /// The pair that must never repeat.
    #[must_use]
    pub const fn next_nonce(&self) -> (Epoch, u64) {
        (self.keys.send_epoch(), self.next)
    }

    /// Moves at run time as the MTU search finds a size, so a caller that cached
    /// it will one day cut a screen to a size this path stopped carrying.
    #[must_use]
    pub const fn payload_limit(&self) -> usize {
        self.mtu.datagram() - HEADER_BYTES - TAG_BYTES
    }

    /// `None` means the *window* refuses the frame, and a window opens only on
    /// events [`poll_deadline`](Self::poll_deadline) already names.
    #[must_use]
    pub fn ready(&self, now: Instant, frame_len: usize) -> Option<Instant> {
        let bytes = frame_len + HEADER_BYTES + TAG_BYTES;
        if !self.admits(self.path.current(), bytes) {
            return None;
        }
        self.congestion.ready(now, bytes)
    }

    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        self.loss.rtt().smoothed()
    }

    #[must_use]
    pub fn stats(&self) -> Stats {
        Stats {
            cwnd: self.congestion.window(),
            bytes_in_flight: self.congestion.in_flight(),
            srtt: self.loss.rtt().smoothed(),
            rttvar: self.loss.rtt().variation(),
            plpmtu: self.mtu.datagram(),
            lost: self.loss.losses(),
            spurious: self.loss.spurious(),
        }
    }

    /// Asked separately so a caller with a queue can decide what to build before
    /// building it: pieces that are then refused are most of the work there is.
    #[must_use]
    pub fn writable(&self, now: Instant, frame_len: usize) -> bool {
        let bytes = frame_len + HEADER_BYTES + TAG_BYTES;
        !self.closed
            && self.admits(self.path.current(), bytes)
            && self.congestion.writable(now, bytes)
    }

    fn admits(&self, to: SocketAddr, bytes: usize) -> bool {
        self.loss.admits() && self.path.may_send(to, bytes)
    }

    pub fn send(
        &mut self,
        frame: &[u8],
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Result<SocketAddr, SendError> {
        let limit = self.payload_limit();
        if frame.len() > limit {
            return Err(SendError::TooLarge {
                actual: frame.len(),
                limit,
            });
        }
        if !self.writable(now, frame.len()) {
            return Err(if self.closed {
                SendError::Closed
            } else {
                SendError::Blocked
            });
        }
        let to = self.path.current();
        self.seal(Kind::Frame, frame, to, now, out).map(|_| to)
    }

    /// Not subject to the window: a close carries nothing and is the last thing
    /// this endpoint will say, so pacing it only costs the peer a timeout.
    pub fn close(&mut self, now: Instant, out: &mut Vec<u8>) -> Result<SocketAddr, SendError> {
        let to = self.path.current();
        let sealed = self.seal(Kind::Close, &[], to, now, out);
        self.closed = true;
        sealed.map(|_| to)
    }

    /// Called automatically on migration: a session that just changed networks
    /// should not keep sealing under keys an observer of the old path collected.
    pub fn rotate(&mut self) -> Result<Epoch, SendError> {
        self.keys.rotate().ok_or(SendError::Exhausted)
    }

    /// Answers first, since a peer waiting on a response is stalled; then
    /// acknowledgements, since a sender waiting on one has a shut window; then a
    /// challenge, the MTU search, and last the keep-alive.
    pub fn poll_transmit(
        &mut self,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Option<(SocketAddr, usize)> {
        self.expire(now);
        if let Some(answer) = self.answer.take()
            && let Ok(bytes) = self.seal(Kind::Response, &answer.token, answer.to, now, out)
        {
            return Some((answer.to, bytes));
        }
        if let Some(sent) = self.acknowledge(now, out) {
            return Some(sent);
        }
        if let Some((to, token)) = self.path.poll_challenge(now) {
            let cost = HEADER_BYTES + token.len() + TAG_BYTES;
            // Asking first is what keeps an address that has not earned a
            // challenge from spending one of the few it is given.
            if !self.path.may_send(to, cost) {
                return None;
            }
            let bytes = self.seal(Kind::Challenge, &token, to, now, out).ok()?;
            return Some((to, bytes));
        }
        if let Some(sent) = self.probe_path_mtu(now, out) {
            return Some(sent);
        }
        self.keepalive(now, out)
    }

    /// What a caller holding a socket sleeps on; without it every timer here
    /// is only as accurate as whatever the caller chose as a tick.
    #[must_use]
    pub fn poll_deadline(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let owed = match self.debt {
            AckDebt::Owed { at, .. } => Some(at),
            AckDebt::Settled => None,
        };
        // Only once something has been sealed: before that there is no instant
        // to name, and the caller is about to poll anyway.
        let keepalive = self
            .quiet_since
            .filter(|_| self.role == Direction::ClientToServer)
            .map(|since| since + KEEPALIVE);
        [
            self.loss.deadline(),
            owed,
            self.mtu.deadline(),
            self.path.challenge_deadline(),
            keepalive,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn expire(&mut self, now: Instant) {
        self.loss.expire(now);
        self.absorb(now);
    }

    /// In one place because the window, the MTU search and the
    /// persistent-congestion rule all read it, and two copies would disagree.
    fn absorb(&mut self, now: Instant) {
        for arrived in self.loss.arrived() {
            self.congestion
                .acknowledged(arrived.bytes, arrived.sent, self.loss.rtt());
            self.mtu.acknowledged(arrived.number, arrived.bytes);
        }
        for gone in self.loss.gone() {
            match gone.cause {
                Cause::Lost => {
                    self.congestion.lost(gone.bytes, gone.sent, now);
                    self.mtu.lost(gone.number, gone.bytes, now);
                }
                // Silence moves neither: a packet nobody mentioned is neither
                // a full queue nor a narrow path.
                Cause::Abandoned => {
                    self.congestion.abandoned(gone.bytes);
                    self.mtu.abandoned(gone.number, now);
                }
            }
        }
        // The window is denominated in datagrams, and the search may have just
        // changed what one is.
        self.congestion.datagram(self.mtu.datagram());
        if self.loss.persistent_congestion() {
            self.congestion.collapse(now);
        }
    }

    fn acknowledge(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<(SocketAddr, usize)> {
        let AckDebt::Owed { at, since, .. } = self.debt else {
            return None;
        };
        if now < at {
            return None;
        }
        let (largest, map) = self.window.acknowledgement()?;
        let ack = Ack {
            largest,
            delay: now.saturating_duration_since(since),
            map,
        };
        let mut body = [0u8; ACK_BODY_BYTES];
        ack.encode(&mut body);
        let to = self.path.current();
        let bytes = self.seal(Kind::Ack, &body, to, now, out).ok()?;
        self.debt = AckDebt::Settled;
        Some((to, bytes))
    }

    fn probe_path_mtu(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<(SocketAddr, usize)> {
        let confirming = self.mtu.confirming();
        let candidate = self.mtu.poll(now)?;
        if !confirming && !self.congestion.writable(now, candidate) {
            return None;
        }
        let padding = candidate - HEADER_BYTES - TAG_BYTES;
        let to = self.path.current();
        let number = self.next;
        // Grown in place: a probe is up to a full datagram of nothing, and
        // that copy would be the entire cost of asking how wide this path is.
        let bytes = self
            .seal_with(Kind::Probe, to, now, out, |out| {
                out.resize(out.len() + padding, 0);
            })
            .ok()?;
        self.mtu.probing(number);
        Some((to, bytes))
    }

    fn keepalive(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<(SocketAddr, usize)> {
        if self.role != Direction::ClientToServer || self.closed {
            return None;
        }
        if std::mem::take(&mut self.sealed_since_poll) {
            self.quiet_since = Some(now);
            return None;
        }
        let since = *self.quiet_since.get_or_insert(now);
        if now.saturating_duration_since(since) < KEEPALIVE {
            return None;
        }
        let to = self.path.current();
        let bytes = self.seal(Kind::Alive, &[], to, now, out).ok()?;
        self.quiet_since = Some(now);
        self.sealed_since_poll = false;
        Some((to, bytes))
    }

    fn seal(
        &mut self,
        kind: Kind,
        body: &[u8],
        to: SocketAddr,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Result<usize, SendError> {
        self.seal_with(kind, to, now, out, |out| out.extend_from_slice(body))
    }

    /// Seal whatever `body` appends to `out`, so a caller that can produce its
    /// bytes in place never builds a second copy of them.
    fn seal_with(
        &mut self,
        kind: Kind,
        to: SocketAddr,
        now: Instant,
        out: &mut Vec<u8>,
        body: impl FnOnce(&mut Vec<u8>),
    ) -> Result<usize, SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        // Nothing joins the flight the table cannot hold a row for, or the
        // controller would be measuring a path it could no longer see.
        if tracked(kind) && !self.loss.admits() {
            return Err(SendError::Blocked);
        }
        if self.next >= self.rekey_at {
            self.keys.rotate().ok_or(SendError::Exhausted)?;
            self.rekey_at = self.next.saturating_add(self.rekey_every);
        }
        let header = Header {
            kind,
            cid: self.cid,
            epoch: self.keys.send_epoch(),
            number: self.next,
        };
        let start = out.len();
        // The header is authenticated data as well as the front of the datagram;
        // its own array lets the payload be written into a still-growing `out`.
        let head = header.encode();
        out.extend_from_slice(&head);
        body(out);
        let payload = &mut out[start + HEADER_BYTES..];
        let tag = aead::seal(self.keys.sending(), &head, header.number, payload);
        out.extend_from_slice(&tag);
        let bytes = out.len() - start;
        // Charged after sealing, since the size is not known until then; a
        // datagram past the budget comes off the buffer rather than the wire.
        if !self.path.may_send(to, bytes) {
            out.truncate(start);
            return Err(SendError::Blocked);
        }
        self.path.spent(to, bytes);
        self.next += 1;
        self.sealed_since_poll = true;
        if tracked(kind) {
            self.congestion.sealed(bytes, now);
            self.loss.sealed(InFlight {
                number: header.number,
                bytes,
                sent: now,
            });
            // `sealed` can retire the oldest of an unbounded flight, and what
            // it retires still has to reach the controller.
            self.absorb(now);
        }
        Ok(bytes)
    }

    /// The order is the whole security argument: authenticate, then admit
    /// against the replay window, then let it touch the path. A packet failing
    /// any of the three has changed nothing about this endpoint.
    pub fn recv(
        &mut self,
        from: SocketAddr,
        now: Instant,
        datagram: &mut [u8],
    ) -> Result<Received, RecvError> {
        let header = Header::decode(datagram)?;
        if header.cid != self.cid {
            return Err(RecvError::WrongConnection);
        }
        let reach = self.keys.reach(header.epoch);
        let body_end = datagram.len() - TAG_BYTES;
        // `Header::decode` already refused anything shorter than both chunks.
        let (front, tag) = datagram
            .split_last_chunk_mut::<TAG_BYTES>()
            .ok_or(MalformedPacket::Short)?;
        let (head, payload) = front
            .split_first_chunk_mut::<HEADER_BYTES>()
            .ok_or(MalformedPacket::Short)?;
        match reach {
            Reach::Current | Reach::Previous => {
                let keys = self.keys.reading(reach).ok_or(RecvError::UnknownEpoch)?;
                aead::open(keys, head, header.number, payload, tag)?;
            }
            Reach::Ahead(ahead) => {
                let keys = self.keys.peek_ahead(ahead).ok_or(RecvError::UnknownEpoch)?;
                aead::open(keys, head, header.number, payload, tag)?;
            }
            Reach::Unreachable => return Err(RecvError::UnknownEpoch),
        }
        // Only now: a forged packet must not be able to move the window, or
        // one datagram would retire every number a live peer is about to use.
        if let Reach::Ahead(ahead) = reach {
            self.keys.follow(ahead).ok_or(RecvError::UnknownEpoch)?;
        }
        if self.window.admit(header.number) != Admission::Fresh {
            return Err(RecvError::Replayed(header.number));
        }
        let payload = HEADER_BYTES..body_end;
        // An authenticated, replay-checked datagram is the only thing allowed
        // to touch the path, and nothing about touching it can fail.
        self.path.arrived(from, datagram.len(), now);
        if header.kind.ack_eliciting() {
            self.owe_acknowledgement(now, header.kind);
        }
        match header.kind {
            Kind::Frame => Ok(Received::Frame(payload)),
            Kind::Challenge => {
                if let Ok(token) = <[u8; 8]>::try_from(&datagram[payload]) {
                    self.answer = Some(Answer { to: from, token });
                }
                Ok(Received::Nothing)
            }
            Kind::Response => {
                let Ok(token) = <[u8; 8]>::try_from(&datagram[payload]) else {
                    return Ok(Received::Nothing);
                };
                match self.path.answered(from, token) {
                    None | Some(Answered::Validated) => Ok(Received::Nothing),
                    Some(Answered::Migrated(moved)) => {
                        // Exhaustion is no reason to refuse the move: the old
                        // keys are still sound, there are just no fresher ones.
                        let _ = self.rotate();
                        // RFC 9002 §5.5: what was measured describes the path
                        // it was measured on.
                        self.congestion.migrated();
                        self.loss.migrated();
                        Ok(Received::Migrated(moved))
                    }
                }
            }
            Kind::Ack => {
                if let Some(ack) = Ack::decode(&datagram[payload])
                    && let Some(ack) = Acknowledgement::checked(ack, self.next)
                {
                    self.loss.acknowledged(ack, now);
                    self.absorb(now);
                    // Proof the path carries traffic both ways, which is the
                    // precondition for spending anything on probing it.
                    self.mtu.proven();
                }
                Ok(Received::Nothing)
            }
            Kind::Alive | Kind::Probe => Ok(Received::Nothing),
            Kind::Close => {
                self.closed = true;
                Ok(Received::Closed)
            }
        }
    }

    fn owe_acknowledgement(&mut self, now: Instant, kind: Kind) {
        let eliciting = match self.debt {
            AckDebt::Settled => 1,
            AckDebt::Owed { eliciting, .. } => eliciting.saturating_add(1),
        };
        // A probe's whole purpose is the answer to it, and waiting 25 ms would
        // put the delay into the round-trip sample it also produces.
        let at = match self.debt {
            _ if kind == Kind::Probe || eliciting >= ACK_EVERY => now,
            AckDebt::Settled => now + MAX_ACK_DELAY,
            AckDebt::Owed { at, .. } => at,
        };
        self.debt = AckDebt::Owed {
            at,
            since: now,
            eliciting,
        };
    }

    #[must_use]
    pub const fn closed(&self) -> bool {
        self.closed
    }

    /// The state a session spends between a peer moving and this side agreeing.
    #[must_use]
    pub const fn probing(&self) -> bool {
        self.path.probing()
    }

    /// The kernel would not send a datagram this connection built, and named
    /// the width the path has instead. Nothing that arrives reaches here, so
    /// this is the one narrowing an off-path forgery cannot drive.
    pub fn path_refused(&mut self, carries: usize, now: Instant) {
        self.mtu.refused(carries, now);
        // As after every acknowledgement: the window counts datagrams, and
        // that may have just stopped meaning what it meant.
        self.congestion.datagram(self.mtu.datagram());
    }

    /// Such a connection owes the network a datagram on a timer.
    #[must_use]
    pub const fn confirming_path_mtu(&self) -> bool {
        self.mtu.confirming()
    }
}

/// Deliberately not challenges: one goes to an address that has not answered,
/// which on a spoofed source never will, so counting those as losses hands an
/// off-path attacker a lever on the working path for one forged packet.
const fn tracked(kind: Kind) -> bool {
    matches!(kind, Kind::Frame | Kind::Probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MAX_PACKET_NUMBER;

    const ROOT: [u8; 32] = [42u8; 32];

    /// A test wanting two endpoints over one connection has to ask twice.
    fn root() -> RootSecret {
        RootSecret::new(ROOT)
    }

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, last], 9000))
    }

    fn connect(cid: u8) -> Endpoint {
        Endpoint::connect(
            ConnectionId::from_bytes([cid; 8]),
            root(),
            addr(1),
            Fragmentation::Refused,
        )
    }

    /// A connecting endpoint and the one that accepted its first frame, before
    /// either has answered the other's challenge.
    fn opened(cid: u8, first: &[u8]) -> (Endpoint, Endpoint, Vec<u8>, Instant) {
        let now = Instant::now();
        let cid = ConnectionId::from_bytes([cid; 8]);
        let mut client = Endpoint::connect(cid, root(), addr(1), Fragmentation::Refused);
        let mut wire = Vec::new();
        client.send(first, now, &mut wire).unwrap();
        let (accepted, received) =
            Endpoint::accept(cid, root(), addr(2), now, &mut wire, Fragmentation::Refused).unwrap();
        assert_eq!(
            received,
            Received::Frame(HEADER_BYTES..HEADER_BYTES + first.len())
        );
        (client, accepted.commit(), wire, now)
    }

    /// Two endpoints of a session that has started: the frame that opened it
    /// crossed, and the address the accepting side was handed has answered.
    fn pair() -> (Endpoint, Endpoint, Vec<u8>, Instant) {
        let (mut client, mut server, wire, now) = opened(1, b"hello");
        assert_eq!(
            exchange(&mut server, &mut client, addr(1), now),
            [Kind::Challenge]
        );
        assert_eq!(
            exchange(&mut client, &mut server, addr(2), now),
            [Kind::Response]
        );
        assert!(!server.probing(), "the address it was handed answered");
        (client, server, wire, now)
    }

    /// Drive one side until it stops talking, and report what crossed.
    fn exchange(
        from: &mut Endpoint,
        to: &mut Endpoint,
        source: SocketAddr,
        now: Instant,
    ) -> Vec<Kind> {
        let mut kinds = Vec::new();
        loop {
            let mut out = Vec::new();
            let Some((_, len)) = from.poll_transmit(now, &mut out) else {
                return kinds;
            };
            let mut datagram = out[out.len() - len..].to_vec();
            kinds.push(Header::decode(&datagram).expect("a datagram").kind);
            let _ = to.recv(source, now, &mut datagram);
        }
    }

    /// Transmit until the named kind goes out, and report where it went.
    fn until(from: &mut Endpoint, kind: Kind, now: Instant, out: &mut Vec<u8>) -> SocketAddr {
        loop {
            out.clear();
            let (to, _) = from.poll_transmit(now, out).expect("something to send");
            if Header::decode(out).expect("a datagram").kind == kind {
                return to;
            }
        }
    }

    /// The frame `recv` reported, read out of the buffer it opened in place.
    fn frame(received: Received, wire: &[u8]) -> &[u8] {
        match received {
            Received::Frame(range) => &wire[range],
            other => panic!("{other:?}"),
        }
    }

    /// The client's traffic starts arriving from `to`; drive the challenge and
    /// the response that commits the move, which the frame alone must not.
    fn migrate(client: &mut Endpoint, server: &mut Endpoint, to: SocketAddr, now: Instant) {
        let held = server.peer();
        let mut moved = Vec::new();
        client.send(b"from a new network", now, &mut moved).unwrap();
        let received = server.recv(to, now, &mut moved).unwrap();
        assert_eq!(frame(received, &moved), b"from a new network");
        assert_eq!(server.peer(), held, "not until the candidate answers");
        assert!(server.probing());

        // The acknowledgement it owes comes first, to the proven address.
        let mut challenge = Vec::new();
        assert_eq!(until(server, Kind::Challenge, now, &mut challenge), to);
        assert_eq!(
            client.recv(addr(1), now, &mut challenge).unwrap(),
            Received::Nothing
        );
        let mut response = Vec::new();
        client.poll_transmit(now, &mut response).unwrap();
        assert_eq!(Header::decode(&response).unwrap().kind, Kind::Response);
        assert_eq!(
            server.recv(to, now, &mut response).unwrap(),
            Received::Migrated(to)
        );
        assert_eq!(server.peer(), to);
        assert!(!server.probing());
    }

    #[test]
    fn a_frame_crosses_and_comes_back() {
        let (mut client, mut server, mut wire, now) = pair();
        assert_eq!(&wire[HEADER_BYTES..HEADER_BYTES + 5], b"hello");
        wire.clear();
        server.send(b"world", now, &mut wire).unwrap();
        let received = client.recv(addr(2), now, &mut wire).unwrap();
        assert_eq!(frame(received, &wire), b"world");
    }

    /// The three ways a datagram fails to be this connection's: the wrong
    /// connection id, a tag that does not match, and a number already seen.
    #[test]
    fn a_datagram_that_is_not_the_peers_is_refused() {
        let (mut client, mut server, _, now) = pair();

        let mut other = connect(2);
        let mut wire = Vec::new();
        other.send(b"stranger", now, &mut wire).unwrap();
        assert_eq!(
            client.recv(addr(1), now, &mut wire),
            Err(RecvError::WrongConnection)
        );

        let mut wire = Vec::new();
        server.send(b"payload", now, &mut wire).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert!(matches!(
            client.recv(addr(2), now, &mut wire),
            Err(RecvError::Auth(_))
        ));

        let mut wire = Vec::new();
        server.send(b"once", now, &mut wire).unwrap();
        let recording = wire.clone();
        client.recv(addr(2), now, &mut wire).unwrap();
        let mut again = recording;
        assert_eq!(
            client.recv(addr(2), now, &mut again),
            Err(RecvError::Replayed(2))
        );
    }

    #[test]
    fn a_frame_larger_than_a_datagram_is_refused_before_it_is_sealed() {
        let (mut client, _, _, now) = pair();
        let mut wire = Vec::new();
        let limit = client.payload_limit();
        assert_eq!(
            client.send(&vec![0u8; limit + 1], now, &mut wire),
            Err(SendError::TooLarge {
                actual: limit + 1,
                limit
            })
        );
        assert!(wire.is_empty(), "a refused frame writes nothing");
    }

    /// The property the daemon's accept path rests on: a datagram that did not
    /// open hands the offer back, and one that did has still sealed nothing.
    #[test]
    fn an_accepted_endpoint_has_sealed_nothing_until_it_is_asked_to() {
        let now = Instant::now();
        let cid = ConnectionId::from_bytes([5; 8]);
        let mut client = Endpoint::connect(cid, root(), addr(1), Fragmentation::Refused);
        let mut wire = Vec::new();
        client.send(b"a resume", now, &mut wire).unwrap();

        let mut forged = wire.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x80;
        let Err(refused) = Endpoint::accept(
            cid,
            root(),
            addr(2),
            now,
            &mut forged,
            Fragmentation::Refused,
        ) else {
            panic!("a forged tag opens nothing");
        };

        let (accepted, _) = Endpoint::accept(
            cid,
            refused.root,
            addr(2),
            now,
            &mut wire,
            Fragmentation::Refused,
        )
        .unwrap();
        let mut server = accepted.commit();
        assert_eq!(server.next_nonce(), (Epoch::first(), 0));
        assert_eq!(server.stats().bytes_in_flight, 0);
        let mut out = Vec::new();
        let (to, _) = server
            .poll_transmit(now, &mut out)
            .expect("the address it was handed is challenged");
        assert_eq!(to, addr(2));
        assert_eq!(Header::decode(&out).unwrap().kind, Kind::Challenge);
    }

    /// An attacker who can spoof a source address must not point a session at a
    /// victim; without the peer's keys the only lever is a recording.
    #[test]
    fn a_replayed_datagram_from_a_new_address_cannot_move_the_path() {
        let (mut client, mut server, _, now) = pair();
        let mut wire = Vec::new();
        client.send(b"legitimate", now, &mut wire).unwrap();
        let recording = wire.clone();
        server.recv(addr(2), now, &mut wire).unwrap();
        let mut spoofed = recording;
        assert!(matches!(
            server.recv(addr(9), now, &mut spoofed),
            Err(RecvError::Replayed(_))
        ));
        assert_eq!(server.peer(), addr(2));
        assert!(!server.probing(), "a refused datagram touches nothing");
    }

    /// Session traffic still goes to the working path, so only the challenge
    /// is charged against the candidate.
    #[test]
    fn an_unanswered_candidate_receives_less_than_it_sent() {
        let (mut client, mut server, _, now) = pair();
        let mut wire = Vec::new();
        client.send(b"x", now, &mut wire).unwrap();
        let arrived = wire.len();
        server.recv(addr(3), now, &mut wire).unwrap();
        let mut sent = 0usize;
        let mut out = Vec::new();
        while let Some((to, bytes)) = server.poll_transmit(now, &mut out) {
            if to == addr(3) {
                sent += bytes;
            }
        }
        assert!(
            sent as u64 <= crate::path::AMPLIFICATION_LIMIT * arrived as u64,
            "{sent} bytes for {arrived} received"
        );
        let mut session = Vec::new();
        assert_eq!(
            server.send(b"a screen", now, &mut session).unwrap(),
            addr(2)
        );
    }

    /// The frame the network was still holding still opens — once.
    #[test]
    fn a_rotation_is_followed_and_the_epoch_it_left_still_opens() {
        let (mut client, mut server, _, now) = pair();
        assert_eq!(client.send_epoch().get(), 0);

        let mut held = Vec::new();
        client.send(b"held by a router", now, &mut held).unwrap();
        let recording = held.clone();

        client.rotate().unwrap();
        assert_eq!(client.send_epoch().get(), 1);
        assert_eq!(client.next_nonce(), (Epoch::from_wire(1), 3));
        let mut wire = Vec::new();
        client.send(b"after the rotation", now, &mut wire).unwrap();
        let received = server.recv(addr(2), now, &mut wire).unwrap();
        assert_eq!(frame(received, &wire), b"after the rotation");

        let received = server.recv(addr(2), now, &mut held).unwrap();
        assert_eq!(frame(received, &held), b"held by a router");
        let mut again = recording;
        assert!(matches!(
            server.recv(addr(2), now, &mut again),
            Err(RecvError::Replayed(_))
        ));
    }

    /// Without the catch-up window this side could never read the peer again.
    #[test]
    fn a_peer_that_rotated_twice_unheard_is_still_readable() {
        let (mut client, mut server, _, now) = pair();
        let mut lost = Vec::new();
        client.rotate().unwrap();
        client.send(b"never arrives", now, &mut lost).unwrap();
        client.rotate().unwrap();
        client.send(b"nor this", now, &mut lost).unwrap();
        client.rotate().unwrap();
        let mut wire = Vec::new();
        client.send(b"three epochs on", now, &mut wire).unwrap();
        assert_eq!(client.send_epoch().get(), 3);
        let received = server.recv(addr(2), now, &mut wire).unwrap();
        assert_eq!(frame(received, &wire), b"three epochs on");
    }

    /// The branch the shipped threshold makes unreachable; wrong, it is wrong
    /// silently and repeats a keystream.
    #[test]
    fn a_sender_crossing_its_rekey_threshold_rotates_without_repeating_a_nonce() {
        let (mut client, mut server, _, now) = pair();
        client.rekey_every(4);
        let mut nonces = std::collections::HashSet::new();
        for n in 0..40u32 {
            let mut wire = Vec::new();
            assert!(nonces.insert(client.next_nonce()), "a nonce repeated");
            client.send(&n.to_be_bytes(), now, &mut wire).unwrap();
            let received = server.recv(addr(2), now, &mut wire).unwrap();
            assert_eq!(frame(received, &wire), n.to_be_bytes());
        }
        assert!(client.send_epoch().get() >= 9, "it rotated as it went");
    }

    /// An unbounded queue must not become an unbounded flight, and a peer that
    /// says nothing must not leave the sender wedged behind a full one.
    #[test]
    fn a_sender_fills_the_window_and_a_timeout_is_what_frees_it() {
        let (mut client, _, _, now) = pair();
        let frame = vec![7u8; client.payload_limit()];
        let mut out = Vec::new();
        let mut sent = 1;
        while client.send(&frame, now, &mut out).is_ok() {
            sent += 1;
            assert!(sent < 100, "the window never closed");
        }
        assert_eq!(
            client.send(&frame, now, &mut out),
            Err(SendError::Blocked),
            "and it says why"
        );
        assert!(client.stats().bytes_in_flight > 0);
        assert!(sent <= 10, "the initial window is ten datagrams");

        let later = now + Duration::from_secs(2);
        client.poll_transmit(later, &mut out);
        assert_eq!(client.stats().bytes_in_flight, 0);
        assert_eq!(client.stats().lost, 0, "silence is not congestion");
        assert!(client.send(&frame, later, &mut out).is_ok());
    }

    /// It has to arrive without a frame going the other way to carry it, and
    /// the delay the peer admits to comes out of the sample, or every estimate
    /// on an idle session is 25 ms long and the loss timer four times that.
    #[test]
    fn what_arrives_is_acknowledged_and_the_sender_measures_the_trip() {
        for (held, back) in [(Duration::ZERO, 50u64), (MAX_ACK_DELAY, 20)] {
            let (mut client, mut server, _, now) = pair();
            let mut wire = Vec::new();
            client.send(b"and another", now, &mut wire).unwrap();
            server.recv(addr(2), now, &mut wire).unwrap();
            assert!(client.stats().bytes_in_flight > 0);

            let mut ack = Vec::new();
            let (to, _) = server
                .poll_transmit(now + held, &mut ack)
                .expect("two frames arrived, so it says so at once");
            assert_eq!(to, addr(2));
            assert_eq!(Header::decode(&ack).unwrap().kind, Kind::Ack);
            let arrives = now + held + Duration::from_millis(back);
            assert_eq!(
                client.recv(addr(2), arrives, &mut ack).unwrap(),
                Received::Nothing
            );
            assert_eq!(client.stats().bytes_in_flight, 0);
            assert_eq!(client.srtt(), Some(Duration::from_millis(back)));
        }
    }

    /// One frame does not deserve its own datagram going back; two do.
    #[test]
    fn a_single_arrival_is_acknowledged_only_after_the_delay() {
        let (_, mut server, _, now) = opened(3, b"one");

        let mut out = Vec::new();
        server
            .poll_transmit(now, &mut out)
            .expect("the address it was handed is challenged first");
        assert_eq!(Header::decode(&out).unwrap().kind, Kind::Challenge);
        out.clear();
        assert!(server.poll_transmit(now, &mut out).is_none());
        assert_eq!(server.poll_deadline(), Some(now + MAX_ACK_DELAY));
        let due = now + MAX_ACK_DELAY;
        assert!(server.poll_transmit(due, &mut out).is_some());
        assert_eq!(Header::decode(&out).unwrap().kind, Kind::Ack);
    }

    /// Or two idle endpoints acknowledge each other until one is unplugged.
    #[test]
    fn an_acknowledgement_does_not_produce_another_one() {
        let (mut client, mut server, _, now) = pair();
        let mut wire = Vec::new();
        client.send(b"a frame", now, &mut wire).unwrap();
        server.recv(addr(2), now, &mut wire).unwrap();
        let later = now + MAX_ACK_DELAY;
        // Drained rather than delivered: an ack reaching the server would start
        // the path-MTU search, and a probe is not what this test is about.
        let mut drained = Vec::new();
        while client.poll_transmit(later, &mut drained).is_some() {}
        assert_eq!(
            exchange(&mut server, &mut client, addr(1), later),
            [Kind::Ack]
        );
        assert!(
            !exchange(&mut client, &mut server, addr(2), later).contains(&Kind::Ack),
            "the client owes nothing for an acknowledgement"
        );
    }

    /// The signal the whole controller is built on.
    #[test]
    fn a_packet_acknowledged_around_shrinks_the_window() {
        let (mut client, mut server, _, now) = pair();
        let before = client.stats().cwnd;
        let mut dropped = Vec::new();
        client.send(b"this one is lost", now, &mut dropped).unwrap();
        for n in 0..4u8 {
            let mut wire = Vec::new();
            client.send(&[n; 32], now, &mut wire).unwrap();
            server.recv(addr(2), now, &mut wire).unwrap();
        }
        let later = now + Duration::from_millis(20);
        let mut ack = Vec::new();
        server.poll_transmit(later, &mut ack).unwrap();
        client.recv(addr(2), later, &mut ack).unwrap();
        assert_eq!(client.stats().lost, 1);
        assert!(client.stats().cwnd < before, "the window paid for it");
    }

    #[test]
    fn a_path_that_carries_more_is_found_and_used() {
        let (mut client, mut server, _, mut now) = pair();
        let base = BASE_DATAGRAM - HEADER_BYTES - TAG_BYTES;
        assert_eq!(client.payload_limit(), base);
        for _ in 0..6 {
            now += Duration::from_millis(30);
            exchange(&mut client, &mut server, addr(2), now);
            now += Duration::from_millis(30);
            exchange(&mut server, &mut client, addr(1), now);
        }
        assert!(
            client.payload_limit() > base,
            "the search never left the base size: {:?}",
            client.stats()
        );
    }

    /// The one narrowing that costs no round trip: the kernel refused a
    /// datagram and said what it would have carried instead.
    #[test]
    fn a_refusal_narrows_the_path_without_a_single_loss() {
        let (mut client, mut server, _, mut now) = pair();
        let base = BASE_DATAGRAM - HEADER_BYTES - TAG_BYTES;
        for _ in 0..6 {
            now += Duration::from_millis(30);
            exchange(&mut client, &mut server, addr(2), now);
            now += Duration::from_millis(30);
            exchange(&mut server, &mut client, addr(1), now);
        }
        assert!(client.payload_limit() > base, "the search never grew");
        client.path_refused(1300, now);
        assert_eq!(client.stats().plpmtu, 1300);
        assert_eq!(
            client.payload_limit(),
            1300 - HEADER_BYTES - TAG_BYTES,
            "what the caller cuts against follows the kernel's answer"
        );
        assert_eq!(client.stats().lost, 0, "and nothing had to be lost first");
    }

    /// `largest` is a high-water mark the detector never lowers, so one such ack
    /// would leave every packet sealed afterwards overtaken: the window on its
    /// floor and endless false black-hole evidence for the MTU search.
    #[test]
    fn an_acknowledgement_of_a_packet_this_side_never_sealed_changes_nothing() {
        let (mut client, mut server, _, now) = pair();
        client.send(b"in flight", now, &mut Vec::new()).unwrap();
        let before = client.stats();
        assert!(before.bytes_in_flight > 0);

        let mut body = [0u8; ACK_BODY_BYTES];
        Ack {
            largest: MAX_PACKET_NUMBER,
            delay: Duration::ZERO,
            map: u64::MAX,
        }
        .encode(&mut body);
        let mut forged = Vec::new();
        server
            .seal(Kind::Ack, &body, addr(2), now, &mut forged)
            .unwrap();

        assert_eq!(
            client.recv(addr(1), now, &mut forged).unwrap(),
            Received::Nothing
        );
        let after = client.stats();
        assert_eq!(after.bytes_in_flight, before.bytes_in_flight);
        assert_eq!(after.cwnd, before.cwnd);
        assert_eq!(after.lost, 0, "nothing was acknowledged around");
    }

    /// A source address is whatever the sender wrote; answering it with an
    /// output burst is an amplifier aimed wherever they liked.
    #[test]
    fn an_accepting_endpoint_sends_an_unanswered_address_no_more_than_it_earned() {
        let (_, mut server, wire, now) = opened(9, b"a resume");
        let arrived = wire.len();

        let screen = vec![7u8; server.payload_limit()];
        let mut out = Vec::new();
        while server.send(&screen, now, &mut out).is_ok() {}
        while server.poll_transmit(now, &mut out).is_some() {}
        assert!(
            out.len() as u64 <= crate::path::AMPLIFICATION_LIMIT * arrived as u64,
            "{} bytes sent for {arrived} received",
            out.len()
        );
        assert!(server.probing(), "and it is asking the address to answer");
        assert!(out.len() >= HEADER_BYTES + TAG_BYTES, "the challenge fits");
    }

    /// RFC 9002 §5.5: a 5 ms minimum on a 100 ms link makes every sample an
    /// overshoot, ending slow start where it is needed most.
    #[test]
    fn a_confirmed_migration_starts_the_controller_again() {
        let (mut client, mut server, _, now) = pair();
        let fresh = connect(8).stats().cwnd;

        let mut wire = Vec::new();
        server.send(b"a screen", now, &mut wire).unwrap();
        client.recv(addr(1), now, &mut wire).unwrap();
        let later = now + Duration::from_millis(50);
        let mut ack = Vec::new();
        client.poll_transmit(now, &mut ack).unwrap();
        server.recv(addr(2), later, &mut ack).unwrap();
        assert_eq!(server.srtt(), Some(Duration::from_millis(50)));
        assert_ne!(server.stats().cwnd, fresh, "the old path was measured");

        migrate(&mut client, &mut server, addr(3), later);

        assert_eq!(server.srtt(), None, "nothing has been measured here yet");
        assert_eq!(server.stats().cwnd, fresh, "and it starts again");
    }

    /// Abandoning the oldest to make room moves neither the window nor the
    /// search, so loss detection would go blind instead of the sender waiting.
    #[test]
    fn a_flight_of_small_datagrams_stops_at_the_table_rather_than_overflowing_it() {
        let (mut client, mut server, _, mut now) = pair();
        let datagram = 1 + HEADER_BYTES + TAG_BYTES;
        let wanted = (crate::loss::MAX_TRACKED + 32) * datagram;

        // Two at a time so the ack is due at once, a moment apart for the pacer.
        while client.stats().cwnd < wanted {
            now += Duration::from_micros(1);
            for byte in 0..2u8 {
                let mut wire = Vec::new();
                client.send(&[byte], now, &mut wire).unwrap();
                server.recv(addr(2), now, &mut wire).unwrap();
            }
            let mut ack = Vec::new();
            server.poll_transmit(now, &mut ack).expect("an ack is due");
            client.recv(addr(1), now, &mut ack).unwrap();
        }

        let mut sealed = 0usize;
        let ceiling = 2 * crate::loss::MAX_TRACKED;
        // Bounded: a table that abandoned its oldest would never refuse.
        while sealed < ceiling {
            now += Duration::from_micros(1);
            if client.send(&[0], now, &mut Vec::new()).is_err() {
                break;
            }
            sealed += 1;
        }
        assert!(sealed > 0 && sealed < ceiling, "never refused");
        let stats = client.stats();
        assert!(
            stats.bytes_in_flight + datagram <= stats.cwnd,
            "the window still had room: {stats:?}"
        );
        // What refused it was the table, at its bound and not past it.
        assert_eq!(stats.bytes_in_flight / datagram, crate::loss::MAX_TRACKED);
    }
}
