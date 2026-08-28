#![forbid(unsafe_code)]

//! Two endpoints, one link, and a clock this file advances: no socket, so a
//! seed reproduces hours of session in a millisecond. Every [`Violation`] is
//! armed on every datagram of every run.

use crate::fault::{Fault, Schedule};
use braid_dgram::endpoint::{Received, RecvError, SendError, Stats};
use braid_dgram::packet::{Header, Kind};
use braid_dgram::path::AMPLIFICATION_LIMIT;
use braid_dgram::{ConnectionId, Direction, Endpoint, Epoch, Fragmentation, RootSecret};
use braid_proto::MAX_FRAME;
use braid_proto::wire::{PACK_TAG, pack, unpack};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    const fn direction(self) -> Direction {
        match self {
            Self::Client => Direction::ClientToServer,
            Self::Server => Direction::ServerToClient,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bandwidth(u64);

impl Bandwidth {
    #[must_use]
    pub const fn bits_per_second(bits: u64) -> Self {
        Self(bits / 8)
    }

    #[must_use]
    pub const fn bytes_per_second(bytes: u64) -> Self {
        Self(bytes)
    }

    fn serialise(self, bytes: usize) -> Duration {
        let rate = u128::from(self.0.max(1));
        let micros = u128::try_from(bytes).unwrap_or(u128::MAX) * 1_000_000 / rate;
        Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }
}

/// One shape both ways; asymmetric loss is [`crate::fault::Asymmetric`].
#[derive(Clone, Copy, Debug)]
pub struct Link {
    /// One-way, and before any fault is applied.
    pub latency: Duration,
    /// `None` is an infinitely fast wire.
    pub bandwidth: Option<Bandwidth>,
    /// `None` with a bandwidth set never drops and only makes everything late,
    /// which is the failure this harness exists to catch.
    pub queue: Option<usize>,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(20),
            bandwidth: None,
            queue: None,
        }
    }
}

impl Link {
    /// 1 Mbps, 200 ms of round trip, 64 KB of queue: half a second of standing
    /// latency if a sender fills it, and a loss-based controller will.
    #[must_use]
    pub const fn narrow() -> Self {
        Self {
            latency: Duration::from_millis(100),
            bandwidth: Some(Bandwidth::bits_per_second(1_000_000)),
            queue: Some(64 * 1024),
        }
    }
}

/// Named rather than content-addressed: two identical frames are two frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrameId(u64);

/// Two [`Endpoint`]s over the same 32 bytes share one: the keys' scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RootId(u32);

/// Every keystream spent this run, across every endpoint: a second endpoint
/// over one root restarts at zero, which a per-endpoint set cannot see.
#[derive(Default)]
struct Nonces {
    roots: Vec<[u8; 32]>,
    spent: HashSet<(RootId, Direction, Epoch, u64)>,
}

impl Nonces {
    fn root(&mut self, bytes: [u8; 32]) -> RootId {
        let index = self
            .roots
            .iter()
            .position(|known| *known == bytes)
            .unwrap_or_else(|| {
                self.roots.push(bytes);
                self.roots.len() - 1
            });
        RootId(u32::try_from(index).expect("a harness does not mint four billion secrets"))
    }

    fn bytes(&self, root: RootId) -> [u8; 32] {
        self.roots[root.0 as usize]
    }

    /// Whether this keystream was still unspent.
    fn spend(&mut self, root: RootId, direction: Direction, epoch: Epoch, number: u64) -> bool {
        self.spent.insert((root, direction, epoch, number))
    }
}

/// Packed here, as production does: the size distribution decides the MTU search.
struct Outgoing {
    id: FrameId,
    body: Vec<u8>,
}

struct InFlight {
    at: Instant,
    to: SocketAddr,
    from: SocketAddr,
    bytes: Vec<u8>,
    /// Ties broken in send order, so iteration order is not nondeterminism.
    order: u64,
}

#[derive(Default)]
struct Bottleneck {
    departures: VecDeque<(Instant, usize)>,
    queued: usize,
    free_at: Option<Instant>,
}

impl Bottleneck {
    /// `None` if the queue was full, so the datagram is dropped.
    fn admit(&mut self, now: Instant, bytes: usize, link: &Link) -> Option<Duration> {
        while let Some(&(at, size)) = self.departures.front()
            && at <= now
        {
            self.departures.pop_front();
            self.queued -= size;
        }
        let Some(bandwidth) = link.bandwidth else {
            self.free_at = None;
            return Some(Duration::ZERO);
        };
        if link.queue.is_some_and(|limit| self.queued + bytes > limit) {
            return None;
        }
        let start = self.free_at.map_or(now, |free| free.max(now));
        let departure = start + bandwidth.serialise(bytes);
        self.free_at = Some(departure);
        self.queued += bytes;
        self.departures.push_back((departure, bytes));
        Some(start.saturating_duration_since(now))
    }
}

#[derive(Default)]
struct Budget {
    received: u64,
    sent: u64,
}

/// A property this run broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// Keyed on the root: two endpoints over one root is what a per-endpoint
    /// set cannot see.
    NonceReuse {
        root: RootId,
        direction: Direction,
        epoch: Epoch,
        number: u64,
    },
    /// A frame reached the session above more than once.
    DuplicateDelivery { side: Side, frame: FrameId },
    /// A frame reached the session above that the peer never sealed.
    Fabricated { side: Side, frame: Vec<u8> },
    /// A body the peer packed did not survive the datagram framing.
    Unpackable { side: Side },
    /// More was sent to an unproven address than it had earned.
    Amplified {
        to: SocketAddr,
        sent: u64,
        received: u64,
    },
    /// A peer moved to an address it had never challenged.
    UnprovenMigration { side: Side, to: SocketAddr },
    /// Nothing is lost — every byte arrives, a quarter of a second late.
    Bufferbloat { queue_ms: u64 },
}

/// A run where nothing was refused is a run whose faults reached nothing.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusals {
    pub replayed: u64,
    pub unauthentic: u64,
    pub malformed: u64,
    pub wrong_connection: u64,
}

impl Refusals {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.replayed + self.unauthentic + self.malformed + self.wrong_connection
    }
}

/// So a transport that never stops talking fails the suite rather than hangs it.
const SETTLE_LIMIT: Duration = Duration::from_mins(10);

/// How far the clock moves when nothing names a deadline at all.
const IDLE_TICK: Duration = Duration::from_millis(1);

const BUFFERBLOAT: Duration = Duration::from_millis(250);

/// Two endpoints connected by a link that does whatever the schedule says.
pub struct Sim<S: Schedule> {
    now: Instant,
    pub link: Link,
    schedule: S,
    flight: Vec<InFlight>,
    order: u64,
    bottleneck: HashMap<Side, Bottleneck>,
    /// Addresses that are receiving nothing, and until when.
    deaf: HashMap<SocketAddr, Instant>,

    client: Endpoint,
    server: Endpoint,
    cid: ConnectionId,
    roots: HashMap<Side, RootId>,
    at: HashMap<Side, SocketAddr>,
    /// Where a spoofed datagram claims to come from. Nothing listens there.
    attacker: SocketAddr,
    /// Without it every test asserts the transport accepts an unbounded burst.
    outbox: HashMap<Side, VecDeque<Outgoing>>,
    frames: u64,

    nonces: Nonces,
    /// Tells a duplicate on the wire apart from a frame the session sent twice.
    carrying: HashMap<(Side, Epoch, u64), FrameId>,
    received: HashMap<Side, Vec<Vec<u8>>>,
    seen: HashMap<Side, HashSet<FrameId>>,
    budgets: HashMap<SocketAddr, Budget>,
    challenged: HashSet<(Side, SocketAddr)>,
    /// Challenge answered, plus the address the connecting side dialled.
    proven: HashSet<(Side, SocketAddr)>,
    /// A second challenge for one move means the first was thrown away.
    challenges: HashMap<Side, u64>,

    pub refusals: Refusals,
    /// The path shrank under them after they were queued.
    pub unsendable: u64,
    pub violations: Vec<Violation>,
}

impl<S: Schedule> Sim<S> {
    #[must_use]
    pub fn new(schedule: S) -> Self {
        let client_at = SocketAddr::from(([10, 0, 0, 2], 51_000));
        let server_at = SocketAddr::from(([10, 0, 0, 1], 60_000));
        let cid = ConnectionId::from_bytes(*b"braidsim");
        let root = [0x5a; 32];
        let mut nonces = Nonces::default();
        let root_id = nonces.root(root);
        Self {
            now: Instant::now(),
            link: Link::default(),
            schedule,
            flight: Vec::new(),
            order: 0,
            bottleneck: HashMap::new(),
            deaf: HashMap::new(),
            // The simulated link has no IP layer to cut a datagram up with.
            client: Endpoint::connect(
                cid,
                RootSecret::new(root),
                server_at,
                Fragmentation::Refused,
            ),
            server: Endpoint::listen(
                cid,
                RootSecret::new(root),
                client_at,
                Fragmentation::Refused,
            ),
            cid,
            roots: HashMap::from([(Side::Client, root_id), (Side::Server, root_id)]),
            at: HashMap::from([(Side::Client, client_at), (Side::Server, server_at)]),
            attacker: SocketAddr::from(([192, 0, 2, 66], 40_000)),
            outbox: HashMap::new(),
            frames: 0,
            nonces,
            carrying: HashMap::new(),
            received: HashMap::new(),
            seen: HashMap::new(),
            budgets: HashMap::new(),
            challenged: HashSet::new(),
            proven: HashSet::from([(Side::Client, server_at)]),
            challenges: HashMap::new(),
            refusals: Refusals::default(),
            unsendable: 0,
            violations: Vec::new(),
        }
    }

    #[must_use]
    pub fn address(&self, side: Side) -> SocketAddr {
        self.at[&side]
    }

    #[must_use]
    pub fn peer_of(&self, side: Side) -> SocketAddr {
        self.endpoint(side).peer()
    }

    #[must_use]
    pub fn challenges(&self, side: Side) -> u64 {
        self.challenges.get(&side).copied().unwrap_or_default()
    }

    #[must_use]
    pub fn now(&self) -> Instant {
        self.now
    }

    #[must_use]
    pub fn stats(&self, side: Side) -> Stats {
        self.endpoint(side).stats()
    }

    /// The datagram carries the *packed* body: one tag short of the endpoint's limit.
    #[must_use]
    pub fn payload_limit(&self, side: Side) -> usize {
        self.endpoint(side).payload_limit().saturating_sub(PACK_TAG)
    }

    /// Frames handed down but not yet taken by the transport.
    #[must_use]
    pub fn pending(&self, side: Side) -> usize {
        self.outbox.get(&side).map_or(0, VecDeque::len)
    }

    const fn endpoint(&self, side: Side) -> &Endpoint {
        match side {
            Side::Client => &self.client,
            Side::Server => &self.server,
        }
    }

    const fn endpoint_mut(&mut self, side: Side) -> &mut Endpoint {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    /// `None` is a frame the path could never carry: this transport fragments
    /// nothing. Otherwise the name the frame keeps for the rest of the run.
    pub fn send(&mut self, side: Side, frame: &[u8]) -> Option<FrameId> {
        let mut body = Vec::new();
        pack(frame, &mut body);
        if body.len() > self.endpoint(side).payload_limit() {
            return None;
        }
        self.frames += 1;
        let id = FrameId(self.frames);
        self.outbox
            .entry(side)
            .or_default()
            .push_back(Outgoing { id, body });
        self.flush();
        Some(id)
    }

    /// Datagrams in flight to the old address are not recalled; they land nowhere.
    pub fn roam(&mut self, to: SocketAddr) {
        self.at.insert(Side::Client, to);
    }

    /// A NAT re-mapping: same path, and the server still has to challenge it,
    /// because a rewritten port and a rewritten datagram look the same.
    pub fn rebind(&mut self, port: u16) {
        let mut moved = self.at[&Side::Client];
        moved.set_port(port);
        self.at.insert(Side::Client, moved);
    }

    /// A laptop lid: every timer comes back overdue at once.
    pub fn suspend(&mut self, by: Duration) {
        self.flight.clear();
        self.bottleneck.clear();
        self.now += by;
        self.flush();
    }

    /// The default address to roam to, so a test need not invent one.
    #[must_use]
    pub fn elsewhere(&self, nth: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 1, nth], 51_000 + u16::from(nth)))
    }

    /// Oldest first.
    #[must_use]
    pub fn delivered(&self, side: Side) -> &[Vec<u8>] {
        self.received.get(&side).map_or(&[], Vec::as_slice)
    }

    pub fn take_delivered(&mut self, side: Side) -> Vec<Vec<u8>> {
        self.received.remove(&side).unwrap_or_default()
    }

    /// Nothing seals these and nobody receives them: they occupy the bottleneck.
    pub fn flood(&mut self, from: Side, datagrams: usize, bytes: usize) {
        let sink = self.attacker;
        let source = self.at[&from];
        for _ in 0..datagrams {
            let Some(wait) = self.queue(from, bytes) else {
                continue;
            };
            self.enqueue(wait + self.link.latency, sink, source, vec![0u8; bytes]);
        }
    }

    pub const fn schedule(&mut self) -> &mut S {
        &mut self.schedule
    }

    pub fn rotate(&mut self, side: Side) {
        let _ = self.endpoint_mut(side).rotate();
    }

    /// The shipped threshold is 2^40 packets, so this branch is otherwise dead.
    pub const fn rekey_every(&mut self, side: Side, packets: u64) {
        self.endpoint_mut(side).rekey_every(packets);
    }

    #[must_use]
    pub fn root_of(&self, side: Side) -> RootId {
        self.roots[&side]
    }

    pub fn root(&mut self, bytes: [u8; 32]) -> RootId {
        self.nonces.root(bytes)
    }

    /// The new endpoint starts at epoch zero and packet number zero, which over
    /// a spent root derives a keystream that is already gone.
    pub fn rebuild(&mut self, side: Side, root: RootId) {
        let bytes = self.nonces.bytes(root);
        let (cid, peer) = (self.cid, self.at[&side.peer()]);
        *self.endpoint_mut(side) = match side {
            Side::Client => {
                Endpoint::connect(cid, RootSecret::new(bytes), peer, Fragmentation::Refused)
            }
            Side::Server => {
                Endpoint::listen(cid, RootSecret::new(bytes), peer, Fragmentation::Refused)
            }
        };
        self.roots.insert(side, root);
        self.outbox.remove(&side);
        // A rebuilt endpoint has proved nothing and been proved nothing.
        self.proven.retain(|(owner, _)| *owner != side);
        self.challenged.retain(|(owner, _)| *owner != side);
        if side == Side::Client {
            self.proven.insert((Side::Client, peer));
        }
    }

    /// Drain both outboxes as far as the windows allow, then poll both endpoints.
    fn flush(&mut self) {
        for side in [Side::Client, Side::Server] {
            loop {
                let now = self.now;
                let Some(queued) = self.outbox.get(&side).and_then(VecDeque::front) else {
                    break;
                };
                // Parking it on the window would hold up the traffic that
                // reopens the window.
                let size = queued.body.len();
                let carried = size <= self.endpoint(side).payload_limit();
                if carried && !self.endpoint(side).writable(now, size) {
                    break;
                }
                let Some(queued) = self.outbox.get_mut(&side).and_then(VecDeque::pop_front) else {
                    break;
                };
                let mut out = Vec::new();
                match self.endpoint_mut(side).send(&queued.body, now, &mut out) {
                    Ok(to) => {
                        if let Ok(header) = Header::decode(&out) {
                            self.carrying
                                .insert((side, header.epoch, header.number), queued.id);
                        }
                        self.emit(side, to, out);
                    }
                    Err(SendError::Blocked) => {
                        self.outbox.entry(side).or_default().push_front(queued);
                        break;
                    }
                    // Dropped rather than requeued, which would spin for ever.
                    Err(SendError::TooLarge { .. }) => self.unsendable += 1,
                    Err(SendError::Closed | SendError::Exhausted) => break,
                }
            }
            loop {
                let mut out = Vec::new();
                let now = self.now;
                let Some((to, _)) = self.endpoint_mut(side).poll_transmit(now, &mut out) else {
                    break;
                };
                if let Ok(header) = Header::decode(&out)
                    && header.kind == Kind::Challenge
                {
                    self.challenged.insert((side, to));
                    *self.challenges.entry(side).or_default() += 1;
                }
                self.emit(side, to, out);
            }
        }
    }

    /// Runs the outbound oracles, then whatever the schedule decided.
    fn emit(&mut self, from: Side, to: SocketAddr, bytes: Vec<u8>) {
        if let Ok(header) = Header::decode(&bytes) {
            let root = self.roots[&from];
            let direction = from.direction();
            if !self
                .nonces
                .spend(root, direction, header.epoch, header.number)
            {
                self.violations.push(Violation::NonceReuse {
                    root,
                    direction,
                    epoch: header.epoch,
                    number: header.number,
                });
            }
        }
        self.charge(from, to, bytes.len() as u64);
        let source = self.at[&from];
        let fault = self.schedule.next(from, &bytes);
        if fault == Fault::Drop {
            return;
        }
        // A datagram about to be dropped must not occupy the bottleneck.
        let Some(wait) = self.queue(from, bytes.len()) else {
            return;
        };
        let held = wait + self.link.latency;
        match fault {
            // Exhaustive, so a new fault cannot skip deciding what the queue does.
            Fault::Drop => {}
            Fault::Deliver => self.enqueue(held, to, source, bytes),
            Fault::Delay(extra) => self.enqueue(held + extra, to, source, bytes),
            Fault::Duplicate => {
                self.enqueue(held, to, source, bytes.clone());
                self.enqueue(held, to, source, bytes);
            }
            Fault::Replay(after) => {
                self.enqueue(held, to, source, bytes.clone());
                self.enqueue(held + after, to, source, bytes);
            }
            Fault::Corrupt(at) => {
                let mut damaged = bytes;
                if !damaged.is_empty() {
                    let index = usize::from(at) % damaged.len();
                    damaged[index] ^= 1 << (at % 8);
                }
                self.enqueue(held, to, source, damaged);
            }
            Fault::Truncate(by) => {
                let mut cut = bytes;
                let keep = cut.len().saturating_sub(usize::from(by) % cut.len().max(1));
                cut.truncate(keep);
                self.enqueue(held, to, source, cut);
            }
            // Only the source is rewritten, so the datagram itself is genuine.
            Fault::Spoof => self.enqueue(held, to, self.attacker, bytes),
            Fault::Blackhole { until } => {
                let ends = self.now + until;
                let ends = self.deaf.get(&to).map_or(ends, |seen| (*seen).max(ends));
                self.deaf.insert(to, ends);
            }
        }
    }

    fn queue(&mut self, from: Side, bytes: usize) -> Option<Duration> {
        let link = self.link;
        let now = self.now;
        let wait = self
            .bottleneck
            .entry(from)
            .or_default()
            .admit(now, bytes, &link)?;
        if wait >= BUFFERBLOAT
            && !self
                .violations
                .iter()
                .any(|violation| matches!(violation, Violation::Bufferbloat { .. }))
        {
            self.violations.push(Violation::Bufferbloat {
                queue_ms: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
            });
        }
        Some(wait)
    }

    /// Account for bytes sent to an address that has not proved it is there.
    fn charge(&mut self, from: Side, to: SocketAddr, bytes: u64) {
        if self.proven.contains(&(from, to)) {
            return;
        }
        let budget = self.budgets.entry(to).or_default();
        budget.sent += bytes;
        let (sent, received) = (budget.sent, budget.received);
        if sent > AMPLIFICATION_LIMIT * received {
            self.violations
                .push(Violation::Amplified { to, sent, received });
        }
    }

    fn enqueue(&mut self, after: Duration, to: SocketAddr, from: SocketAddr, bytes: Vec<u8>) {
        self.order += 1;
        self.flight.push(InFlight {
            at: self.now + after,
            to,
            from,
            bytes,
            order: self.order,
        });
    }

    fn resident(&self, at: SocketAddr) -> Option<Side> {
        [Side::Client, Side::Server]
            .into_iter()
            .find(|side| self.at[side] == at)
    }

    /// Returns whether anything happened.
    pub fn step(&mut self) -> bool {
        let Some(index) = self.soonest() else {
            return false;
        };
        let packet = self.flight.swap_remove(index);
        self.now = self.now.max(packet.at);
        self.deliver(packet);
        self.flush();
        true
    }

    fn soonest(&self) -> Option<usize> {
        self.flight
            .iter()
            .enumerate()
            .min_by_key(|(_, packet)| (packet.at, packet.order))
            .map(|(index, _)| index)
    }

    fn deliver(&mut self, packet: InFlight) {
        // Not an error: it is the outage between a move and the path following.
        if self
            .deaf
            .get(&packet.to)
            .is_some_and(|until| self.now < *until)
        {
            return;
        }
        let Some(side) = self.resident(packet.to) else {
            return;
        };
        let before = self.endpoint(side).peer();
        let mut bytes = packet.bytes;
        // Read while the datagram is still sealed: `recv` decrypts in place.
        let sealed = Header::decode(&bytes)
            .ok()
            .map(|header| (side.peer(), header.epoch, header.number));
        let now = self.now;
        let outcome = self.endpoint_mut(side).recv(packet.from, now, &mut bytes);
        self.note(side, packet.from, &bytes, sealed, outcome, before);
    }

    fn note(
        &mut self,
        side: Side,
        from: SocketAddr,
        buffer: &[u8],
        sealed: Option<(Side, Epoch, u64)>,
        outcome: Result<Received, RecvError>,
        peer_before: SocketAddr,
    ) {
        match outcome {
            Ok(received) => {
                self.budgets.entry(from).or_default().received += buffer.len() as u64;
                match received {
                    Received::Frame(range) => self.hand_up(side, &buffer[range], sealed),
                    Received::Migrated(to) => {
                        if !self.challenged.contains(&(side, to)) {
                            self.violations
                                .push(Violation::UnprovenMigration { side, to });
                        }
                    }
                    Received::Nothing | Received::Closed => {}
                }
                // Checking the challenge went to this exact address stops a
                // genuine response, re-sourced by a spoof, proving that address.
                if Header::decode(buffer).is_ok_and(|header| header.kind == Kind::Response)
                    && self.challenged.contains(&(side, from))
                {
                    self.proven.insert((side, from));
                }
            }
            Err(RecvError::Replayed(_)) => self.refusals.replayed += 1,
            // An epoch this endpoint cannot reach is one it cannot authenticate.
            Err(RecvError::Auth(_) | RecvError::UnknownEpoch) => self.refusals.unauthentic += 1,
            Err(RecvError::Malformed(_)) => self.refusals.malformed += 1,
            Err(RecvError::WrongConnection) => self.refusals.wrong_connection += 1,
        }
        let after = self.endpoint(side).peer();
        if after != peer_before && !self.challenged.contains(&(side, after)) {
            self.violations
                .push(Violation::UnprovenMigration { side, to: after });
        }
    }

    fn hand_up(&mut self, side: Side, body: &[u8], sealed: Option<(Side, Epoch, u64)>) {
        let mut frame = Vec::new();
        if unpack(body, MAX_FRAME as usize, &mut frame).is_err() {
            self.violations.push(Violation::Unpackable { side });
            return;
        }
        let Some(id) = sealed.and_then(|key| self.carrying.get(&key).copied()) else {
            self.violations.push(Violation::Fabricated { side, frame });
            return;
        };
        if !self.seen.entry(side).or_default().insert(id) {
            self.violations
                .push(Violation::DuplicateDelivery { side, frame: id });
            return;
        }
        self.received.entry(side).or_default().push(frame);
    }

    /// Asking the endpoints puts the acknowledgement delay, the loss timer and
    /// the probe interval under test at the instants they actually name.
    fn next_event(&self) -> Option<Instant> {
        let landing = self.flight.iter().map(|packet| packet.at).min();
        [
            landing,
            self.client.poll_deadline(),
            self.server.poll_deadline(),
            self.paced(Side::Client),
            self.paced(Side::Server),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The one timer [`Endpoint::poll_deadline`] cannot report: the answer
    /// depends on the next frame's size, which only the queue above knows.
    fn paced(&self, side: Side) -> Option<Instant> {
        let queued = self.outbox.get(&side).and_then(VecDeque::front)?;
        self.endpoint(side).ready(self.now, queued.body.len())
    }

    fn quiet(&self) -> bool {
        self.flight.is_empty()
            && self.pending(Side::Client) == 0
            && self.pending(Side::Server) == 0
            && !self.client.probing()
            && !self.server.probing()
            // A path-MTU suspicion owes a probe, and the answer moves the
            // datagram size, so stopping here reports an undecided question.
            && !self.client.confirming_path_mtu()
            && !self.server.confirming_path_mtu()
    }

    pub fn advance(&mut self, by: Duration) {
        let until = self.now + by;
        self.run(until, false);
        self.now = self.now.max(until);
        self.flush();
    }

    /// "Quiet" deliberately includes *no challenge outstanding*: a probe retries
    /// on a quarter-second timer, so stopping when the wire went empty reports a
    /// failed migration on every link that lost a challenge.
    pub fn settle(&mut self) {
        let deadline = self.now + SETTLE_LIMIT;
        self.run(deadline, true);
    }

    fn run(&mut self, until: Instant, stop_when_quiet: bool) {
        loop {
            self.flush();
            if stop_when_quiet && self.quiet() {
                return;
            }
            if self.flight.iter().any(|packet| packet.at <= self.now) {
                self.step();
                continue;
            }
            // Strictly forward: a past deadline the flush did not act on is one
            // nothing will act on now, and standing still would hang the suite.
            let next = match self.next_event() {
                Some(next) if next > self.now => next,
                None if self.pending(Side::Client) + self.pending(Side::Server) == 0 => return,
                _ => self.now + IDLE_TICK,
            };
            if next > until {
                return;
            }
            self.now = next;
            if self.now >= until {
                return;
            }
        }
    }

    /// # Panics
    /// With the violation, which is the whole output of a harness run.
    pub fn assert_sound(&self) {
        assert!(
            self.violations.is_empty(),
            "transport violated its own contract: {:?}",
            self.violations
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{Narrows, Perfect};

    /// The oracle has to be right about a link before it is trusted about a
    /// transport.
    #[test]
    fn a_bottleneck_serialises_drops_a_full_queue_and_never_invents_one() {
        let link = Link {
            latency: Duration::ZERO,
            bandwidth: Some(Bandwidth::bytes_per_second(1_000)),
            queue: Some(2_000),
        };
        let mut bottleneck = Bottleneck::default();
        let now = Instant::now();
        assert_eq!(bottleneck.admit(now, 1_000, &link), Some(Duration::ZERO));
        assert_eq!(
            bottleneck.admit(now, 1_000, &link),
            Some(Duration::from_secs(1)),
            "a second's worth is already on the wire"
        );
        assert_eq!(
            bottleneck.admit(now, 1, &link),
            None,
            "and the queue is full"
        );
        assert_eq!(
            bottleneck.admit(now + Duration::from_secs(1), 1_000, &link),
            Some(Duration::from_secs(1)),
            "the first has drained, so there is room again"
        );

        let unlimited = Link::default();
        let mut bottleneck = Bottleneck::default();
        for _ in 0..1_000 {
            assert_eq!(
                bottleneck.admit(now, 9_000, &unlimited),
                Some(Duration::ZERO),
                "an unlimited link must not invent a queue"
            );
        }
    }

    #[test]
    fn the_bufferbloat_oracle_fires_only_on_a_sender_with_no_control_at_all() {
        let mut sim = Sim::new(Perfect);
        sim.link = Link::narrow();
        sim.flood(Side::Server, 226, 1_200);
        assert!(
            sim.violations
                .iter()
                .any(|violation| matches!(violation, Violation::Bufferbloat { .. })),
            "a quarter of a megabyte into a 1 Mbps link is two seconds of queue: {:?}",
            sim.violations
        );

        let mut sim = Sim::new(Perfect);
        sim.link = Link::narrow();
        // A tenth of the rate, which is a session not sending a screen.
        for _ in 0..20 {
            sim.flood(Side::Server, 1, 1_200);
            sim.advance(Duration::from_millis(100));
        }
        sim.assert_sound();
    }

    #[test]
    fn a_second_endpoint_repeats_a_keystream_over_a_spent_root_but_not_a_fresh_one() {
        let mut sim = Sim::new(Perfect);
        let spent = sim.root_of(Side::Server);
        // Until the address it was handed has answered, the accepting side
        // seals nothing at all.
        sim.send(Side::Client, b"a keystroke")
            .expect("a small frame");
        sim.settle();
        sim.send(Side::Server, b"a screen").expect("a small frame");
        sim.settle();
        sim.assert_sound();

        // Packet zero of a *fresh* root is a keystream nobody has spent.
        let fresh = sim.root([0xA7; 32]);
        assert_ne!(fresh, spent);
        sim.rebuild(Side::Server, fresh);
        sim.send(Side::Client, b"another").expect("a small frame");
        sim.settle();
        sim.assert_sound();

        sim.rebuild(Side::Server, spent);
        sim.send(Side::Client, b"a third").expect("a small frame");
        sim.settle();
        assert!(
            sim.violations
                .iter()
                .any(|violation| matches!(violation, Violation::NonceReuse { .. })),
            "an endpoint restarted at packet zero over a spent root unnoticed: {:?}",
            sim.violations
        );
    }

    #[test]
    fn two_identical_frames_are_delivered_twice_without_a_violation() {
        let mut sim = Sim::new(Perfect);
        let first = sim.send(Side::Client, b"\x1b[A").expect("a keystroke");
        let second = sim.send(Side::Client, b"\x1b[A").expect("a keystroke");
        assert_ne!(first, second);
        sim.settle();
        sim.assert_sound();
        assert_eq!(sim.delivered(Side::Server), vec![b"\x1b[A".to_vec(); 2]);
    }

    /// The link carries the packed body, not the frame verbatim.
    #[test]
    fn a_frame_reaches_the_link_packed_rather_than_verbatim() {
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(40);
        let mut sim = Sim::new(Narrows {
            limit: screen.len(),
            otherwise: Perfect,
        });
        sim.send(Side::Server, &screen)
            .expect("a frame the base path carries");
        sim.settle();
        sim.assert_sound();
        assert_eq!(sim.delivered(Side::Client), [screen]);
    }
}
