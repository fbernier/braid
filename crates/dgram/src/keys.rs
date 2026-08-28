#![forbid(unsafe_code)]

//! Where the keys come from, and what stops a nonce from ever repeating.
//! BLAKE3 derivation below a root secret that arrives inside the ssh channel:
//! one ChaCha20-Poly1305 key per epoch each way. The invariant is that
//! `(epoch, number)` never repeats within a direction — numbers ascend for the
//! connection's life and a rotation does not restart them.

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};

/// Spent exactly once. Move-only: two [`KeySchedule`]s over one root are the
/// same keystream twice.
pub struct RootSecret([u8; 32]);

impl RootSecret {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Prints no bytes; a derived `Debug` would leak the whole connection key.
impl std::fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootSecret(..)")
    }
}

impl Drop for RootSecret {
    fn drop(&mut self) {
        // `write_volatile` is unavailable here, so `black_box` is all there is.
        self.0.fill(0);
        let _ = core::hint::black_box(&self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    /// Spelled out, not built, so two versions cannot disagree on a `format!`.
    const fn context(self) -> &'static str {
        match self {
            Self::ClientToServer => "braid dgram v2 client-to-server",
            Self::ServerToClient => "braid dgram v2 server-to-client",
        }
    }

    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Epoch(u8);

impl Epoch {
    #[must_use]
    pub const fn first() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn from_wire(byte: u8) -> Self {
        Self(byte)
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// `None` at the last: a wrap puts a spent keystream back in service.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// So traffic that must be answered cannot exhaust the nonce space. 256
/// epochs of `2^40` is exactly the `2^48` the wire carries.
pub const REKEY_AFTER: u64 = 1 << 40;

/// One key each way, not two: ChaCha20-Poly1305 seals and authenticates under
/// the same secret, so the second key generic composition needed is gone.
#[derive(Clone)]
pub struct DirectionKey(ChaCha20Poly1305);

impl DirectionKey {
    fn derive(secret: &[u8; 32], direction: Direction) -> Self {
        let key = Key::from(blake3::derive_key(direction.context(), secret));
        Self(ChaCha20Poly1305::new(&key))
    }

    pub(crate) const fn cipher(&self) -> &ChaCha20Poly1305 {
        &self.0
    }
}

/// One-way: a key recovered from a live process opens nothing older.
struct Ratchet {
    epoch: Epoch,
    secret: [u8; 32],
}

impl Ratchet {
    const CONTEXT: &'static str = "braid dgram v2 epoch ratchet";

    fn new(root: &[u8; 32]) -> Self {
        Self {
            epoch: Epoch::first(),
            secret: *root,
        }
    }

    fn advance(&mut self) -> Option<Epoch> {
        let next = self.epoch.next()?;
        self.secret = blake3::derive_key(Self::CONTEXT, &self.secret);
        self.epoch = next;
        Some(next)
    }
}

/// Bounded, or epoch 255 asks a receiver at epoch 0 for 255 derivations.
pub const MAX_EPOCH_CATCHUP: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The epoch we are already reading.
    Current,
    /// The one we retired, kept for datagrams reordered across a rotation.
    Previous,
    /// Never zero, never above [`MAX_EPOCH_CATCHUP`].
    Ahead(u8),
    /// Not within catch-up range: not a peer that rotated, so not a peer.
    Unreachable,
}

/// The directions rotate independently: each side counts only its own packets.
pub struct KeySchedule {
    send: Ratchet,
    send_key: DirectionKey,
    sending: Direction,
    recv: Ratchet,
    recv_key: DirectionKey,
    /// Stored, not derived: a catch-up of two leaves a gap with no keys.
    recv_previous: Option<(Epoch, DirectionKey)>,
    /// The epoch byte is read before the tag, so without this cache a forged
    /// flood buys eight BLAKE3 derivations each.
    ahead: [Option<DirectionKey>; MAX_EPOCH_CATCHUP as usize],
}

impl KeySchedule {
    /// `sending` is this endpoint's own direction; the other is what it reads.
    #[must_use]
    pub fn new(root: &RootSecret, sending: Direction) -> Self {
        let send = Ratchet::new(&root.0);
        let recv = Ratchet::new(&root.0);
        Self {
            send_key: DirectionKey::derive(&send.secret, sending),
            recv_key: DirectionKey::derive(&recv.secret, sending.opposite()),
            sending,
            send,
            recv,
            recv_previous: None,
            ahead: std::array::from_fn(|_| None),
        }
    }

    #[must_use]
    pub const fn send_epoch(&self) -> Epoch {
        self.send.epoch
    }

    #[must_use]
    pub const fn recv_epoch(&self) -> Epoch {
        self.recv.epoch
    }

    #[must_use]
    pub const fn sending(&self) -> &DirectionKey {
        &self.send_key
    }

    pub fn rotate(&mut self) -> Option<Epoch> {
        let epoch = self.send.advance()?;
        self.send_key = DirectionKey::derive(&self.send.secret, self.sending);
        Some(epoch)
    }

    #[must_use]
    pub fn reach(&self, epoch: Epoch) -> Reach {
        if epoch == self.recv.epoch {
            return Reach::Current;
        }
        if let Some((retired, _)) = &self.recv_previous
            && *retired == epoch
        {
            return Reach::Previous;
        }
        match epoch.get().checked_sub(self.recv.epoch.get()) {
            Some(ahead) if ahead <= MAX_EPOCH_CATCHUP => Reach::Ahead(ahead),
            _ => Reach::Unreachable,
        }
    }

    /// `Reach::Ahead` is not one: [`follow`](Self::follow) waits for the tag.
    #[must_use]
    pub fn reading(&self, reach: Reach) -> Option<&DirectionKey> {
        match reach {
            Reach::Current => Some(&self.recv_key),
            Reach::Previous => self.recv_previous.as_ref().map(|(_, keys)| keys),
            Reach::Ahead(_) | Reach::Unreachable => None,
        }
    }

    /// Derived without committing: one forged byte must retire nothing.
    pub fn peek_ahead(&mut self, ahead: u8) -> Option<&DirectionKey> {
        if ahead == 0 || ahead > MAX_EPOCH_CATCHUP {
            return None;
        }
        let slot = usize::from(ahead) - 1;
        if self.ahead[slot].is_none() {
            self.derive_ahead();
        }
        self.ahead[slot].as_ref()
    }

    /// Reaching the furthest epoch walks past every nearer one anyway.
    fn derive_ahead(&mut self) {
        let direction = self.sending.opposite();
        let mut epoch = self.recv.epoch;
        let mut secret = self.recv.secret;
        for slot in &mut self.ahead {
            let Some(next) = epoch.next() else { return };
            epoch = next;
            secret = blake3::derive_key(Ratchet::CONTEXT, &secret);
            *slot = Some(DirectionKey::derive(&secret, direction));
        }
    }

    /// Adopt the peer's rotation, having opened a datagram sealed under it.
    pub fn follow(&mut self, ahead: u8) -> Option<Epoch> {
        if ahead == 0 || ahead > MAX_EPOCH_CATCHUP {
            return None;
        }
        let retired = self.recv.epoch;
        let mut epoch = None;
        for _ in 0..ahead {
            epoch = Some(self.recv.advance()?);
        }
        let key = std::mem::replace(
            &mut self.recv_key,
            DirectionKey::derive(&self.recv.secret, self.sending.opposite()),
        );
        self.recv_previous = Some((retired, key));
        // The ratchet these came from has moved, so they are stale.
        self.ahead = std::array::from_fn(|_| None);
        epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [7u8; 32];

    fn schedule(sending: Direction) -> KeySchedule {
        KeySchedule::new(&RootSecret::new(ROOT), sending)
    }

    /// A key is not readable once it is a cipher, so what it seals under a
    /// fixed header and nonce stands in for its identity.
    fn fingerprint(key: &DirectionKey) -> [u8; crate::packet::TAG_BYTES] {
        crate::aead::seal(key, &[0u8; crate::packet::HEADER_BYTES], 0, &mut [])
    }

    #[test]
    fn the_two_directions_never_share_a_key() {
        let client = schedule(Direction::ClientToServer);
        let server = schedule(Direction::ServerToClient);
        assert_eq!(fingerprint(client.sending()), fingerprint(&server.recv_key));
        assert_eq!(fingerprint(&client.recv_key), fingerprint(server.sending()));
        assert_ne!(fingerprint(client.sending()), fingerprint(server.sending()));
    }

    #[test]
    fn a_rotation_replaces_the_keys_it_came_from() {
        let mut schedule = schedule(Direction::ClientToServer);
        let before = fingerprint(schedule.sending());
        assert_eq!(schedule.rotate(), Some(Epoch::from_wire(1)));
        assert_ne!(fingerprint(schedule.sending()), before);
        assert_eq!(schedule.send_epoch(), Epoch::from_wire(1));
    }

    /// What stays behind as previous is the epoch this side was on, not the
    /// one it skipped.
    #[test]
    fn a_reader_behind_catches_up_in_one_step() {
        for steps in 1..=MAX_EPOCH_CATCHUP {
            let mut sender = schedule(Direction::ClientToServer);
            let mut reader = schedule(Direction::ServerToClient);
            let left_behind = fingerprint(reader.reading(Reach::Current).unwrap());
            for _ in 0..steps {
                sender.rotate().unwrap();
            }
            assert_eq!(reader.reach(sender.send_epoch()), Reach::Ahead(steps));
            assert_eq!(
                fingerprint(reader.peek_ahead(steps).unwrap()),
                fingerprint(sender.sending())
            );
            reader.follow(steps).unwrap();
            assert_eq!(reader.recv_epoch(), Epoch::from_wire(steps));
            assert_eq!(
                fingerprint(reader.reading(Reach::Current).unwrap()),
                fingerprint(sender.sending())
            );
            assert_eq!(reader.reach(Epoch::first()), Reach::Previous);
            assert_eq!(
                fingerprint(reader.reading(Reach::Previous).unwrap()),
                left_behind,
                "the epoch this side was reading, not the one it skipped"
            );
            for skipped in 1..steps {
                assert_eq!(
                    reader.reach(Epoch::from_wire(skipped)),
                    Reach::Unreachable,
                    "epoch {skipped} was stepped over"
                );
            }
        }
    }

    /// One epoch of grace, not two.
    #[test]
    fn the_epoch_before_last_is_no_longer_readable() {
        let mut reader = schedule(Direction::ServerToClient);
        let first = fingerprint(reader.reading(Reach::Current).unwrap());
        reader.follow(1).unwrap();
        assert_eq!(fingerprint(reader.reading(Reach::Previous).unwrap()), first);
        reader.follow(1).unwrap();
        assert_ne!(fingerprint(reader.reading(Reach::Previous).unwrap()), first);
        assert_eq!(reader.reach(Epoch::first()), Reach::Unreachable);
    }

    /// What keeps a forged epoch byte from asking for two hundred derivations.
    #[test]
    fn an_epoch_further_ahead_than_the_catch_up_bound_is_not_a_peer() {
        let mut reader = schedule(Direction::ServerToClient);
        assert_eq!(
            reader.reach(Epoch::from_wire(MAX_EPOCH_CATCHUP)),
            Reach::Ahead(MAX_EPOCH_CATCHUP)
        );
        assert_eq!(
            reader.reach(Epoch::from_wire(MAX_EPOCH_CATCHUP + 1)),
            Reach::Unreachable
        );
        assert_eq!(reader.reach(Epoch::from_wire(200)), Reach::Unreachable);
        assert!(reader.peek_ahead(0).is_none());
        assert!(reader.peek_ahead(MAX_EPOCH_CATCHUP + 1).is_none());
    }

    /// A flood naming an epoch ahead must not charge a ratchet walk each.
    #[test]
    fn the_look_ahead_keys_are_derived_once_and_kept() {
        let mut reader = schedule(Direction::ServerToClient);
        assert!(
            reader.ahead.iter().all(Option::is_none),
            "nothing is derived until an epoch is claimed"
        );
        let claimed = fingerprint(reader.peek_ahead(1).expect("in reach"));
        assert!(
            reader.ahead.iter().all(Option::is_some),
            "one look-ahead derives the whole window, so a flood repeats none of it"
        );
        assert_eq!(
            fingerprint(reader.ahead[0].as_ref().expect("derived")),
            claimed
        );
        let held = std::ptr::from_ref(reader.peek_ahead(MAX_EPOCH_CATCHUP).expect("in reach"));
        assert_eq!(
            std::ptr::from_ref(reader.peek_ahead(MAX_EPOCH_CATCHUP).expect("in reach")),
            held,
            "and the answer is the one already held"
        );

        let ahead = fingerprint(reader.peek_ahead(2).expect("in reach"));
        reader.follow(1).unwrap();
        assert!(reader.ahead.iter().all(Option::is_none));
        assert_eq!(
            fingerprint(reader.peek_ahead(1).expect("in reach")),
            ahead,
            "one epoch ahead of the new one is two ahead of the old"
        );
    }

    #[test]
    fn the_last_epoch_cannot_rotate() {
        let mut schedule = schedule(Direction::ClientToServer);
        for _ in 0..255 {
            schedule.rotate().unwrap();
        }
        assert_eq!(schedule.send_epoch().get(), 255);
        assert_eq!(schedule.rotate(), None);
    }
}
