#![forbid(unsafe_code)]

//! The header every datagram carries in the clear. Nothing here is encrypted —
//! it routes a datagram and names the key that opens it — but every byte is fed
//! to the tag, so rewriting it makes authentication fail.

use crate::keys::Epoch;
use std::time::Duration;

/// The IPv6 minimum of 1280, less room for tunnels that take a few dozen bytes.
pub const BASE_DATAGRAM: usize = 1200;

/// The largest the search may reach, so also every read buffer's size.
pub const MAX_DATAGRAM: usize = 9000;

/// `kind`, connection id, key epoch, packet number.
pub const HEADER_BYTES: usize = 1 + 8 + 1 + 6;

/// Bytes of authentication tag on every datagram.
pub const TAG_BYTES: usize = 16;

/// A buffer bound, not a send bound: see [`crate::Endpoint::payload_limit`].
pub const MAX_PAYLOAD: usize = MAX_DATAGRAM - HEADER_BYTES - TAG_BYTES;

/// Packet numbers are six bytes on the wire, and a connection that spends all
/// 256 epochs at the `2^40` rekey threshold lands exactly here and stops.
pub const MAX_PACKET_NUMBER: u64 = (1 << 48) - 1;
const _: () = assert!(MAX_PACKET_NUMBER == crate::keys::REKEY_AFTER * 256 - 1);

/// Routes by name, not source address, so a moved client is not a stranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId([u8; 8]);

impl ConnectionId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> [u8; 8] {
        self.0
    }

    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// In the header, not a first plaintext byte: probes have no payload at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// One `braid` protocol frame.
    Frame = 0,
    /// Eight bytes a peer must echo before this side will send to its address.
    Challenge = 1,
    /// The echo of a challenge.
    Response = 2,
    /// Nothing at all: keeps a NAT mapping alive and invites a challenge.
    Alive = 3,
    /// This side is done; the session above decides what a close means.
    Close = 4,
    /// What has arrived, so the sender can measure the path.
    Ack = 5,
    /// Padding to a candidate size; losing one costs nothing but the search.
    Probe = 6,
}

impl Kind {
    #[must_use]
    pub const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Frame),
            1 => Some(Self::Challenge),
            2 => Some(Self::Response),
            3 => Some(Self::Alive),
            4 => Some(Self::Close),
            5 => Some(Self::Ack),
            6 => Some(Self::Probe),
            _ => None,
        }
    }

    /// An ack is not, or two ends would never stop; a keep-alive is not, or an
    /// idle connection would carry double the traffic.
    #[must_use]
    pub const fn ack_eliciting(self) -> bool {
        match self {
            Self::Frame | Self::Challenge | Self::Response | Self::Probe => true,
            Self::Alive | Self::Close | Self::Ack => false,
        }
    }
}

/// Bytes an [`Ack`] body occupies: a 48-bit number, a delay, and a bitmap.
pub const ACK_BODY_BYTES: usize = 6 + 4 + 8;

/// One range rather than QUIC's list, since nothing retransmits and only the
/// controller and the estimator read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub largest: u64,
    /// The sender subtracts this before believing a round-trip sample.
    pub delay: Duration,
    /// Bit *i* set means `largest - 1 - i` arrived too.
    pub map: u64,
}

impl Ack {
    pub fn encode(&self, out: &mut [u8; ACK_BODY_BYTES]) {
        assert!(self.largest <= MAX_PACKET_NUMBER, "packet number overflow");
        out[..6].copy_from_slice(&self.largest.to_be_bytes()[2..]);
        let micros = u32::try_from(self.delay.as_micros()).unwrap_or(u32::MAX);
        out[6..10].copy_from_slice(&micros.to_be_bytes());
        out[10..].copy_from_slice(&self.map.to_be_bytes());
    }

    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        let body: &[u8; ACK_BODY_BYTES] = body.try_into().ok()?;
        let mut largest = [0u8; 8];
        largest[2..].copy_from_slice(&body[..6]);
        let mut micros = [0u8; 4];
        micros.copy_from_slice(&body[6..10]);
        let mut map = [0u8; 8];
        map.copy_from_slice(&body[10..]);
        Some(Self {
            largest: u64::from_be_bytes(largest),
            delay: Duration::from_micros(u64::from(u32::from_be_bytes(micros))),
            map: u64::from_be_bytes(map),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub cid: ConnectionId,
    pub epoch: Epoch,
    /// Unique per epoch per direction. Reusing one reuses a keystream.
    pub number: u64,
}

impl Header {
    /// # Panics
    /// If `number` exceeds [`MAX_PACKET_NUMBER`]; the sender rekeys long before
    /// that, so reaching it means the nonce discipline is already lost.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        assert!(self.number <= MAX_PACKET_NUMBER, "packet number overflow");
        let mut out = [0u8; HEADER_BYTES];
        out[0] = self.kind as u8;
        out[1..9].copy_from_slice(&self.cid.as_bytes());
        out[9] = self.epoch.get();
        out[10..].copy_from_slice(&self.number.to_be_bytes()[2..]);
        out
    }

    pub fn decode(datagram: &[u8]) -> Result<Self, MalformedPacket> {
        if datagram.len() < HEADER_BYTES + TAG_BYTES {
            return Err(MalformedPacket::Short);
        }
        let kind = Kind::from_wire(datagram[0]).ok_or(MalformedPacket::UnknownKind(datagram[0]))?;
        let mut cid = [0u8; 8];
        cid.copy_from_slice(&datagram[1..9]);
        let mut number = [0u8; 8];
        number[2..].copy_from_slice(&datagram[10..16]);
        Ok(Self {
            kind,
            cid: ConnectionId(cid),
            epoch: Epoch::from_wire(datagram[9]),
            number: u64::from_be_bytes(number),
        })
    }
}

/// Counted separately from a datagram that failed authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MalformedPacket {
    #[error("datagram is smaller than a header and a tag")]
    Short,
    #[error("unknown packet kind {0}")]
    UnknownKind(u8),
}

/// Unauthenticated: it selects which key to try; the tag decides the claim.
pub fn peek(datagram: &[u8]) -> Result<ConnectionId, MalformedPacket> {
    Header::decode(datagram).map(|header| header.cid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            kind: Kind::Frame,
            cid: ConnectionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
            epoch: Epoch::first(),
            number: 0x0000_1234_5678_9abc,
        }
    }

    /// The number's two high bytes must decode as zero, not as what followed.
    #[test]
    fn a_header_survives_the_wire() {
        for number in [0, 0x0000_1234_5678_9abc, MAX_PACKET_NUMBER] {
            let original = Header { number, ..header() };
            let mut out = original.encode().to_vec();
            out.resize(HEADER_BYTES + TAG_BYTES, 0);
            assert_eq!(Header::decode(&out).unwrap(), original, "{number}");
        }
    }

    #[test]
    fn a_malformed_datagram_is_refused_before_any_key_is_chosen() {
        assert_eq!(
            Header::decode(&header().encode()),
            Err(MalformedPacket::Short)
        );
        let mut out = vec![0u8; HEADER_BYTES + TAG_BYTES];
        out[0] = 9;
        assert_eq!(Header::decode(&out), Err(MalformedPacket::UnknownKind(9)));
    }

    #[test]
    fn an_acknowledgement_survives_the_wire() {
        let ack = Ack {
            largest: MAX_PACKET_NUMBER,
            delay: Duration::from_micros(24_500),
            map: 0xdead_beef_0000_0001,
        };
        let mut out = [0u8; ACK_BODY_BYTES];
        ack.encode(&mut out);
        assert_eq!(Ack::decode(&out), Some(ack));
        assert_eq!(Ack::decode(&[0u8; ACK_BODY_BYTES - 1]), None);
        assert_eq!(Ack::decode(&[0u8; ACK_BODY_BYTES + 1]), None);
    }

    /// Four bytes of microseconds, so an hour reports an hour, not zero.
    #[test]
    fn an_absurd_acknowledgement_delay_saturates_rather_than_wrapping() {
        let mut out = [0u8; ACK_BODY_BYTES];
        Ack {
            largest: 1,
            delay: Duration::from_mins(150),
            map: 0,
        }
        .encode(&mut out);
        assert_eq!(
            Ack::decode(&out).unwrap().delay,
            Duration::from_micros(u64::from(u32::MAX))
        );
    }

    /// The rule that keeps two ends from acknowledging each other for ever.
    #[test]
    fn an_acknowledgement_does_not_elicit_one() {
        assert!(!Kind::Ack.ack_eliciting());
        assert!(!Kind::Alive.ack_eliciting());
        assert!(Kind::Frame.ack_eliciting());
        assert!(Kind::Probe.ack_eliciting());
    }
}
