#![forbid(unsafe_code)]

//! The datagram half of `brd`'s transport: an unreliable, authenticated,
//! address-agile link. Reliability lives above this crate, so adding it here
//! would reintroduce the head-of-line blocking this transport exists to avoid:
//! [`loss`] drives the send rate and never puts a packet back on the wire.

pub mod aead;
pub mod congestion;
pub mod endpoint;
pub mod keys;
pub mod loss;
pub mod mtu;
pub mod packet;
pub mod path;
pub mod window;

pub use endpoint::{Accepted, Endpoint, Received, RecvError, Rejected, SendError, Stats};
pub use keys::{Direction, Epoch, RootSecret};
pub use mtu::Fragmentation;
pub use packet::{BASE_DATAGRAM, ConnectionId, MAX_DATAGRAM, MAX_PAYLOAD, MalformedPacket, peek};
pub use window::ReplayWindow;
