#![forbid(unsafe_code)]

//! Deterministic loss-injecting harness: I/O-free endpoints, a fault schedule
//! consulted per datagram, and oracles that run on every datagram of every run.
//!
//! ```
//! use braid_sim::fault::GilbertElliott;
//! use braid_sim::net::{Side, Sim};
//!
//! let mut sim = Sim::new(GilbertElliott::typical(1));
//! for n in 0..200u32 {
//!     sim.send(Side::Client, &n.to_be_bytes()).expect("four bytes fit");
//! }
//! sim.settle();
//! sim.assert_sound();
//! ```

pub mod fault;
pub mod net;
pub mod rng;

pub use fault::{Asymmetric, Bytes, Fault, GilbertElliott, Narrows, Perfect, Schedule, Script};
pub use net::{Bandwidth, FrameId, Link, Refusals, RootId, Side, Sim, Violation};
pub use rng::Rng;
