#![no_main]

//! `recv` is the one function an unauthenticated attacker reaches, before any
//! tag check. It slices a caller-owned buffer by lengths taken from the
//! datagram itself, so the failure this looks for is an index, not a forgery.

use braid_dgram::endpoint::Endpoint;
use braid_dgram::packet::ConnectionId;
use braid_dgram::{Fragmentation, RootSecret};
use libfuzzer_sys::fuzz_target;
use std::net::SocketAddr;
use std::time::Instant;

fn addr(last: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, last], 40_000 + u16::from(last)))
}

fuzz_target!(|data: &[u8]| {
    let cid = ConnectionId::from_bytes(*b"fuzzconn");
    let root = [0x11; 32];
    let mut client = Endpoint::connect(cid, RootSecret::new(root), addr(1), Fragmentation::Refused);
    let mut server = Endpoint::listen(cid, RootSecret::new(root), addr(2), Fragmentation::Refused);

    // A genuine datagram first, so the mutated input reaches an endpoint with
    // real state. One clock for the whole run, or the round-trip samples
    // depend on how long the fuzzer took.
    let now = Instant::now();
    let mut genuine = Vec::new();
    if client.send(b"hello", now, &mut genuine).is_ok() {
        let _ = server.recv(addr(2), now, &mut genuine);
    }

    let mut buffer = data.to_vec();
    let _ = server.recv(addr(3), now, &mut buffer);
    let mut again = data.to_vec();
    let _ = client.recv(addr(1), now, &mut again);
});
