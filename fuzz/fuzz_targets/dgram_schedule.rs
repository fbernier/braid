#![no_main]

//! Coverage-guided search over the network: every byte libFuzzer produces is
//! one decision about one datagram, judged by the simulator's own oracles.

use braid_sim::fault::Bytes;
use braid_sim::net::{Side, Sim};
use libfuzzer_sys::fuzz_target;

/// Enough frames to cross the replay window's 256 numbers, few enough that a
/// fuzzer gets through many schedules a second.
const FRAMES: u32 = 400;

fuzz_target!(|data: &[u8]| {
    let mut sim = Sim::new(Bytes::new(data));
    for n in 0..FRAMES {
        // Both directions, so the server's key epoch is reached too.
        sim.send(Side::Client, &n.to_be_bytes());
        sim.send(Side::Server, &(!n).to_be_bytes());
        // What makes path validation and key rotation reachable from bytes.
        if n % 97 == 96 {
            let elsewhere = sim.elsewhere((n % 7 + 1) as u8);
            sim.roam(elsewhere);
        }
    }
    sim.settle();
    sim.assert_sound();
});
