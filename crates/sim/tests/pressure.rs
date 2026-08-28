//! What the transport does to a link that pushes back: a bottleneck, a queue
//! in front of it, a size limit that appears mid-run, a clock that jumps.

use braid_sim::fault::{Fault, GilbertElliott, Narrows, Perfect, Schedule, Script};
use braid_sim::net::{Bandwidth, Link, Side, Sim};
use braid_sim::rng::Rng;
use std::ops::Range;
use std::time::Duration;

/// Filled from the seeded generator rather than one repeated byte, because the
/// harness packs what it sends: nine thousand dots leave as thirty on the wire.
fn frame(n: u32, size: usize) -> Vec<u8> {
    let mut bytes = n.to_be_bytes().to_vec();
    let mut rng = Rng::seeded(u64::from(n));
    while bytes.len() < size.max(4) {
        bytes.extend_from_slice(&rng.next_u64().to_be_bytes());
    }
    bytes.truncate(size.max(4));
    bytes
}

/// Hands frames of `size` down, then lets the link finish carrying them. Every
/// size here fits the base path, so a refusal is the harness misconfigured.
fn pour<S: Schedule>(sim: &mut Sim<S>, from: Side, frames: Range<u32>, size: usize) {
    for n in frames {
        assert!(
            sim.send(from, &frame(n, size)).is_some(),
            "frame {n} did not fit"
        );
    }
    sim.settle();
}

/// Runs the path-MTU search to the end on a schedule that carries jumbo
/// datagrams. Returns the base budget and the one the search found.
fn widen<S: Schedule>(sim: &mut Sim<S>) -> (usize, usize) {
    let base = sim.payload_limit(Side::Server);
    pour(sim, Side::Server, 0..60, 400);
    let wide = sim.payload_limit(Side::Server);
    assert!(wide > base, "the search never found the wide path");
    (base, wide)
}

struct Gate {
    open: bool,
}

impl Schedule for Gate {
    fn next(&mut self, _from: Side, _datagram: &[u8]) -> Fault {
        if self.open {
            Fault::Deliver
        } else {
            Fault::Drop
        }
    }
}

/// The headline regime: a slow path with a deep buffer and a quarter of a
/// megabyte to deliver. Uncontrolled that is two seconds of standing queue, and
/// nothing is lost either way, which is why loss was never going to catch it.
#[test]
fn a_bulk_sender_on_a_slow_deep_buffered_link_converges_instead_of_collapsing() {
    let mut sim = Sim::new(Perfect);
    sim.link = Link::narrow();
    pour(&mut sim, Side::Server, 0..300, 1_000);

    sim.assert_sound();
    assert_eq!(
        sim.delivered(Side::Client).len(),
        300,
        "the link loses nothing, so a controlled sender loses nothing"
    );
    assert_eq!(sim.pending(Side::Server), 0, "and it all left the queue");
    let stats = sim.stats(Side::Server);
    assert!(
        stats.cwnd < 100_000,
        "the window ran away with itself: {stats:?}"
    );
    assert!(stats.srtt.is_some(), "nothing measured the path: {stats:?}");
}

/// A keystroke has to cross a slow path at the path's latency, not a buffer's.
#[test]
fn a_keystroke_sized_session_never_builds_a_queue_at_all() {
    let mut sim = Sim::new(Perfect);
    sim.link = Link::narrow();
    for n in 0..100u32 {
        let _ = sim.send(Side::Client, &frame(n, 8));
        sim.advance(Duration::from_millis(30));
    }
    sim.settle();
    sim.assert_sound();
    assert_eq!(sim.delivered(Side::Server).len(), 100);
}

/// A jumbo path is worth seven times the datagrams, found without being told.
#[test]
fn a_wide_path_is_found_and_the_datagram_grows_to_fit_it() {
    let mut sim = Sim::new(Perfect);
    let base = sim.payload_limit(Side::Server);
    pour(&mut sim, Side::Server, 0..200, 400);
    sim.assert_sound();
    assert!(
        sim.payload_limit(Side::Server) > base,
        "the search never left the base size: {:?}",
        sim.stats(Side::Server)
    );
    assert_eq!(sim.delivered(Side::Client).len(), 200);
}

/// A tunnel appears: small datagrams still cross, so every timer says the
/// connection is healthy while every screen disappears.
#[test]
fn a_path_that_stops_carrying_full_size_datagrams_falls_back_and_recovers() {
    let mut sim = Sim::new(Narrows {
        limit: 9_000,
        otherwise: Perfect,
    });
    let (base, _) = widen(&mut sim);

    sim.schedule().limit = 1_300;
    for n in 100..200u32 {
        // Keystroke-sized frames prove the path is alive while screen-sized
        // ones vanish, which is the pair of facts the black-hole rule needs.
        let size = if n % 2 == 0 {
            sim.payload_limit(Side::Server)
        } else {
            16
        };
        let _ = sim.send(Side::Server, &frame(n, size));
    }
    sim.settle();
    assert_eq!(
        sim.payload_limit(Side::Server),
        base,
        "it never fell back: {:?}",
        sim.stats(Side::Server)
    );

    let before = sim.delivered(Side::Client).len();
    for n in 200..260u32 {
        let size = sim.payload_limit(Side::Server);
        let _ = sim.send(Side::Server, &frame(n, size));
    }
    sim.settle();
    sim.assert_sound();
    assert!(
        sim.delivered(Side::Client).len() > before + 50,
        "only {} more arrived after the fallback",
        sim.delivered(Side::Client).len() - before
    );
}

/// A session reads the budget once, cuts a quarter of a megabyte to it, and the
/// search then moves the budget underneath. The refusal must cost those frames
/// and nothing else: read as a dead transport it retires the connection, which
/// costs a `Ctrl-C` the client's ten-second silence deadline.
#[test]
fn frames_cut_for_a_path_that_then_narrows_are_lost_without_costing_the_connection() {
    let mut sim = Sim::new(Narrows {
        limit: 9_000,
        otherwise: Perfect,
    });
    sim.link = Link::narrow();
    // There is no stale budget until there is a budget that moved.
    let (base, wide) = widen(&mut sim);

    // More cut to that budget than this link carries before the tunnel appears.
    // Small frames among them because a session's are: a `Ping` between two
    // screens still fits a path that has stopped carrying the screens.
    for n in 100..3_000u32 {
        let size = if n % 4 == 0 { 16 } else { wide };
        let _ = sim.send(Side::Server, &frame(n, size));
    }
    assert!(
        sim.pending(Side::Server) > 0,
        "the burst drained, so nothing was cut for a path that then moved"
    );
    sim.schedule().limit = 1_300;
    sim.settle();

    assert_eq!(
        sim.payload_limit(Side::Server),
        base,
        "the path never fell back, so nothing was ever too large for it"
    );
    assert!(
        sim.unsendable > 0,
        "no frame outlived the budget it was cut to: {:?}",
        sim.stats(Side::Server)
    );
    sim.assert_sound();

    // The client's half is what retiring the connection takes away.
    let arrived = sim.delivered(Side::Server).len();
    pour(&mut sim, Side::Client, 500..520, 8);
    sim.assert_sound();
    assert_eq!(
        sim.delivered(Side::Server).len(),
        arrived + 20,
        "the link stopped carrying the client's half after the path narrowed"
    );
}

/// A key schedule admitting only the next epoch leaves a receiver further
/// behind than that permanently deaf. Two rotations in one outage does it.
#[test]
fn a_peer_that_rotated_twice_during_an_outage_is_still_heard() {
    let mut sim = Sim::new(Gate { open: true });
    let _ = sim.send(Side::Client, &frame(0, 32));
    sim.settle();
    assert_eq!(sim.delivered(Side::Server).len(), 1);

    sim.schedule().open = false;
    for step in 1..=2u32 {
        sim.rotate(Side::Client);
        let _ = sim.send(Side::Client, &frame(step, 32));
        sim.settle();
    }
    assert_eq!(
        sim.delivered(Side::Server).len(),
        1,
        "the outage swallowed both"
    );

    sim.schedule().open = true;
    let _ = sim.send(Side::Client, &frame(3, 32));
    sim.settle();
    sim.assert_sound();
    assert_eq!(
        sim.delivered(Side::Server).last().map(Vec::as_slice),
        Some(frame(3, 32).as_slice()),
        "two epochs of catch-up were not followed"
    );
}

/// At the shipped threshold of 2^40 packets this branch is otherwise dead, and
/// it is the one that would repeat a keystream.
#[test]
fn a_session_that_rekeys_as_it_goes_never_repeats_a_nonce() {
    let mut sim = Sim::new(GilbertElliott::typical(31));
    sim.rekey_every(Side::Client, 8);
    sim.rekey_every(Side::Server, 5);
    for n in 0..400u32 {
        let _ = sim.send(Side::Client, &frame(n, 64));
        let _ = sim.send(Side::Server, &frame(100_000 + n, 64));
    }
    sim.settle();
    sim.assert_sound();
    assert!(
        sim.delivered(Side::Server).len() > 100,
        "the session stopped carrying anything across its rotations"
    );
}

/// Every timer comes back overdue at once: none may panic, none may wedge.
#[test]
fn a_session_survives_the_clock_jumping_an_hour() {
    let mut sim = Sim::new(Perfect);
    pour(&mut sim, Side::Client, 0..20, 128);
    let before = sim.delivered(Side::Server).len();

    let _ = sim.send(Side::Client, &frame(999, 128));
    sim.suspend(Duration::from_hours(1));
    sim.settle();

    pour(&mut sim, Side::Client, 1_000..1_020, 128);
    sim.assert_sound();
    assert!(
        sim.delivered(Side::Server).len() >= before + 20,
        "the session did not come back: {} then {}",
        before,
        sim.delivered(Side::Server).len()
    );
}

/// The commonest real network event, and the one `roam` does not model: the
/// address holds and a NAT re-maps the flow to a new external port.
#[test]
fn a_nat_that_remaps_the_port_is_challenged_and_then_followed() {
    let mut sim = Sim::new(Perfect);
    pour(&mut sim, Side::Client, 0..10, 64);
    let home = sim.address(Side::Client);
    assert_eq!(sim.peer_of(Side::Server), home);

    sim.rebind(home.port() + 7);
    let _ = sim.send(Side::Client, &frame(10, 64));
    sim.settle();

    sim.assert_sound();
    assert_eq!(sim.peer_of(Side::Server), sim.address(Side::Client));
    assert_eq!(sim.peer_of(Side::Server).ip(), home.ip(), "same address");
    assert_ne!(sim.peer_of(Side::Server).port(), home.port());
    assert_eq!(sim.delivered(Side::Server).len(), 11);
}

/// The sender is not told, so it must not give up permanently — nor keep its
/// window, which was measured on a path that has since carried nothing.
#[test]
fn an_address_that_goes_deaf_for_a_while_is_found_again() {
    // Twelve cross, then one stops the far side for four seconds and the rest
    // are carried normally: the recovery is under test, not the outage.
    let mut script = vec![Fault::Deliver; 12];
    script.push(Fault::Blackhole {
        until: Duration::from_secs(4),
    });
    script.push(Fault::Deliver);
    let mut sim = Sim::new(Script::new(script));

    let size = sim.payload_limit(Side::Client);
    let mut floor = usize::MAX;
    let mut peak = 0;
    let mut arrived_before = 0;
    for n in 0..50u32 {
        let _ = sim.send(Side::Client, &frame(n, size));
        sim.advance(Duration::from_millis(200));
        floor = floor.min(sim.stats(Side::Client).cwnd);
        peak = peak.max(sim.stats(Side::Client).cwnd);
        // Twenty rounds is four seconds, which is where the outage ends.
        if n == 20 {
            arrived_before = sim.delivered(Side::Server).len();
        }
    }
    sim.settle();

    sim.assert_sound();
    assert!(floor < peak, "the window never moved at all: {floor} bytes");
    assert!(
        floor <= 2 * sim.stats(Side::Client).plpmtu,
        "a path carrying nothing kept its window: {floor} bytes, peak {peak}"
    );
    assert!(
        sim.delivered(Side::Server).len() > arrived_before + 20,
        "the session never came back: {} arrived, {} before the outage",
        sim.delivered(Side::Server).len(),
        arrived_before
    );
}

/// RFC 9002 section 5.5: a 5 ms minimum carried onto a 100 ms link makes every
/// sample there read as a queue building, ending slow start on the path that
/// needs it most, while the outage has already driven the window to its floor.
#[test]
fn a_session_that_roams_from_a_fast_path_to_a_slow_one_recovers_its_rate() {
    let mut sim = Sim::new(Perfect);
    sim.link.latency = Duration::from_millis(5);
    pour(&mut sim, Side::Server, 0..200, 1_000);
    let fast = sim.stats(Side::Server);
    assert!(
        fast.srtt
            .is_some_and(|srtt| srtt < Duration::from_millis(20)),
        "the fast path was never measured: {fast:?}"
    );

    // A lid closes on that network and opens on another.
    for n in 200..260u32 {
        let _ = sim.send(Side::Server, &frame(n, 1_000));
    }
    sim.suspend(Duration::from_secs(3));
    sim.link.latency = Duration::from_millis(100);
    let moved = sim.elsewhere(4);
    sim.roam(moved);
    assert!(sim.send(Side::Client, b"still here").is_some());
    sim.settle();
    assert_eq!(sim.peer_of(Side::Server), moved);

    let _ = sim.take_delivered(Side::Client);
    let started = sim.now();
    pour(&mut sim, Side::Server, 1_000..1_400, 1_000);
    let took = sim.now().saturating_duration_since(started);

    sim.assert_sound();
    assert_eq!(sim.delivered(Side::Client).len(), 400);
    let slow = sim.stats(Side::Server);
    assert!(
        took < Duration::from_millis(2_500),
        "four hundred datagrams took {took:?} on a 200 ms path: {slow:?}"
    );
    assert!(
        slow.srtt
            .is_some_and(|srtt| srtt > Duration::from_millis(150)),
        "the estimator still describes the path that was left: {slow:?}"
    );
    assert_eq!(
        slow.spurious, 0,
        "a loss timer built on the old path declares the new one lost: {slow:?}"
    );
    assert!(
        slow.cwnd > 4 * slow.plpmtu,
        "the window never left the floor the outage put it on: {slow:?}"
    );
}

/// RFC 8899: congestion loss must never be read as a black hole. Nothing here
/// is dropped by a schedule — a full queue turns away the large datagrams
/// first, which is exactly the shape a size-blind rule looks for.
#[test]
fn a_bulk_sender_losing_full_size_packets_to_a_full_queue_keeps_its_path() {
    let mut sim = Sim::new(Perfect);
    // No budget to defend until the search has found one.
    pour(&mut sim, Side::Server, 0..200, 400);
    let wide = sim.payload_limit(Side::Server);
    assert!(
        wide > 4_000,
        "the search never found a wide path: {:?}",
        sim.stats(Side::Server)
    );

    // 32 KB of queue is under four full-size datagrams of headroom once full.
    sim.link = Link {
        latency: Duration::from_millis(10),
        bandwidth: Some(Bandwidth::bits_per_second(10_000_000)),
        queue: Some(32 * 1024),
    };
    for n in 1_000..3_000u32 {
        let size = if n % 4 == 0 { 16 } else { wide };
        let _ = sim.send(Side::Server, &frame(n, size));
    }
    sim.settle();

    assert!(
        sim.stats(Side::Server).lost > 0,
        "the queue never dropped anything, so this proves nothing: {:?}",
        sim.stats(Side::Server)
    );
    assert_eq!(
        sim.payload_limit(Side::Server),
        wide,
        "a full queue was read as a path that stopped carrying: {:?}",
        sim.stats(Side::Server)
    );
    assert_eq!(
        sim.unsendable, 0,
        "frames were thrown away under a budget that should never have moved"
    );

    // An `Exit` lost this way leaves the client waiting out its silence
    // deadline for a shell that already exited.
    let farewell = frame(9_999, 16);
    assert!(sim.send(Side::Server, &farewell).is_some());
    sim.settle();
    sim.assert_sound();
    assert!(
        sim.delivered(Side::Client).contains(&farewell),
        "the farewell never arrived"
    );
}
