//! What the datagram transport promises, against a link that breaks it on
//! purpose. Nothing here asserts on a message the transport happens to send.

use braid_sim::fault::{Fault, GilbertElliott, Perfect, Schedule, Script};
use braid_sim::net::{Side, Sim};
use std::time::Duration;

/// Frames with a body, so a run carries something the link has to serialise.
fn frame(n: u32) -> Vec<u8> {
    let mut bytes = n.to_be_bytes().to_vec();
    bytes.extend_from_slice(b" the quick brown fox jumps over the lazy dog");
    bytes
}

fn pour<S: Schedule>(sim: &mut Sim<S>, side: Side, count: u32) {
    for n in 0..count {
        assert!(sim.send(side, &frame(n)).is_some());
    }
    sim.settle();
}

#[test]
fn a_link_that_breaks_nothing_delivers_everything_once() {
    let mut sim = Sim::new(Perfect);
    pour(&mut sim, Side::Client, 500);
    sim.assert_sound();
    let delivered = sim.delivered(Side::Server);
    assert_eq!(delivered.len(), 500);
    assert_eq!(delivered[0], frame(0));
    assert_eq!(delivered[499], frame(499));
}

/// The headline property: what arrives is a subset of what was sent, in which
/// nothing appears twice — and the transport keeps going.
#[test]
fn a_burst_lossy_link_loses_frames_and_breaks_nothing_else() {
    for seed in 0..32u64 {
        let mut sim = Sim::new(GilbertElliott::hostile(seed));
        pour(&mut sim, Side::Client, 400);
        sim.assert_sound();
        let delivered = sim.delivered(Side::Server).len();
        assert!(
            delivered < 400,
            "seed {seed} lost nothing, so it tested nothing"
        );
        assert!(delivered > 40, "seed {seed} delivered only {delivered}");
    }
}

/// One fault on every datagram: what was sent still arrives exactly once, and
/// the copies the fault made are refused by the replay window and nothing else.
#[test]
fn a_uniformly_faulty_link_still_delivers_every_frame_once() {
    // A window has a width, and 150 datagrams of uniform reordering is inside it.
    for (fault, count, replays) in [
        (Fault::Duplicate, 200_u32, 200_u64),
        // At least: the recording covers the keep-alives emitted while the run
        // waited out the two seconds.
        (Fault::Replay(Duration::from_secs(2)), 150, 150),
        // Everything late by the same amount, so nothing overtook anything.
        (Fault::Delay(Duration::from_secs(5)), 150, 0),
    ] {
        let mut sim = Sim::new(Script::new(vec![fault]));
        pour(&mut sim, Side::Client, count);
        sim.assert_sound();
        assert_eq!(
            sim.delivered(Side::Server).len(),
            usize::try_from(count).expect("a small count"),
            "{fault:?}"
        );
        assert!(
            sim.refusals.replayed >= replays,
            "{fault:?}: {:?}",
            sim.refusals
        );
        assert_eq!(
            sim.refusals.total(),
            sim.refusals.replayed,
            "{fault:?}: nothing was refused for any other reason"
        );
    }
}

/// Both have to be silent refusals rather than a corrupted keystroke reaching
/// a shell.
#[test]
fn a_damaged_datagram_never_becomes_a_frame() {
    for fault in [Fault::Corrupt(3), Fault::Truncate(9)] {
        let mut sim = Sim::new(Script::new(vec![fault]));
        pour(&mut sim, Side::Client, 100);
        sim.assert_sound();
        assert!(sim.delivered(Side::Server).is_empty(), "{fault:?}");
        assert_eq!(sim.refusals.total(), 100, "{fault:?}");
    }
}

#[test]
fn a_client_that_changes_network_is_followed_after_it_proves_the_address() {
    let mut sim = Sim::new(Perfect);
    pour(&mut sim, Side::Client, 10);
    assert_eq!(sim.peer_of(Side::Server), sim.address(Side::Client));

    let moved = sim.elsewhere(7);
    sim.roam(moved);
    assert!(sim.send(Side::Client, &frame(10)).is_some());
    sim.settle();

    sim.assert_sound();
    assert_eq!(sim.peer_of(Side::Server), moved);
    assert_eq!(sim.delivered(Side::Server).len(), 11);

    // And the session runs on the new path.
    assert!(sim.send(Side::Server, b"a screen").is_some());
    sim.settle();
    assert_eq!(sim.delivered(Side::Client), [b"a screen".to_vec()]);
}

/// Holds the next client datagram so it lands after the client has moved: both
/// paths live for a round trip, which is the ordinary shape of a rebind.
#[derive(Default)]
struct Straggler {
    hold: Option<Duration>,
}

impl Schedule for Straggler {
    fn next(&mut self, from: Side, _datagram: &[u8]) -> Fault {
        match from {
            // Client only, so a keep-alive the server emits first cannot spend
            // the hold the test armed.
            Side::Client => match self.hold.take() {
                Some(by) => Fault::Delay(by),
                None => Fault::Deliver,
            },
            Side::Server => Fault::Deliver,
        }
    }
}

/// Retiring the outstanding challenge on a straggler sealed at the old address
/// throws away the token the client is at that moment answering, so the move
/// has to be proposed again with a fresh one.
#[test]
fn a_move_on_a_reordering_link_costs_one_round_trip() {
    let mut sim = Sim::new(Straggler::default());
    pour(&mut sim, Side::Client, 5);
    assert_eq!(sim.peer_of(Side::Server), sim.address(Side::Client));
    let before = sim.challenges(Side::Server);

    // One latency: it lands after the server has challenged the new address
    // and before the answer gets back.
    sim.schedule().hold = Some(sim.link.latency);
    assert!(sim.send(Side::Client, &frame(5)).is_some());

    let moved = sim.elsewhere(3);
    sim.roam(moved);
    let began = sim.now();
    assert!(sim.send(Side::Client, &frame(6)).is_some());

    // Nothing more is typed: the move must complete on the challenge already
    // outstanding.
    for _ in 0..16 {
        sim.settle();
        if sim.peer_of(Side::Server) == moved {
            break;
        }
        sim.advance(Duration::from_millis(250));
    }
    let cost = sim.now() - began;

    sim.assert_sound();
    assert_eq!(sim.peer_of(Side::Server), moved);
    assert_eq!(sim.delivered(Side::Server).len(), 7);
    assert_eq!(
        sim.challenges(Side::Server) - before,
        1,
        "one challenge, so the straggler cost the move nothing"
    );
    assert!(
        cost <= 3 * sim.link.latency,
        "the move took {cost:?}, which is more than the round trip it should cost"
    );
}

/// The migration path has to be re-enterable, not a one-shot.
#[test]
fn repeated_roaming_on_a_lossy_link_converges_every_time() {
    let mut sim = Sim::new(GilbertElliott::typical(11));
    for step in 1..=4u8 {
        let moved = sim.elsewhere(step);
        sim.roam(moved);
        for n in 0..30u32 {
            let _ = sim.send(Side::Client, &frame(u32::from(step) * 1000 + n));
        }
        sim.settle();
        sim.assert_sound();
        assert_eq!(sim.peer_of(Side::Server), moved, "after move {step}");
    }
}

/// A user who moved and typed nothing has only the keep-alive to break the
/// deadlock.
#[test]
fn a_client_that_moves_and_then_types_nothing_is_still_found() {
    let mut sim = Sim::new(Perfect);
    pour(&mut sim, Side::Client, 5);
    let moved = sim.elsewhere(9);
    sim.roam(moved);

    sim.advance(Duration::from_secs(3));
    sim.settle();

    sim.assert_sound();
    assert_eq!(sim.peer_of(Side::Server), moved);
    assert!(
        sim.send(Side::Server, b"a screen for the new address")
            .is_some()
    );
    sim.settle();
    assert_eq!(
        sim.delivered(Side::Client),
        [b"a screen for the new address".to_vec()]
    );
}

/// The shape an off-path attacker can actually produce: it cannot seal a
/// datagram of its own, so re-sourcing every datagram — and replaying what it
/// re-sourced — still never moves the session.
#[test]
fn a_spoofed_source_address_never_captures_the_session() {
    for script in [
        vec![Fault::Spoof],
        vec![
            Fault::Deliver,
            Fault::Spoof,
            Fault::Replay(Duration::from_millis(600)),
        ],
    ] {
        let mut sim = Sim::new(Script::new(script));
        let home = sim.address(Side::Client);
        pour(&mut sim, Side::Client, 90);
        sim.assert_sound();
        assert_eq!(sim.peer_of(Side::Server), home);
    }
}

/// The session is authenticated by ssh; the address on the front of the
/// datagram that resumes it is not, so anyone who completes that handshake once
/// could aim the session's first burst of output at a victim.
#[test]
fn an_accepting_endpoint_holds_its_output_until_the_address_answers() {
    let mut sim = Sim::new(Perfect);
    // Every session's first round trip: a resume in, a screen out, and the
    // screen queued before anything has arrived.
    assert!(sim.send(Side::Client, b"a resume").is_some());
    for n in 0..40u32 {
        assert!(sim.send(Side::Server, &frame(n)).is_some());
    }
    sim.settle();

    sim.assert_sound();
    assert_eq!(sim.delivered(Side::Server).len(), 1);
    assert_eq!(
        sim.delivered(Side::Client).len(),
        40,
        "and once the address has answered, all of it goes"
    );
}

/// Rotation happens on every completed migration, each restarting at zero.
#[test]
fn no_nonce_is_ever_used_twice_across_rotation_and_roaming() {
    let mut sim = Sim::new(GilbertElliott::typical(5));
    for step in 1..=20u8 {
        sim.roam(sim.elsewhere(step % 8 + 1));
        for n in 0..25u32 {
            let _ = sim.send(Side::Client, &frame(u32::from(step) * 100 + n));
            let _ = sim.send(Side::Server, &frame(50_000 + u32::from(step) * 100 + n));
        }
        sim.settle();
    }
    sim.assert_sound();
}

/// A failing seed has to be a number somebody can rerun.
#[test]
fn a_seed_reproduces_its_run_exactly() {
    let run = |seed: u64| {
        let mut sim = Sim::new(GilbertElliott::hostile(seed));
        pour(&mut sim, Side::Client, 300);
        (
            sim.delivered(Side::Server).to_vec(),
            sim.refusals,
            sim.peer_of(Side::Server),
        )
    };
    assert_eq!(run(4242), run(4242));
    assert_ne!(run(4242).0.len(), run(4243).0.len());
}

/// Liveness: a transport that refused everything would pass every test above.
#[test]
fn a_hostile_link_still_carries_a_session() {
    let mut sim = Sim::new(GilbertElliott::hostile(77));
    pour(&mut sim, Side::Client, 1_000);
    sim.assert_sound();
    let delivered = sim.delivered(Side::Server).len();
    assert!(delivered > 200, "only {delivered} of 1000 arrived");
}
