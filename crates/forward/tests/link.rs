#![forbid(unsafe_code)]

//! Both ends of a forward, in one process, over a link that loses, reorders,
//! duplicates and stops entirely for a while.

use braid_forward::{
    Ack, Contradiction, FORWARD_WINDOW, MAX_FORWARD_CHUNK, SackRun, SackRuns, Stream,
};
use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

/// The datagram floor, which is what an unprobed path gets.
const BUDGET: usize = 1138;
const TICK: Duration = Duration::from_millis(5);

/// Deterministic and seeded: a random seed makes a one-run-in-fifty failure
/// unreproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[derive(Clone)]
enum Frame {
    Data { off: u64, fin: bool, bytes: Vec<u8> },
    Ack(Ack),
}

struct Wire {
    flight: VecDeque<(u64, Frame)>,
    loss: u64,
    duplicate: u64,
    reorder: u64,
    /// Ticks for which the link carries nothing at all.
    blackout: std::ops::Range<u64>,
}

impl Wire {
    fn send(&mut self, tick: u64, rng: &mut Rng, frame: Frame) {
        if self.blackout.contains(&tick) || rng.chance(self.loss) {
            return;
        }
        let delay = if rng.chance(self.reorder) { 3 } else { 1 };
        if rng.chance(self.duplicate) {
            self.flight.push_back((tick + delay + 1, frame.clone()));
        }
        self.flight.push_back((tick + delay, frame));
    }

    fn due(&mut self, tick: u64) -> Vec<Frame> {
        let mut ready = Vec::new();
        let mut held = VecDeque::new();
        while let Some((at, frame)) = self.flight.pop_front() {
            if at <= tick {
                ready.push(frame);
            } else {
                held.push_back((at, frame));
            }
        }
        self.flight = held;
        ready
    }
}

struct End {
    stream: Stream,
    source: Vec<u8>,
    written: usize,
    sink: Vec<u8>,
}

impl End {
    fn new(source: Vec<u8>) -> Self {
        Self {
            stream: Stream::new(),
            source,
            written: 0,
            sink: Vec::new(),
        }
    }

    fn fill(&mut self, now: Instant) {
        while self.written < self.source.len() {
            let room = self.stream.writable();
            if room == 0 {
                return;
            }
            let end = (self.written + room).min(self.source.len());
            let taken = self.stream.write(&self.source[self.written..end], now);
            if taken == 0 {
                return;
            }
            self.written += taken;
        }
        self.stream.finish();
    }

    fn drain(&mut self) {
        let (front, back) = self.stream.readable();
        let taken = front.len() + back.len();
        self.sink.extend_from_slice(front);
        self.sink.extend_from_slice(back);
        self.stream.consume(taken);
    }
}

/// One wire per direction: the client's segments and the daemon's never share
/// a queue.
fn transfer(loss: u64, duplicate: u64, reorder: u64, blackout: std::ops::Range<u64>) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let up: Vec<u8> = (0..200_000_u32).map(|n| (n % 251) as u8).collect();
    let down: Vec<u8> = (0..150_000_u32).map(|n| (n % 241) as u8).collect();
    let mut a = End::new(up.clone());
    let mut b = End::new(down.clone());
    let mut to_b = Wire {
        flight: VecDeque::new(),
        loss,
        duplicate,
        reorder,
        blackout: blackout.clone(),
    };
    let mut to_a = Wire {
        flight: VecDeque::new(),
        loss,
        duplicate,
        reorder,
        blackout,
    };
    let start = Instant::now();
    let mut body = Vec::new();
    let mut tick = 0_u64;
    let ceiling = 4_000_000_u64;
    while tick < ceiling {
        let now = start + TICK * u32::try_from(tick).expect("a bounded run");
        for direction in 0..2 {
            let (near, wire) = if direction == 0 {
                (&mut a, &mut to_b)
            } else {
                (&mut b, &mut to_a)
            };
            near.fill(now);
            body.clear();
            if let Some(segment) = near.stream.poll_transmit(now, BUDGET, &mut body) {
                near.stream.transmitted(segment, now);
                wire.send(
                    tick,
                    &mut rng,
                    Frame::Data {
                        off: segment.off,
                        fin: segment.fin,
                        bytes: body.clone(),
                    },
                );
            }
            if let Some(ack) = near.stream.poll_ack() {
                wire.send(tick, &mut rng, Frame::Ack(ack));
            }
        }
        for frame in to_b.due(tick) {
            deliver(&mut b.stream, &frame, now);
        }
        for frame in to_a.due(tick) {
            deliver(&mut a.stream, &frame, now);
        }
        a.drain();
        b.drain();
        if a.stream.is_done() && b.stream.is_done() {
            break;
        }
        tick += 1;
    }
    assert!(tick < ceiling, "the transfer never converged");
    assert_eq!(a.sink, down, "what the client read is what the daemon sent");
    assert_eq!(b.sink, up, "what the daemon read is what the client sent");
}

fn deliver(stream: &mut Stream, frame: &Frame, now: Instant) {
    match frame {
        Frame::Data { off, fin, bytes } => {
            stream
                .on_data(*off, *fin, bytes)
                .expect("a peer that does not contradict itself");
        }
        Frame::Ack(ack) => {
            stream
                .on_ack(ack.off, ack.window, &ack.held, now)
                .expect("a peer that does not contradict itself");
        }
    }
}

/// One direction of a link that loses nothing: what `from` owes reaches `to`,
/// and whatever `to` then owes reaches `from`.
fn couple(from: &mut Stream, to: &mut Stream, now: Instant, body: &mut Vec<u8>) {
    body.clear();
    if let Some(segment) = from.poll_transmit(now, MAX_FORWARD_CHUNK, body) {
        from.transmitted(segment, now);
        to.on_data(segment.off, segment.fin, body)
            .expect("a peer that does not contradict itself");
    }
    if let Some(ack) = to.poll_ack() {
        from.on_ack(ack.off, ack.window, &ack.held, now)
            .expect("a peer that does not contradict itself");
    }
}

#[test]
fn a_forward_converges_over_a_link_that_misbehaves() {
    // (loss, duplicate, reorder, blackout)
    for (loss, duplicate, reorder, blackout) in [
        (0, 0, 0, 0..0),
        (10, 0, 0, 0..0),
        (5, 10, 15, 0..0),
        // Every frame in both directions destroyed for longer than the
        // retransmission ceiling: the forward must resume, not restart.
        (2, 0, 5, 400..1600),
        (30, 5, 20, 0..0),
    ] {
        transfer(loss, duplicate, reorder, blackout);
    }
}

#[test]
fn a_segment_never_exceeds_the_budget() {
    let now = Instant::now();
    let mut stream = Stream::new();
    stream.write(&vec![0_u8; MAX_FORWARD_CHUNK * 4], now);
    let mut body = Vec::new();
    let segment = stream.poll_transmit(now, BUDGET, &mut body).expect("one");
    assert!(segment.len <= BUDGET);
    assert_eq!(body.len(), segment.len);
}

#[test]
fn a_stream_the_peer_never_answers_keeps_owing_the_same_bytes() {
    let start = Instant::now();
    let mut stream = Stream::new();
    stream.write(b"payload", start);
    let mut first = Vec::new();
    let one = stream
        .poll_transmit(start, BUDGET, &mut first)
        .expect("a segment");
    stream.transmitted(one, start);
    let later = start + Duration::from_secs(30);
    let mut again = Vec::new();
    let two = stream
        .poll_transmit(later, BUDGET, &mut again)
        .expect("the same bytes again");
    assert_eq!((one.off, one.len), (two.off, two.len));
    assert_eq!(first, again);
}

/// A `-L` tunnel whose local end stops reading: the only thing between the
/// peer's probes and this process's memory is a window the receiver enforces.
#[test]
fn a_receiver_that_stops_reading_stays_bounded_and_still_finishes() {
    let start = Instant::now();
    let payload: Vec<u8> = (0..900_000_u32).map(|n| (n % 251) as u8).collect();
    let mut a = End::new(payload.clone());
    let mut b = Stream::new();
    b.finish();
    let stall = 0..4_000_u64;
    let mut sink: Vec<u8> = Vec::new();
    let mut body = Vec::new();
    let mut tick = 0_u64;
    let ceiling = 100_000_u64;
    while tick < ceiling {
        let now = start + TICK * u32::try_from(tick).expect("a bounded run");
        a.fill(now);
        couple(&mut a.stream, &mut b, now, &mut body);
        couple(&mut b, &mut a.stream, now, &mut body);
        let (front, back) = b.readable();
        let buffered = front.len() + back.len();
        assert!(
            buffered <= FORWARD_WINDOW,
            "a stalled receiver holds no more than it advertised, and holds {buffered}"
        );
        if !stall.contains(&tick) {
            sink.extend_from_slice(front);
            sink.extend_from_slice(back);
            b.consume(buffered);
        }
        if a.stream.is_done() && b.is_done() {
            break;
        }
        tick += 1;
    }
    assert!(tick < ceiling, "the stall never resolved");
    assert_eq!(sink, payload, "what came out is what went in");
}

/// Send one window, lose the head, and report what the repair cost: the only
/// numbers that separate a selective repair from a rewind.
fn repair_cost(selective: bool) -> (usize, usize) {
    // Exactly the credit a sender starts with, so the whole payload is on the
    // wire before the first acknowledgement arrives.
    let payload = vec![b'z'; MAX_FORWARD_CHUNK];
    let now = Instant::now();
    let (mut a, mut b) = (Stream::new(), Stream::new());
    assert_eq!(a.write(&payload, now), payload.len());
    let mut body = Vec::new();
    let mut head = true;
    loop {
        body.clear();
        let Some(segment) = a.poll_transmit(now, BUDGET, &mut body) else {
            break;
        };
        a.transmitted(segment, now);
        // The head is the segment the link drops; the rest is held past the gap.
        if head {
            head = false;
        } else {
            b.on_data(segment.off, segment.fin, &body)
                .expect("a peer that does not contradict itself");
        }
    }
    let ack = b
        .poll_ack()
        .expect("a receiver holding a gap owes an answer");
    assert_eq!(ack.off, 0, "nothing is contiguous yet");
    let ranges = if selective {
        ack.held.clone()
    } else {
        SackRuns::EMPTY
    };
    a.on_ack(ack.off, ack.window, &ranges, now)
        .expect("a peer that does not contradict itself");
    let later = now + Duration::from_secs(5);
    let (mut segments, mut bytes) = (0, 0);
    loop {
        body.clear();
        let Some(segment) = a.poll_transmit(later, BUDGET, &mut body) else {
            break;
        };
        a.transmitted(segment, later);
        b.on_data(segment.off, segment.fin, &body)
            .expect("a peer that does not contradict itself");
        segments += 1;
        bytes += segment.len;
    }
    let (front, back) = b.readable();
    assert_eq!(
        [front, back].concat(),
        payload,
        "the repair has to actually fill the gap"
    );
    (segments, bytes)
}

#[test]
fn a_lost_head_is_repaired_without_resending_the_window_behind_it() {
    let (segments, bytes) = repair_cost(true);
    assert_eq!(
        (segments, bytes),
        (1, BUDGET),
        "a peer that named what it holds is owed only the hole"
    );
    let (rewound, resent) = repair_cost(false);
    assert_eq!(
        resent, MAX_FORWARD_CHUNK,
        "without the ranges the sender rewinds to the acknowledged base"
    );
    assert!(
        rewound > segments * 20,
        "the selective repair has to be the cheap one: {rewound} segments against {segments}"
    );
}

#[test]
fn a_peer_holding_bytes_that_were_never_sent_contradicts_the_stream() {
    let now = Instant::now();
    let mut a = Stream::new();
    a.write(b"abcdefgh", now);
    let mut body = Vec::new();
    let segment = a.poll_transmit(now, BUDGET, &mut body).expect("a segment");
    a.transmitted(segment, now);
    let run = SackRun {
        gap: NonZeroU32::new(1).expect("a gap"),
        len: NonZeroU32::new(64).expect("a length"),
    };
    let held = SackRuns::new(vec![run]).expect("one run");
    assert_eq!(
        a.on_ack(0, 4096, &held, now),
        Err(Contradiction),
        "the peer named bytes past everything this side ever put on the wire"
    );
}

/// Segments to feed, and the runs the receiver should then be holding.
type HeldCase<'a> = (&'a [(u64, &'a [u8])], &'a [(u64, u64)]);

#[test]
fn a_receiver_names_one_run_per_gap_it_is_holding() {
    // Segments that abut describe one run of bytes this side holds.
    let cases: [HeldCase<'_>; 2] = [
        (
            &[
                (100, b"abcdefghij"),
                (300, b"abcdefghij"),
                (500, b"abcdefghij"),
            ],
            &[(100, 110), (300, 310), (500, 510)],
        ),
        (&[(100, b"abcde"), (105, b"fghij")], &[(100, 110)]),
    ];
    for (segments, expected) in cases {
        let mut b = Stream::new();
        for (off, bytes) in segments {
            b.on_data(*off, false, bytes)
                .expect("a peer that does not contradict itself");
        }
        let Ack { off, held, .. } = b.poll_ack().expect("an ack");
        assert_eq!(off, 0);
        assert_eq!(held.absolute(off).collect::<Vec<_>>(), expected);
    }
}
