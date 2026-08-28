//! Ghostty calls the effect callbacks from a Zig stack frame: without the
//! guard these tests kill the harness rather than fail an assertion.

use braid_proto::GridSize;
use braid_vt::{ContinuationLimit, EffectSink, ScrollbackLimit, VtEngine, VtError};
use std::cell::Cell;
use std::rc::Rc;

/// Answered synchronously, so one byte reaches `enquiry` and then the PTY
/// write carrying the reply.
const ENQ: &[u8] = b"\x05";

#[derive(Default)]
struct PanicOnPtyWrite {
    writes: Cell<usize>,
}

impl EffectSink for PanicOnPtyWrite {
    fn pty_write(&self, _bytes: &[u8]) {
        self.writes.set(self.writes.get() + 1);
        panic!("pty_write is broken");
    }
}

#[derive(Default)]
struct PanicOnEnquiry {
    enquiries: Cell<usize>,
}

impl EffectSink for PanicOnEnquiry {
    fn pty_write(&self, _bytes: &[u8]) {}

    fn enquiry(&self) {
        self.enquiries.set(self.enquiries.get() + 1);
        panic!("enquiry is broken");
    }
}

fn engine<S: EffectSink + 'static>(sink: Rc<S>) -> VtEngine<S> {
    VtEngine::new(
        GridSize { cols: 8, rows: 2 },
        ScrollbackLimit(0),
        ContinuationLimit(64),
        sink,
    )
    .expect("terminal should initialize")
}

fn message(error: &VtError) -> &str {
    match error {
        VtError::SinkPanic(message) => message,
        other => panic!("expected a caught sink panic, got {other}"),
    }
}

/// A session reporting the same failure on every later write cannot tell a
/// broken sink from a wedged terminal.
#[test]
fn a_panicking_pty_write_is_reported_once_and_the_terminal_keeps_parsing() {
    let sink = Rc::new(PanicOnPtyWrite::default());
    let mut engine = engine(Rc::clone(&sink));

    let error = engine
        .feed(ENQ)
        .expect_err("a panicking sink must surface as an error");

    assert!(message(&error).contains("pty_write is broken"));
    assert_eq!(sink.writes.get(), 1);

    engine
        .feed(b"hi")
        .expect("input that reaches no sink must still parse");
    let frame = engine.repaint().expect("render snapshot should succeed");
    assert_eq!(frame.rows[0].text.as_str(), "hi      ");
}

#[test]
fn a_panicking_query_callback_is_reported_instead_of_unwinding_into_zig() {
    let sink = Rc::new(PanicOnEnquiry::default());
    let mut engine = engine(Rc::clone(&sink));

    let error = engine
        .feed(ENQ)
        .expect_err("a panicking sink must surface as an error");

    assert!(message(&error).contains("enquiry is broken"));
    assert_eq!(sink.enquiries.get(), 1);
}

#[test]
fn the_first_panic_of_a_feed_is_the_one_reported() {
    struct Numbered(Cell<usize>);

    impl EffectSink for Numbered {
        fn pty_write(&self, _bytes: &[u8]) {
            let nth = self.0.get() + 1;
            self.0.set(nth);
            panic!("write {nth}");
        }
    }

    let sink = Rc::new(Numbered(Cell::new(0)));
    let mut engine = engine(Rc::clone(&sink));

    // ENQ then XTVERSION: two replies, so two writes inside one feed.
    let error = engine
        .feed(b"\x05\x1b[>q")
        .expect_err("a panicking sink must surface as an error");

    assert_eq!(sink.0.get(), 2, "both callbacks must still have run");
    assert!(message(&error).contains("write 1"));
}
