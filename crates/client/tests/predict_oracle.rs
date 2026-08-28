//! Differential oracle for the prediction path: one `VtEngine` is fed the
//! session's output, a second only what `Display` wrote. They must agree the
//! moment a prediction settles.

use braid_client::Display;
use braid_client::predict::{Prediction, Typing};
use braid_client::render::Assembled;
use braid_proto::{
    ByteOff, CmdSeq, Generation, GridSize, InputCue, MAX_FRAME, RowUpdate, ScreenHeader,
    ScreenVersion, ServerMessage, Version, encode_screen_parts,
};
use braid_vt::{ContinuationLimit, EffectSink, RepaintFrame, ScrollbackLimit, VtEngine};
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

struct Silent;

impl EffectSink for Silent {
    fn pty_write(&self, _bytes: &[u8]) {}
}

fn engine(size: GridSize) -> VtEngine<Silent> {
    VtEngine::new(
        size,
        ScrollbackLimit(64 * 1024),
        ContinuationLimit(1024 * 1024),
        Rc::new(Silent),
    )
    .expect("terminal should initialize")
}

#[derive(Clone, Default)]
struct Tap(Rc<RefCell<Vec<u8>>>);

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Grid equality only: damage says when a frame was taken, not what is shown.
fn same_grid(source: &RepaintFrame, replica: &RepaintFrame) -> bool {
    source.rows.len() == replica.rows.len()
        && source
            .rows
            .iter()
            .zip(&replica.rows)
            .all(|(expected, actual)| {
                expected.text == actual.text
                    && expected.cells == actual.cells
                    && expected.runs == actual.runs
            })
}

struct Session {
    /// The pty's own terminal: the only authority on what the screen should be.
    server: VtEngine<Silent>,
    /// The user's terminal, fed nothing but the bytes the client wrote.
    replica: VtEngine<Silent>,
    display: Display<Tap>,
    tap: Tap,
    size: GridSize,
    next: CmdSeq,
    /// The newest keystroke the server answered, sent as both delivery and echo ack.
    answered: Option<CmdSeq>,
    version: ScreenVersion,
    /// Whether the client has asked for a whole screen since this was built.
    repaint: bool,
}

impl Session {
    fn new(size: GridSize) -> Self {
        let tap = Tap::default();
        Self {
            server: engine(size),
            replica: engine(size),
            // `Always`: the round-trip gate decides whether to draw, and every
            // case here is about what drawing leaves behind.
            display: Display::new(tap.clone(), Prediction::Always),
            tap,
            size,
            next: CmdSeq::first(),
            answered: None,
            version: ScreenVersion::initial(),
            repaint: false,
        }
    }

    fn shown(&mut self) {
        let written = std::mem::take(&mut *self.tap.0.borrow_mut());
        self.replica
            .feed(&written)
            .expect("the client writes bytes a terminal parses");
    }

    /// The server's own cue rule, restated because the client holds no emulator.
    fn cue(&self) -> InputCue {
        let cue = self.server.cursor_cue().expect("a cursor cue");
        if cue.alternate || cue.mouse_tracking || !cue.visible || cue.pending_wrap {
            return InputCue::Opaque;
        }
        InputCue::Echoing {
            room: self.size.cols.saturating_sub(cue.col).saturating_sub(1),
        }
    }

    /// A chunk of session output, with the cue the server would send beside it.
    fn session(&mut self, bytes: &[u8]) {
        self.server
            .feed(bytes)
            .expect("session output should parse");
        let cue = self.cue();
        self.repaint |= self
            .display
            .output(bytes, cue, self.answered)
            .expect("session output reaches the terminal");
        self.display.flush().expect("the session loop flushes");
        self.shown();
    }

    fn key(&mut self, typed: &[u8]) -> CmdSeq {
        let seq = self.next;
        self.next = seq.next();
        self.display
            .predict(typed, Some(seq), Typing::Continuous)
            .expect("a keystroke reaches the terminal");
        self.shown();
        seq
    }

    fn answer(&mut self, seq: CmdSeq) {
        self.display.acknowledged(seq);
        self.answered = Some(seq);
    }

    /// Type a keystroke and let the session echo it back byte for byte.
    fn echoed(&mut self, typed: &[u8]) {
        let seq = self.key(typed);
        self.answer(seq);
        self.session(typed);
    }

    /// Open a run: the first keystroke always costs a round trip and draws nothing.
    fn open_run(&mut self, typed: &[u8]) {
        self.echoed(typed);
        assert!(
            !self.ahead(),
            "an unconfirmed run draws nothing, so the terminals agree"
        );
    }

    /// Whether the terminal is showing something the session has not sent.
    fn ahead(&mut self) -> bool {
        let source = self.server.repaint().expect("a server repaint").clone();
        let replica = self.replica.repaint().expect("a replica repaint");
        !same_grid(&source, replica)
    }

    /// Indistinguishable terminals, reached without asking for a whole screen.
    fn assert_settled(&mut self, label: &str) {
        let source = self.server.repaint().expect("a server repaint").clone();
        let replica = self.replica.repaint().expect("a replica repaint");
        assert_eq!(source.rows.len(), replica.rows.len(), "{label}: row count");
        for (index, (expected, actual)) in source.rows.iter().zip(&replica.rows).enumerate() {
            assert_eq!(expected.text, actual.text, "{label}: row {index} text");
            assert_eq!(expected.cells, actual.cells, "{label}: row {index} cells");
            assert_eq!(expected.runs, actual.runs, "{label}: row {index} styles");
        }
        assert_eq!(source.cursor, replica.cursor, "{label}: cursor");
        assert!(
            !self.repaint,
            "{label}: the client asked for a whole screen"
        );
    }

    /// A whole screen, through the real encoder and decoder.
    fn screen(&mut self) -> Option<Assembled> {
        let frame = self.server.repaint().expect("a server repaint").clone();
        let version = self.version;
        self.version = version.next();
        let header = ScreenHeader {
            generation: Generation::initial(),
            version,
            next_off: ByteOff::zero(),
            size: frame.size,
            cursor: frame.cursor,
            cursor_visible: frame.cursor_visible,
            cursor_shape: frame.cursor_shape,
            cursor_blinking: frame.cursor_blinking,
            modes: frame.modes,
            sticky: frame.sticky.clone(),
        };
        let rows =
            frame.rows.iter().enumerate().map(|(index, row)| {
                RowUpdate::whole(u16::try_from(index).expect("a row index"), row)
            });
        let parts = encode_screen_parts(&header, None, None, rows, MAX_FRAME as usize)
            .expect("a screen this size fits the wire");
        let mut assembled = None;
        for wire in &parts {
            let ServerMessage::Screen { part } =
                ServerMessage::decode(&wire[4..], Version::LOCAL).expect("the encoder's own frame")
            else {
                panic!("expected a screen piece");
            };
            let done = self
                .display
                .part(part, self.size.rows)
                .expect("a piece renders")
                .expect("a piece the client can apply");
            assembled = assembled.or(done);
        }
        self.display.flush().expect("the session loop flushes");
        self.shown();
        assembled
    }
}

/// Room for a shell line and a few rows to wrap into.
const GRID: GridSize = GridSize { cols: 80, rows: 6 };

/// A terminal narrow enough that a dozen keystrokes reach its right margin.
const NARROW: GridSize = GridSize { cols: 24, rows: 4 };

/// The prompt a session opens with: nothing is predicted onto an undescribed screen.
const PROMPT: &[u8] = b"user@host:~$ ";

#[test]
fn a_confirmed_prediction_is_the_echo_it_suppressed() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"l");
    // Every chunk carries a glyph: a lone trailing space is indistinguishable
    // from the blank it lands on and would make `ahead` vacuous.
    for typed in [&b"s"[..], b" -", b"l", b"a"] {
        let seq = session.key(typed);
        assert!(
            session.ahead(),
            "a confirmed run draws the keystroke ahead of the session"
        );
        session.answer(seq);
        session.session(typed);
        session.assert_settled("typing under a confirmed run");
    }
}

/// The guess comes off the row in front of the output that convicts it, at the
/// columns it occupies — which for a two-cell glyph is not the one-cell erase.
#[test]
fn a_wrong_prediction_is_taken_back_before_the_output_that_convicts_it() {
    for (open, typed) in [
        (&b"c"[..], &b"d"[..]),
        (&b"e"[..], "cho \u{4e16}".as_bytes()),
    ] {
        let mut session = Session::new(GRID);
        session.session(PROMPT);
        session.open_run(open);
        let seq = session.key(typed);
        assert!(session.ahead(), "the guess is on the terminal");
        session.answer(seq);
        // Not an echo: a completion menu, or something else to say.
        session.session(b"Q");
        session.assert_settled("a local undo in front of the output that ended the run");
    }
}

#[test]
fn a_partial_echo_absorbed_across_two_reads_never_doubles() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"e");
    let seq = session.key(b"cho hi");
    assert!(session.ahead(), "six keystrokes drawn ahead of the session");
    session.answer(seq);
    // One chunk of typing echoed across two reads, as a slow link produces.
    session.session(b"cho ");
    assert!(
        session.ahead(),
        "two predicted characters are still owed an echo"
    );
    session.session(b"hi");
    session.assert_settled("an echo split across two reads");
}

#[test]
fn a_prediction_outstanding_when_a_screen_lands_is_repainted_over() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"t");
    let seq = session.key(b"op");
    assert!(session.ahead(), "the guess is on the terminal");
    assert!(
        session.screen().is_none(),
        "a screen that crossed a prediction is never acknowledged"
    );
    session.assert_settled("a whole screen over a drawn prediction");
    // The same screen, with nothing local standing on it, may be acknowledged.
    session.answer(seq);
    session.session(b"op");
    assert!(
        session.screen().is_some(),
        "a screen that crossed nothing is acknowledged"
    );
    session.assert_settled("a whole screen with the run settled");
}

#[test]
fn a_wide_glyph_is_drawn_and_erased_by_the_columns_it_occupies() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"e");
    let seq = session.key("cho 世界".as_bytes());
    assert!(
        session.ahead(),
        "two-cell glyphs drawn ahead of the session"
    );
    session.answer(seq);
    session.session("cho 世界".as_bytes());
    session.assert_settled("wide glyphs echoed back");

    // The erase owed for two columns is not the erase owed for one.
    let seq = session.key(b"\x08");
    assert!(session.ahead(), "the erase is on the terminal");
    session.answer(seq);
    session.session(b"\x08\x08  \x08\x08");
    session.assert_settled("a predicted erase of a two-cell character");
}

#[test]
fn a_combining_mark_folds_onto_the_cell_the_prediction_caused() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"c");
    let seq = session.key(b"af");
    assert!(session.ahead(), "the guess is on the terminal");
    session.answer(seq);
    session.session(b"af");
    session.assert_settled("typing ahead of a mark");

    // No divergence check: the predicted `e` and the mark are separate writes,
    // and a repaint between them costs the replica its mark — an emulator
    // property, not one under test here.
    let seq = session.key(b"e");
    session.answer(seq);
    session.session("e\u{301}".as_bytes());
    session.assert_settled("a mark echoed onto a predicted cell");

    // A mark typed alone is never drawn: zero width has no column of its own.
    let seq = session.key("\u{301}".as_bytes());
    assert!(!session.ahead(), "a combining mark is not predicted");
    session.answer(seq);
    session.session("\u{301}".as_bytes());
    session.assert_settled("a combining mark typed on its own");
}

#[test]
fn a_prediction_never_reaches_the_row_s_last_cell() {
    let mut session = Session::new(NARROW);
    session.session(b"$ ");
    session.open_run(b"a");
    // Up to the second-to-last column, the last one a prediction is offered room in.
    let free = usize::from(NARROW.cols) - 3 - 1;
    for _ in 0..free {
        let seq = session.key(b"z");
        assert!(session.ahead(), "there is still room on the row");
        session.answer(seq);
        session.session(b"z");
        session.assert_settled("typing toward the right margin");
    }

    // The row's last cell: predicting into it commits to a wrap the session has not made.
    let seq = session.key(b"y");
    assert!(
        !session.ahead(),
        "the last cell is never predicted into, so nothing is drawn"
    );
    session.answer(seq);
    session.session(b"y");
    session.assert_settled("the session filling the last cell itself");

    // The terminal is now holding a pending wrap, which makes the cue opaque.
    let seq = session.key(b"w");
    assert!(!session.ahead(), "an opaque cue draws nothing");
    session.answer(seq);
    session.session(b"w");
    session.assert_settled("the row wrapping under the session");

    // Prediction resumes on the row the wrap landed on, once a keystroke there is confirmed.
    session.open_run(b"v");
    let seq = session.key(b"u");
    assert!(session.ahead(), "the new row has room again");
    session.answer(seq);
    session.session(b"u");
    session.assert_settled("typing on the row the wrap landed on");
}

#[test]
fn predict_then_partial_echo_then_undo_then_a_screen() {
    let mut session = Session::new(GRID);
    session.session(PROMPT);
    session.open_run(b"g");
    let seq = session.key(b"it st");
    assert!(
        session.ahead(),
        "five keystrokes drawn ahead of the session"
    );
    session.answer(seq);
    session.session(b"it ");
    assert!(
        session.ahead(),
        "two predicted characters are still owed an echo"
    );
    // The rest never does: the shell answered with something else.
    session.session(b"Q");
    session.assert_settled("a local undo behind a half-absorbed echo");
    assert!(
        session.screen().is_some(),
        "nothing local is drawn, so the screen is acknowledged"
    );
    session.assert_settled("a screen over a row a repair had just cleared");
    // A screen leaves the cue opaque, so the keystroke after it is bookkeeping.
    session.echoed(b"x");
    session.open_run(b"y");
    let seq = session.key(b"z");
    assert!(session.ahead(), "the run reopens after the screen");
    session.answer(seq);
    session.session(b"z");
    session.assert_settled("typing after a screen");
}
