#![no_main]

//! The PTY byte stream, from the emulator to the wire: a frame the emulator
//! can produce and the encoder cannot carry is a session that stops
//! repainting, and neither half can be asked about it alone.

use braid_proto::{
    ByteOff, Generation, GridSize, RowUpdate, ScreenHeader, ScreenVersion, Version,
    encode_screen_parts,
};
use braid_vt::{ContinuationLimit, EffectSink, ScrollbackLimit, VtEngine, VtError};
use libfuzzer_sys::fuzz_target;
use std::rc::Rc;

/// What a real session gives the daemon before the first byte arrives.
const COLS: u16 = 80;
const ROWS: u16 = 24;
const SCROLLBACK: usize = 64 * 1024;
const CONTINUATION: usize = 64 * 1024;

/// The budget a datagram path states before path-MTU discovery has answered.
const BUDGET: usize = braid_proto::MIN_DATAGRAM_FRAME;

/// Taken and dropped: Ghostty writes the reply from inside `vt_write`, so a
/// sink that panicked would report the callback, not the parser.
struct Discard;

impl EffectSink for Discard {
    fn pty_write(&self, _bytes: &[u8]) {}
}

fn header(size: GridSize) -> ScreenHeader {
    ScreenHeader {
        generation: Generation::initial(),
        version: ScreenVersion::initial(),
        next_off: ByteOff::zero(),
        size,
        cursor: Some((0, 0)),
        cursor_visible: true,
        cursor_shape: braid_proto::CursorShape::Block,
        cursor_blinking: false,
        modes: braid_proto::ModeSet::empty(),
        sticky: braid_proto::StickyState::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    let size = GridSize::new(COLS, ROWS).expect("a fixed grid");
    let mut engine: VtEngine<Discard> = VtEngine::new(
        size,
        ScrollbackLimit(SCROLLBACK),
        ContinuationLimit(CONTINUATION),
        Rc::new(Discard),
    )
    .expect("a terminal of a fixed size");

    // In chunks: a sequence split across two reads is the state the parser
    // carries between them.
    for chunk in data.chunks(64.max(data.len() / 8 + 1)) {
        match engine.feed(chunk) {
            Ok(()) | Err(VtError::ContinuationLimit) => {}
            Err(other) => panic!("feed refused {} bytes: {other}", chunk.len()),
        }
    }

    let frame = match engine.repaint() {
        Ok(frame) => frame,
        // A refusal the session handles, not a corrupt frame.
        Err(VtError::ClusterTooLarge) => return,
        Err(other) => panic!("repaint failed: {other}"),
    };
    assert_eq!(frame.size, size, "a repaint reported a grid nobody set");
    assert_eq!(
        frame.rows.len(),
        usize::from(size.rows),
        "a repaint reported {} rows of a {}-row grid",
        frame.rows.len(),
        size.rows
    );

    let mut head = header(size);
    head.cursor = frame.cursor;
    head.cursor_visible = frame.cursor_visible;
    head.cursor_shape = frame.cursor_shape;
    head.cursor_blinking = frame.cursor_blinking;
    head.modes = frame.modes;
    head.sticky = frame.sticky.clone();

    let rows = frame
        .rows
        .iter()
        .enumerate()
        .map(|(row, frame)| RowUpdate::whole(u16::try_from(row).expect("a row index"), frame));
    let parts = encode_screen_parts(&head, None, None, rows, BUDGET)
        .expect("a screen the emulator produced is a screen the wire carries");
    for part in &parts {
        assert!(
            part.len() <= BUDGET + 4,
            "a piece cut to {BUDGET} bytes went out at {}",
            part.len()
        );
        braid_proto::ServerMessage::decode(&part[4..], Version::LOCAL)
            .expect("a piece this side just encoded");
    }
});
