#![no_main]

//! Round trip for `encode_screen_parts`: every piece fits the caller's budget
//! and decodes, the pieces are counted and placed, and they concatenate back.

use braid_proto::{
    ByteOff, CellStyle, CursorShape, EncodeError, Generation, GridSize, MAX_DEFERRED,
    MAX_DEFERRED_BYTES, MAX_RUN_BYTES, MAX_TITLE, MIN_DATAGRAM_FRAME, ModeSet, RowFrame, RowSpan,
    RowUpdate, ScreenHeader, ScreenPart, ScreenVersion, ScrollBand, ServerMessage, StickyState,
    StyleColor, StyleRun, Version, encode_screen_parts,
};
use libfuzzer_sys::fuzz_target;

/// Bytes `encode` prepends and `decode` never sees.
const PREFIX: usize = 4;

/// The fuzzer's bytes, read as a description of a *legal* screen.
struct Input<'a> {
    bytes: &'a [u8],
}

impl Input<'_> {
    /// Zero once the input runs out, so a short case is a small screen.
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.bytes.split_first().unwrap_or((&0, &[]));
        self.bytes = rest;
        *first
    }

    fn flag(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    fn below(&mut self, bound: u16) -> u16 {
        ((u16::from(self.byte()) << 8) | u16::from(self.byte())) % bound
    }
}

/// Cells, characters and bytes have to disagree for a cut to be exercised.
const GRAPHEMES: [(&str, u16); 4] = [("a", 1), ("é", 1), ("漢", 2), ("👨\u{200d}👩\u{200d}👧", 2)];

/// What the encoder drops on the way out: trailing blanks no style paints.
fn elide(row: &RowFrame) -> RowFrame {
    RowFrame {
        text: row.text[..row.painted_bytes()].to_owned(),
        runs: row.runs.clone(),
        cells: row.cells,
    }
}

/// One row, under runs no wider than [`MAX_RUN_BYTES`], the bound that gives
/// every row a cut point inside it.
fn row(input: &mut Input<'_>, cols: u16) -> RowFrame {
    let (grapheme, width) = GRAPHEMES[usize::from(input.byte()) % GRAPHEMES.len()];
    let bytes = u32::try_from(grapheme.len()).expect("a short grapheme");
    let clusters = (input.below(cols) + 1) / width;
    let tiled = clusters * width;
    let mut frame = RowFrame {
        text: grapheme.repeat(usize::from(clusters)),
        runs: Vec::new(),
        cells: tiled,
    };
    // A styled row is the one with a boundary to cut at.
    if input.flag() {
        let clusters_per_run = u16::try_from(MAX_RUN_BYTES / bytes).expect("clusters a run covers");
        // A run costs twenty bytes against the one its cell text costs, so a
        // per-cell colouring is the row that does not fit a datagram.
        let per_run = if input.flag() {
            width
        } else {
            (input.below(clusters_per_run) + 1) * width
        };
        let mut placed = 0_u16;
        while placed < tiled {
            let run_cells = per_run.min(tiled - placed);
            frame.runs.push(StyleRun {
                cells: run_cells,
                bytes: u32::from(run_cells / width) * bytes,
                style: CellStyle {
                    fg: StyleColor::Palette(input.byte()),
                    ..CellStyle::default()
                },
            });
            placed += run_cells;
        }
    }
    // Runs tile a prefix, so a blank tail carries no style — and that is what
    // the encoder drops on the way out.
    let blanks = input.below(8).min(cols - frame.cells);
    frame.text.push_str(&" ".repeat(usize::from(blanks)));
    frame.cells += blanks;
    frame
}

/// A sticky block large enough to crowd the rows out of the head, the shape
/// that leaves a piece's fixed part larger than the rows it carries.
fn deferred(input: &mut Input<'_>) -> Vec<String> {
    let count = usize::from(input.byte()) % (MAX_DEFERRED + 1);
    let mut entries = Vec::with_capacity(count);
    let mut total = 0;
    for _ in 0..count {
        let bound = u16::try_from(MAX_DEFERRED_BYTES / MAX_DEFERRED + 1).expect("a bound");
        let body = "52;c;".to_owned() + &"A".repeat(usize::from(input.below(bound)));
        total += body.len();
        if total > MAX_DEFERRED_BYTES {
            break;
        }
        entries.push(body);
    }
    entries
}

/// A band the decoder will accept: `top < bottom <= rows`, `0 < lines <= bottom - top`.
fn band(input: &mut Input<'_>, rows: u16) -> Option<ScrollBand> {
    if rows < 2 || !input.flag() {
        return None;
    }
    let top = input.below(rows - 1);
    let bottom = top + 1 + input.below(rows - top);
    Some(ScrollBand {
        top,
        bottom,
        lines: 1 + input.below(bottom - top),
    })
}

fn header(input: &mut Input<'_>, size: GridSize) -> ScreenHeader {
    ScreenHeader {
        generation: Generation::initial(),
        version: ScreenVersion::initial(),
        next_off: ByteOff::from_u64(u64::from(input.below(u16::MAX))),
        size,
        // Inside the grid: a piece that never decodes checks nothing here.
        cursor: input.flag().then_some((0, 0)),
        cursor_visible: true,
        cursor_shape: CursorShape::Block,
        cursor_blinking: false,
        modes: ModeSet::empty(),
        // Heads carry the sticky block whole, so a long title crowds out rows.
        sticky: StickyState {
            title: input.flag().then(|| {
                let bound = u16::try_from(MAX_TITLE + 1).expect("a title bound");
                "t".repeat(usize::from(input.below(bound))).into()
            }),
            kitty_keyboard: 0,
            bell: false,
            saved_cursor: input.flag().then_some((0, 0)),
            pending_wrap: input.flag(),
            deferred: deferred(input),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input { bytes: data };
    let size = GridSize::new(input.below(256) + 1, input.below(32) + 1).expect("a legal grid");
    let header = header(&mut input, size);
    let base = input.flag().then(ScreenVersion::initial);
    // Below a planner's own header it must answer rather than loop.
    let budget = match input.byte() % 4 {
        0 | 1 => MIN_DATAGRAM_FRAME,
        2 => usize::from(input.below(2048)),
        _ => usize::from(input.below(u16::MAX)),
    };

    // Non-descending: one row may arrive as several spans.
    let mut named: Vec<u16> = Vec::new();
    let mut next = 0_u16;
    while next < size.rows {
        named.push(next);
        next += input.below(3) + 1;
    }
    let rows: Vec<RowFrame> = named.iter().map(|_| row(&mut input, size.cols)).collect();
    let scroll_sent = band(&mut input, size.rows);

    // A delta names a run range, not a row. Generated here so the oracle
    // judges what came back against what was asked for, independently of
    // whatever the encoder cut.
    let updates: Vec<RowUpdate<'_>> = named
        .iter()
        .copied()
        .zip(rows.iter())
        .map(|(row, frame)| {
            if frame.runs.is_empty() || !input.flag() {
                return RowUpdate::whole(row, frame);
            }
            let count = frame.runs.len();
            let first = usize::from(input.below(u16::try_from(count).unwrap_or(u16::MAX)));
            let last = first + 1 + usize::from(input.byte()) % (count - first);
            RowUpdate {
                row,
                frame,
                runs: (first, last),
                clear_tail: input.flag(),
            }
        })
        .collect();
    let partial: Vec<bool> = updates
        .iter()
        .map(|one| one.runs != (0, one.frame.runs.len()))
        .collect();

    let parts =
        match encode_screen_parts(&header, base, scroll_sent, updates.iter().copied(), budget) {
            Ok(parts) => parts,
            // The one refusal a screen of legal rows can earn.
            Err(EncodeError::Oversize) => return,
            Err(other) => panic!("a screen of legal rows was refused for {other:?}"),
        };

    let mut grouped: Vec<(u16, Vec<RowSpan>)> = Vec::new();
    for (place, frame) in parts.iter().enumerate() {
        assert!(
            frame.len() <= budget,
            "piece {place} is {} bytes of a {budget}-byte budget",
            frame.len()
        );
        let Ok(ServerMessage::Screen { part }) =
            ServerMessage::decode(&frame[PREFIX..], Version::LOCAL)
        else {
            panic!("piece {place} is not a screen this decoder takes");
        };
        let spans = match (place, part) {
            (
                0,
                ScreenPart::Head {
                    header: sent,
                    base: sent_base,
                    scroll,
                    pieces,
                    rows,
                },
            ) => {
                assert_eq!(sent, header, "the head describes another screen");
                assert_eq!(sent_base, base, "the head names another base");
                assert_eq!(scroll, scroll_sent, "the head restates another band");
                assert_eq!(
                    usize::from(pieces),
                    parts.len(),
                    "the head miscounted the pieces"
                );
                rows
            }
            (
                place,
                ScreenPart::Tail {
                    generation,
                    version,
                    pieces,
                    index,
                    rows,
                },
            ) => {
                assert_eq!(
                    (generation, version),
                    (header.generation, header.version),
                    "a tail belongs to another screen"
                );
                assert_eq!(usize::from(pieces), parts.len(), "a tail miscounted them");
                assert_eq!(usize::from(index), place, "a tail named the wrong place");
                rows
            }
            (place, _) => panic!("piece {place} is the wrong shape"),
        };
        let mut in_piece: Vec<(u16, u16)> = Vec::new();
        for span in spans {
            assert!(
                !in_piece.contains(&(span.row, span.col)),
                "piece {place} names row {} at column {} twice",
                span.row,
                span.col
            );
            assert!(
                u32::from(span.col) + u32::from(span.frame.cells) <= u32::from(size.cols),
                "piece {place} puts row {} past the grid",
                span.row
            );
            in_piece.push((span.row, span.col));
            match grouped.iter().position(|(row, _)| *row == span.row) {
                Some(at) => grouped[at].1.push(span),
                None => grouped.push((span.row, vec![span])),
            }
        }
    }

    // A chunk boundary is a run boundary: text joins, runs join, columns add.
    for (index, (row, mut chunks)) in grouped.into_iter().enumerate() {
        let cut = chunks.len() > 1;
        assert!(
            chunks.iter().all(|chunk| chunk.chunk == cut),
            "row {row} arrived in {} entries and the chunk flag disagrees",
            chunks.len()
        );
        chunks.sort_by_key(|chunk| chunk.col);
        let update = &updates[index];
        assert_eq!(row, update.row, "the pieces renamed a row");
        assert_eq!(
            chunks[0].col,
            column_of(update.frame, update.runs.0),
            "row {row} starts at the wrong column"
        );
        // Only the last chunk erases, or a cut row erases its own later chunks.
        let (last, earlier) = chunks.split_last().expect("a row with no chunks");
        assert_eq!(
            last.clear_tail, update.clear_tail,
            "row {row} lost the erase it was cut with"
        );
        assert!(
            earlier.iter().all(|chunk| !chunk.clear_tail),
            "row {row} erases its tail before the tail arrives"
        );
        let mut frame = RowFrame::default();
        let mut byte = chunks[0].byte;
        for chunk in chunks {
            assert_eq!(chunk.byte, byte, "row {row} has a gap in its text");
            byte += u32::try_from(chunk.frame.text.len()).expect("a short chunk");
            frame.text.push_str(&chunk.frame.text);
            frame.runs.extend(chunk.frame.runs);
            frame.cells += chunk.frame.cells;
        }
        // Against the range, not a re-slice: the oracle must not borrow the
        // arithmetic it judges.
        assert_eq!(
            frame.runs,
            update.frame.runs[update.runs.0..update.runs.1],
            "row {row} carries runs nobody asked for"
        );
        if !partial[index] {
            assert_eq!(frame, elide(update.frame), "row {row} did not reassemble");
        }
    }
});

/// The column a row's `index`th style run begins at.
fn column_of(row: &RowFrame, index: usize) -> u16 {
    row.runs[..index].iter().map(|run| run.cells).sum()
}
