//! Differential oracle for the repaint format: a capture rendered through the
//! client's emitter must land the terminal it came from. Both sides are
//! `braid_vt`, so this cannot catch SGR ghostty parses and other terminals do not.

use braid_client::render::{Assembled, Predictions, Screen};
use braid_proto::{
    ByteOff, Generation, GridSize, MAX_FRAME, MIN_DATAGRAM_FRAME, RowFrame, RowSpan, RowUpdate,
    ScreenHeader, ScreenPart, ScreenVersion, ScrollBand, ServerMessage, Version,
    encode_screen_parts,
};
use braid_vt::{ContinuationLimit, EffectSink, RepaintFrame, ScrollbackLimit, VtEngine};
use std::fmt::Write as _;
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

const STREAM_BUDGET: usize = MAX_FRAME as usize;

/// The smallest MTU a path is assumed to carry, which cuts wide rows into chunks.
const DATAGRAM_BUDGET: usize = MIN_DATAGRAM_FRAME;

const BUDGETS: [(&str, usize); 2] = [("stream", STREAM_BUDGET), ("datagram", DATAGRAM_BUDGET)];

/// Below any real MTU: the largest budget that cuts every capture here into
/// pieces. `MIN_DATAGRAM_FRAME` carries an eighty-column screen whole.
const CUT_BUDGET: usize = 160;

const CLEAR_VIEWPORT: &[u8] = b"\x1b[2J";

fn header(frame: &RepaintFrame, version: ScreenVersion) -> ScreenHeader {
    ScreenHeader {
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
    }
}

fn all_rows(rows: &[RowFrame]) -> impl Iterator<Item = RowUpdate<'_>> + Clone {
    rows.iter()
        .enumerate()
        .map(|(index, row)| RowUpdate::whole(u16::try_from(index).expect("a row index"), row))
}

/// The rows a delta names: the run range each row differs in, plus the erase a
/// shorter row owes.
fn changed_rows<'a>(base: &[RowFrame], now: &'a [RowFrame]) -> Vec<RowUpdate<'a>> {
    now.iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let previous = base.get(index)?;
            let runs = row.changed_span(previous)?;
            Some(RowUpdate {
                row: u16::try_from(index).expect("a row index"),
                frame: row,
                runs,
                clear_tail: row.painted_bytes() < previous.painted_bytes(),
            })
        })
        .collect()
}

fn part_rows(part: &ScreenPart) -> &[RowSpan] {
    match part {
        ScreenPart::Head { rows, .. } | ScreenPart::Tail { rows, .. } => rows,
    }
}

fn wired<'a>(
    head: &ScreenHeader,
    base: Option<ScreenVersion>,
    scroll: Option<ScrollBand>,
    rows: impl Iterator<Item = RowUpdate<'a>> + Clone,
    budget: usize,
) -> Vec<ScreenPart> {
    encode_screen_parts(head, base, scroll, rows, budget)
        .expect("a screen this size fits the wire")
        .iter()
        .map(|frame| {
            let ServerMessage::Screen { part } = ServerMessage::decode(&frame[4..], Version::LOCAL)
                .expect("the encoder's own frame decodes")
            else {
                panic!("expected a screen piece");
            };
            part
        })
        .collect()
}

/// A whole screen — no base, so it replaces whatever the client held.
fn whole(frame: &RepaintFrame, version: ScreenVersion, budget: usize) -> Vec<ScreenPart> {
    wired(
        &header(frame, version),
        None,
        None,
        all_rows(&frame.rows),
        budget,
    )
}

/// The screen the encoder was handed, as a piece with no wire in between.
fn unwired(frame: &RepaintFrame, version: ScreenVersion) -> ScreenPart {
    ScreenPart::Head {
        header: header(frame, version),
        base: None,
        scroll: None,
        pieces: 1,
        rows: all_rows(&frame.rows)
            .map(|update| RowSpan {
                row: update.row,
                chunk: false,
                col: 0,
                byte: 0,
                clear_tail: false,
                frame: update.frame.clone(),
            })
            .collect(),
    }
}

/// Deliver every piece of a screen to a client, in the order given.
fn feed(
    screen: &mut Screen,
    output: &mut Vec<u8>,
    parts: &[ScreenPart],
    terminal_rows: u16,
) -> Assembled {
    let mut assembled = None;
    for part in parts {
        let done = screen
            .part(output, part.clone(), terminal_rows, Predictions::Settled)
            .expect("a piece renders")
            .expect("a piece the client can apply");
        assert!(
            done.is_none() || assembled.is_none(),
            "a screen is assembled once, not once per piece"
        );
        assembled = assembled.or(done);
    }
    assembled.expect("every piece arrived, so the screen assembles")
}

fn render(parts: &[ScreenPart], terminal_rows: u16) -> Vec<u8> {
    let mut rendered = Vec::new();
    feed(&mut Screen::default(), &mut rendered, parts, terminal_rows);
    rendered
}

fn replay(size: GridSize, rendered: &[u8]) -> RepaintFrame {
    let mut replica = engine(size);
    replica.feed(rendered).expect("rendered bytes should parse");
    replica.repaint().expect("replica repaint").clone()
}

fn clears_the_viewport(rendered: &[u8]) -> bool {
    rendered
        .windows(CLEAR_VIEWPORT.len())
        .any(|window| window == CLEAR_VIEWPORT)
}

/// Every field a repaint carries but `dirty`: damage never goes on the wire.
fn assert_same(label: &str, source: &RepaintFrame, replica: &RepaintFrame) {
    assert_eq!(source.size, replica.size, "{label}: size");
    assert_eq!(source.modes, replica.modes, "{label}: modes");
    assert_eq!(source.cursor, replica.cursor, "{label}: cursor position");
    assert_eq!(
        source.cursor_visible, replica.cursor_visible,
        "{label}: cursor visibility"
    );
    assert_eq!(
        source.cursor_shape, replica.cursor_shape,
        "{label}: cursor shape"
    );
    assert_eq!(
        source.cursor_blinking, replica.cursor_blinking,
        "{label}: cursor blink"
    );
    assert_eq!(
        source.sticky.title, replica.sticky.title,
        "{label}: window title"
    );
    assert_eq!(
        source.sticky.kitty_keyboard, replica.sticky.kitty_keyboard,
        "{label}: kitty keyboard flags"
    );
    assert_eq!(source.rows.len(), replica.rows.len(), "{label}: row count");
    for (index, (expected, actual)) in source.rows.iter().zip(&replica.rows).enumerate() {
        assert_eq!(expected.text, actual.text, "{label}: row {index} text");
        assert_eq!(expected.cells, actual.cells, "{label}: row {index} cells");
        assert_eq!(expected.runs, actual.runs, "{label}: row {index} styles");
    }
}

fn captured(size: GridSize, capture: &[u8]) -> RepaintFrame {
    let mut source = engine(size);
    source.feed(capture).expect("capture should parse");
    // The engine refills one frame in place, so each side is cloned before use.
    source.repaint().expect("source repaint").clone()
}

fn round_trip(size: GridSize, capture: &[u8], budget: usize) -> (RepaintFrame, RepaintFrame) {
    let frame = captured(size, capture);
    let parts = whole(&frame, ScreenVersion::initial(), budget);
    let replayed = replay(size, &render(&parts, size.rows));
    (frame, replayed)
}

fn check(label: &str, size: GridSize, capture: &[u8]) {
    for (transport, budget) in BUDGETS {
        let (source, replica) = round_trip(size, capture, budget);
        assert_same(&format!("{label} ({transport})"), &source, &replica);
    }
}

const GRID: GridSize = GridSize { cols: 80, rows: 24 };

/// Wide enough that one colourful row outgrows a datagram on its own.
const WIDE: GridSize = GridSize {
    cols: 400,
    rows: 24,
};

/// Wide enough that a row of ZWJ families outgrows a datagram: at two hundred
/// columns such a row came to 1014 bytes and fitted one piece, cutting nothing.
const CLUSTERED: GridSize = GridSize { cols: 280, rows: 4 };

/// `ls --color`: 16-colour SGR, one attribute at a time, short rows.
fn listing_capture() -> Vec<u8> {
    concat!(
        "\x1b[0m\x1b[01;34mCargo.toml\x1b[0m  ",
        "\x1b[01;32mbrd\x1b[0m  ",
        "\x1b[01;36mlink\x1b[0m  ",
        "\x1b[40;33;01mtar.gz\x1b[0m\r\n",
        "plain.txt  \x1b[38;5;208mindexed\x1b[0m  \x1b[38;2;255;99;71mtruecolor\x1b[0m\r\n",
    )
    .into()
}

/// A full-screen editor: alt screen, bracketed paste, focus reporting, status line.
fn editor_capture() -> Vec<u8> {
    let mut capture = Vec::new();
    capture.extend_from_slice(b"\x1b[?1049h\x1b[?2004h\x1b[?1004h\x1b[?1006h\x1b[?1002h");
    capture.extend_from_slice(b"\x1b[2J\x1b[H");
    for line in 1..=20 {
        capture.extend_from_slice(
            format!("\x1b[38;5;244m{line:>3}\x1b[0m  \x1b[38;5;170mfn\x1b[0m main() {{\r\n")
                .as_bytes(),
        );
    }
    capture.extend_from_slice(b"\x1b[24;1H\x1b[7m");
    capture.extend_from_slice(&b" ".repeat(80));
    capture.extend_from_slice(b"\x1b[24;2Hmain.rs [+]\x1b[0m");
    capture.extend_from_slice(b"\x1b[5 q\x1b[3;8H");
    capture
}

/// An ncurses application: box drawing, a scrolling region, underline styles.
fn ncurses_capture() -> Vec<u8> {
    let mut capture = Vec::new();
    capture.extend_from_slice(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H");
    capture.extend_from_slice("\u{250c}".as_bytes());
    capture.extend_from_slice("\u{2500}".repeat(78).as_bytes());
    capture.extend_from_slice("\u{2510}\r\n".as_bytes());
    for row in 0..10 {
        capture.extend_from_slice(
            format!(
                "\u{2502}\x1b[48;5;{};38;5;15m cpu {row:>2} \x1b[0m\x1b[79;1H\u{2502}\r\n",
                17 + row
            )
            .as_bytes(),
        );
    }
    capture.extend_from_slice(b"\x1b[4:3m\x1b[58;5;196mcurly\x1b[0m ");
    capture.extend_from_slice(b"\x1b[4:4mdotted\x1b[0m \x1b[4:5mdashed\x1b[0m ");
    capture.extend_from_slice(b"\x1b[21mdouble\x1b[0m \x1b[4munder\x1b[0m\r\n");
    capture.extend_from_slice(b"\x1b[2;20r\x1b[15;1H");
    capture
}

/// Every boolean attribute at once, over a true-colour pair.
fn attributes_capture() -> Vec<u8> {
    b"\x1b[1;2;3;4;5;7;9;53;38;2;12;34;56;48;2;200;150;100mattrs\x1b[0m tail".into()
}

/// A row that fills the last column beside short rows: where a pending wrap or a
/// late erase eats a cell.
fn full_width_capture() -> Vec<u8> {
    let mut capture = Vec::new();
    capture.extend_from_slice(b"\x1b[H\x1b[48;5;19m");
    capture.extend_from_slice(&b"W".repeat(80));
    capture.extend_from_slice(b"\x1b[0m");
    capture.extend_from_slice(b"\x1b[2;1Hshort\r\n");
    capture.extend_from_slice(b"\x1b[3;1H\x1b[41m");
    capture.extend_from_slice(&b" ".repeat(80));
    capture.extend_from_slice(b"\x1b[0m\x1b[4;1Hafter");
    capture
}

/// The screen the shell leaves behind: no styling at all.
fn prompt_capture() -> Vec<u8> {
    b"user@host:~$ ls -la\r\ntotal 0\r\n".into()
}

/// A title and a keyboard stack, set by the byte stream on the way past.
fn sticky_capture() -> Vec<u8> {
    b"\x1b]2;deploy \xe2\x80\x94 prod\x1b\\\x1b[>5u\x1b[Hrunning".into()
}

/// A style run every cell on a 400-column grid, which exceeds a datagram frame.
fn dense_colour_capture() -> Vec<u8> {
    let mut capture = String::from("\x1b[2J\x1b[H");
    for row in 0..WIDE.rows {
        for cell in 0..WIDE.cols {
            let index = (u32::from(row) * u32::from(WIDE.cols) + u32::from(cell)) % 256;
            write!(capture, "\x1b[38;5;{index};48;5;{}m", (index + 137) % 256)
                .expect("string write");
            capture.push(char::from(
                b'a' + u8::try_from(index % 26).expect("a letter offset"),
            ));
        }
        if row + 1 != WIDE.rows {
            capture.push_str("\x1b[0m\r\n");
        }
    }
    // Deliberately not the last row; see `assert_cut_clear_of_the_cursor`.
    capture.push_str("\x1b[0m\x1b[3;5H");
    capture.into_bytes()
}

/// ZWJ family emoji, coloured one cluster at a time: the largest chunks this
/// format produces, and a cut that split a family would come back as other glyphs.
fn zwj_family_capture() -> Vec<u8> {
    let mut capture = String::from("\x1b[2J\x1b[H");
    for row in 0..CLUSTERED.rows {
        for cluster in 0..(CLUSTERED.cols / 2) {
            write!(capture, "\x1b[38;5;{}m", (cluster + row * 7) % 256).expect("string write");
            capture.push_str("\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}");
        }
        if row + 1 != CLUSTERED.rows {
            capture.push_str("\x1b[0m\r\n");
        }
    }
    // As above: the cursor is two rows off the one painted last.
    capture.push_str("\x1b[0m\x1b[2;9H");
    capture.into_bytes()
}

/// Wide glyphs, combining marks, emoji, a regional-indicator pair and a ZWJ family.
fn wide_captures() -> Vec<(&'static str, Vec<u8>)> {
    // A wide glyph on a row's last column is where a terminal inserts a spacer.
    let mut margin = String::from("\x1b[H");
    for _ in 0..(usize::from(GRID.cols) / 2 - 1) {
        margin.push('x');
    }
    margin.push('\u{4f60}');
    margin.push_str("wrapped");
    vec![
        ("cjk", "\x1b[H\u{4f60}\u{597d}\u{4e16}\u{754c} tail".into()),
        (
            "cjk styled",
            "\x1b[H\x1b[31m\u{6f22}\u{5b57}\x1b[0m plain \x1b[1;44m\u{30ab}\u{30ca}\x1b[0m".into(),
        ),
        (
            "combining marks",
            "\x1b[He\u{301}a\u{308}o\u{30a} \x1b[32mcafe\u{301}\x1b[0m".into(),
        ),
        (
            "emoji and zwj",
            "\x1b[H\u{1f44d} \u{1f1e8}\u{1f1e6} \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467} end"
                .into(),
        ),
        ("wide at the margin", margin.into()),
    ]
}

fn captures() -> Vec<(&'static str, Vec<u8>)> {
    let mut all = vec![
        ("ls --color", listing_capture()),
        ("editor", editor_capture()),
        ("ncurses", ncurses_capture()),
        ("attributes", attributes_capture()),
        ("full width", full_width_capture()),
        ("plain prompt", prompt_capture()),
        ("title and keyboard", sticky_capture()),
    ];
    all.extend(wide_captures());
    all
}

/// The wide and clustered captures are the one input class the cell model can get
/// wrong: a repaint that walked characters as columns passed every other one here.
/// Trailing blanks that carry no style are dropped at encode — a blank 1024x512
/// screen is 4146 bytes rather than 528434 — and none of that may reach the grid.
/// `CUT_BUDGET` then cuts every capture: a row split at a run boundary, a fragment
/// starting at a column nothing on the wire names, the rejoin.
#[test]
fn every_capture_round_trips_whole_elided_and_cut_to_the_bone() {
    let mut elided = false;
    let mut chunked = 0;
    for (label, capture) in captures() {
        check(label, GRID, &capture);

        let frame = captured(GRID, &capture);
        let held = unwired(&frame, ScreenVersion::initial());
        let sent = whole(&frame, ScreenVersion::initial(), STREAM_BUDGET);
        elided |= sent
            .iter()
            .flat_map(part_rows)
            .zip(&frame.rows)
            .any(|(sent, whole)| sent.frame.text.len() < whole.text.len());
        assert_eq!(
            render(std::slice::from_ref(&held), GRID.rows),
            render(&sent, GRID.rows),
            "{label}: elision changed what the client writes"
        );

        let parts = whole(&frame, ScreenVersion::initial(), CUT_BUDGET);
        assert!(
            parts.len() > 1,
            "{label}: a budget that cuts nothing tests nothing"
        );
        if parts.iter().flat_map(part_rows).any(|row| row.chunk) {
            chunked += 1;
        }
        assert_same(
            &format!("{label} cut to the bone"),
            &frame,
            &replay(GRID, &render(&parts, GRID.rows)),
        );
    }
    assert!(elided, "no capture exercised the elision");
    assert!(
        chunked > 0,
        "no capture was cut across a row, which is the half only this reaches"
    );
}

/// The cheap case must stay cheap, or the repaint format has taxed every
/// ordinary prompt to pay for `vim`.
#[test]
fn a_plain_prompt_carries_no_style_runs() {
    let (source, _) = round_trip(GRID, &prompt_capture(), STREAM_BUDGET);
    assert!(
        source.rows.iter().all(|row| row.runs.is_empty()),
        "an unstyled screen must not emit style runs"
    );
}

/// The intra-row diff is the only place this emitter speaks in columns, and so the
/// only place a wide glyph can drift; no round trip above reaches it. Where this
/// side's width table and libghostty's disagree the row is repainted whole.
#[test]
fn a_screen_diffed_behind_wide_glyphs_lands_on_the_terminal_s_columns() {
    for (transport, budget) in BUDGETS {
        for (label, capture) in wide_captures() {
            let mut source = engine(GRID);
            source.feed(&capture).expect("capture should parse");
            let held = source.repaint().expect("source repaint").clone();

            let mut screen = Screen::default();
            let mut rendered = Vec::new();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&held, ScreenVersion::initial(), budget),
                GRID.rows,
            );

            // Appended where the capture left the cursor, so the change sits
            // behind every cluster in front of it.
            source.feed(b" CHANGED").expect("capture should parse");
            let shown = source.repaint().expect("source repaint").clone();

            let mark = rendered.len();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&shown, ScreenVersion::initial().next(), budget),
                GRID.rows,
            );
            assert!(
                !clears_the_viewport(&rendered[mark..]),
                "{label} ({transport}): a screen the client could diff erased the viewport"
            );
            assert_same(
                &format!("{label} diffed behind wide glyphs ({transport})"),
                &shown,
                &replay(GRID, &rendered),
            );
        }
    }
}

/// Rows cut across pieces are painted when the last piece lands, which is after
/// the piece carrying them has already put the cursor back, so a capture whose
/// cursor sits on the row painted last could not tell a restoring client apart.
fn assert_cut_clear_of_the_cursor(label: &str, frame: &RepaintFrame, parts: &[ScreenPart]) {
    let last = parts
        .iter()
        .flat_map(part_rows)
        .filter(|row| row.chunk)
        .map(|row| row.row)
        .max()
        .expect("the capture exists to be cut across pieces, and was not");
    assert_ne!(
        Some(last),
        frame.cursor.map(|(_, row)| row),
        "{label}: the row painted last is the cursor's own, so a cursor left \
         on it would pass"
    );
}

/// The two captures wide enough that the wire cuts a row into chunks.
#[test]
fn a_screen_cut_into_chunks_round_trips() {
    for (label, size, capture) in [
        ("dense colour", WIDE, dense_colour_capture()),
        ("zwj families", CLUSTERED, zwj_family_capture()),
    ] {
        check(label, size, &capture);
        let frame = captured(size, &capture);
        let parts = whole(&frame, ScreenVersion::initial(), DATAGRAM_BUDGET);
        assert!(
            parts.len() > 1,
            "{label}: the capture that exists to be cut across pieces was not cut"
        );
        assert_cut_clear_of_the_cursor(label, &frame, &parts);
    }
}

/// A tail carries no header, so its rows are indexed against a grid only the head
/// names: what the client assembles must not depend on the order they arrived in.
/// The client holds sixteen overtaking tails and drops the rest, so captures cut
/// into more pieces than that are checked in order only.
#[test]
fn pieces_delivered_in_reverse_assemble_the_same_screen() {
    const HELD_TAILS: usize = 16;

    let mut multi_piece = 0;
    let mut chunked = 0;
    let mut all = captures()
        .into_iter()
        .map(|(label, capture)| (label, GRID, capture))
        .collect::<Vec<_>>();
    all.push(("zwj families", CLUSTERED, zwj_family_capture()));

    for (cut, budget) in [
        ("datagram", DATAGRAM_BUDGET),
        ("cut to the bone", CUT_BUDGET),
    ] {
        for (label, size, capture) in &all {
            let frame = captured(*size, capture);
            let parts = whole(&frame, ScreenVersion::initial(), budget);
            // A head is not a tail, so it is the pieces after it that are held.
            if parts.len() < 2 || parts.len() > HELD_TAILS + 1 {
                continue;
            }
            multi_piece += 1;
            if parts.iter().flat_map(part_rows).any(|row| row.chunk) {
                chunked += 1;
            }

            let mut forwards = Vec::new();
            let in_order = feed(&mut Screen::default(), &mut forwards, &parts, size.rows);
            let mut reversed: Vec<ScreenPart> = parts;
            reversed.reverse();
            let mut backwards = Vec::new();
            let out_of_order = feed(&mut Screen::default(), &mut backwards, &reversed, size.rows);

            assert_eq!(
                in_order, out_of_order,
                "{label} ({cut}): a reordered screen assembled as a different screen"
            );
            assert_same(
                &format!("{label} reversed ({cut})"),
                &replay(*size, &forwards),
                &replay(*size, &backwards),
            );
            // Against the capture too: two identically wrong terminals must not pass.
            assert_same(
                &format!("{label} reversed ({cut})"),
                &frame,
                &replay(*size, &backwards),
            );
        }
    }
    assert!(
        multi_piece > 0,
        "no capture was cut into pieces there was anything to reorder"
    );
    assert!(
        chunked > 0,
        "no reordered capture carried a row cut across pieces"
    );
}

/// A whole screen paints the difference against the rows the client already holds
/// rather than erasing the viewport and repainting every one of them. The other
/// half is the refusal: passthrough writes rows this model does not track, so the
/// first byte past a screen retires it as a paint base and the next must erase.
#[test]
fn a_whole_screen_diffs_against_the_terminal_it_already_painted() {
    const PASSTHROUGH: &[u8] = b"\r\na row no screen ever named\r\n";

    for (transport, budget) in BUDGETS {
        for (label, capture) in captures() {
            let mut source = engine(GRID);
            source
                .feed(b"\x1b[2J\x1b[Hthe screen this client already holds")
                .expect("capture should parse");
            let held = source.repaint().expect("source repaint").clone();
            source.feed(&capture).expect("capture should parse");
            let shown = source.repaint().expect("source repaint").clone();

            let version = ScreenVersion::initial();
            let mut screen = Screen::default();
            let mut rendered = Vec::new();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&held, version, budget),
                GRID.rows,
            );

            let mark = rendered.len();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&shown, version.next(), budget),
                GRID.rows,
            );
            assert!(
                !clears_the_viewport(&rendered[mark..]),
                "{label} ({transport}): a screen the client could diff erased the viewport"
            );
            assert_same(
                &format!("{label} diffed ({transport})"),
                &shown,
                &replay(GRID, &rendered),
            );

            // Steady state is byte-exact passthrough, and these bytes moved rows
            // the model still claims to hold.
            screen.observe(PASSTHROUGH);
            rendered.extend_from_slice(PASSTHROUGH);
            let mark = rendered.len();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&shown, version.next().next(), budget),
                GRID.rows,
            );
            assert!(
                clears_the_viewport(&rendered[mark..]),
                "{label} ({transport}): a screen was diffed against a terminal passthrough moved"
            );
            assert_same(
                &format!("{label} after passthrough ({transport})"),
                &shown,
                &replay(GRID, &rendered),
            );
        }
    }
}

fn filled_viewport() -> String {
    let mut filled = String::from("\x1b[H");
    for line in 1..=GRID.rows {
        write!(filled, "row {line} of the viewport").expect("string write");
        if line != GRID.rows {
            filled.push_str("\r\n");
        }
    }
    filled
}

/// The whole-viewport scroll both terminals are given once a band has landed.
const AFTERWARDS: &[u8] = b"\x1b[24;1H\r\nafter the band";

/// A band that moved by one line changes every row in it, and the client hands the
/// band to `CSI r`: under test are both the movement and the region it leaves.
fn assert_band_delta_lands(label: &str, band: ScrollBand, moved: &[u8]) {
    for (transport, budget) in BUDGETS {
        let mut source = engine(GRID);
        source
            .feed(filled_viewport().as_bytes())
            .expect("capture should parse");
        let before = source.repaint().expect("source repaint").clone();

        let mut screen = Screen::default();
        let mut rendered = Vec::new();
        feed(
            &mut screen,
            &mut rendered,
            &whole(&before, ScreenVersion::initial(), budget),
            GRID.rows,
        );
        let mut replica = engine(GRID);
        replica
            .feed(&rendered)
            .expect("rendered repaint should parse");

        source.feed(moved).expect("capture should parse");
        let after = source.repaint().expect("source repaint").clone();

        // The rows the client holds once it has applied the band: the delta's base.
        let (top, bottom) = (usize::from(band.top), usize::from(band.bottom));
        let lines = usize::from(band.lines);
        let mut base = before.rows.clone();
        base[top..bottom].rotate_left(lines);
        for row in base[top..bottom].iter_mut().rev().take(lines) {
            *row = RowFrame::default();
        }
        let rows = changed_rows(&base, &after.rows);
        assert!(
            rows.len() < after.rows.len(),
            "{label}: a delta naming every row is not a scroll"
        );

        let delta = wired(
            &header(&after, ScreenVersion::initial().next()),
            Some(ScreenVersion::initial()),
            Some(band),
            rows.iter().copied(),
            budget,
        );
        // A scroll is only representable on a screen that fits one piece: a client
        // that applied one and lost a piece holds every row at an unnameable offset.
        assert_eq!(
            delta.len(),
            1,
            "{label} ({transport}): a scroll is one piece"
        );

        let mut applied = Vec::new();
        feed(&mut screen, &mut applied, &delta, GRID.rows);
        let bytes = String::from_utf8(applied.clone()).expect("the client writes UTF-8");
        assert!(
            bytes.contains(&format!("\x1b[{};{}r", band.top + 1, band.bottom)),
            "{label} ({transport}): the band is moved inside its own region: {bytes:?}"
        );
        replica.feed(&applied).expect("rendered delta should parse");
        let scrolled = replica.repaint().expect("replica repaint").clone();

        assert_same(&format!("{label} ({transport})"), &after, &scrolled);
        assert_same(
            &format!("{label} against the screen it replaces ({transport})"),
            &replay(
                GRID,
                &render(&whole(&after, ScreenVersion::initial(), budget), GRID.rows),
            ),
            &scrolled,
        );

        // A scroll region outlives the screen that set it, so only a client that
        // restored the region lands the same grid on the scroll that follows.
        source.feed(AFTERWARDS).expect("capture should parse");
        let ended = source.repaint().expect("source repaint").clone();
        replica
            .feed(AFTERWARDS)
            .expect("rendered repaint should parse");
        assert_same(
            &format!("{label} once the region is restored ({transport})"),
            &ended,
            &replica.repaint().expect("replica repaint").clone(),
        );
    }
}

/// The whole viewport, and the interior band that made the verb worth having: a
/// one-line scroll of a 200x50 screen costs ~10.3 KiB of re-sent rows in a
/// viewport-only band and ~274 bytes in an interior one.
#[test]
fn a_scroll_band_lands_the_grid_a_full_screen_does() {
    for (label, band, moved) in [
        (
            "whole viewport",
            ScrollBand {
                top: 0,
                bottom: GRID.rows,
                lines: 3,
            },
            &b"\r\nscrolled one\r\nscrolled two\r\nscrolled three"[..],
        ),
        (
            "interior band",
            ScrollBand {
                top: 2,
                bottom: 20,
                lines: 2,
            },
            &b"\x1b[3;20r\x1b[20;1H\r\nbanded one\r\nbanded two\x1b[r"[..],
        ),
    ] {
        assert_band_delta_lands(label, band, moved);
    }
}

/// A row whose change starts past its first style run is named from that run and
/// not from column one; a row that got shorter carries an erase for the columns it
/// gave up. The columns either span leaves alone are the client's own, and a
/// client that placed them wrong shows it here.
#[test]
fn a_delta_span_lands_over_the_row_the_client_already_holds() {
    const HELD: &[u8] = b"\x1b[H\x1b[31mERROR\x1b[0m 00:00:00 waiting";

    for (transport, budget) in BUDGETS {
        for (label, change, names, complaint) in [
            (
                "partial row",
                &b"\x1b[1;13H59"[..],
                (|span: &RowSpan| span.col > 0) as fn(&RowSpan) -> bool,
                "nothing in this delta was a partial row",
            ),
            (
                "clear tail",
                &b"\x1b[1;7H\x1b[K"[..],
                (|span: &RowSpan| span.clear_tail) as fn(&RowSpan) -> bool,
                "the row that got shorter carried no erase",
            ),
        ] {
            let mut source = engine(GRID);
            source.feed(HELD).expect("capture should parse");
            let before = source.repaint().expect("source repaint").clone();

            let mut screen = Screen::default();
            let mut rendered = Vec::new();
            feed(
                &mut screen,
                &mut rendered,
                &whole(&before, ScreenVersion::initial(), budget),
                GRID.rows,
            );
            let mut replica = engine(GRID);
            replica
                .feed(&rendered)
                .expect("rendered repaint should parse");

            source.feed(change).expect("capture should parse");
            let after = source.repaint().expect("source repaint").clone();

            let rows = changed_rows(&before.rows, &after.rows);
            let delta = wired(
                &header(&after, ScreenVersion::initial().next()),
                Some(ScreenVersion::initial()),
                None,
                rows.iter().copied(),
                budget,
            );
            assert!(
                delta.iter().flat_map(part_rows).any(names),
                "{label} ({transport}): {complaint}"
            );

            let mut applied = Vec::new();
            feed(&mut screen, &mut applied, &delta, GRID.rows);
            replica.feed(&applied).expect("rendered delta should parse");
            assert_same(
                &format!("{label} ({transport})"),
                &after,
                &replica.repaint().expect("replica repaint").clone(),
            );
        }
    }
}

/// The three pieces of state a screen restates that never reach a `RepaintFrame`
/// — no DECSC accessor, a pending wrap on the cursor, session-filled deferred
/// OSCs — so each is checked by asking the replica what it did with them.
#[test]
fn the_state_a_screen_cannot_restate_is_replayed_into_the_terminal() {
    let frame = captured(GRID, b"\x1b[Hthe row the cursor sits at the end of");
    let mut head = header(&frame, ScreenVersion::initial());
    head.sticky.deferred = vec!["2;first".into(), "2;second".into()];
    head.sticky.saved_cursor = Some((7, 3));
    head.sticky.pending_wrap = true;
    head.cursor = Some((GRID.cols - 1, 0));

    let rendered = render(
        &wired(&head, None, None, all_rows(&frame.rows), STREAM_BUDGET),
        GRID.rows,
    );
    let bytes = String::from_utf8(rendered.clone()).expect("the client writes UTF-8");
    assert!(
        bytes.contains("\x1b]2;first\x1b\\\x1b]2;second\x1b\\"),
        "deferred bodies are replayed in order, always ST: {bytes:?}"
    );

    let mut replica = engine(GRID);
    replica
        .feed(&rendered)
        .expect("rendered repaint should parse");
    assert_eq!(
        replica
            .repaint()
            .expect("replica repaint")
            .sticky
            .title
            .as_deref(),
        Some("second"),
        "a terminal parsed both replayed sequences, and the later one won"
    );
    assert!(
        replica.cursor_cue().expect("a cursor cue").pending_wrap,
        "the wrap the session owed is owed by the terminal too"
    );

    // A saved cursor is only observable by asking for it back, as `ESC 8` does.
    replica.feed(b"\x1b8").expect("a restore should parse");
    assert_eq!(
        replica.repaint().expect("replica repaint").cursor,
        Some((7, 3)),
        "an `ESC 8` lands where the session's DECSC left the cursor"
    );
}

/// A session's grid is the smallest attached terminal, so a second client joining
/// shrinks it: the terminal must not still be showing the rows it gave up.
#[test]
fn the_region_outside_a_smaller_session_grid_is_cleared() {
    const SHARED: GridSize = GridSize {
        cols: GRID.cols,
        rows: 10,
    };

    let filled = filled_viewport();

    for (transport, budget) in BUDGETS {
        let alone = captured(GRID, filled.as_bytes());
        let shared = captured(SHARED, b"\x1b[Hthe grid a second client left");

        let mut screen = Screen::default();
        let mut rendered = Vec::new();
        feed(
            &mut screen,
            &mut rendered,
            &whole(&alone, ScreenVersion::initial(), budget),
            GRID.rows,
        );
        feed(
            &mut screen,
            &mut rendered,
            &whole(&shared, ScreenVersion::initial().next(), budget),
            GRID.rows,
        );

        let terminal = replay(GRID, &rendered);
        assert_eq!(
            terminal.rows[0].text.trim_end(),
            "the grid a second client left",
            "{transport}: the shrunken grid was not painted"
        );
        for (index, row) in terminal
            .rows
            .iter()
            .enumerate()
            .skip(usize::from(SHARED.rows))
        {
            assert!(
                row.text.trim().is_empty(),
                "{transport}: row {index} still shows the larger grid: {:?}",
                row.text
            );
        }
    }
}

/// Random SGR over random text on a fixed seed: the combinations nobody wrote.
#[test]
fn random_sgr_sequences_round_trip() {
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let attributes = [1_u8, 2, 3, 5, 7, 9, 53];
    let underlines = ["4", "21", "4:3", "4:4", "4:5"];

    for case in 0..64 {
        let mut capture = Vec::from(b"\x1b[2J\x1b[H".as_slice());
        for _ in 0..40 {
            let mut sgr = String::from("\x1b[0");
            for attribute in attributes {
                if next() % 4 == 0 {
                    write!(sgr, ";{attribute}").expect("string write");
                }
            }
            if next() % 3 == 0 {
                sgr.push(';');
                sgr.push_str(underlines[(next() % 5) as usize]);
            }
            match next() % 3 {
                0 => write!(sgr, ";38;5;{}", next() % 256).expect("string write"),
                1 => write!(
                    sgr,
                    ";38;2;{};{};{}",
                    next() % 256,
                    next() % 256,
                    next() % 256
                )
                .expect("string write"),
                _ => {}
            }
            match next() % 3 {
                0 => write!(sgr, ";48;5;{}", next() % 256).expect("string write"),
                1 => write!(
                    sgr,
                    ";48;2;{};{};{}",
                    next() % 256,
                    next() % 256,
                    next() % 256
                )
                .expect("string write"),
                _ => {}
            }
            sgr.push('m');
            capture.extend_from_slice(sgr.as_bytes());
            let width = usize::try_from(next() % 12 + 1).expect("a small count");
            for _ in 0..width {
                capture.push(b'a' + u8::try_from(next() % 26).expect("a letter offset"));
            }
        }
        capture.extend_from_slice(b"\x1b[0m");
        check(&format!("random case {case}"), GRID, &capture);
    }
}
