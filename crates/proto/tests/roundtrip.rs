//! Every message variant survives the wire unchanged, and no damaged frame
//! reaches a panic. Cases come from a seeded xorshift so a failure repeats.

use braid_proto::{
    ByteOff, CAPABILITY_BYTES, Capability, CellStyle, ClientId, ClientMessage, CmdSeq,
    ConfirmedOutput, CursorShape, DatagramOffer, DecodeError, DetachReason, EncodeError,
    ForwardResetReason, ForwardTarget, Generation, GridSize, InputCue, MAX_ATTACHMENTS,
    MAX_CLIENT_FRAME, MAX_COMMAND, MAX_COMMAND_WORDS, MAX_DEFERRED, MAX_DEFERRED_BYTES, MAX_ENV,
    MAX_ENV_VARS, MAX_FORWARD_CHUNK, MAX_FORWARD_HOST, MAX_FRAME, MAX_INPUT_CHUNK, MAX_MATCH_LINE,
    MAX_MATCHES, MAX_OUTPUT_CHUNK, MAX_PATTERN, MAX_RUN_BYTES, MAX_SESSIONS, MAX_TERM, MAX_TITLE,
    MIN_DATAGRAM_FRAME, ModeSet, RejectReason, ResumeRequest, RowChunk, RowFrame, RowSpan,
    RowUpdate, SackRuns, ScreenHeader, ScreenPart, ScreenVersion, ScrollBand, SearchMatch,
    ServerMessage, SessionEnv, SessionId, SessionSummary, StickyState, StreamId, StyleAttrs,
    StyleColor, StyleRun, UnderlineStyle, Version, VersionRange, encode_screen_parts, read_frame,
    screen::MAX_CLUSTER_BYTES,
};
use std::collections::HashSet;
use std::io::Cursor;
use std::mem::{Discriminant, discriminant};

/// Every row in the screen's own order.
fn in_order(rows: &[RowFrame]) -> impl Iterator<Item = RowUpdate<'_>> + Clone + '_ {
    rows.iter()
        .enumerate()
        .map(|(row, frame)| RowUpdate::whole(u16::try_from(row).expect("a row index"), frame))
}

fn one_row(row: &RowFrame) -> impl Iterator<Item = RowUpdate<'_>> + Clone {
    std::iter::once(RowUpdate::whole(0, row))
}

/// A whole row as one piece names it.
fn span(row: u16, frame: RowFrame) -> RowSpan {
    RowSpan {
        row,
        chunk: false,
        col: 0,
        byte: 0,
        clear_tail: false,
        frame,
    }
}

/// Bytes `encode` prepends and `decode` never sees.
const PREFIX: usize = 4;

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn flag(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.below(1 << 8)).expect("a byte")
    }

    fn u16(&mut self) -> u16 {
        u16::try_from(self.below(1 << 16)).expect("a 16-bit value")
    }

    fn u32(&mut self) -> u32 {
        u32::try_from(self.below(1 << 32)).expect("a 32-bit value")
    }

    /// The extremes the decoder bounds against, and small sizes otherwise.
    fn dimension(&mut self, max: u16) -> u16 {
        match self.below(8) {
            0 => max,
            1 => 1,
            _ => u16::try_from(self.below(u64::from(max).min(64)) + 1).expect("a dimension"),
        }
    }
}

/// Cells, characters and bytes are three different numbers here; ASCII alone makes all three agree.
const GRAPHEMES: [(&str, u16); 8] = [
    ("a", 1),
    ("~", 1),
    ("é", 1),
    ("e\u{301}", 1),
    ("漢", 2),
    ("👍", 2),
    ("🇨🇦", 2),
    ("👨\u{200d}👩\u{200d}👧", 2),
];

/// One row's worth of cells: the text, and what each cell contributed to it.
fn row_cells(rng: &mut Rng, cols: u16) -> (String, Vec<(u32, u16)>) {
    let mut text = String::new();
    let mut cells = Vec::new();
    let mut used = 0_u16;
    loop {
        let (grapheme, width) = GRAPHEMES[usize::try_from(rng.below(8)).expect("an index")];
        if used + width > cols {
            break;
        }
        text.push_str(grapheme);
        cells.push((
            u32::try_from(grapheme.len()).expect("a short grapheme"),
            width,
        ));
        used += width;
    }
    (text, cells)
}

fn short_text(rng: &mut Rng, max: u64) -> String {
    let cells = u16::try_from(rng.below(max)).expect("a short length");
    row_cells(rng, cells).0
}

fn fill<const N: usize>(rng: &mut Rng) -> [u8; N] {
    let mut out = [0; N];
    for slot in &mut out {
        *slot = rng.byte();
    }
    out
}

/// Small mostly, exactly at the bound sometimes, and one byte past it often enough to be refused.
fn payload_len(rng: &mut Rng, bound: usize) -> usize {
    match rng.below(16) {
        0 => bound,
        1 => bound + 1,
        2 => 0,
        _ => usize::try_from(rng.below(512)).expect("a small length"),
    }
}

fn chunk(rng: &mut Rng, bound: usize) -> Vec<u8> {
    (0..payload_len(rng, bound)).map(|_| rng.byte()).collect()
}

fn style_color(rng: &mut Rng) -> StyleColor {
    match rng.below(3) {
        0 => StyleColor::Default,
        1 => StyleColor::Palette(rng.byte()),
        _ => StyleColor::Rgb(rng.byte(), rng.byte(), rng.byte()),
    }
}

fn cell_style(rng: &mut Rng) -> CellStyle {
    CellStyle {
        fg: style_color(rng),
        bg: style_color(rng),
        underline_color: style_color(rng),
        attrs: StyleAttrs::from_bits(rng.byte()),
        underline: UnderlineStyle::from_wire(u8::try_from(rng.below(6)).expect("an underline"))
            .expect("a wire value the table names"),
    }
}

/// Runs tiling a prefix of the row, which is the only shape the decoder takes.
fn style_runs(rng: &mut Rng, cols: u16, cells: &[(u32, u16)]) -> Vec<StyleRun> {
    let mut runs = Vec::new();
    let mut index = 0_usize;
    for _ in 0..rng.below(u64::from(cols).min(8) + 1) {
        let left = u64::try_from(cells.len() - index).expect("a cell count");
        let take = usize::try_from(rng.below(left + 1)).expect("a cell count");
        let (bytes, width) = cells[index..index + take].iter().fold(
            (0_u32, 0_u16),
            |(bytes, width), (cell_bytes, cell_width)| (bytes + cell_bytes, width + cell_width),
        );
        runs.push(StyleRun {
            cells: width,
            bytes,
            style: cell_style(rng),
        });
        index += take;
    }
    runs
}

/// One row, or an empty one once the screen has spent its byte budget.
fn row_frame(rng: &mut Rng, cols: u16, budget: &mut usize) -> RowFrame {
    let width = u16::try_from(rng.below(u64::from(cols.min(48)) + 1)).expect("a cell count");
    let (mut text, mut cells) = row_cells(rng, width);
    let used: u16 = cells.iter().map(|(_, width)| width).sum();
    // Trailing blanks no style paints are the one thing the encoder drops.
    let blanks = u16::try_from(rng.below(u64::from(cols - used).min(8) + 1)).expect("a cell count");
    for _ in 0..blanks {
        text.push(' ');
        cells.push((1, 1));
    }
    let runs = style_runs(rng, cols, &cells);
    let row = RowFrame {
        cells: cells.iter().map(|(_, width)| width).sum(),
        text,
        runs,
    };
    // Widest encoding: length, text, cell count, run count, all-RGB runs.
    let cost = 8 + row.text.len() + row.runs.len() * 20;
    if cost > *budget {
        return RowFrame::default();
    }
    *budget -= cost;
    row
}

/// The frame less the header, the sticky block and the 16 bytes each row costs beyond its text.
fn frame_budget(size: GridSize) -> usize {
    usize::try_from(MAX_FRAME).expect("a 32-bit limit fits a usize")
        - 1024
        - MAX_DEFERRED_BYTES
        - 16 * usize::from(size.rows)
}

fn grid(rng: &mut Rng) -> GridSize {
    GridSize::new(
        rng.dimension(GridSize::MAX_COLS),
        rng.dimension(GridSize::MAX_ROWS),
    )
    .expect("a dimension inside the grid bounds")
}

fn generation(rng: &mut Rng) -> Generation {
    // xorshift64 never yields zero, and zero is the one rejected value.
    Generation::from_u64(rng.next_u64()).expect("a non-zero generation")
}

fn version(rng: &mut Rng) -> ScreenVersion {
    ScreenVersion::from_u64(rng.next_u64()).expect("a non-zero version")
}

/// Outside the grid often enough to reach the refusal: a clamp would hide a server-side desync.
fn cursor(rng: &mut Rng, size: GridSize) -> Option<(u16, u16)> {
    match rng.below(8) {
        0 => None,
        1 => Some((size.cols, rng.u16() % size.rows)),
        2 => Some((rng.u16() % size.cols, size.rows)),
        3 => Some((rng.u16(), rng.u16())),
        _ => Some((rng.u16() % size.cols, rng.u16() % size.rows)),
    }
}

/// OSC bodies at the bounds the encoder drops from and past the one the decoder refuses.
fn deferred(rng: &mut Rng) -> Vec<String> {
    match rng.below(12) {
        0..=5 => Vec::new(),
        6 => vec![String::from("52;c;aGVsbG8=")],
        // Past the entry bound: the encoder keeps the newest sixteen.
        7 => (0..20).map(|mark| format!("133;A;{mark}")).collect(),
        // Past the byte bound, in one oversize entry and in many small ones.
        8 => vec!["8;;https://example/".repeat(512)],
        9 => (0..8).map(|_| "0;".to_owned() + &"t".repeat(600)).collect(),
        10 => vec![String::from("7;file://host/tmp"), String::from("9;done")],
        _ => vec![String::from("0;a\u{7}title")],
    }
}

fn sticky_state(rng: &mut Rng, size: GridSize) -> StickyState {
    StickyState {
        title: rng.flag().then(|| short_text(rng, 24).into()),
        kitty_keyboard: rng.byte(),
        bell: rng.flag(),
        saved_cursor: rng.flag().then(|| cursor(rng, size)).flatten(),
        pending_wrap: rng.flag(),
        deferred: deferred(rng),
    }
}

fn screen_header(rng: &mut Rng, size: GridSize) -> ScreenHeader {
    ScreenHeader {
        generation: generation(rng),
        version: version(rng),
        next_off: ByteOff::from_u64(rng.next_u64()),
        size,
        cursor: cursor(rng, size),
        cursor_visible: rng.flag(),
        cursor_shape: CursorShape::from_wire(u8::try_from(rng.below(4)).expect("a shape"))
            .expect("a wire value the table names"),
        cursor_blinking: rng.flag(),
        modes: ModeSet::from_bits(rng.u32()),
        sticky: sticky_state(rng, size),
    }
}

/// Non-descending: a row may be named by several spans, and it is their *columns* that must ascend.
fn part_indices(rng: &mut Rng, rows: u16, count: u64) -> Vec<u16> {
    let mut ascending = Vec::new();
    let mut next = 0_u16;
    for _ in 0..count {
        if next >= rows {
            break;
        }
        ascending.push(next);
        if !rng.flag() {
            next = next.saturating_add(u16::try_from(rng.below(3) + 1).expect("a step"));
        }
    }
    let damage = rng.below(12);
    if damage == 0 && ascending.len() > 1 {
        ascending.reverse();
    } else if let Some(last) = ascending.last_mut() {
        match damage {
            1 => *last = rows,
            // A row index carrying a flag bit is one the encoder cannot restate.
            2 => *last |= ROW_CHUNK_FLAG,
            3 => *last |= ROW_CLEAR_TAIL_FLAG,
            _ => {}
        }
    }
    ascending
}

/// Restated rather than reached for: no legal row index reaches bit 14.
const ROW_CHUNK_FLAG: u16 = 0x8000;
const ROW_CLEAR_TAIL_FLAG: u16 = 0x4000;

/// Where a span lands, and the two refusals: off the end of the row, and an unreachable byte.
fn span_place(rng: &mut Rng, cols: u16, frame: &RowFrame) -> (u16, u32) {
    let room = cols.saturating_sub(frame.cells);
    let col = match rng.below(12) {
        0 => cols,
        1 => room.saturating_add(1),
        _ => u16::try_from(rng.below(u64::from(room) + 1)).expect("a column"),
    };
    let ceiling = u64::from(cols) * MAX_CLUSTER_BYTES as u64;
    let byte = match rng.below(12) {
        0 => u32::MAX,
        _ => u32::try_from(rng.below(ceiling.saturating_sub(frame.text.len() as u64) + 1))
            .expect("an offset"),
    };
    (col, byte)
}

/// A movement a client can apply, and the ones the decoder refuses: none, too far, off-grid, empty.
fn scroll(rng: &mut Rng, rows: u16) -> Option<ScrollBand> {
    let band = |top, bottom, lines| Some(ScrollBand { top, bottom, lines });
    match rng.below(10) {
        0..=3 => None,
        4 if rows > 1 => band(
            0,
            rows,
            u16::try_from(rng.below(u64::from(rows))).unwrap_or(0) + 1,
        ),
        // The band the shape exists for: everything above a status bar.
        5 if rows > 1 => band(0, rows - 1, 1),
        6 if rows > 1 => band(1, rows, 1),
        7 => band(0, rows, 0),
        8 => band(0, rows.saturating_add(1), 1),
        _ => band(rng.u16(), rng.u16(), rng.u16()),
    }
}

/// One, several, and the none the decoder refuses.
fn pieces(rng: &mut Rng) -> u16 {
    match rng.below(8) {
        0 => 0,
        1 => u16::MAX,
        _ => u16::try_from(rng.below(4) + 1).expect("a piece count"),
    }
}

/// A later piece's place, and the edges refused: the `Head`'s own index, and past the last piece.
fn part_index(rng: &mut Rng, pieces: u16) -> u16 {
    match rng.below(8) {
        0 => 0,
        1 => pieces,
        2 => rng.u16(),
        _ if pieces > 1 => u16::try_from(rng.below(u64::from(pieces) - 1) + 1).expect("an index"),
        _ => 1,
    }
}

/// A `Tail`'s rows go against a grid it does not name, which is the reassembling client's to check.
fn screen_part(rng: &mut Rng) -> ScreenPart {
    let size = grid(rng);
    let count = rng.below(u64::from(size.rows) + 1);
    let mut budget = frame_budget(size);
    let rows: Vec<RowSpan> = part_indices(rng, size.rows, count)
        .into_iter()
        .map(|row| {
            let frame = row_frame(rng, size.cols, &mut budget);
            let (col, byte) = span_place(rng, size.cols, &frame);
            RowSpan {
                row,
                chunk: rng.flag(),
                col,
                byte,
                clear_tail: rng.flag(),
                frame,
            }
        })
        .collect();
    let pieces = pieces(rng);
    if rng.flag() {
        ScreenPart::Head {
            header: screen_header(rng, size),
            base: rng.flag().then(|| version(rng)),
            scroll: scroll(rng, size.rows),
            pieces,
            rows,
        }
    } else {
        ScreenPart::Tail {
            generation: generation(rng),
            version: version(rng),
            pieces,
            index: part_index(rng, pieces),
            rows,
        }
    }
}

/// Absent for a daemon on a link that blocks UDP, which is not broken.
fn offer(rng: &mut Rng) -> Option<DatagramOffer> {
    if !rng.flag() {
        return None;
    }
    let cid = fill(rng);
    let secret = fill(rng);
    let ip = fill(rng);
    Some(DatagramOffer {
        ip,
        port: rng.u16(),
        cid,
        secret,
    })
}

fn cue(rng: &mut Rng) -> InputCue {
    if rng.flag() {
        InputCue::Opaque
    } else {
        InputCue::Echoing { room: rng.u16() }
    }
}

/// Zero on the wire is `None` and nothing else, so both states are generated.
fn opt_seq(rng: &mut Rng) -> Option<CmdSeq> {
    rng.flag()
        .then(|| CmdSeq::from_u64(rng.next_u64()).expect("xorshift64 never yields zero"))
}

fn capability(rng: &mut Rng) -> Capability {
    Capability::from_bytes(fill(rng))
}

fn session_id(rng: &mut Rng) -> SessionId {
    SessionId::from_bytes(fill(rng))
}

fn client_id(rng: &mut Rng) -> ClientId {
    ClientId::from_bytes(fill(rng))
}

/// Both sides of `[A-Za-z0-9._+-]{1,64}`: a `TERM` reaches a child process's environment.
fn term(rng: &mut Rng) -> String {
    const NAMES: [&str; 5] = [
        "xterm",
        "xterm-256color",
        "screen.linux",
        "rxvt-unicode-256color",
        "vt100+fnkeys",
    ];
    match rng.below(8) {
        0 => String::new(),
        1 => "x".repeat(MAX_TERM + 1),
        2 => String::from("xterm 256color"),
        3 => String::from("xterm\u{1b}[0m"),
        4 => "x".repeat(MAX_TERM),
        _ => String::from(NAMES[usize::try_from(rng.below(5)).expect("an index")]),
    }
}

/// Both bounds and past each, with names and values on both sides of the rules.
fn env(rng: &mut Rng) -> SessionEnv {
    const BAD_NAMES: [&str; 4] = ["1PATH", "SSH-TTY", "", "PATH=x"];
    match rng.below(8) {
        // Sixteen variables of a three-byte name and three of framing: `MAX_ENV`, or one past it.
        0 | 1 => {
            let over = rng.flag();
            SessionEnv(
                (0..MAX_ENV_VARS)
                    .map(|index| {
                        let extra = usize::from(over && index == 0);
                        (format!("V{index:02}"), "x".repeat(250 + extra))
                    })
                    .collect(),
            )
        }
        2 => SessionEnv(
            (0..=MAX_ENV_VARS)
                .map(|index| (format!("V{index:02}"), String::from("y")))
                .collect(),
        ),
        3 => SessionEnv(vec![(
            String::from("SSH_TTY"),
            format!("/dev/pts/{}\u{1b}", rng.below(64)),
        )]),
        4 => SessionEnv(vec![(
            String::from(BAD_NAMES[usize::try_from(rng.below(4)).expect("an index")]),
            String::from("value"),
        )]),
        _ => SessionEnv(
            (0..rng.below(4))
                .map(|index| (format!("BRD_{index}"), short_text(rng, 12)))
                .collect(),
        ),
    }
}

/// At `MAX_COMMAND`, past it, and carrying the control bytes it is printed without.
fn command(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => "x".repeat(MAX_COMMAND),
        1 => "x".repeat(MAX_COMMAND + 1),
        2 => format!("vim\u{1b}]0;{}\u{7}", rng.below(9)),
        3 => String::new(),
        _ => short_text(rng, 24),
    }
}

/// At `MAX_PATTERN`, past it, the empty pattern that matches everything, and control bytes.
fn pattern(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => "x".repeat(MAX_PATTERN),
        1 => "x".repeat(MAX_PATTERN + 1),
        2 => String::new(),
        3 => format!("err\u{1b}[2J{}", rng.below(9)),
        _ => short_text(rng, 24),
    }
}

/// At `MAX_MATCH_LINE`, past it, control bytes, and the wide glyphs real terminal text is made of.
fn match_line(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => "x".repeat(MAX_MATCH_LINE),
        1 => "x".repeat(MAX_MATCH_LINE + 1),
        2 => format!("make\u{1b}]0;{}\u{7}", rng.below(9)),
        3 => String::new(),
        _ => short_text(rng, 48),
    }
}

fn attachments(rng: &mut Rng) -> u16 {
    let bound = u64::try_from(MAX_ATTACHMENTS).expect("an attachment count");
    u16::try_from(rng.below(bound + 1)).expect("an attachment count")
}

fn argv(rng: &mut Rng) -> Vec<String> {
    match rng.below(8) {
        // Sixteen words of six bytes and two of framing each is exactly `MAX_COMMAND`.
        0 | 1 => {
            let over = rng.flag();
            (0..MAX_COMMAND_WORDS)
                .map(|index| {
                    let tail = if over && index == 0 { "x" } else { "" };
                    format!("word{index:02}{tail}")
                })
                .collect()
        }
        2 => (0..=MAX_COMMAND_WORDS)
            .map(|index| format!("w{index}"))
            .collect(),
        3 => vec![String::from("tmux"), String::new()],
        4 => vec![String::from("tmux"), String::from("attach")],
        _ => Vec::new(),
    }
}

fn session_list(rng: &mut Rng) -> Vec<SessionSummary> {
    let bound = u64::try_from(MAX_SESSIONS).expect("a session count");
    let count = match rng.below(8) {
        0 => bound,
        1 => bound + 1,
        _ => rng.below(6),
    };
    (0..count)
        .map(|_| SessionSummary {
            session_id: session_id(rng),
            size: grid(rng),
            attachments: attachments(rng),
            active_unix: rng.next_u64(),
            command: command(rng),
        })
        .collect()
}

/// None, `MAX_MATCHES`, and one past it.
fn search_matches(rng: &mut Rng) -> Vec<SearchMatch> {
    let bound = u64::try_from(MAX_MATCHES).expect("a match count");
    let count = match rng.below(8) {
        0 => bound,
        1 => bound + 1,
        2 => 0,
        _ => rng.below(6),
    };
    (0..count)
        .map(|_| SearchMatch {
            session_id: session_id(rng),
            distance: rng.u32(),
            line: match_line(rng),
        })
        .collect()
}

/// The first stream a client allocates, the last one it can, and between.
fn stream_id(rng: &mut Rng) -> StreamId {
    match rng.below(8) {
        0 => StreamId::first(),
        1 => StreamId::from_u32(u32::MAX).expect("a stream id"),
        _ => StreamId::from_u32(rng.u32() | 1).expect("a non-zero stream id"),
    }
}

/// A host reaches a resolver and a diagnostic: empty, over-long and control bytes are refusals.
fn forward_host(rng: &mut Rng) -> String {
    match rng.below(8) {
        0 => "x".repeat(MAX_FORWARD_HOST),
        1 => "x".repeat(MAX_FORWARD_HOST + 1),
        2 => String::new(),
        3 => format!("db\u{1b}]0;{}\u{7}", rng.below(9)),
        4 => String::from("127.0.0.1"),
        5 => String::from("::1"),
        6 => String::from("münchen.internal"),
        _ => format!("db{}.internal", rng.below(16)),
    }
}

/// A destination port, and the zero that is not one.
fn forward_port(rng: &mut Rng) -> u16 {
    match rng.below(8) {
        0 => 0,
        1 => u16::MAX,
        _ => u16::try_from(rng.below(u64::from(u16::MAX)) + 1).expect("a port"),
    }
}

fn forward_target(rng: &mut Rng) -> ForwardTarget {
    ForwardTarget {
        host: forward_host(rng),
        port: forward_port(rng),
    }
}

/// A receive window: shut, wide open, and everything between.
fn forward_window(rng: &mut Rng) -> u32 {
    match rng.below(8) {
        0 => 0,
        1 => u32::MAX,
        _ => rng.u32(),
    }
}

fn forward_reset_reason(rng: &mut Rng) -> ForwardResetReason {
    match rng.below(5) {
        0 => ForwardResetReason::Refused,
        1 => ForwardResetReason::Unreachable,
        2 => ForwardResetReason::Closed,
        3 => ForwardResetReason::Limit,
        _ => ForwardResetReason::Internal,
    }
}

fn client_message(rng: &mut Rng, kind: u64) -> ClientMessage {
    let seq = CmdSeq::from_u64(rng.next_u64()).expect("xorshift64 never yields zero");
    match kind {
        0 => ClientMessage::Hello {
            versions: VersionRange::LOCAL,
            size: grid(rng),
            term: term(rng),
            env: env(rng),
            command: argv(rng),
            client: client_id(rng),
        },
        1 => ClientMessage::Input {
            seq,
            bytes: chunk(rng, MAX_INPUT_CHUNK),
        },
        2 => ClientMessage::Resize {
            seq,
            size: grid(rng),
        },
        3 => ClientMessage::RequestRepaint { seq },
        4 => ClientMessage::ScreenAck {
            generation: generation(rng),
            version: version(rng),
        },
        5 => ClientMessage::Close { seq },
        6 => ClientMessage::Resume {
            versions: VersionRange::LOCAL,
            seq,
            request: ResumeRequest {
                session_id: session_id(rng),
                capability: capability(rng),
                confirmed_output: ConfirmedOutput {
                    generation: generation(rng),
                    next_off: ByteOff::from_u64(rng.next_u64()),
                },
                client: client_id(rng),
            },
        },
        7 => ClientMessage::Detach { seq },
        8 => ClientMessage::Pong {
            token: rng.next_u64(),
            consumed: ByteOff::from_u64(rng.next_u64()),
        },
        9 => ClientMessage::ListSessions,
        10 => ClientMessage::KillSession {
            session_id: session_id(rng),
        },
        11 => ClientMessage::Consumed {
            off: ByteOff::from_u64(rng.next_u64()),
        },
        12 => ClientMessage::Search {
            pattern: pattern(rng),
            limit: rng.u16(),
        },
        13 => ClientMessage::ForwardOpen {
            seq,
            stream: stream_id(rng),
            target: forward_target(rng),
        },
        14 => ClientMessage::ForwardData {
            stream: stream_id(rng),
            off: ByteOff::from_u64(rng.next_u64()),
            fin: rng.flag(),
            bytes: chunk(rng, MAX_FORWARD_CHUNK),
        },
        15 => ClientMessage::ForwardAck {
            held: SackRuns::EMPTY,
            stream: stream_id(rng),
            off: ByteOff::from_u64(rng.next_u64()),
            window: forward_window(rng),
        },
        16 => ClientMessage::ForwardReset {
            stream: stream_id(rng),
            reason: forward_reset_reason(rng),
        },
        _ => ClientMessage::HelloForward {
            versions: VersionRange::LOCAL,
            client: client_id(rng),
        },
    }
}

fn server_message(rng: &mut Rng, kind: u64) -> ServerMessage {
    match kind {
        0 => ServerMessage::Hello {
            version: Version::LOCAL,
            size: grid(rng),
            session_id: session_id(rng),
            capability: capability(rng),
            offer: offer(rng),
        },
        1 => ServerMessage::Output {
            off: ByteOff::from_u64(rng.next_u64()),
            bytes: chunk(rng, MAX_OUTPUT_CHUNK),
            cue: cue(rng),
            echo_ack: opt_seq(rng),
        },
        2 => ServerMessage::Exit {
            code: rng.u32().cast_signed(),
        },
        3 => ServerMessage::Reject {
            reason: reject_reason(rng),
        },
        4 => ServerMessage::CommandAck {
            highest: opt_seq(rng),
        },
        5 => ServerMessage::Detached {
            reason: if rng.flag() {
                DetachReason::Requested
            } else {
                DetachReason::Replaced
            },
        },
        6 => ServerMessage::Ping {
            token: rng.next_u64(),
            echo_ack: opt_seq(rng),
            interval_ms: rng.u16(),
        },
        7 => ServerMessage::SessionList {
            sessions: session_list(rng),
        },
        8 => ServerMessage::SearchResults {
            matches: search_matches(rng),
        },
        9 => ServerMessage::Screen {
            part: screen_part(rng),
        },
        10 => ServerMessage::ForwardData {
            stream: stream_id(rng),
            off: ByteOff::from_u64(rng.next_u64()),
            fin: rng.flag(),
            bytes: chunk(rng, MAX_FORWARD_CHUNK),
        },
        11 => ServerMessage::ForwardAck {
            held: SackRuns::EMPTY,
            stream: stream_id(rng),
            off: ByteOff::from_u64(rng.next_u64()),
            window: forward_window(rng),
        },
        12 => ServerMessage::ForwardReset {
            stream: stream_id(rng),
            reason: forward_reset_reason(rng),
        },
        _ => ServerMessage::HelloForward {
            version: Version::LOCAL,
            session_id: session_id(rng),
            capability: capability(rng),
            offer: offer(rng),
        },
    }
}

fn version_range(rng: &mut Rng) -> VersionRange {
    let oldest = 1 + u16::try_from(rng.below(64)).expect("a small version");
    let span = u16::try_from(rng.below(8)).expect("a small span");
    VersionRange::new(oldest, oldest + span).expect("an ordered range")
}

/// Every reason, and the payload that makes `Version` a second shape rather than a discriminant.
fn reject_reason(rng: &mut Rng) -> RejectReason {
    match rng.below(7) {
        0 => RejectReason::Version {
            server: version_range(rng),
            client: version_range(rng),
        },
        1 => RejectReason::UnknownSession,
        2 => RejectReason::SequenceGap,
        3 => RejectReason::InputBacklog,
        4 => RejectReason::Internal,
        5 => RejectReason::TooManySessions,
        _ => RejectReason::TooManyAttachments,
    }
}

/// Restated rather than reached for: asking the encoder what it accepts proves nothing.
fn valid_term(term: &str) -> bool {
    !term.is_empty()
        && term.len() <= MAX_TERM
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.' | b'_'))
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn env_exceeds_bound(env: &SessionEnv) -> bool {
    env.0.len() > MAX_ENV_VARS
        || env
            .0
            .iter()
            .map(|(name, value)| name.len() + value.len() + 3)
            .sum::<usize>()
            > MAX_ENV
        || env.0.iter().any(|(name, value)| {
            name.len() > usize::from(u8::MAX)
                || !valid_env_name(name)
                || value.chars().any(char::is_control)
        })
}

/// A row's text is bounded by the cells it claims, at `MAX_CLUSTER_BYTES` each.
fn row_exceeds_its_cells(row: &RowFrame) -> bool {
    row.painted_bytes() > usize::from(row.cells) * MAX_CLUSTER_BYTES
}

fn command_exceeds_bound(command: &[String]) -> bool {
    command.len() > MAX_COMMAND_WORDS
        || command.iter().map(|word| word.len() + 2).sum::<usize>() > MAX_COMMAND
        || command.iter().any(String::is_empty)
}

/// Named precisely: a test that only asks whether it refused cannot tell a bound from a mistake.
fn client_refusal(msg: &ClientMessage) -> Option<EncodeError> {
    match msg {
        ClientMessage::Hello {
            term, env, command, ..
        } => {
            if !valid_term(term) {
                Some(EncodeError::BadTerm)
            } else if env_exceeds_bound(env) {
                Some(EncodeError::BadEnv)
            } else if command_exceeds_bound(command) {
                Some(EncodeError::BadCommand)
            } else {
                None
            }
        }
        ClientMessage::Input { bytes, .. } => {
            (bytes.len() > MAX_INPUT_CHUNK).then_some(EncodeError::Oversize)
        }
        ClientMessage::Search { pattern, .. } => (pattern.is_empty()
            || pattern.len() > MAX_PATTERN
            || pattern.chars().any(char::is_control))
        .then_some(EncodeError::BadPattern),
        ClientMessage::ForwardOpen { target, .. } => (target.host.is_empty()
            || target.host.len() > MAX_FORWARD_HOST
            || target.host.chars().any(char::is_control)
            || target.port == 0)
            .then_some(EncodeError::BadForwardTarget),
        ClientMessage::ForwardData { bytes, .. } => {
            (bytes.len() > MAX_FORWARD_CHUNK).then_some(EncodeError::Oversize)
        }
        _ => None,
    }
}

fn server_refusal(msg: &ServerMessage) -> Option<EncodeError> {
    match msg {
        ServerMessage::Output { bytes, .. } => {
            (bytes.len() > MAX_OUTPUT_CHUNK).then_some(EncodeError::Oversize)
        }
        ServerMessage::SessionList { sessions } => {
            if sessions.len() > MAX_SESSIONS {
                Some(EncodeError::Oversize)
            } else {
                sessions
                    .iter()
                    .any(|session| {
                        session.command.len() > MAX_COMMAND
                            || session.command.chars().any(char::is_control)
                    })
                    .then_some(EncodeError::BadSessionName)
            }
        }
        ServerMessage::SearchResults { matches } => {
            if matches.len() > MAX_MATCHES {
                Some(EncodeError::Oversize)
            } else {
                matches
                    .iter()
                    .any(|found| {
                        found.line.len() > MAX_MATCH_LINE
                            || found.line.chars().any(char::is_control)
                    })
                    .then_some(EncodeError::BadMatch)
            }
        }
        // A piece refuses at the first thing it cannot write, so this order is the encoder's own.
        ServerMessage::Screen { part } => {
            if let ScreenPart::Head { header, .. } = part
                && kept_deferred(&header.sticky.deferred)
                    .iter()
                    .any(|entry| entry.chars().any(char::is_control))
            {
                return Some(EncodeError::BadDeferred);
            }
            part_rows(part).iter().find_map(|row| {
                if row.row & (ROW_CHUNK_FLAG | ROW_CLEAR_TAIL_FLAG) == 0 {
                    row_exceeds_its_cells(&row.frame).then_some(EncodeError::Oversize)
                } else {
                    Some(EncodeError::RowIndex(row.row))
                }
            })
        }
        ServerMessage::ForwardData { bytes, .. } => {
            (bytes.len() > MAX_FORWARD_CHUNK).then_some(EncodeError::Oversize)
        }
        _ => None,
    }
}

/// `RowCount` is not among them: a screen names the rows it carries, so nothing here states it.
fn refusal_index(error: &EncodeError) -> Option<usize> {
    Some(match error {
        EncodeError::Oversize => 0,
        EncodeError::BadTerm => 1,
        EncodeError::BadEnv => 2,
        EncodeError::BadCommand => 3,
        EncodeError::BadSessionName => 4,
        EncodeError::BadPattern => 5,
        EncodeError::BadMatch => 6,
        EncodeError::RowIndex(_) => 7,
        EncodeError::BadDeferred => 8,
        EncodeError::BadForwardTarget => 9,
        // Only the cut states these, and the cut is not a message.
        EncodeError::BadScroll(_) | EncodeError::RowCount { .. } => return None,
    })
}

/// The suffix the encoder keeps: the newest entries that fit the budget.
fn kept_deferred(deferred: &[String]) -> &[String] {
    let mut total = 0_usize;
    let mut start = deferred.len();
    for (index, entry) in deferred.iter().enumerate().rev() {
        total += entry.len() + 2;
        if total > MAX_DEFERRED_BYTES || deferred.len() - index > MAX_DEFERRED {
            break;
        }
        start = index;
    }
    &deferred[start..]
}

fn reject_index(reason: RejectReason) -> usize {
    match reason {
        RejectReason::Version { .. } => 0,
        RejectReason::UnknownSession => 1,
        RejectReason::SequenceGap => 2,
        RejectReason::InputBacklog => 3,
        RejectReason::Internal => 4,
        RejectReason::TooManySessions => 5,
        RejectReason::TooManyAttachments => 6,
    }
}

/// The encoder is not a filter: these are shapes a peer states and the decoder owes a refusal
/// for. The discriminant is the index into `Coverage::decode_refused`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Cursor,
    SavedCursor,
    Scroll,
    Order,
    Span,
    Pieces,
}

/// Only a screen has one; everything else this direction is bounded by the encoder alone.
fn server_decode_refuses(msg: &ServerMessage) -> Option<Refusal> {
    match msg {
        ServerMessage::Screen { part } => screen_part_refuses(part),
        _ => None,
    }
}

/// In the order the decoder reaches them. A `Tail` names no grid, so nothing here bounds its rows.
fn screen_part_refuses(part: &ScreenPart) -> Option<Refusal> {
    match part {
        ScreenPart::Head {
            header,
            scroll,
            pieces,
            rows,
            ..
        } => {
            if header
                .cursor
                .is_some_and(|(x, y)| x >= header.size.cols || y >= header.size.rows)
            {
                return Some(Refusal::Cursor);
            }
            if header
                .sticky
                .saved_cursor
                .is_some_and(|(x, y)| x >= header.size.cols || y >= header.size.rows)
            {
                return Some(Refusal::SavedCursor);
            }
            if scroll.is_some_and(|band| !applicable(band, header.size.rows)) {
                return Some(Refusal::Scroll);
            }
            if *pieces == 0 || (scroll.is_some() && *pieces != 1) {
                return Some(Refusal::Pieces);
            }
            if rows.len() > usize::from(header.size.rows)
                || rows.iter().any(|row| row.row >= header.size.rows)
                || out_of_order(rows)
            {
                return Some(Refusal::Order);
            }
            misplaced(rows, header.size.cols).then_some(Refusal::Span)
        }
        ScreenPart::Tail {
            pieces,
            index,
            rows,
            ..
        } => {
            if *pieces < 2 || *index == 0 || *index >= *pieces {
                return Some(Refusal::Pieces);
            }
            if out_of_order(rows) {
                return Some(Refusal::Order);
            }
            misplaced(rows, GridSize::MAX_COLS).then_some(Refusal::Span)
        }
    }
}

/// The same three inequalities the decoder holds a band to, restated.
fn applicable(band: ScrollBand, rows: u16) -> bool {
    band.top < band.bottom
        && band.bottom <= rows
        && band.lines > 0
        && band.lines <= band.bottom - band.top
}

/// Either makes a piece depend on the order it is applied in.
fn out_of_order(rows: &[RowSpan]) -> bool {
    rows.windows(2).any(|pair| {
        pair[1].row < pair[0].row || (pair[1].row == pair[0].row && pair[1].col <= pair[0].col)
    })
}

/// Held against what the wire carried, not the trailing blanks it dropped.
fn misplaced(rows: &[RowSpan], cols: u16) -> bool {
    rows.iter().any(|span| {
        usize::from(span.col) + usize::from(span.frame.cells) > usize::from(cols)
            || span.byte as usize + span.frame.painted_bytes()
                > usize::from(cols) * MAX_CLUSTER_BYTES
    })
}
fn part_rows(part: &ScreenPart) -> &[RowSpan] {
    match part {
        ScreenPart::Head { rows, .. } | ScreenPart::Tail { rows, .. } => rows,
    }
}

/// What the encoder drops on the way out: trailing blanks no style paints.
fn elide(row: &RowFrame) -> RowFrame {
    RowFrame {
        text: row.text[..row.painted_bytes()].to_owned(),
        runs: row.runs.clone(),
        cells: row.cells,
    }
}

fn elide_server(msg: &ServerMessage) -> ServerMessage {
    match msg {
        ServerMessage::Screen { part } => {
            let mut part = part.clone();
            match &mut part {
                ScreenPart::Head { header, rows, .. } => {
                    // The other thing the encoder drops: the oldest deferred OSCs.
                    header.sticky.deferred = kept_deferred(&header.sticky.deferred).to_vec();
                    *rows = elide_rows(rows);
                }
                ScreenPart::Tail { rows, .. } => *rows = elide_rows(rows),
            }
            ServerMessage::Screen { part }
        }
        other => other.clone(),
    }
}

fn elide_rows(rows: &[RowSpan]) -> Vec<RowSpan> {
    rows.iter()
        .map(|row| RowSpan {
            frame: elide(&row.frame),
            ..row.clone()
        })
        .collect()
}

/// The rows as a client reassembles them, trailing blanks dropped.
fn expected_rows(rows: &[RowFrame]) -> Vec<(u16, RowFrame)> {
    rows.iter()
        .enumerate()
        .map(|(row, frame)| (u16::try_from(row).expect("a row index"), elide(frame)))
        .collect()
}

/// What the traffic reached, so a generator that stopped producing a shape fails the run.
#[derive(Default)]
struct Coverage {
    client_seen: HashSet<Discriminant<ClientMessage>>,
    server_seen: HashSet<Discriminant<ServerMessage>>,
    reason_seen: [u32; 7],
    /// Acknowledgements by presence: absent, then present.
    ack_seen: [u32; 2],
    /// Sessions by how many clients are watching, across the whole range.
    attachments_seen: [u32; MAX_ATTACHMENTS + 1],
    encode_refused: [u32; 10],
    decode_refused: [u32; 6],
    /// Pieces by shape: a head, then a tail.
    part_seen: [u32; 2],
    /// Heads by what they carry: a whole screen, then a delta.
    base_seen: [u32; 2],
    /// Screens whose rows carried a blank tail the encoder dropped.
    elided: u32,
}

impl Coverage {
    fn note_refusal(&mut self, refusal: Refusal) {
        self.decode_refused[refusal as usize] += 1;
    }

    fn note_server(&mut self, msg: &ServerMessage) {
        self.server_seen.insert(discriminant(msg));
        match msg {
            ServerMessage::Reject { reason } => self.reason_seen[reject_index(*reason)] += 1,
            ServerMessage::Output { echo_ack, .. } | ServerMessage::Ping { echo_ack, .. } => {
                self.ack_seen[usize::from(echo_ack.is_some())] += 1;
            }
            ServerMessage::CommandAck { highest } => {
                self.ack_seen[usize::from(highest.is_some())] += 1;
            }
            ServerMessage::SessionList { sessions } => {
                for session in sessions {
                    self.attachments_seen[usize::from(session.attachments)] += 1;
                }
            }
            ServerMessage::Screen { part } => {
                self.part_seen[usize::from(matches!(part, ScreenPart::Tail { .. }))] += 1;
                if let ScreenPart::Head { base, .. } = part {
                    self.base_seen[usize::from(base.is_some())] += 1;
                }
            }
            _ => {}
        }
    }
}

fn check_client(msg: &ClientMessage, coverage: &mut Coverage) {
    match msg.encode(Version::LOCAL) {
        Ok(frame) => {
            assert_eq!(
                client_refusal(msg),
                None,
                "an over-bound client message reached the wire"
            );
            let decoded = ClientMessage::decode(&frame[PREFIX..], Version::LOCAL)
                .expect("a frame this encoder just wrote");
            assert_eq!(&decoded, msg, "a client message changed on the wire");
            coverage.client_seen.insert(discriminant(&decoded));
        }
        Err(error) => {
            if let Some(index) = refusal_index(&error) {
                coverage.encode_refused[index] += 1;
            }
            assert_eq!(
                Some(error),
                client_refusal(msg),
                "the encoder stated the wrong refusal for a client message"
            );
        }
    }
}

fn check_server(msg: &ServerMessage, coverage: &mut Coverage) {
    let frame = match msg.encode(Version::LOCAL) {
        Ok(frame) => {
            assert_eq!(
                server_refusal(msg),
                None,
                "an over-bound server message reached the wire: {msg:?}"
            );
            frame
        }
        Err(error) => {
            if let Some(index) = refusal_index(&error) {
                coverage.encode_refused[index] += 1;
            }
            assert_eq!(
                Some(error),
                server_refusal(msg),
                "the encoder stated the wrong refusal for a server message: {msg:?}"
            );
            return;
        }
    };
    match (
        ServerMessage::decode(&frame[PREFIX..], Version::LOCAL),
        server_decode_refuses(msg),
    ) {
        (Ok(decoded), None) => {
            let expected = elide_server(msg);
            coverage.elided += u32::from(&expected != msg);
            assert_eq!(decoded, expected, "a server message changed on the wire");
            coverage.note_server(&decoded);
        }
        (Ok(_), Some(refusal)) => {
            panic!("the decoder took a screen it owes a {refusal:?} refusal");
        }
        (Err(error), Some(refusal)) => {
            assert!(
                matches!(error, DecodeError::InvalidField),
                "a {refusal:?} refusal came back as {error}"
            );
            coverage.note_refusal(refusal);
        }
        (Err(error), None) => {
            panic!("the decoder refused a frame this encoder just wrote: {msg:?}, {error}")
        }
    }
}

const CLIENT_VARIANTS: usize = 18;
const SERVER_VARIANTS: usize = 14;
/// Divisible by both, so every variant is generated the same number of times.
const CASES: u64 = 12_600;

#[test]
fn every_message_variant_survives_the_wire_unchanged() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut coverage = Coverage::default();

    for case in 0..CASES {
        let client = client_message(&mut rng, case % CLIENT_VARIANTS as u64);
        check_client(&client, &mut coverage);
        let server = server_message(&mut rng, case % SERVER_VARIANTS as u64);
        check_server(&server, &mut coverage);
    }

    assert_eq!(
        coverage.client_seen.len(),
        CLIENT_VARIANTS,
        "a client variant never round-tripped"
    );
    assert_eq!(
        coverage.server_seen.len(),
        SERVER_VARIANTS,
        "a server variant never round-tripped"
    );
    for (counts, what) in [
        (&coverage.reason_seen[..], "a reject reason"),
        (
            &coverage.ack_seen[..],
            "an acknowledgement, absent or present",
        ),
        (&coverage.attachments_seen[..], "an attachment count"),
        (
            &coverage.encode_refused[..],
            "a wire bound, so its refusal went untested",
        ),
        (
            &coverage.decode_refused[..],
            "a shape the decoder owes a refusal for",
        ),
        (&coverage.part_seen[..], "a screen piece as head or as tail"),
        (&coverage.base_seen[..], "a head whole or as a delta"),
    ] {
        assert!(
            counts.iter().all(|count| *count > 0),
            "{what} was never generated: {counts:?}"
        );
    }
    assert!(
        coverage.elided > 0,
        "no generated screen ever carried a blank tail, so the elision went untested"
    );
}

/// One frame per client variant, small enough to mutate byte by byte.
#[expect(
    clippy::too_many_lines,
    reason = "one literal per variant, and the assertion below is what makes the list exhaustive"
)]
fn client_corpus() -> Vec<Vec<u8>> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let size = GridSize::new(10, 3).expect("a small grid");

    let clients = [
        ClientMessage::Hello {
            versions: VersionRange::LOCAL,
            size,
            term: String::from("xterm-256color"),
            env: SessionEnv(vec![(String::from("LANG"), String::from("en_CA.UTF-8"))]),
            command: vec![String::from("tmux"), String::from("attach")],
            client: client_id(&mut rng),
        },
        ClientMessage::Input {
            seq: CmdSeq::first(),
            bytes: b"\x1b[Als -la\r".to_vec(),
        },
        ClientMessage::Resize {
            seq: CmdSeq::first(),
            size,
        },
        ClientMessage::RequestRepaint {
            seq: CmdSeq::first(),
        },
        ClientMessage::ScreenAck {
            generation: Generation::initial(),
            version: ScreenVersion::initial(),
        },
        ClientMessage::Close {
            seq: CmdSeq::first(),
        },
        ClientMessage::Resume {
            versions: VersionRange::LOCAL,
            seq: CmdSeq::first(),
            request: ResumeRequest {
                session_id: session_id(&mut rng),
                capability: capability(&mut rng),
                confirmed_output: ConfirmedOutput {
                    generation: Generation::initial(),
                    next_off: ByteOff::from_u64(4096),
                },
                client: client_id(&mut rng),
            },
        },
        ClientMessage::Detach {
            seq: CmdSeq::first(),
        },
        ClientMessage::Pong {
            token: 7,
            consumed: ByteOff::from_u64(4096),
        },
        ClientMessage::ListSessions,
        ClientMessage::KillSession {
            session_id: session_id(&mut rng),
        },
        ClientMessage::Consumed {
            off: ByteOff::from_u64(8192),
        },
        ClientMessage::Search {
            pattern: String::from("error: "),
            limit: 32,
        },
        ClientMessage::ForwardOpen {
            seq: CmdSeq::first(),
            stream: StreamId::first(),
            target: ForwardTarget {
                host: String::from("localhost"),
                port: 5432,
            },
        },
        ClientMessage::ForwardData {
            stream: StreamId::first(),
            off: ByteOff::from_u64(4096),
            fin: true,
            bytes: b"SELECT 1;\n".to_vec(),
        },
        ClientMessage::ForwardAck {
            held: SackRuns::EMPTY,
            stream: StreamId::first(),
            off: ByteOff::from_u64(8192),
            window: 65_535,
        },
        ClientMessage::ForwardReset {
            stream: StreamId::first(),
            reason: ForwardResetReason::Refused,
        },
        ClientMessage::HelloForward {
            versions: VersionRange::LOCAL,
            client: ClientId::from_bytes([0x5A; 16]),
        },
    ];

    assert_eq!(clients.len(), CLIENT_VARIANTS);
    let mut frames: Vec<Vec<u8>> = clients
        .iter()
        .map(|msg| msg.encode(Version::LOCAL).expect("a small message"))
        .collect();
    // A `Hello` naming no command is the common shape and a shorter frame.
    frames.push(
        ClientMessage::Hello {
            versions: VersionRange::LOCAL,
            size,
            term: String::from("xterm"),
            env: SessionEnv::default(),
            command: Vec::new(),
            client: client_id(&mut rng),
        }
        .encode(Version::LOCAL)
        .expect("a small message"),
    );
    frames
}

/// One frame per server variant, screens included.
fn server_corpus() -> Vec<Vec<u8>> {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let size = GridSize::new(10, 3).expect("a small grid");
    // A corpus frame that never decodes mutates nothing, and the saved cursor and deferred OSC
    // are branches the mutator only reaches if the corpus carries them.
    let mut header = screen_header(&mut rng, size);
    header.cursor = Some((size.cols - 1, size.rows - 1));
    header.sticky.saved_cursor = Some((0, 0));
    header.sticky.deferred = vec![String::from("52;c;aGk=")];
    let mut frames = one_of_each(&mut rng, size, &header);
    frames.extend(second_shapes(&header));
    frames
}

/// A *second* encoding of a variant already above, so mutation reaches the branch each one takes.
fn second_shapes(header: &ScreenHeader) -> Vec<Vec<u8>> {
    [
        // `Version` is the one reason carrying a payload.
        ServerMessage::Reject {
            reason: RejectReason::UnknownSession,
        },
        // An absent acknowledgement is eight zero bytes where a present one is a position.
        ServerMessage::CommandAck { highest: None },
        // A tail carries no header, so the count, the index and the row order are all of it.
        ServerMessage::Screen {
            part: ScreenPart::Tail {
                generation: header.generation,
                version: header.version,
                pieces: 2,
                index: 1,
                rows: vec![span(0, RowFrame::default())],
            },
        },
        // The absent base, the piece count and the chunk flag are three branches nothing else takes.
        ServerMessage::Screen {
            part: ScreenPart::Head {
                header: header.clone(),
                base: None,
                scroll: None,
                pieces: 2,
                rows: vec![RowSpan {
                    chunk: true,
                    ..span(
                        0,
                        RowFrame {
                            text: String::from("ls "),
                            runs: Vec::new(),
                            cells: 3,
                        },
                    )
                }],
            },
        },
    ]
    .iter()
    .map(|msg| msg.encode(Version::LOCAL).expect("a small message"))
    .collect()
}

/// One frame per `ServerMessage` variant: a variant with no frame here would be mutated by nothing.
#[expect(
    clippy::too_many_lines,
    reason = "one literal per variant, and the assertion below is what makes the list exhaustive"
)]
fn one_of_each(rng: &mut Rng, size: GridSize, header: &ScreenHeader) -> Vec<Vec<u8>> {
    // Seven columns of five characters over eleven bytes, with a run boundary.
    let row = RowFrame {
        text: String::from("ls 漢👍"),
        runs: vec![
            StyleRun {
                cells: 3,
                bytes: 3,
                style: cell_style(rng),
            },
            StyleRun {
                cells: 4,
                bytes: 7,
                style: CellStyle::default(),
            },
        ],
        cells: 7,
    };

    let servers = [
        ServerMessage::Hello {
            version: Version::LOCAL,
            size,
            session_id: session_id(rng),
            capability: capability(rng),
            offer: Some(DatagramOffer {
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 3],
                port: 44_501,
                cid: [3; 8],
                secret: [7; 32],
            }),
        },
        ServerMessage::Output {
            off: ByteOff::from_u64(9),
            bytes: b"total 0\r\n".to_vec(),
            cue: InputCue::Echoing { room: 7 },
            echo_ack: CmdSeq::from_u64(3),
        },
        ServerMessage::Exit { code: -1 },
        ServerMessage::Reject {
            reason: RejectReason::Version {
                server: VersionRange::new(7, 9).expect("a range"),
                client: VersionRange::LOCAL,
            },
        },
        ServerMessage::CommandAck {
            highest: CmdSeq::from_u64(9),
        },
        ServerMessage::Detached {
            reason: DetachReason::Replaced,
        },
        ServerMessage::Ping {
            token: 7,
            echo_ack: CmdSeq::from_u64(4),
            interval_ms: 500,
        },
        ServerMessage::SessionList {
            sessions: vec![SessionSummary {
                session_id: session_id(rng),
                size,
                attachments: 2,
                active_unix: 1_700_000_000,
                command: String::from("vim -O a b"),
            }],
        },
        ServerMessage::SearchResults {
            matches: vec![SearchMatch {
                session_id: session_id(rng),
                distance: 12,
                line: String::from("make: *** [all] 漢字"),
            }],
        },
        // The base, the band and the row indices are three fields only a screen carries.
        ServerMessage::Screen {
            part: ScreenPart::Head {
                header: header.clone(),
                base: Some(ScreenVersion::initial()),
                scroll: Some(ScrollBand {
                    top: 0,
                    bottom: 3,
                    lines: 1,
                }),
                pieces: 1,
                rows: vec![span(0, row), span(2, RowFrame::default())],
            },
        },
        ServerMessage::ForwardData {
            stream: StreamId::first(),
            off: ByteOff::zero(),
            fin: false,
            bytes: b"PostgreSQL 16\n".to_vec(),
        },
        ServerMessage::ForwardAck {
            held: SackRuns::EMPTY,
            stream: StreamId::first(),
            off: ByteOff::from_u64(4096),
            window: 0,
        },
        ServerMessage::ForwardReset {
            stream: StreamId::first(),
            reason: ForwardResetReason::Unreachable,
        },
        ServerMessage::HelloForward {
            version: Version::LOCAL,
            session_id: SessionId::from_bytes([0x3C; 16]),
            capability: Capability::from_bytes([0x7E; CAPABILITY_BYTES]),
            offer: None,
        },
    ];

    assert_eq!(servers.len(), SERVER_VARIANTS);
    servers
        .iter()
        .map(|msg| msg.encode(Version::LOCAL).expect("a small message"))
        .collect()
}

/// Every single-byte damage to `frame`, then every truncation of it.
fn mutations(frame: &[u8]) -> Vec<Vec<u8>> {
    // Boundary bytes rather than a random spray: a tag, a length, a bool and a discriminant.
    const DAMAGE: [u8; 6] = [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff];
    let mut out = Vec::with_capacity(frame.len() * (DAMAGE.len() + 2));
    for index in 0..frame.len() {
        for value in DAMAGE {
            let mut mutant = frame.to_vec();
            mutant[index] = value;
            out.push(mutant);
        }
        let mut flipped = frame.to_vec();
        flipped[index] ^= 0xff;
        out.push(flipped);
        out.push(frame[..index].to_vec());
    }
    out.push(frame.to_vec());
    out
}

/// Bytes past the last field a decoder knows are skipped, so the property is a fixed point.
fn client_is_canonical(payload: &[u8]) -> bool {
    let Ok(msg) = ClientMessage::decode(payload, Version::LOCAL) else {
        return false;
    };
    let again = msg
        .encode(Version::LOCAL)
        .expect("a message the decoder accepted must re-encode");
    assert_eq!(
        ClientMessage::decode(&again[PREFIX..], Version::LOCAL).expect("a re-encoded frame"),
        msg,
        "a client message is not a fixed point of the codec"
    );
    true
}

fn server_is_canonical(payload: &[u8]) -> bool {
    let Ok(msg) = ServerMessage::decode(payload, Version::LOCAL) else {
        return false;
    };
    let frame = msg
        .encode(Version::LOCAL)
        .expect("a message the decoder accepted must re-encode");
    let again =
        ServerMessage::decode(&frame[PREFIX..], Version::LOCAL).expect("a re-encoded frame");
    let elided = elide_server(&msg);
    assert_eq!(again, elided, "re-encoding lost more than trailing blanks");
    assert_eq!(
        again
            .encode(Version::LOCAL)
            .expect("a message the decoder accepted must re-encode"),
        frame,
        "eliding trailing blanks is not a fixed point"
    );
    true
}

#[test]
fn damaged_frames_are_refused_rather_than_fatal() {
    let (clients, servers) = (client_corpus(), server_corpus());
    let mut accepted = 0_u32;
    let mut refused = 0_u32;

    // A daemon takes only what a client can legally send, and only a server sends a screen.
    for (frames, canonical, limit) in [
        (
            &clients,
            client_is_canonical as fn(&[u8]) -> bool,
            MAX_CLIENT_FRAME,
        ),
        (
            &servers,
            server_is_canonical as fn(&[u8]) -> bool,
            MAX_FRAME,
        ),
    ] {
        for frame in frames {
            for mutant in mutations(frame) {
                // The length the reader trusts sizes an allocation, so it hands back exactly those.
                if let Ok(payload) = read_frame(&mut Cursor::new(&mutant), limit) {
                    let claimed =
                        u32::from_be_bytes(mutant[..PREFIX].try_into().expect("a length prefix"));
                    assert_eq!(
                        u32::try_from(payload.len()).ok(),
                        Some(claimed),
                        "the reader took a frame that is not the length it claims"
                    );
                    assert_eq!(payload, &mutant[PREFIX..PREFIX + payload.len()]);
                }
                // Decoding runs on the payload the reader would have handed over, damage and all.
                let payload = mutant.get(PREFIX..).unwrap_or(&[]);
                if canonical(payload) {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
        }
    }

    assert!(
        accepted > 0 && refused > 0,
        "damage was uniformly {} ({accepted} accepted, {refused} refused)",
        if accepted == 0 { "fatal" } else { "invisible" }
    );

    // A length prefix is read before anything is validated, and it sizes a `vec![0; length]`.
    for length in [0, MAX_FRAME + 1, u32::MAX] {
        let mut frame = Vec::from(length.to_be_bytes());
        frame.extend_from_slice(b"payload");
        assert!(
            matches!(
                read_frame(&mut Cursor::new(&frame), MAX_FRAME),
                Err(DecodeError::Oversize { actual, limit: MAX_FRAME }) if actual == length
            ),
            "a frame claiming {length} bytes was not refused as oversize"
        );
    }
    // At the limit the length is legal, so the seven bytes behind it are a torn frame.
    let mut at_limit = Vec::from(MAX_FRAME.to_be_bytes());
    at_limit.extend_from_slice(b"payload");
    assert!(matches!(
        read_frame(&mut Cursor::new(&at_limit), MAX_FRAME),
        Err(DecodeError::Truncated)
    ));
}

/// A one-row screen of a one-column grid, carrying `text` its encoder would never have written.
fn one_cell_screen(text: &str) -> Vec<u8> {
    let size = GridSize::new(1, 1).expect("a one-cell grid");
    let mut frame = ServerMessage::Screen {
        part: ScreenPart::Head {
            header: plain_header(size),
            base: None,
            scroll: None,
            pieces: 1,
            rows: vec![span(
                0,
                RowFrame {
                    text: String::new(),
                    runs: Vec::new(),
                    cells: 1,
                },
            )],
        },
    }
    .encode(Version::LOCAL)
    .expect("an empty one-cell screen");

    // The row is the tail of the frame: a length, no text, a cell count and a
    // run count.
    let at = frame.len() - 8;
    let len = u32::try_from(text.len()).expect("a length that fits the field");
    frame.splice(at..at + PREFIX, len.to_be_bytes());
    frame.splice(at + PREFIX..at + PREFIX, text.bytes());
    let length = u32::try_from(frame.len() - PREFIX).expect("a frame length");
    frame[..PREFIX].copy_from_slice(&length.to_be_bytes());
    frame
}

fn decode_part(frame: &[u8]) -> ScreenPart {
    let ServerMessage::Screen { part } = ServerMessage::decode(&frame[PREFIX..], Version::LOCAL)
        .expect("a piece this encoder wrote")
    else {
        panic!("a screen");
    };
    part
}

fn decoded_header(frame: &[u8]) -> ScreenHeader {
    let ScreenPart::Head { header, .. } = decode_part(frame) else {
        panic!("a head");
    };
    header
}

/// A message this encoder wrote decodes back into itself.
fn survives_client(msg: &ClientMessage) {
    let frame = msg.encode(Version::LOCAL).expect("a small message");
    let decoded = ClientMessage::decode(&frame[PREFIX..], Version::LOCAL)
        .expect("a frame this encoder wrote");
    assert_eq!(&decoded, msg);
}

fn survives_server(msg: &ServerMessage) {
    let frame = msg.encode(Version::LOCAL).expect("a small message");
    let decoded = ServerMessage::decode(&frame[PREFIX..], Version::LOCAL)
        .expect("a frame this encoder wrote");
    assert_eq!(&decoded, msg);
}

/// Two different numbers mean a screen encodes on the server and is refused by the client.
#[test]
fn a_screen_the_server_can_encode_is_a_screen_the_client_accepts() {
    let size = GridSize::new(1024, 512).expect("a large but legal grid");
    let header = plain_header(size);
    let rows = vec![
        RowFrame {
            text: "x".repeat(usize::from(size.cols)),
            runs: Vec::new(),
            cells: size.cols,
        };
        usize::from(size.rows)
    ];
    let parts = encode_screen_parts(&header, None, None, in_order(&rows), stream_frame())
        .expect("a full ASCII screen fits the wire");
    assert_eq!(
        parts.len(),
        1,
        "a full ASCII screen no longer fits one frame"
    );
    assert!(
        parts[0].len() - PREFIX > 512 * 1024,
        "the case only bites past the old 512 KiB limit: {}",
        parts[0].len()
    );
    assert_eq!(
        reassemble(&parts, stream_frame()),
        expected_rows(&rows),
        "the client refused what the server sent"
    );
}

/// A 1x1 grid carrying a megabyte of text is refused rather than written to the user's terminal.
#[test]
fn a_row_may_not_carry_more_than_its_grid_can_hold() {
    let at_bound = "x".repeat(MAX_CLUSTER_BYTES);
    assert!(matches!(
        ServerMessage::decode(&one_cell_screen(&at_bound)[PREFIX..], Version::LOCAL),
        Ok(ServerMessage::Screen {
            part: ScreenPart::Head { .. }
        })
    ));
    for over in [
        "x".repeat(MAX_CLUSTER_BYTES + 1),
        "x".repeat(1024 * 1024),
        "漢".repeat(MAX_CLUSTER_BYTES),
    ] {
        assert!(
            matches!(
                ServerMessage::decode(&one_cell_screen(&over)[PREFIX..], Version::LOCAL),
                Err(DecodeError::InvalidField)
            ),
            "the decoder took {} bytes of text for one column",
            over.len()
        );
    }

    // The encoder measures against `cells`, proved `<= cols` at decode, so the two agree.
    let header = plain_header(GridSize::new(1024, 1).expect("a one-row grid"));
    for cells in [1_u16, 2, 37, 1024] {
        let row = RowFrame {
            text: "x".repeat(usize::from(cells) * MAX_CLUSTER_BYTES),
            runs: Vec::new(),
            cells,
        };
        let parts = encode_screen_parts(&header, None, None, one_row(&row), stream_frame())
            .expect("a row at its own bound");
        assert_eq!(
            reassemble(&parts, stream_frame()),
            vec![(0, elide(&row))],
            "a row at its own bound did not survive the wire"
        );

        let mut over = row;
        over.text.push('x');
        assert_eq!(
            encode_screen_parts(&header, None, None, one_row(&over), stream_frame()),
            Err(EncodeError::Oversize)
        );
    }
}

/// Found by `cargo fuzz`: a row declaring no columns and carrying text could not be re-encoded.
#[test]
fn a_rows_text_is_bounded_by_its_own_width_and_not_only_by_the_grid() {
    let good = one_cell_screen("[");
    let decoded =
        ServerMessage::decode(&good[PREFIX..], Version::LOCAL).expect("one column holds one cell");
    assert_eq!(
        decoded.encode(Version::LOCAL).expect("and can restate it"),
        good,
        "the round trip this test's counterexample is measured against"
    );

    // The tail is the row: a length, its text, a cell count and a run count.
    let mut none = good;
    let cells_at = none.len() - 4;
    none.splice(cells_at..cells_at + 2, 0_u16.to_be_bytes());
    assert!(
        matches!(
            ServerMessage::decode(&none[PREFIX..], Version::LOCAL),
            Err(DecodeError::InvalidField)
        ),
        "a row that renders no columns cannot carry text"
    );
}

/// A bound smaller than the frame makes a delta fall back to a screen four times its size.
#[test]
fn a_delta_is_never_larger_than_the_screen_it_replaces() {
    let size = GridSize::new(GridSize::MAX_COLS, GridSize::MAX_ROWS).expect("the largest grid");
    let header = plain_header(size);
    let wide = RowFrame {
        text: "漢".repeat(usize::from(size.cols) / 2),
        runs: Vec::new(),
        cells: size.cols,
    };
    let rows = vec![wide; usize::from(size.rows)];
    let screen = encode_screen_parts(&header, None, None, in_order(&rows), stream_frame())
        .expect("a full CJK screen fits the frame");
    let delta = encode_screen_parts(
        &header,
        Some(ScreenVersion::initial()),
        None,
        in_order(&rows[..128]),
        stream_frame(),
    )
    .expect("a delta the deleted bound refused");
    assert_eq!(
        (screen.len(), delta.len()),
        (1, 1),
        "either of these still fits one frame whole"
    );
    assert!(
        delta[0].len() * 3 < screen[0].len(),
        "the delta is {} bytes against a screen of {}",
        delta[0].len(),
        screen[0].len()
    );

    // The frame bounds a *piece*: a screen past it is cut rather than refused.
    let dense = RowFrame {
        text: "x".repeat(usize::from(size.cols) * MAX_CLUSTER_BYTES),
        runs: Vec::new(),
        cells: size.cols,
    };
    let heavy = vec![dense; 32];
    let parts = encode_screen_parts(
        &header,
        Some(ScreenVersion::initial()),
        None,
        in_order(&heavy),
        stream_frame(),
    )
    .expect("a screen larger than a frame is cut into frames");
    assert!(parts.len() > 1, "two megabytes of rows fit one frame");
    assert_eq!(
        reassemble(&parts, stream_frame()),
        expected_rows(&heavy),
        "a screen cut into frames did not reassemble"
    );
}

/// `encoded_len` sizes a screen in one pass: an upper bound, or a realloc thirty times a second.
#[test]
fn a_rows_encoded_length_is_never_less_than_the_bytes_it_writes() {
    /// A row with no text and no runs: a length, a cell count and a run count.
    const EMPTY_ROW: usize = 8;

    let mut rng = Rng(0x0bad_c0de_dead_beef);
    let size = GridSize::new(GridSize::MAX_COLS, 1).expect("a one-row grid");
    let header = screen_header(&mut rng, size);
    let one = |row: &RowFrame| {
        encode_screen_parts(&header, None, None, one_row(row), stream_frame())
            .expect("a row inside its own grid")[0]
            .len()
    };
    let bare = one(&RowFrame::default());
    let mut widest = 0_usize;
    for _ in 0..512 {
        let mut budget = frame_budget(size);
        let row = row_frame(&mut rng, size.cols, &mut budget);
        let written = one(&row) - bare + EMPTY_ROW;
        assert!(
            row.encoded_len() >= written,
            "a row of {} runs claimed {} bytes and wrote {written}",
            row.runs.len(),
            row.encoded_len()
        );
        widest = widest.max(written);
    }
    assert!(
        widest > EMPTY_ROW,
        "every generated row was empty, so the bound went untested"
    );
}

/// A four-row screen with a cursor the decoder does not owe a refusal for.
fn part_header() -> ScreenHeader {
    let mut rng = Rng(0x243f_6a88_85a3_08d3);
    let size = GridSize::new(8, 4).expect("a small grid");
    ScreenHeader {
        cursor: Some((0, 0)),
        ..screen_header(&mut rng, size)
    }
}

/// A full 80x24 screen: about two kilobytes of rows, more than any datagram carries.
fn wide_screen() -> (ScreenHeader, Vec<RowFrame>) {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let size = GridSize::new(80, 24).expect("a grid");
    let header = ScreenHeader {
        cursor: Some((0, 0)),
        ..screen_header(&mut rng, size)
    };
    let rows = (0..size.rows)
        .map(|_| RowFrame {
            text: "x".repeat(usize::from(size.cols)),
            runs: Vec::new(),
            cells: size.cols,
        })
        .collect();
    (header, rows)
}

fn empty_rows(rows: &[u16]) -> Vec<RowSpan> {
    rows.iter()
        .map(|row| span(*row, RowFrame::default()))
        .collect()
}

fn head(pieces: u16, scroll: Option<ScrollBand>, rows: &[u16]) -> ScreenPart {
    ScreenPart::Head {
        header: part_header(),
        base: None,
        scroll,
        pieces,
        rows: empty_rows(rows),
    }
}

fn tail(pieces: u16, index: u16, rows: &[u16]) -> ScreenPart {
    ScreenPart::Tail {
        generation: Generation::initial(),
        version: ScreenVersion::initial(),
        pieces,
        index,
        rows: empty_rows(rows),
    }
}

/// A one-piece head naming no rows: the shape the header tests are about.
fn headless(header: ScreenHeader) -> ScreenPart {
    ScreenPart::Head {
        header,
        base: None,
        scroll: None,
        pieces: 1,
        rows: Vec::new(),
    }
}

fn part_frame(part: ScreenPart) -> Vec<u8> {
    ServerMessage::Screen { part }
        .encode(Version::LOCAL)
        .expect("a piece of a small screen")
}

/// The encoder is not a filter: these are shapes a peer states.
fn part_refusal(part: ScreenPart) -> DecodeError {
    ServerMessage::decode(&part_frame(part)[PREFIX..], Version::LOCAL)
        .expect_err("the decoder took a piece it owes a refusal")
}

/// Every piece fits the path, the pieces name the rows in the screen's order, the head counts them.
#[test]
fn a_screen_past_the_budget_is_cut_into_pieces_that_each_fit_it() {
    let (header, rows) = wide_screen();
    let parts = encode_screen_parts(&header, None, None, in_order(&rows), MIN_DATAGRAM_FRAME)
        .expect("a screen that fits once it is cut");
    assert!(parts.len() >= 2, "a full 80x24 screen fit one datagram");
    assert_eq!(
        reassemble(&parts, MIN_DATAGRAM_FRAME),
        expected_rows(&rows),
        "the pieces do not name the screen's rows in the screen's order"
    );
}

/// The cursor, the modes and the sticky state ride in the head of even a screen naming no rows.
#[test]
fn a_screen_with_no_rows_is_one_piece_and_still_a_head() {
    let (header, _) = wide_screen();
    let parts = encode_screen_parts(
        &header,
        Some(ScreenVersion::initial()),
        None,
        [].iter().copied(),
        MIN_DATAGRAM_FRAME,
    )
    .expect("a screen of no rows");
    assert_eq!(parts.len(), 1);
    let ScreenPart::Head {
        base, pieces, rows, ..
    } = decode_part(&parts[0])
    else {
        panic!("a head");
    };
    assert_eq!(
        (base, pieces, rows.len()),
        (ScreenVersion::from_u64(1), 1, 0)
    );
}

/// A client never told the viewport moved holds every row at an offset no later screen will name.
#[test]
fn a_scroll_that_needs_more_than_one_piece_is_refused() {
    let (header, rows) = wide_screen();
    let all = || in_order(&rows);
    // Everything above the status bar: the band that fires on real output.
    let band = ScrollBand {
        top: 0,
        bottom: header.size.rows - 1,
        lines: 1,
    };
    assert_eq!(
        encode_screen_parts(&header, None, Some(band), all(), MIN_DATAGRAM_FRAME),
        Err(EncodeError::Oversize)
    );
    // The retry the caller is left with is the same screen without it.
    assert!(encode_screen_parts(&header, None, None, all(), MIN_DATAGRAM_FRAME).is_ok());

    // And a screen that turns out to be one piece keeps the band it chose.
    let single = encode_screen_parts(
        &header,
        None,
        Some(band),
        in_order(&rows[..2]),
        MIN_DATAGRAM_FRAME,
    )
    .expect("two rows and a scroll inside one datagram");
    assert_eq!(single.len(), 1);
    let ScreenPart::Head { scroll, pieces, .. } = decode_part(&single[0]) else {
        panic!("a head");
    };
    assert_eq!((scroll, pieces), (Some(band), 1));
}

/// A head that both scrolls and was cut, a piece of no screen, a tail out of place, rows that fall.
#[test]
fn a_piece_no_client_could_apply_is_refused() {
    let band = ScrollBand {
        top: 0,
        bottom: 4,
        lines: 1,
    };
    let mut cases = vec![
        (
            String::from("a head that scrolls and was cut in two"),
            head(2, Some(band), &[0]),
        ),
        (
            String::from("a head of no pieces at all"),
            head(0, None, &[0]),
        ),
    ];
    cases.extend(
        [0, 2, u16::MAX].map(|index| (format!("piece {index} of two"), tail(2, index, &[0]))),
    );
    cases.extend([0, 1].map(|pieces| {
        (
            format!("a tail of a screen in {pieces} pieces"),
            tail(pieces, 1, &[0]),
        )
    }));
    for rows in [[1, 1], [2, 1], [3, 3]] {
        cases.push((format!("a head naming rows {rows:?}"), head(1, None, &rows)));
        cases.push((format!("a tail naming rows {rows:?}"), tail(2, 1, &rows)));
    }
    for (what, part) in cases {
        assert!(
            matches!(part_refusal(part), DecodeError::InvalidField),
            "the decoder admitted {what}"
        );
    }
}

/// The secret is a bearer credential: it must not reach a log line through `Debug`.
#[test]
fn a_hello_round_trips_with_a_datagram_offer_and_without_one() {
    let secret: [u8; 32] =
        std::array::from_fn(|index| 100 + u8::try_from(index).expect("a short secret"));
    let offer = DatagramOffer {
        ip: [1; 16],
        port: 9,
        cid: [0xab; 8],
        secret,
    };
    let hello = |offer| ServerMessage::Hello {
        version: Version::LOCAL,
        size: GridSize::new(80, 24).expect("a grid"),
        session_id: SessionId::from_bytes([5; 16]),
        capability: Capability::from_bytes([6; CAPABILITY_BYTES]),
        offer,
    };
    for message in [hello(None), hello(Some(offer))] {
        survives_server(&message);
    }
    // Present, absent, and nothing else: a third presence byte is a shape this protocol lacks.
    let mut absent = hello(None).encode(Version::LOCAL).expect("a small message");
    *absent.last_mut().expect("a presence byte") = 2;
    assert!(matches!(
        ServerMessage::decode(&absent[PREFIX..], Version::LOCAL),
        Err(DecodeError::InvalidField)
    ));

    let printed = format!("{offer:?}");
    for byte in secret {
        assert!(
            !printed.contains(&byte.to_string()),
            "a datagram secret reached a log line through {printed}"
        );
    }
}

/// What a stream gives a screen: the frame, and nothing smaller.
fn stream_frame() -> usize {
    usize::try_from(MAX_FRAME).expect("a 32-bit limit fits a usize")
}

/// No sticky title on purpose: the tests below count a piece's bytes against a path it must fit.
fn plain_header(size: GridSize) -> ScreenHeader {
    ScreenHeader {
        generation: Generation::initial(),
        version: ScreenVersion::initial(),
        next_off: ByteOff::zero(),
        size,
        cursor: Some((0, 0)),
        cursor_visible: true,
        cursor_shape: CursorShape::Block,
        cursor_blinking: false,
        modes: ModeSet::empty(),
        sticky: StickyState::default(),
    }
}

/// A run boundary is the only offset where a byte position and a column are both known.
fn styled_row(grapheme: &str, width: u16, cells: u16, per_run: u16) -> RowFrame {
    assert_eq!(
        per_run % width,
        0,
        "a run ends on a cluster boundary or it ends nowhere"
    );
    let bytes = u32::try_from(grapheme.len()).expect("a short grapheme");
    let clusters = cells / width;
    let mut row = RowFrame {
        text: grapheme.repeat(usize::from(clusters)),
        runs: Vec::new(),
        cells: clusters * width,
    };
    let mut placed = 0_u16;
    while placed < row.cells {
        let run_cells = per_run.min(row.cells - placed);
        let run_bytes = u32::from(run_cells / width) * bytes;
        assert!(
            run_bytes <= MAX_RUN_BYTES,
            "a run of {run_bytes} bytes is one the emulator does not build"
        );
        row.runs.push(StyleRun {
            cells: run_cells,
            bytes: run_bytes,
            style: CellStyle {
                fg: StyleColor::Palette(u8::try_from(placed % 256).expect("a palette index")),
                ..CellStyle::default()
            },
        });
        placed += run_cells;
    }
    row
}

/// The rows a wide terminal actually produces; eighty bytes of ASCII exercises none of the cut.
fn wide_rows() -> [(&'static str, RowFrame); 4] {
    [
        (
            "600 columns under 60 style runs",
            styled_row("x", 1, 600, 10),
        ),
        ("200 columns coloured per cell", styled_row("x", 1, 200, 1)),
        (
            "200 columns of ZWJ family emoji",
            styled_row("👨\u{200d}👩\u{200d}👧", 2, 200, 56),
        ),
        (
            "1024 columns of full-width CJK",
            styled_row("漢", 2, 1024, 340),
        ),
    ]
}

/// The rules that live *between* pieces: each fits its path, names a row once, and concatenates.
fn reassemble(parts: &[Vec<u8>], budget: usize) -> Vec<(u16, RowFrame)> {
    let mut grouped: Vec<(u16, Vec<RowSpan>)> = Vec::new();
    for (place, frame) in parts.iter().enumerate() {
        assert!(
            frame.len() <= budget,
            "piece {place} is {} bytes of a {budget}-byte path",
            frame.len()
        );
        let spans = match (place, decode_part(frame)) {
            (0, ScreenPart::Head { pieces, rows, .. }) => {
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
                    pieces,
                    index,
                    rows,
                    ..
                },
            ) => {
                assert_eq!(usize::from(pieces), parts.len(), "a tail miscounted them");
                assert_eq!(usize::from(index), place, "a tail named the wrong place");
                rows
            }
            (place, _) => panic!("piece {place} is the wrong shape"),
        };
        let mut named: Vec<u16> = Vec::new();
        for span in spans {
            assert!(
                !named.contains(&span.row),
                "piece {place} names row {} twice",
                span.row
            );
            named.push(span.row);
            match grouped.iter().position(|(row, _)| *row == span.row) {
                Some(at) => grouped[at].1.push(span),
                None => grouped.push((span.row, vec![span])),
            }
        }
    }
    grouped
        .into_iter()
        .map(|(row, chunks)| {
            let cut = chunks.len() > 1;
            assert!(
                chunks.iter().all(|chunk| chunk.chunk == cut),
                "row {row} arrived in {} entries and the chunk flag disagrees",
                chunks.len()
            );
            let mut frame = RowFrame::default();
            let mut byte = 0_u32;
            for chunk in chunks {
                // A client places a span by the column and byte it names, not by what came before.
                assert_eq!(
                    (chunk.col, chunk.byte, chunk.clear_tail),
                    (frame.cells, byte, false),
                    "row {row} named a span at the wrong place"
                );
                byte += u32::try_from(chunk.frame.text.len()).expect("a row a u32 can measure");
                frame.text.push_str(&chunk.frame.text);
                frame.runs.extend(chunk.frame.runs);
                frame.cells += chunk.frame.cells;
            }
            (row, frame)
        })
        .collect()
}

/// Every row here is one an ordinary session produces, and none of them fit a datagram.
#[test]
fn a_row_too_wide_for_a_datagram_is_cut_into_chunks_that_reassemble() {
    for (name, row) in wide_rows() {
        let size = GridSize::new(row.cells, 1).expect("a one-row grid");
        let header = plain_header(size);
        assert!(
            row.encoded_len() > MIN_DATAGRAM_FRAME,
            "{name} fits a datagram whole, so it tests no cut"
        );
        let parts = encode_screen_parts(&header, None, None, one_row(&row), MIN_DATAGRAM_FRAME)
            .unwrap_or_else(|error| panic!("{name} is a row this encoder must cut: {error}"));
        assert!(parts.len() >= 2, "{name} was carried whole");
        assert_eq!(
            reassemble(&parts, MIN_DATAGRAM_FRAME),
            vec![(0, elide(&row))],
            "{name} did not reassemble"
        );
    }
}

/// A row cut across pieces is the one shape that could break the once-and-in-order rule.
#[test]
fn a_screen_of_cut_rows_names_each_row_once_per_piece_and_in_order() {
    // A piece carrying one chunk of one row and whole rows beside it is the mix the rule is about.
    let plain = styled_row("a", 1, 60, 20);
    let mut rows = vec![plain.clone()];
    for (_, wide) in wide_rows() {
        rows.push(wide);
        rows.push(plain.clone());
    }
    let count = u16::try_from(rows.len()).expect("a row count");
    let size = GridSize::new(GridSize::MAX_COLS, count).expect("a grid");
    let header = plain_header(size);
    let parts = encode_screen_parts(&header, None, None, in_order(&rows), MIN_DATAGRAM_FRAME)
        .expect("a screen of rows this encoder must cut");

    for (place, frame) in parts.iter().enumerate() {
        let part = decode_part(frame);
        let named: Vec<u16> = part_rows(&part).iter().map(|span| span.row).collect();
        assert!(
            named.windows(2).all(|pair| pair[0] < pair[1]),
            "piece {place} names rows {named:?}"
        );
    }
    assert_eq!(
        reassemble(&parts, MIN_DATAGRAM_FRAME),
        expected_rows(&rows),
        "the pieces did not concatenate back into the screen"
    );
}

/// The cutting above must cost a plain 80-column screen nothing at all.
#[test]
fn a_row_that_fits_its_budget_is_exactly_one_chunk() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let size = GridSize::new(GridSize::MAX_COLS, 1).expect("a one-row grid");
    let mut widest = 0_usize;
    for _ in 0..512 {
        let mut budget = frame_budget(size);
        let row = row_frame(&mut rng, size.cols, &mut budget);
        // The row's own length is the boundary the property is stated at.
        for bound in [row.encoded_len(), MIN_DATAGRAM_FRAME, stream_frame()] {
            let chunks: Vec<RowChunk<'_>> = row.chunks(bound).collect();
            assert_eq!(
                chunks.as_slice(),
                [row.whole()],
                "a row of {} bytes was cut at a budget of {bound}",
                row.encoded_len()
            );
        }
        widest = widest.max(row.encoded_len());
    }
    assert!(
        widest > 8,
        "every generated row was empty, so the property went untested"
    );
}

/// A row is cut at style-run boundaries, so a run larger than a piece has no cut point inside it.
#[test]
fn a_run_larger_than_a_piece_is_refused_rather_than_cut() {
    let size = GridSize::new(GridSize::MAX_COLS, 1).expect("a one-row grid");
    let header = plain_header(size);

    // Runs at the bound tile a row twice as wide as a datagram, and every piece still fits one.
    let at_bound = styled_row("é", 1, GridSize::MAX_COLS, 256);
    assert!(
        at_bound.runs.iter().all(|run| run.bytes == MAX_RUN_BYTES),
        "the row under test is not built of runs at the bound"
    );
    let parts = encode_screen_parts(&header, None, None, one_row(&at_bound), MIN_DATAGRAM_FRAME)
        .expect("runs at the bound are runs this encoder can cut");
    assert!(parts.len() >= 2, "the row under test fit one datagram");
    assert_eq!(
        reassemble(&parts, MIN_DATAGRAM_FRAME),
        vec![(0, elide(&at_bound))]
    );

    // The same text under one run is the same row with nowhere to cut it.
    let cells = at_bound.cells;
    let bytes = u32::try_from(at_bound.text.len()).expect("a row a u32 can measure");
    let oversize = RowFrame {
        runs: vec![StyleRun {
            cells,
            bytes,
            style: CellStyle::default(),
        }],
        ..at_bound
    };
    assert_eq!(
        encode_screen_parts(&header, None, None, one_row(&oversize), MIN_DATAGRAM_FRAME),
        Err(EncodeError::Oversize)
    );
}

/// A `MAX_TITLE` title is what makes the fixed part of a piece larger than the piece.
#[test]
fn a_header_no_piece_has_room_for_is_refused_rather_than_looped_on() {
    let size = GridSize::new(80, 1).expect("a one-row grid");
    let header = ScreenHeader {
        sticky: StickyState {
            title: Some("t".repeat(MAX_TITLE).into()),
            ..StickyState::default()
        },
        ..plain_header(size)
    };
    let row = styled_row("x", 1, size.cols, 40);
    let screen = || one_row(&row);

    let mut refused = 0_u32;
    let mut spilled = 0_u32;
    for budget in 0..=MIN_DATAGRAM_FRAME {
        match encode_screen_parts(&header, None, None, screen(), budget) {
            Err(EncodeError::Oversize) => refused += 1,
            Err(other) => panic!("a {budget}-byte piece was refused for {other}"),
            Ok(parts) => {
                assert_eq!(
                    reassemble(&parts, budget),
                    vec![(0, elide(&row))],
                    "a {budget}-byte piece lost the row"
                );
                spilled += u32::from(parts.len() > 1);
            }
        }
    }
    assert!(
        refused > 0 && spilled > 0,
        "a title of {MAX_TITLE} bytes was never refused ({refused}) or never spilled ({spilled})"
    );

    // The longest title still reaches a datagram whole, which makes the above a corner.
    let whole = encode_screen_parts(&header, None, None, screen(), MIN_DATAGRAM_FRAME)
        .expect("a title and a row inside one datagram");
    assert_eq!(whole.len(), 1);
    assert_eq!(
        decoded_header(&whole[0]).sticky.title,
        header.sticky.title,
        "the longest title a screen may carry did not survive a datagram"
    );
}

/// What an older client reads a newer server's refusal as. A screen is cut, so no reason at 7.
#[test]
fn every_reject_reason_keeps_the_wire_number_it_is_decoded_by() {
    for (reason, wire) in [
        (
            RejectReason::Version {
                server: VersionRange::new(7, 9).expect("a range"),
                client: VersionRange::LOCAL,
            },
            0,
        ),
        (RejectReason::UnknownSession, 1),
        (RejectReason::SequenceGap, 2),
        (RejectReason::InputBacklog, 3),
        (RejectReason::Internal, 4),
        (RejectReason::TooManySessions, 5),
        (RejectReason::TooManyAttachments, 6),
    ] {
        let message = ServerMessage::Reject { reason };
        let frame = message.encode(Version::LOCAL).expect("a small message");
        assert_eq!(frame[PREFIX + 1], wire, "{reason:?} moved on the wire");
        survives_server(&message);
    }
    for retired in [7_u8, 8, u8::MAX] {
        assert!(
            matches!(
                ServerMessage::decode(&[server_reject_tag(), retired], Version::LOCAL),
                Err(DecodeError::InvalidField)
            ),
            "the decoder took reject reason {retired}"
        );
    }
}

/// Taken from the encoder: a literal here would restate the tag assignment a second time.
fn tag_of_client(message: &ClientMessage) -> u8 {
    message.encode(Version::LOCAL).expect("a small message")[PREFIX]
}

fn tag_of_server(message: &ServerMessage) -> u8 {
    message.encode(Version::LOCAL).expect("a small message")[PREFIX]
}

fn client_forward_data_tag() -> u8 {
    tag_of_client(&ClientMessage::ForwardData {
        stream: StreamId::first(),
        off: ByteOff::zero(),
        fin: false,
        bytes: Vec::new(),
    })
}

fn server_forward_data_tag() -> u8 {
    tag_of_server(&ServerMessage::ForwardData {
        stream: StreamId::first(),
        off: ByteOff::zero(),
        fin: false,
        bytes: Vec::new(),
    })
}

fn server_reject_tag() -> u8 {
    tag_of_server(&ServerMessage::Reject {
        reason: RejectReason::Internal,
    })
}

/// The encoder will not write a flag bit this version does not state; a peer ahead will.
fn forward_data_payload(tag: u8, flags: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![tag];
    body.extend_from_slice(&StreamId::first().get().to_be_bytes());
    body.extend_from_slice(&0_u64.to_be_bytes());
    body.push(flags);
    let len = u32::try_from(bytes.len()).expect("a chunk length");
    body.extend_from_slice(&len.to_be_bytes());
    body.extend_from_slice(bytes);
    body
}

/// A decoder ignoring bits it does not know takes a future `fin` as a chunk and leaks the stream.
#[test]
fn a_forward_data_flag_this_version_does_not_state_is_refused() {
    assert!(matches!(
        ClientMessage::decode(
            &forward_data_payload(client_forward_data_tag(), 1, b"x"),
            Version::LOCAL
        ),
        Ok(ClientMessage::ForwardData { fin: true, .. })
    ));
    assert!(matches!(
        ServerMessage::decode(
            &forward_data_payload(server_forward_data_tag(), 0, b"x"),
            Version::LOCAL
        ),
        Ok(ServerMessage::ForwardData { fin: false, .. })
    ));
    for flags in [0b10_u8, 0b1000_0000, 0xff] {
        let client = ClientMessage::decode(
            &forward_data_payload(client_forward_data_tag(), flags, b"x"),
            Version::LOCAL,
        );
        let server = ServerMessage::decode(
            &forward_data_payload(server_forward_data_tag(), flags, b"x"),
            Version::LOCAL,
        );
        assert!(
            matches!(client, Err(DecodeError::InvalidField))
                && matches!(server, Err(DecodeError::InvalidField)),
            "forward flags {flags:#b} reached a message: {client:?}, {server:?}"
        );
    }
}

/// A host reaches a resolver and a diagnostic, and port zero is not a destination.
#[test]
fn a_forward_open_naming_no_destination_is_refused_at_both_ends() {
    let open = |host: String, port| ClientMessage::ForwardOpen {
        seq: CmdSeq::first(),
        stream: StreamId::first(),
        target: ForwardTarget { host, port },
    };
    for (name, host, port) in [
        ("no host at all", String::new(), 22_u16),
        ("past the DNS limit", "x".repeat(MAX_FORWARD_HOST + 1), 22),
        ("an OSC in the host", String::from("db\u{1b}]0;x\u{7}"), 22),
        ("port zero", String::from("localhost"), 0),
    ] {
        assert_eq!(
            open(host.clone(), port).encode(Version::LOCAL),
            Err(EncodeError::BadForwardTarget),
            "the encoder wrote {name}"
        );
        // The length field is a `u8`, so the over-long host is the one shape the wire cannot state.
        let Ok(len) = u8::try_from(host.len()) else {
            continue;
        };
        let mut body = vec![tag_of_client(&open(String::from("db"), 22))];
        body.extend_from_slice(&CmdSeq::first().get().to_be_bytes());
        body.extend_from_slice(&StreamId::first().get().to_be_bytes());
        body.push(len);
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        assert!(
            matches!(
                ClientMessage::decode(&body, Version::LOCAL),
                Err(DecodeError::InvalidField)
            ),
            "the decoder took {name}"
        );
    }
    survives_client(&open("x".repeat(MAX_FORWARD_HOST), 22));
}

/// The chunk is the reorder unit, so a larger one is a reservation this side never agreed to.
#[test]
fn a_forward_payload_past_its_chunk_is_refused_at_both_ends() {
    let data = |len: usize| ClientMessage::ForwardData {
        stream: StreamId::first(),
        off: ByteOff::zero(),
        fin: false,
        bytes: vec![b'x'; len],
    };
    survives_client(&data(MAX_FORWARD_CHUNK));
    assert_eq!(
        data(MAX_FORWARD_CHUNK + 1).encode(Version::LOCAL),
        Err(EncodeError::Oversize)
    );
    assert_eq!(
        ServerMessage::ForwardData {
            stream: StreamId::first(),
            off: ByteOff::zero(),
            fin: false,
            bytes: vec![b'x'; MAX_FORWARD_CHUNK + 1],
        }
        .encode(Version::LOCAL),
        Err(EncodeError::Oversize)
    );
    let over = vec![b'x'; MAX_FORWARD_CHUNK + 1];
    let limit = u32::try_from(MAX_FORWARD_CHUNK).expect("a 32-bit bound");
    let past = |actual: u32, stated: u32| actual == limit + 1 && stated == limit;
    assert!(
        matches!(
            ClientMessage::decode(&forward_data_payload(client_forward_data_tag(), 0, &over), Version::LOCAL),
            Err(DecodeError::Oversize { actual, limit: stated }) if past(actual, stated)
        ),
        "a client took a chunk past the bound"
    );
    assert!(
        matches!(
            ServerMessage::decode(&forward_data_payload(server_forward_data_tag(), 0, &over), Version::LOCAL),
            Err(DecodeError::Oversize { actual, limit: stated }) if past(actual, stated)
        ),
        "a server took a chunk past the bound"
    );
}

/// A row of `text`, one narrow cell per byte.
fn ascii_row(text: &str) -> RowFrame {
    RowFrame {
        text: text.into(),
        runs: Vec::new(),
        cells: u16::try_from(text.len()).expect("a short row"),
    }
}

/// A one-piece delta over the four-row grid `part_header` names.
fn delta(rows: Vec<RowSpan>) -> ScreenPart {
    ScreenPart::Head {
        header: part_header(),
        base: Some(ScreenVersion::initial()),
        scroll: None,
        pieces: 1,
        rows,
    }
}

/// A row may be named by several spans in one piece, and it is their *columns* that must ascend.
#[test]
fn several_spans_of_one_row_survive_the_wire_in_column_order() {
    let part = delta(vec![
        RowSpan {
            chunk: true,
            ..span(1, ascii_row("ab"))
        },
        RowSpan {
            chunk: true,
            col: 2,
            byte: 2,
            clear_tail: true,
            ..span(1, ascii_row("cd"))
        },
        RowSpan {
            col: 4,
            byte: 9,
            clear_tail: true,
            ..span(2, ascii_row("ef"))
        },
    ]);
    survives_server(&ServerMessage::Screen { part });
}

/// A corrupted line, not a wrong repaint: the client writes it at the column the span states.
#[test]
fn a_span_that_does_not_land_inside_its_row_is_refused() {
    let ceiling = u32::from(u16::try_from(8 * MAX_CLUSTER_BYTES).expect("a small ceiling"));
    for (what, text, col, byte) in [
        (
            "columns running off the end of an eight-column grid",
            "ab",
            7,
            0,
        ),
        ("a span starting past the last column", "a", 8, 0),
        (
            "a byte offset past what a row's text can hold",
            "ab",
            0,
            ceiling - 1,
        ),
        ("a byte offset no row could reach at all", "a", 0, u32::MAX),
    ] {
        let span = RowSpan {
            col,
            byte,
            ..span(0, ascii_row(text))
        };
        assert!(
            matches!(part_refusal(delta(vec![span])), DecodeError::InvalidField),
            "the decoder admitted {what}"
        );
    }
}

/// A piece stays independent of the order it is applied in.
#[test]
fn spans_of_one_row_whose_columns_do_not_ascend_are_refused() {
    for (first, second) in [(2_u16, 2_u16), (2, 1)] {
        let part = delta(vec![
            RowSpan {
                chunk: true,
                col: first,
                ..span(1, ascii_row("a"))
            },
            RowSpan {
                chunk: true,
                col: second,
                byte: 1,
                ..span(1, ascii_row("b"))
            },
        ]);
        assert!(
            matches!(part_refusal(part), DecodeError::InvalidField),
            "the decoder admitted spans at columns {first} then {second}"
        );
    }
}

/// A `Tail` names no grid, so at `u16::MAX` a run count buys two megabytes from a tiny datagram.
#[test]
fn a_piece_claiming_more_runs_than_a_grid_has_columns_is_refused() {
    let tail = |runs: u16| {
        let mut body = vec![
            tag_of_server(&ServerMessage::Screen {
                part: ScreenPart::Tail {
                    generation: Generation::initial(),
                    version: ScreenVersion::initial(),
                    pieces: 2,
                    index: 1,
                    rows: Vec::new(),
                },
            }),
            1,
        ];
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&1_u64.to_be_bytes());
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&1_u16.to_be_bytes());
        // One row: index zero, at column zero, at byte zero.
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&0_u32.to_be_bytes());
        // No text, no cells, and a run count out of thin air.
        body.extend_from_slice(&0_u32.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&runs.to_be_bytes());
        body
    };
    let claim = tail(u16::MAX);
    assert!(
        claim.len() < 64,
        "the payload under test grew to {} bytes",
        claim.len()
    );
    assert!(matches!(
        ServerMessage::decode(&claim, Version::LOCAL),
        Err(DecodeError::InvalidField)
    ));
    // The runs it names are not there, so the frame ends before them.
    assert!(matches!(
        ServerMessage::decode(&tail(GridSize::MAX_COLS), Version::LOCAL),
        Err(DecodeError::Truncated)
    ));
}

/// Without these a `yank` over OSC 52 inside a sync episode silently pastes stale content.
#[test]
fn a_screens_deferred_state_survives_the_wire() {
    let mut header = part_header();
    header.sticky.saved_cursor = Some((7, 3));
    header.sticky.pending_wrap = true;
    header.sticky.deferred = vec![
        String::from("52;c;aGVsbG8="),
        String::from("133;A"),
        String::from("8;;https://example/x"),
    ];
    let frame = part_frame(headless(header.clone()));
    assert_eq!(decoded_header(&frame).sticky, header.sticky);
}

/// A saved cursor is restored by positioning the terminal there, so it is bounded like the live one.
#[test]
fn a_saved_cursor_outside_the_grid_is_refused_like_the_live_one() {
    for saved in [(8, 0), (0, 4), (u16::MAX, u16::MAX)] {
        let mut header = part_header();
        header.sticky.saved_cursor = Some(saved);
        assert!(
            matches!(part_refusal(headless(header)), DecodeError::InvalidField),
            "the decoder admitted a saved cursor at {saved:?} on an 8x4 grid"
        );
    }
}

/// An OSC body carries no terminator: a control byte closes the string early and reaches the user.
#[test]
fn a_deferred_sequence_carrying_a_control_byte_is_refused_at_both_ends() {
    let mut header = part_header();
    header.sticky.deferred = vec![String::from("0;plain title")];
    let frame = part_frame(headless(header.clone()));

    // Dropping the entry quietly is the exact silence the field exists to end.
    let mut hostile = header;
    hostile.sticky.deferred = vec![String::from("52;c;a\u{1b}]0;pwned\u{7}")];
    assert_eq!(
        ServerMessage::Screen {
            part: headless(hostile)
        }
        .encode(Version::LOCAL),
        Err(EncodeError::BadDeferred)
    );

    // And the decoder refuses one a peer states anyway.
    let at = frame
        .windows(5)
        .position(|window| window == b"plain")
        .expect("the entry is in the frame");
    let mut damaged = frame;
    damaged[at] = 0x1b;
    assert!(matches!(
        ServerMessage::decode(&damaged[PREFIX..], Version::LOCAL),
        Err(DecodeError::InvalidField)
    ));
}

/// Bounded at encode, oldest first out, so OSC 133 marks cannot push a screen past its path.
#[test]
fn a_deferred_list_past_its_bounds_keeps_the_newest_entries() {
    let mut header = part_header();
    header.sticky.deferred = (0..MAX_DEFERRED * 3)
        .map(|n| format!("133;A;{n}"))
        .collect();
    let expected = header.sticky.deferred[MAX_DEFERRED * 2..].to_vec();
    let frame = part_frame(headless(header));
    assert_eq!(decoded_header(&frame).sticky.deferred, expected);

    // This side's own bound is what keeps the head inside a datagram.
    let mut over = frame[PREFIX..].to_vec();
    let first = expected[0].as_bytes();
    let at = over
        .windows(first.len())
        .position(|window| window == first)
        .expect("the first kept entry is in the frame");
    // The count sits before that entry's own two-byte length.
    let bound = u8::try_from(MAX_DEFERRED).expect("a small bound");
    assert_eq!(over[at - 3], bound);
    over[at - 3] = bound + 1;
    assert!(matches!(
        ServerMessage::decode(&over, Version::LOCAL),
        Err(DecodeError::InvalidField)
    ));
}

/// A row tiled by one style run per entry, so a run index and a column line up.
fn run_row(runs: &[&str]) -> RowFrame {
    RowFrame {
        text: runs.concat(),
        runs: runs
            .iter()
            .map(|piece| StyleRun {
                cells: u16::try_from(piece.len()).expect("a short run"),
                bytes: u32::try_from(piece.len()).expect("a short run"),
                style: CellStyle::default(),
            })
            .collect(),
        cells: u16::try_from(runs.concat().len()).expect("a short row"),
    }
}

/// A one-piece delta carrying one span, and the rows a client decodes from it.
fn one_span(size: GridSize, update: RowUpdate<'_>) -> (Vec<u8>, Vec<RowSpan>) {
    let mut parts = encode_screen_parts(
        &plain_header(size),
        Some(ScreenVersion::initial()),
        None,
        std::iter::once(update),
        MIN_DATAGRAM_FRAME,
    )
    .expect("one span of one row");
    assert_eq!(parts.len(), 1);
    let frame = parts.remove(0);
    let ScreenPart::Head { rows, .. } = decode_part(&frame) else {
        panic!("a head");
    };
    (frame, rows)
}

/// What a tmux status bar repainting its clock costs; without a column the row goes whole.
#[test]
fn a_row_that_changed_in_the_middle_travels_as_a_span_of_that_row() {
    let size = GridSize::new(40, 2).expect("a small grid");
    let before = run_row(&["[0] ", "12:00", " host"]);
    let after = run_row(&["[0] ", "12:01", " host"]);
    let runs = after.changed_span(&before).expect("the clock moved");
    assert_eq!(runs, (1, 2));

    let (frame, rows) = one_span(
        size,
        RowUpdate {
            row: 1,
            frame: &after,
            runs,
            clear_tail: false,
        },
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].row, rows[0].col, rows[0].byte, rows[0].clear_tail),
        (1, 4, 4, false)
    );
    assert_eq!(rows[0].frame.text, "12:01");
    // A piece carries a header `encoded_len` knows nothing about, so compare through the encoder.
    let (whole, _) = one_span(size, RowUpdate::whole(1, &after));
    assert!(
        frame.len() < whole.len(),
        "a span of {} bytes did not beat the whole row at {} bytes",
        frame.len(),
        whole.len()
    );
}

/// A row that lost everything past the span owes an erase with no text to hang it on.
#[test]
fn a_row_that_got_shorter_carries_the_erase_it_owes() {
    let size = GridSize::new(40, 2).expect("a small grid");
    let before = run_row(&["keep ", "gone gone gone"]);
    let after = run_row(&["keep "]);
    let runs = after.changed_span(&before).expect("the tail went");
    assert_eq!(runs, (1, 1));

    let (_, rows) = one_span(
        size,
        RowUpdate {
            row: 0,
            frame: &after,
            runs,
            clear_tail: true,
        },
    );
    assert_eq!(rows.len(), 1, "the erase was dropped with its empty span");
    assert_eq!(
        (rows[0].col, rows[0].byte, rows[0].clear_tail),
        (5, 5, true)
    );
    assert!(rows[0].frame.text.is_empty());
}

/// Applying the erase to an earlier piece would wipe columns the spans behind it are about to fill.
#[test]
fn only_the_last_span_of_a_cut_row_carries_the_erase() {
    // An unstyled run costs eleven bytes beside its text: sixteen runs is what overruns a piece.
    let wide: Vec<String> = (0..16).map(|_| "x".repeat(64)).collect();
    let row = run_row(&wide.iter().map(String::as_str).collect::<Vec<_>>());
    let size = GridSize::new(GridSize::MAX_COLS, 1).expect("a one-row grid");
    let parts = encode_screen_parts(
        &plain_header(size),
        Some(ScreenVersion::initial()),
        None,
        std::iter::once(RowUpdate {
            row: 0,
            frame: &row,
            runs: (0, row.runs.len()),
            clear_tail: true,
        }),
        MIN_DATAGRAM_FRAME,
    )
    .expect("a row this encoder must cut");
    assert!(parts.len() >= 2, "the row under test fit one datagram");

    let erasing: Vec<bool> = parts
        .iter()
        .flat_map(|frame| {
            let part = decode_part(frame);
            part_rows(&part)
                .iter()
                .map(|span| span.clear_tail)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        erasing.iter().filter(|owed| **owed).count(),
        1,
        "the erase was written {erasing:?}"
    );
    assert!(*erasing.last().expect("at least one span"));
}
