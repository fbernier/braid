//! The vocabulary of a resumable screen: grid, style, cursor, modes, sticky state.
//! Row text is data: controls are refused at decode, never rendered as commands.

use crate::{
    Cursor, DecodeError, EncodeError, decode_bool, decode_cursor, encode_cursor, put_u16, put_u32,
};
use std::sync::Arc;

pub const MAX_TITLE: usize = 512;

pub const MAX_DEFERRED: usize = 16;
pub const MAX_DEFERRED_BYTES: usize = 4096;

/// Bounds row text at `cells * MAX_CLUSTER_BYTES`: the encoder checks that product
/// against `cells`, the decoder against `cols`, which it proves `cells` fits.
pub const MAX_CLUSTER_BYTES: usize = 64;

/// Palette indices stay unresolved: resolving them against the *server's* palette
/// would recolour the user's terminal on every reconnect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StyleColor {
    #[default]
    Default,
    Palette(u8),
    Rgb(u8, u8, u8),
}

impl StyleColor {
    const fn encoded_len(self) -> usize {
        match self {
            Self::Default => 1,
            Self::Palette(_) => 2,
            Self::Rgb(..) => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct StyleAttrs(u8);

impl StyleAttrs {
    pub const NONE: Self = Self(0);
    pub const BOLD: Self = Self(1 << 0);
    pub const ITALIC: Self = Self(1 << 1);
    pub const FAINT: Self = Self(1 << 2);
    pub const BLINK: Self = Self(1 << 3);
    pub const INVERSE: Self = Self(1 << 4);
    pub const INVISIBLE: Self = Self(1 << 5);
    pub const STRIKETHROUGH: Self = Self(1 << 6);
    pub const OVERLINE: Self = Self(1 << 7);

    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    #[must_use]
    pub const fn with(self, flag: Self, on: bool) -> Self {
        if on {
            Self(self.0 | flag.0)
        } else {
            Self(self.0 & !flag.0)
        }
    }

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// SGR 4:n underline shapes; the discriminant is the wire value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum UnderlineStyle {
    #[default]
    None = 0,
    Single = 1,
    Double = 2,
    Curly = 3,
    Dotted = 4,
    Dashed = 5,
}

impl UnderlineStyle {
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Single),
            2 => Some(Self::Double),
            3 => Some(Self::Curly),
            4 => Some(Self::Dotted),
            5 => Some(Self::Dashed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CellStyle {
    pub fg: StyleColor,
    pub bg: StyleColor,
    pub underline_color: StyleColor,
    pub attrs: StyleAttrs,
    pub underline: UnderlineStyle,
}

impl CellStyle {
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// A span of consecutive cells sharing one style. `cells` is columns and `bytes` is
/// bytes of [`RowFrame::text`]: wide glyphs and combining marks make the two differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StyleRun {
    pub cells: u16,
    pub bytes: u32,
    pub style: CellStyle,
}

impl StyleRun {
    /// Exact, not a widest-colour bound: overcharging cuts a coloured screen into
    /// more pieces than its bytes need.
    pub(crate) const fn style_len(self) -> usize {
        RUN_FIXED
            + self.style.fg.encoded_len()
            + self.style.bg.encoded_len()
            + self.style.underline_color.encoded_len()
    }
}

/// One cluster per rendered column in `text` — the second column of a wide glyph
/// contributes none, so `cells` travels explicitly. Runs tile a prefix; every cell
/// and byte past the last run carries the default style.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowFrame {
    pub text: String,
    pub runs: Vec<StyleRun>,
    pub cells: u16,
}

impl RowFrame {
    #[must_use]
    pub fn styled_cells(&self) -> u32 {
        self.runs.iter().map(|run| u32::from(run.cells)).sum()
    }

    #[must_use]
    pub fn styled_bytes(&self) -> usize {
        self.runs
            .iter()
            .map(|run| run.bytes as usize)
            .sum::<usize>()
            .min(self.text.len())
    }

    /// A row is painted over an erased line, so unstyled trailing blanks are dropped
    /// at encode. Both operands are char boundaries.
    #[must_use]
    pub fn painted_bytes(&self) -> usize {
        self.styled_bytes()
            .max(self.text.trim_end_matches(' ').len())
            .min(self.text.len())
    }

    #[must_use]
    pub fn whole(&self) -> RowChunk<'_> {
        RowChunk {
            text: &self.text[..self.painted_bytes()],
            runs: &self.runs,
            cells: self.cells,
            col: 0,
            byte: 0,
        }
    }

    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.whole().encoded_len()
    }

    fn clamp_runs(&self, runs: (usize, usize)) -> (usize, usize) {
        let first = runs.0.min(self.runs.len());
        (first, runs.1.clamp(first, self.runs.len()))
    }

    /// Column and byte offset at which run `first` begins.
    fn run_start(&self, first: usize) -> (u16, usize) {
        let mut col = 0_u16;
        let mut byte = 0_usize;
        for run in self.runs.iter().take(first) {
            col = col.saturating_add(run.cells);
            byte += run.bytes as usize;
        }
        (col, byte)
    }

    pub(crate) fn span_len(&self, runs: (usize, usize)) -> usize {
        let (first, end) = self.clamp_runs(runs);
        let (_, from) = self.run_start(first);
        let bytes = if end == self.runs.len() {
            self.painted_bytes().saturating_sub(from)
        } else {
            self.runs[first..end]
                .iter()
                .map(|run| run.bytes as usize)
                .sum()
        };
        CHUNK_FIXED + bytes + style_len(&self.runs[first..end])
    }

    #[must_use]
    pub fn chunks(&self, budget: usize) -> RowChunks<'_> {
        self.span((0, self.runs.len()), budget)
    }

    /// The row's unstyled tail belongs to a range ending at `runs.len()` and to no
    /// other, that being the only range whose end is the end of the row.
    #[must_use]
    pub fn span(&self, runs: (usize, usize), budget: usize) -> RowChunks<'_> {
        let (first, end) = self.clamp_runs(runs);
        let (cell, byte) = self.run_start(first);
        RowChunks {
            row: self,
            painted: self.painted_bytes(),
            budget,
            run: first,
            end,
            byte,
            cell,
            done: false,
        }
    }

    /// Run indices, not columns: a run boundary is the only offset where both a column
    /// and a byte position are known. A run whose *extent* changed moves every column
    /// after it, so from there the range runs to the end of the row.
    pub fn changed_span(&self, previous: &RowFrame) -> Option<(usize, usize)> {
        let common = self.runs.len().min(previous.runs.len());
        let mut first = None;
        let mut last = 0;
        let mut byte = 0_usize;
        let mut aligned = self.runs.len() == previous.runs.len();
        for (index, (mine, theirs)) in self.runs.iter().zip(previous.runs.iter()).enumerate() {
            let placed = mine.cells == theirs.cells && mine.bytes == theirs.bytes;
            let end = byte + mine.bytes as usize;
            if !placed
                || mine.style != theirs.style
                || self.text.get(byte..end) != previous.text.get(byte..end)
            {
                first.get_or_insert(index);
                last = index + 1;
            }
            if !placed {
                aligned = false;
                break;
            }
            byte = end;
        }
        // The unstyled tail is not a run, so nothing above compares it.
        let tail = self.cells != previous.cells
            || self.text.get(byte..self.painted_bytes())
                != previous.text.get(byte..previous.painted_bytes());
        if !aligned || tail {
            first.get_or_insert(common);
            last = self.runs.len();
        }
        let first = first?;
        Some((first, last.max(first)))
    }
}

/// Rows are cut at run boundaries and nowhere else — the only offset where both a byte
/// position and a column are known — so a bounded run is what makes every row cuttable.
pub const MAX_RUN_BYTES: u32 = 512;

/// Reassembly is concatenation in text, runs and columns: a chunk boundary is a run one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowChunk<'a> {
    pub text: &'a str,
    pub runs: &'a [StyleRun],
    pub cells: u16,
    /// Non-zero means the client keeps whatever it holds in the columns before it.
    pub col: u16,
    /// Byte offset of `text` within the whole row's text.
    pub byte: u32,
}

impl RowChunk<'_> {
    /// Exactly; where the chunk lands in the row is written by the piece around it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        CHUNK_FIXED + self.text.len() + style_len(self.runs)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.runs.is_empty() && self.cells == 0
    }
}

/// Text length, column count and run count.
pub(crate) const CHUNK_FIXED: usize = 8;

/// A run's two extents, its attributes and its underline shape, before its colours.
const RUN_FIXED: usize = 8;

fn style_len(runs: &[StyleRun]) -> usize {
    runs.iter().map(|run| run.style_len()).sum()
}

/// Two of cells, four of bytes, one each of attrs and underline, one per shortest
/// colour: what the payload could hold, so a run count alone cannot drive a reserve.
pub(crate) const MIN_RUN_BYTES: usize = 11;

/// Row text is bounded by `MAX_COLS * MAX_CLUSTER_BYTES`, so the saturation is
/// unreachable; it keeps the offset off a panicking path.
fn narrow(byte: usize) -> u32 {
    u32::try_from(byte).unwrap_or(u32::MAX)
}

#[derive(Clone)]
pub struct RowChunks<'a> {
    row: &'a RowFrame,
    painted: usize,
    budget: usize,
    run: usize,
    /// One past the last run this cut may reach; short of `row.runs.len()` for a delta.
    end: usize,
    byte: usize,
    cell: u16,
    done: bool,
}

impl RowChunks<'_> {
    /// Read before iterating this is the span's own start — the only place to hang the
    /// erase a row that shrank to nothing owes, since it yields no chunk to carry it.
    #[must_use]
    pub fn start(&self) -> (u16, u32) {
        (self.cell, narrow(self.byte))
    }
}

impl<'a> Iterator for RowChunks<'a> {
    type Item = RowChunk<'a>;

    fn next(&mut self) -> Option<RowChunk<'a>> {
        if self.done {
            return None;
        }
        let first_run = self.run;
        let first_byte = self.byte;
        let first_cell = self.cell;
        let mut cost = CHUNK_FIXED;
        let mut cells = 0_u16;
        while self.run < self.end
            && let Some(run) = self.row.runs.get(self.run)
        {
            let unit = run.bytes as usize + run.style_len();
            // A run that fits no empty chunk is emitted alone, so the caller can name
            // an oversize piece rather than a row cut where no column is known.
            if cost + unit > self.budget && self.run > first_run {
                break;
            }
            cost += unit;
            cells = cells.saturating_add(run.cells);
            self.byte += run.bytes as usize;
            self.run += 1;
        }
        if self.run == self.end && self.end == self.row.runs.len() {
            // The tail carries the columns no run named, including the trailing
            // blanks `painted_bytes` dropped, which the chunks must re-add.
            let tail_bytes = self.painted.saturating_sub(self.byte);
            let tail_cells = self.row.cells.saturating_sub(self.cell + cells);
            if cost + tail_bytes <= self.budget || (first_run == self.run && cells == 0) {
                self.byte = self.painted.max(self.byte);
                cells = cells.saturating_add(tail_cells);
                self.done = true;
            }
        } else if self.run == self.end {
            // A span stopping short of the last run owns no tail: those columns belong
            // to a later span, or to the row the client holds already.
            self.done = true;
        }
        let text = self
            .row
            .text
            .get(first_byte..self.byte.min(self.painted))
            .unwrap_or_default();
        let chunk = RowChunk {
            text,
            runs: &self.row.runs[first_run..self.run],
            cells,
            col: first_cell,
            byte: narrow(first_byte),
        };
        self.cell = self.cell.saturating_add(cells);
        // A row with no cells and no text is still a row the piece has to name.
        if chunk.is_empty() && first_run > 0 {
            self.done = true;
            return None;
        }
        if !self.done && first_run == self.run {
            self.done = true;
        }
        Some(chunk)
    }
}

/// `top`/`bottom` are a half-open row range, `lines` is how far up the band shifted. A
/// band, not the viewport: a status line means a viewport form never fires on real output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrollBand {
    pub top: u16,
    pub bottom: u16,
    pub lines: u16,
}

impl ScrollBand {
    /// The client hands these to `CSI r` and scrolls inside them. Downward is not
    /// representable: no client holds the rows a reverse scroll reveals.
    pub(crate) fn is_applicable(self, rows: u16) -> bool {
        self.top < self.bottom
            && self.bottom <= rows
            && self.lines > 0
            && self.lines <= self.bottom - self.top
    }
}

/// `Unset` is not a shape but the absence of any DECSCUSR the session issued; a
/// client renders it by resetting to whatever the user configured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CursorShape {
    #[default]
    Unset,
    Block,
    Underline,
    Bar,
}

impl CursorShape {
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Unset => 0,
            Self::Block => 1,
            Self::Underline => 2,
            Self::Bar => 3,
        }
    }

    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unset),
            1 => Some(Self::Block),
            2 => Some(Self::Underline),
            3 => Some(Self::Bar),
            _ => None,
        }
    }

    /// `Unset` is parameter 0 — the reset that hands the choice back to the client's
    /// terminal, blink included — so `blinking` does not apply to it.
    #[must_use]
    pub const fn decscusr(self, blinking: bool) -> u8 {
        let steady = match self {
            Self::Unset => return 0,
            Self::Block => 2,
            Self::Underline => 4,
            Self::Bar => 6,
        };
        if blinking { steady - 1 } else { steady }
    }
}

/// State a passthrough episode set that is not a grid, a style or a mode. Lost at the
/// first repaint after a reconnect: nothing re-sends a title or re-pushes a key stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StickyState {
    /// Shared: a screen carries it thirty times a second, it changes once a session.
    pub title: Option<Arc<str>>,
    /// Kitty keyboard protocol flags in effect, restored with `CSI > flags u`.
    pub kitty_keyboard: u8,
    /// A `BEL` arriving during a sync episode is otherwise dropped with the stream.
    pub bell: bool,
    /// Unset when the session issued no DECSC: an `ESC 8` without it restores whatever
    /// the *user's own* terminal last saved.
    pub saved_cursor: Option<(u16, u16)>,
    /// Not derivable from the position: a cursor that arrived at the last column and
    /// one that printed into it put the next character in different rows.
    pub pending_wrap: bool,
    /// OSC bodies alone — the bytes between `ESC ]` and the terminator, neither
    /// included — so the no-control-bytes rule holds. Oldest dropped first at encode.
    pub deferred: Vec<String>,
}

/// The wire position is the array index, so the list is append-only. Absent: 25 and 12
/// (the cursor fields carry them), 47 and 1047 (1049 supersedes), 2026 (would freeze the
/// terminal mid-frame), 6 (DECOM without the DECSTBM libghostty hides lands CUP off).
pub const REPAINT_MODES: [u16; 20] = [
    1,    // DECCKM: decides what the arrow keys send
    7,    // DECAWM: autowrap
    66,   // DECNKM: application keypad
    1000, // X11 mouse button tracking
    1002, // button-event mouse tracking
    1003, // any-event mouse tracking
    1004, // focus in/out reporting
    1005, // UTF-8 mouse encoding
    1006, // SGR mouse encoding
    1007, // alternate scroll
    1015, // urxvt mouse encoding
    1016, // SGR pixel mouse encoding
    1036, // meta sends escape
    1049, // alternate screen with saved cursor
    2004, // bracketed paste
    2027, // grapheme clustering
    5,    // DECSCNM: reverse video
    9,    // X10 mouse compatibility
    45,   // reverse wraparound
    67,   // DECBKM: backarrow sends backspace
];

const _: () = assert!(REPAINT_MODES.len() <= u32::BITS as usize);

/// Modes an exiting client owes the terminal a `DECRST` for. DECAWM (7) and grapheme
/// clustering (2027) are excluded: for those, "off" would be a change, not an undo.
pub const RESET_ON_EXIT: ModeSet = {
    let mut set = ModeSet::empty();
    let mut index = 0;
    while index < REPAINT_MODES.len() {
        if REPAINT_MODES[index] != 7 && REPAINT_MODES[index] != 2027 {
            set.set(index, true);
        }
        index += 1;
    }
    set
};

/// The on/off state of every mode in [`REPAINT_MODES`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct ModeSet(u32);

impl ModeSet {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Bits past [`REPAINT_MODES`] are dropped for a local caller; [`Self::decode`]
    /// refuses them, since two spellings of one frame is how a byte gets past a length.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::MASK)
    }

    pub(crate) const fn decode(bits: u32) -> Option<Self> {
        if bits & !Self::MASK != 0 {
            return None;
        }
        Some(Self(bits))
    }

    const MASK: u32 = if REPAINT_MODES.len() == u32::BITS as usize {
        u32::MAX
    } else {
        (1_u32 << REPAINT_MODES.len()) - 1
    };

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn set(&mut self, index: usize, on: bool) {
        let bit = 1_u32 << index;
        if on {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    #[must_use]
    pub const fn get(self, index: usize) -> bool {
        self.0 & (1_u32 << index) != 0
    }

    /// Each mode number paired with whether it is set.
    pub fn iter(self) -> impl Iterator<Item = (u16, bool)> {
        REPAINT_MODES
            .into_iter()
            .enumerate()
            .map(move |(index, mode)| (mode, self.get(index)))
    }
}

pub(crate) fn encode_style_color(out: &mut Vec<u8>, color: StyleColor) {
    match color {
        StyleColor::Default => out.push(0),
        StyleColor::Palette(index) => out.extend_from_slice(&[1, index]),
        StyleColor::Rgb(r, g, b) => out.extend_from_slice(&[2, r, g, b]),
    }
}

fn decode_style_color(c: &mut Cursor<'_>) -> Result<StyleColor, DecodeError> {
    match c.take(1)?[0] {
        0 => Ok(StyleColor::Default),
        1 => Ok(StyleColor::Palette(c.take(1)?[0])),
        2 => {
            let rgb = c.take(3)?;
            Ok(StyleColor::Rgb(rgb[0], rgb[1], rgb[2]))
        }
        _ => Err(DecodeError::InvalidField),
    }
}

/// Oldest out first: the newest OSC is the one the user just caused.
fn deferred_start(deferred: &[String]) -> usize {
    let mut total = 0_usize;
    let mut start = deferred.len();
    for (index, entry) in deferred.iter().enumerate().rev() {
        total += entry.len() + 2;
        if total > MAX_DEFERRED_BYTES || deferred.len() - index > MAX_DEFERRED {
            break;
        }
        start = index;
    }
    start
}

/// Oversize and control-bearing titles are elided rather than refused: a peer that
/// refuses this frame refuses every later one, leaving the session alive and unreachable.
fn wire_title(sticky: &StickyState) -> Option<&str> {
    sticky
        .title
        .as_deref()
        .filter(|title| title.len() <= MAX_TITLE && !has_control(title))
}

/// Bytes [`encode_sticky`] will write, exactly: the screen cut is computed against it.
pub(crate) fn sticky_bytes(sticky: &StickyState) -> usize {
    let title = wire_title(sticky).map_or(1, |title| 3 + title.len());
    let saved = if sticky.saved_cursor.is_some() { 5 } else { 1 };
    let deferred: usize = sticky.deferred[deferred_start(&sticky.deferred)..]
        .iter()
        .map(|entry| entry.len() + 2)
        .sum();
    title + 1 + 1 + saved + 1 + 1 + deferred
}

pub(crate) fn encode_sticky(out: &mut Vec<u8>, sticky: &StickyState) -> Result<(), EncodeError> {
    match wire_title(sticky) {
        Some(title) => {
            out.push(1);
            let len = u16::try_from(title.len()).map_err(|_| EncodeError::Oversize)?;
            put_u16(out, len);
            out.extend_from_slice(title.as_bytes());
        }
        None => out.push(0),
    }
    out.push(sticky.kitty_keyboard);
    out.push(u8::from(sticky.bell));
    encode_cursor(out, sticky.saved_cursor);
    out.push(u8::from(sticky.pending_wrap));
    let kept = &sticky.deferred[deferred_start(&sticky.deferred)..];
    out.push(u8::try_from(kept.len()).map_err(|_| EncodeError::BadDeferred)?);
    for entry in kept {
        // An OSC body carries no terminator of its own, so reaching this means the
        // scanner kept one and the frame is one the peer would refuse.
        if has_control(entry) {
            return Err(EncodeError::BadDeferred);
        }
        let len = u16::try_from(entry.len()).map_err(|_| EncodeError::BadDeferred)?;
        put_u16(out, len);
        out.extend_from_slice(entry.as_bytes());
    }
    Ok(())
}

pub(crate) fn decode_sticky(c: &mut Cursor<'_>) -> Result<StickyState, DecodeError> {
    let title = match c.take(1)?[0] {
        0 => None,
        1 => {
            let len = usize::from(c.u16()?);
            if len > MAX_TITLE {
                return Err(DecodeError::InvalidField);
            }
            let title = std::str::from_utf8(c.take(len)?).map_err(|_| DecodeError::BadUtf8)?;
            // A title reaches the terminal inside an OSC string, and a control byte in
            // one closes the string early and hands the rest to the parser.
            reject_control(title)?;
            Some(Arc::from(title))
        }
        _ => return Err(DecodeError::InvalidField),
    };
    let kitty_keyboard = c.take(1)?[0];
    let bell = decode_bool(c)?;
    let saved_cursor = decode_cursor(c)?;
    let pending_wrap = decode_bool(c)?;
    let count = usize::from(c.take(1)?[0]);
    if count > MAX_DEFERRED {
        return Err(DecodeError::InvalidField);
    }
    // An entry cannot cost less than its own length prefix, whatever the count claims.
    let mut deferred = Vec::with_capacity(count.min(c.remaining() / 2));
    let mut total = 0_usize;
    for _ in 0..count {
        let len = usize::from(c.u16()?);
        total += len + 2;
        if total > MAX_DEFERRED_BYTES {
            return Err(DecodeError::InvalidField);
        }
        let entry = std::str::from_utf8(c.take(len)?).map_err(|_| DecodeError::BadUtf8)?;
        reject_control(entry)?;
        deferred.push(entry.to_owned());
    }
    Ok(StickyState {
        title,
        kitty_keyboard,
        bell,
        saved_cursor,
        pending_wrap,
        deferred,
    })
}

/// C1 and DEL as well as C0: a lone `0x9d` is an OSC introducer to a terminal that
/// decodes 8-bit controls.
pub(crate) fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

pub(crate) fn reject_control(text: &str) -> Result<(), DecodeError> {
    if has_control(text) {
        return Err(DecodeError::InvalidField);
    }
    Ok(())
}

/// Controls are blanked byte-for-byte, never dropped: a run names byte counts, so a
/// replacement of another length moves every column after it. C0 and DEL become a
/// space, C1 becomes the only two-byte blank there is.
///
/// Blanked rather than left to the decoder's refusal, which must stay a refusal: a
/// client meeting `InvalidField` exits, reattaches and is handed the same screen
/// forever. Ghostty stores a `DLE` as an ordinary cell (`fuzz_targets/vt_feed.rs`).
fn push_row_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    // None of these three can be a continuation byte (0x80..=0xBF), so scanning bytes
    // cannot mistake the tail of a character for its lead.
    if !bytes
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x1f | 0x7f | 0xc2))
    {
        out.extend_from_slice(bytes);
        return;
    }
    let (mut at, mut copied) = (0, 0);
    while at < bytes.len() {
        let (width, blank): (usize, &[u8]) = match bytes[at] {
            0x00..=0x1f | 0x7f => (1, b" "),
            0xc2 if matches!(bytes.get(at + 1), Some(0x80..=0x9f)) => (2, "\u{a0}".as_bytes()),
            _ => {
                at += 1;
                continue;
            }
        };
        out.extend_from_slice(&bytes[copied..at]);
        out.extend_from_slice(blank);
        at += width;
        copied = at;
    }
    out.extend_from_slice(&bytes[copied..]);
}

pub(crate) fn encode_row_chunk(out: &mut Vec<u8>, chunk: &RowChunk<'_>) -> Result<(), EncodeError> {
    let bytes = chunk.text.as_bytes();
    if bytes.len() > usize::from(chunk.cells) * MAX_CLUSTER_BYTES {
        return Err(EncodeError::Oversize);
    }
    let len = u32::try_from(bytes.len()).map_err(|_| EncodeError::Oversize)?;
    put_u32(out, len);
    push_row_text(out, chunk.text);
    put_u16(out, chunk.cells);
    let count = u16::try_from(chunk.runs.len()).map_err(|_| EncodeError::Oversize)?;
    put_u16(out, count);
    for run in chunk.runs {
        put_u16(out, run.cells);
        put_u32(out, run.bytes);
        out.push(run.style.attrs.bits());
        out.push(run.style.underline.to_wire());
        encode_style_color(out, run.style.fg);
        encode_style_color(out, run.style.bg);
        encode_style_color(out, run.style.underline_color);
    }
    Ok(())
}

/// A decoded [`RowFrame`] already fits its screen, its runs land on character
/// boundaries inside its own text, and it carries no control bytes.
pub(crate) fn decode_row_frame(c: &mut Cursor<'_>, cols: u16) -> Result<RowFrame, DecodeError> {
    let len = usize::try_from(c.u32()?).map_err(|_| DecodeError::InvalidField)?;
    // The grid bounds the *allocation*, because `cells` has not been read yet.
    if len > usize::from(cols) * MAX_CLUSTER_BYTES {
        return Err(DecodeError::InvalidField);
    }
    let text = std::str::from_utf8(c.take(len)?)
        .map_err(|_| DecodeError::BadUtf8)?
        .to_owned();
    reject_control(&text)?;
    let cells = c.u16()?;
    if cells > cols {
        return Err(DecodeError::InvalidField);
    }
    // And the row's own width bounds what is *legal*, that being the encoder's bound:
    // without it a row naming no columns decodes here and cannot be re-encoded (fuzzer).
    if len > usize::from(cells) * MAX_CLUSTER_BYTES {
        return Err(DecodeError::InvalidField);
    }
    let count = c.u16()?;
    if count > cols {
        return Err(DecodeError::InvalidField);
    }
    // Whatever a header claims, a run costs bytes: reserving from the count alone lets
    // ~34 bytes of wire buy two megabytes when a `Tail` arrives with no real `cols`.
    let room = c.remaining() / MIN_RUN_BYTES;
    let mut runs = Vec::with_capacity(usize::from(count).min(room));
    let mut covered_cells = 0_u32;
    let mut covered_bytes = 0_usize;
    for _ in 0..count {
        let run_cells = c.u16()?;
        let run_bytes = c.u32()?;
        let attrs = StyleAttrs::from_bits(c.take(1)?[0]);
        let underline =
            UnderlineStyle::from_wire(c.take(1)?[0]).ok_or(DecodeError::InvalidField)?;
        let fg = decode_style_color(c)?;
        let bg = decode_style_color(c)?;
        let underline_color = decode_style_color(c)?;
        covered_cells += u32::from(run_cells);
        covered_bytes = covered_bytes
            .checked_add(usize::try_from(run_bytes).map_err(|_| DecodeError::InvalidField)?)
            .ok_or(DecodeError::InvalidField)?;
        if covered_cells > u32::from(cells) || !text.is_char_boundary(covered_bytes) {
            return Err(DecodeError::InvalidField);
        }
        runs.push(StyleRun {
            cells: run_cells,
            bytes: run_bytes,
            style: CellStyle {
                fg,
                bg,
                underline_color,
                attrs,
                underline,
            },
        });
    }
    Ok(RowFrame { text, runs, cells })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire positions keep the server's capture and the client's emit on the same mode.
    #[test]
    fn the_mode_table_is_append_only_and_names_each_mode_once() {
        assert_eq!(
            &REPAINT_MODES[..16],
            &[
                1, 7, 66, 1000, 1002, 1003, 1004, 1005, 1006, 1007, 1015, 1016, 1036, 1049, 2004,
                2027
            ]
        );
        assert_eq!(REPAINT_MODES.len(), 20);
        // Origin mode without the DECSTBM no screen carries lands every CUP off.
        assert!(!REPAINT_MODES.contains(&6));
        let mut named: Vec<u16> = REPAINT_MODES.to_vec();
        named.sort_unstable();
        named.dedup();
        assert_eq!(named.len(), REPAINT_MODES.len(), "a mode is named twice");
    }

    /// Every bit the table names survives the wire, and no bit it does not.
    #[test]
    fn every_mode_bit_round_trips_and_no_other_bit_does() {
        for (index, mode) in REPAINT_MODES.iter().enumerate() {
            let mut modes = ModeSet::empty();
            modes.set(index, true);
            let decoded = ModeSet::decode(modes.bits()).expect("a bit the table names");
            assert_eq!(decoded, modes);
            let on: Vec<u16> = decoded
                .iter()
                .filter_map(|(named, enabled)| enabled.then_some(named))
                .collect();
            assert_eq!(on, vec![*mode]);
            modes.set(index, false);
            assert_eq!(modes, ModeSet::empty());
        }
        let all = ModeSet::from_bits(u32::MAX);
        assert_eq!(ModeSet::decode(all.bits()), Some(all));
        assert!(all.iter().all(|(_, enabled)| enabled));
        // A bit past the table is dropped for a local caller and refused from a peer:
        // two spellings of one frame is how a byte gets past someone else's length.
        assert_eq!(ModeSet::from_bits(1 << 31), ModeSet::empty());
        assert_eq!(ModeSet::decode(1 << REPAINT_MODES.len()), None);
    }

    #[test]
    fn decscusr_selects_the_blink_variant_and_leaves_unset_a_reset() {
        for (shape, blinking, want) in [
            (CursorShape::Block, true, 1),
            (CursorShape::Block, false, 2),
            (CursorShape::Underline, true, 3),
            (CursorShape::Underline, false, 4),
            (CursorShape::Bar, true, 5),
            (CursorShape::Bar, false, 6),
            // Parameter 0 hands the choice back to the terminal, blink included.
            (CursorShape::Unset, true, 0),
            (CursorShape::Unset, false, 0),
        ] {
            assert_eq!(shape.decscusr(blinking), want, "{shape:?} blink {blinking}");
        }
    }

    fn encode_whole(out: &mut Vec<u8>, row: &RowFrame) -> Result<(), EncodeError> {
        encode_row_chunk(out, &row.whole())
    }

    fn plain_row(text: &str, cells: u16) -> RowFrame {
        RowFrame {
            text: text.into(),
            runs: Vec::new(),
            cells,
        }
    }

    #[test]
    fn a_row_that_cannot_tile_its_grid_is_refused() {
        for (label, row) in [
            (
                "a run wider than the row",
                RowFrame {
                    text: "ab".into(),
                    cells: 2,
                    runs: vec![StyleRun {
                        cells: 9,
                        bytes: 2,
                        style: CellStyle::default(),
                    }],
                },
            ),
            (
                "a row wider than the grid",
                RowFrame {
                    text: "ab".into(),
                    cells: 9,
                    runs: Vec::new(),
                },
            ),
            // A run boundary inside a character is a byte range that is not a `str`.
            (
                "a run splitting a character",
                RowFrame {
                    text: "\u{4f60}".into(),
                    cells: 2,
                    runs: vec![StyleRun {
                        cells: 2,
                        bytes: 1,
                        style: CellStyle::default(),
                    }],
                },
            ),
        ] {
            let mut out = Vec::new();
            encode_whole(&mut out, &row).unwrap();
            assert!(
                matches!(
                    decode_row_frame(&mut Cursor::new(&out), 4),
                    Err(DecodeError::InvalidField)
                ),
                "{label}"
            );
        }
    }

    /// A row carrying an escape would let a remote program drive the local terminal.
    #[test]
    fn control_characters_in_row_text_are_blanked_at_encode_and_refused_at_decode() {
        // Every width `char::is_control` covers — C0, DEL, two-byte C1 — each one cell.
        let row = RowFrame {
            text: "a\u{1b}[2Jb\u{7f}c\u{9d}d".into(),
            cells: 10,
            runs: Vec::new(),
        };
        let mut out = Vec::new();
        encode_whole(&mut out, &row).expect("a row of ten cells");
        let mut c = Cursor::new(&out);
        let decoded = decode_row_frame(&mut c, 80).expect("a row this side just encoded");
        assert_eq!(decoded.text, "a [2Jb c\u{a0}d");
        assert_eq!(
            decoded.text.len(),
            row.text.len(),
            "the substitution moved every column after it"
        );
        assert_eq!(decoded.cells, row.cells);

        // A frame this side cannot write is still one a peer can state.
        let mut hostile = Vec::new();
        let text = "a\u{1b}b".as_bytes();
        put_u32(
            &mut hostile,
            u32::try_from(text.len()).expect("a short row"),
        );
        hostile.extend_from_slice(text);
        put_u16(&mut hostile, 3);
        put_u16(&mut hostile, 0);
        assert!(matches!(
            decode_row_frame(&mut Cursor::new(&hostile), 80),
            Err(DecodeError::InvalidField)
        ));
    }

    /// A bound the two ends disagree on is how a screen encodes and is then discarded.
    #[test]
    fn everything_the_encoder_emits_the_decoder_accepts() {
        for cols in [1_u16, 2, 64, 1024] {
            for cells in [1, cols / 2 + 1, cols] {
                let row = RowFrame {
                    text: "x".repeat(usize::from(cells) * MAX_CLUSTER_BYTES),
                    runs: Vec::new(),
                    cells,
                };
                let mut out = Vec::new();
                encode_whole(&mut out, &row).expect("a row at its own bound");
                let mut c = Cursor::new(&out);
                assert_eq!(decode_row_frame(&mut c, cols).unwrap(), row);

                let mut over = row;
                over.text.push('x');
                let mut out = Vec::new();
                assert!(
                    matches!(encode_whole(&mut out, &over), Err(EncodeError::Oversize)),
                    "the encoder wrote {} bytes into {cells} cells",
                    over.text.len()
                );
            }
        }
    }

    /// Reassembly is concatenation in all three extents, which holds only because a run
    /// boundary is the one offset where both a byte position and a column are known.
    #[test]
    fn a_row_too_wide_for_its_budget_is_cut_at_run_boundaries() {
        let runs: Vec<StyleRun> = (0..8)
            .map(|index| StyleRun {
                cells: 64,
                bytes: 64,
                style: CellStyle {
                    fg: StyleColor::Palette(index),
                    ..CellStyle::default()
                },
            })
            .collect();
        let row = RowFrame {
            runs,
            ..plain_row(&"x".repeat(512), 512)
        };
        assert!(row.runs[0].bytes <= MAX_RUN_BYTES);

        let budget = 300;
        let chunks: Vec<RowChunk<'_>> = row.chunks(budget).collect();
        assert!(chunks.len() > 1, "a row twice the budget was carried whole");
        for chunk in &chunks {
            assert!(
                chunk.encoded_len() <= budget,
                "a chunk of {} bytes does not fit {budget}",
                chunk.encoded_len()
            );
        }
        assert_eq!(
            chunks.iter().map(|chunk| chunk.text).collect::<String>(),
            row.text
        );
        assert_eq!(
            chunks
                .iter()
                .flat_map(|chunk| chunk.runs)
                .copied()
                .collect::<Vec<_>>(),
            row.runs
        );
        assert_eq!(
            chunks.iter().map(|chunk| chunk.cells).sum::<u16>(),
            row.cells
        );
    }

    /// The one row this module cannot cut: it goes over whole and the caller refuses it.
    #[test]
    fn a_run_larger_than_the_budget_is_handed_over_whole() {
        let row = RowFrame {
            text: "x".repeat(512),
            runs: vec![StyleRun {
                cells: 512,
                bytes: 512,
                style: CellStyle::default(),
            }],
            cells: 512,
        };
        let chunks: Vec<RowChunk<'_>> = row.chunks(64).collect();
        assert_eq!(chunks, vec![row.whole()]);
        assert!(chunks[0].encoded_len() > 64);
    }

    /// One-column runs, so a run index and a column are the same number.
    fn tiled(runs: &[&str]) -> RowFrame {
        RowFrame {
            text: runs.concat(),
            runs: runs
                .iter()
                .map(|piece| StyleRun {
                    cells: u16::try_from(piece.chars().count()).expect("a short run"),
                    bytes: u32::try_from(piece.len()).expect("a short run"),
                    style: CellStyle::default(),
                })
                .collect(),
            cells: u16::try_from(runs.concat().chars().count()).expect("a short row"),
        }
    }

    /// A client that knew only the column or only the byte could not place the span.
    #[test]
    fn a_span_of_a_row_starts_where_its_runs_start() {
        // The leading run is three bytes a column, so the two start numbers differ.
        let row = tiled(&["\u{6f22}\u{5b57}", "ab", "cd"]);
        let chunks: Vec<RowChunk<'_>> = row.span((1, 3), row.encoded_len()).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!((chunks[0].col, chunks[0].byte), (2, 6));
        assert_eq!(chunks[0].text, "abcd");
        assert_eq!(chunks[0].cells, 4);

        // And the whole row is the span that starts at nothing.
        assert_eq!(
            row.span((0, row.runs.len()), row.encoded_len())
                .collect::<Vec<_>>(),
            vec![row.whole()]
        );
    }

    /// Columns past a bounded span belong to a later span, or to the row already held.
    #[test]
    fn only_a_span_reaching_the_last_run_carries_the_rows_tail() {
        let row = RowFrame {
            cells: 8,
            ..tiled(&["ab", "cd"])
        };
        let bounded: Vec<RowChunk<'_>> = row.span((0, 1), row.encoded_len()).collect();
        assert_eq!((bounded.len(), bounded[0].cells), (1, 2));

        let reaching: Vec<RowChunk<'_>> = row.span((1, 2), row.encoded_len()).collect();
        assert_eq!((reaching.len(), reaching[0].cells), (1, 6));
        assert_eq!((reaching[0].col, reaching[0].byte), (2, 2));
    }

    #[test]
    fn a_span_wider_than_a_piece_is_cut_into_chunks_that_each_name_their_place() {
        let runs = vec!["x".repeat(64); 8];
        let row = tiled(&runs.iter().map(String::as_str).collect::<Vec<_>>());
        let chunks: Vec<RowChunk<'_>> = row.span((2, 8), 200).collect();
        assert!(chunks.len() > 1, "a span three times the budget was whole");
        let mut col = 128_u16;
        let mut byte = 128_u32;
        for chunk in &chunks {
            assert_eq!((chunk.col, chunk.byte), (col, byte));
            col += chunk.cells;
            byte += u32::try_from(chunk.text.len()).expect("a short chunk");
        }
        assert_eq!((col, byte), (512, 512));
    }

    /// What a status bar costs: a clock repainting changes two runs of forty.
    #[test]
    fn changed_span_names_the_runs_a_client_must_repaint() {
        let four = tiled(&["aa", "bb", "cc", "dd"]);
        let mut restyled = four.clone();
        restyled.runs[1].style.attrs = StyleAttrs::BOLD;
        let mut retyped = four.clone();
        retyped.text.replace_range(4..6, "zz");
        let three = tiled(&["aa", "bb", "cc"]);
        let widened = tiled(&["aa", "bbb", "cc"]);
        let shorter = tiled(&["aa", "bb"]);
        let taller = RowFrame {
            cells: 6,
            ..shorter.clone()
        };
        for (label, after, before, want) in [
            ("one run restyled", &restyled, &four, Some((1, 2))),
            ("text alone, same extents", &retyped, &four, Some((2, 3))),
            // A run whose extent changed moves every column after it.
            ("a run that changed width", &widened, &three, Some((1, 3))),
            ("a row that lost a run", &shorter, &three, Some((2, 2))),
            ("an unchanged row", &shorter, &shorter, None),
            ("a tail that grew", &taller, &shorter, Some((2, 2))),
        ] {
            assert_eq!(after.changed_span(before), want, "{label}");
        }

        // The span naming no runs still carries the tail: the columns past it are stale.
        let chunks: Vec<RowChunk<'_>> = shorter.span((2, 2), shorter.encoded_len()).collect();
        assert!(chunks.is_empty() || chunks[0].is_empty());
    }

    #[test]
    fn a_deferred_list_past_its_bounds_keeps_the_newest_entries() {
        let many: Vec<String> = (0..MAX_DEFERRED * 2)
            .map(|n| format!("133;A;{n}"))
            .collect();
        let kept = &many[deferred_start(&many)..];
        assert_eq!(kept.len(), MAX_DEFERRED);
        assert_eq!(kept[MAX_DEFERRED - 1], many[many.len() - 1]);

        let heavy: Vec<String> = (0..8).map(|_| "0;".to_owned() + &"t".repeat(600)).collect();
        let kept = &heavy[deferred_start(&heavy)..];
        assert!(
            kept.iter().map(|entry| entry.len() + 2).sum::<usize>() <= MAX_DEFERRED_BYTES,
            "the kept entries are {} bytes",
            kept.iter().map(String::len).sum::<usize>()
        );
        assert!(!kept.is_empty(), "the budget dropped every entry");

        // One entry too large to ever fit is dropped rather than truncated.
        let huge = vec!["8;;https://example/".repeat(512)];
        assert_eq!(deferred_start(&huge), 1);
    }

    fn round_trip_sticky(sticky: &StickyState) -> StickyState {
        let mut out = Vec::new();
        encode_sticky(&mut out, sticky).expect("a sticky block");
        assert_eq!(out.len(), sticky_bytes(sticky), "the cut budget was wrong");
        let mut c = Cursor::new(&out);
        let decoded = decode_sticky(&mut c).expect("a block this side just wrote");
        assert_eq!(c.remaining(), 0);
        decoded
    }

    /// `decode_sticky` refuses either, so an encoder that wrote one would strand the
    /// session: the client refuses the frame, reattaches, and is handed it forever.
    #[test]
    fn a_title_the_decoder_would_refuse_is_elided_rather_than_written() {
        let longest = "t".repeat(MAX_TITLE);
        for title in [
            "vim\u{1b}]0;pwned\u{7}",
            "vim\u{9d}0;pwned",
            "vim\u{7f}",
            "vim\n",
            &"t".repeat(MAX_TITLE + 1),
        ] {
            let sticky = StickyState {
                title: Some(title.into()),
                ..StickyState::default()
            };
            assert_eq!(round_trip_sticky(&sticky).title, None, "title {title:?}");
        }
        let sticky = StickyState {
            title: Some(longest.as_str().into()),
            ..StickyState::default()
        };
        assert_eq!(
            round_trip_sticky(&sticky).title.as_deref(),
            Some(longest.as_str()),
            "the longest legal title was elided"
        );

        // A title the encoder cannot produce is still one a peer can state.
        let mut hostile = vec![1_u8];
        put_u16(&mut hostile, 3);
        hostile.extend_from_slice(b"a\x1bb");
        hostile.extend_from_slice(&[0, 0, 0, 0, 0]);
        assert!(matches!(
            decode_sticky(&mut Cursor::new(&hostile)),
            Err(DecodeError::InvalidField)
        ));
    }
}
