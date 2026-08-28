#![forbid(unsafe_code)]

use braid_proto::{
    CellStyle, CursorShape, GridSize, MAX_RUN_BYTES, ModeSet, REPAINT_MODES, RowFrame, StickyState,
    StyleAttrs, StyleColor, StyleRun, UnderlineStyle,
};
use libghostty_vt::fmt::Format;
use libghostty_vt::render::CursorVisualStyle;
use libghostty_vt::screen::{CellWide, Screen};
use libghostty_vt::selection::FormatOptions;
use libghostty_vt::style::{Style, StyleColor as GhosttyColor, Underline};
use libghostty_vt::terminal::{
    ConformanceLevel, CursorStyle as GhosttyCursorStyle, DeviceAttributeFeature, DeviceAttributes,
    DeviceType, Mode, ModeKind, PrimaryDeviceAttributes, SecondaryDeviceAttributes,
    TertiaryDeviceAttributes,
};
use libghostty_vt::unicode::codepoint_width;
use libghostty_vt::{Error as GhosttyError, RenderState, Terminal, render};
use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::Arc;
use thiserror::Error;

/// Bytes of scrollback history the terminal may retain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrollbackLimit(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContinuationLimit(pub usize);

/// Ceiling on the buffer [`VtEngine::search`] reuses, so a wrong `required`
/// cannot turn one search into an unbounded allocation.
const SEARCH_BUFFER_MAX: usize = 16 * 1024 * 1024;

/// What braid answers a Device Attributes query with.
///
/// libghostty-vt answers all three DA queries on its own; pinning them here is
/// what makes the reply a decision of braid's rather than a library default
/// that can move underneath the client. It is load-bearing now that the server
/// cuts an answered query out of what a client is sent: whatever this claims
/// is what the application will act on, and the client's own terminal never
/// gets to disagree.
///
/// So the set is what braid carries end-to-end. `SIXEL` and `ReGIS` are absent
/// because an image reaches the client as frame rows the wire has no blit for,
/// `CLIPBOARD` because there is no OSC 52 read path back, and `COLUMNS_132`
/// because `REPAINT_MODES` does not carry DECCOLM: an application taking that
/// invitation would switch a width the client is never told about.
const DEVICE_ATTRIBUTES: DeviceAttributes = DeviceAttributes {
    primary: PrimaryDeviceAttributes::new(
        ConformanceLevel::VT220,
        // Selective erase is resolved into cells here, so what the wire carries
        // is the result rather than the protected attribute behind it.
        &[
            DeviceAttributeFeature::SELECTIVE_ERASE,
            DeviceAttributeFeature::ANSI_COLOR,
        ],
    ),
    secondary: SecondaryDeviceAttributes {
        device_type: DeviceType::VT220,
        firmware_version: 0,
        rom_cartridge: 0,
    },
    tertiary: TertiaryDeviceAttributes { unit_id: 0 },
};

/// A set of rows, one bit each.
///
/// Damage is tracked outside the grid because it is a scheduling concern that
/// never goes on the wire, and because the server must keep its own copy: an
/// emulator whose dirty bits are cleared when a frame is *sent* loses that
/// damage permanently if the frame is dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowMask {
    words: Vec<u64>,
}

impl RowMask {
    #[must_use]
    pub fn with_rows(rows: u16) -> Self {
        Self {
            words: vec![0; Self::words_for(rows)],
        }
    }

    /// Empty, sized for `rows`, keeping the allocation.
    pub fn reset(&mut self, rows: u16) {
        self.words.clear();
        self.words.resize(Self::words_for(rows), 0);
    }

    #[must_use]
    pub fn filled(rows: u16) -> Self {
        let mut mask = Self::with_rows(rows);
        for row in 0..rows {
            mask.set(row);
        }
        mask
    }

    pub fn set(&mut self, row: u16) {
        let (word, bit) = Self::position(row);
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= bit;
    }

    #[must_use]
    pub fn get(&self, row: u16) -> bool {
        let (word, bit) = Self::position(row);
        self.words.get(word).is_some_and(|slot| slot & bit != 0)
    }

    pub fn union(&mut self, other: &Self) {
        if self.words.len() < other.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (slot, word) in self.words.iter_mut().zip(&other.words) {
            *slot |= word;
        }
    }

    pub fn clear_all(&mut self) {
        self.words.fill(0);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Rows present in the mask, ascending.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        Self::bits(self.words.iter().copied())
    }

    /// Rows present in either mask, ascending, without materialising a third.
    pub fn iter_either<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = u16> + 'a {
        let words = self.words.len().max(other.words.len());
        Self::bits((0..words).map(move |index| {
            self.words.get(index).copied().unwrap_or(0)
                | other.words.get(index).copied().unwrap_or(0)
        }))
    }

    /// Set bits as row indices, ascending. `trailing_zeros` costs one iteration
    /// for the mask naming one row, not sixty-four.
    fn bits(words: impl Iterator<Item = u64>) -> impl Iterator<Item = u16> {
        words.enumerate().flat_map(|(index, mut word)| {
            let base = index * u64::BITS as usize;
            std::iter::from_fn(move || {
                let bit = (word != 0).then(|| word.trailing_zeros() as usize)?;
                word &= word - 1;
                u16::try_from(base + bit).ok()
            })
        })
    }

    fn words_for(rows: u16) -> usize {
        usize::from(rows).div_ceil(u64::BITS as usize)
    }

    const fn position(row: u16) -> (usize, u64) {
        let index = row as usize;
        (
            index / u64::BITS as usize,
            1_u64 << (index % u64::BITS as usize),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepaintFrame {
    pub size: GridSize,
    pub rows: Vec<RowFrame>,
    pub cursor: Option<(u16, u16)>,
    pub cursor_visible: bool,
    pub cursor_shape: CursorShape,
    pub cursor_blinking: bool,
    pub modes: ModeSet,
    pub sticky: StickyState,
    /// Rows changed since the previous repaint: Ghostty's own flags, except
    /// after a render-state rebuild, where the row's content decides.
    pub dirty: RowMask,
}

#[expect(clippy::struct_excessive_bools, reason = "distinct emulator facts")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorCue {
    pub col: u16,
    /// The next printable character wraps to the following row.
    pub pending_wrap: bool,
    pub visible: bool,
    /// A full-screen application owns the grid.
    pub alternate: bool,
    pub mouse_tracking: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrollbackMatch {
    /// Rows back from the bottom of the history; 0 is the last line.
    pub distance: u32,
    pub line: String,
}

#[derive(Debug, Error)]
pub enum VtError {
    #[error("libghostty: {0}")]
    Ghostty(String),
    #[error("terminal input exceeds continuation limit")]
    ContinuationLimit,
    #[error("scrollback text exceeds the search buffer ceiling")]
    SearchTooLarge,
    #[error("a grapheme cluster does not fit a run's byte count")]
    ClusterTooLarge,
    #[error("effect sink panicked: {0}")]
    SinkPanic(Box<str>),
}

/// Effects Ghostty raises while parsing, delivered from a Zig stack frame.
/// Every method must return normally: an unwind there is undefined behaviour,
/// so a panic is caught, reported as [`VtError::SinkPanic`], and lost.
pub trait EffectSink {
    fn pty_write(&self, bytes: &[u8]);

    /// Called for an ENQ query before Ghostty emits the configured reply.
    fn enquiry(&self) {}

    /// Called for an XTVERSION query before Ghostty emits the configured reply.
    fn xtversion(&self) {}
}

#[derive(Clone, Default)]
struct CaughtPanic(Rc<Cell<Option<Box<str>>>>);

impl CaughtPanic {
    /// Runs `effect`, substituting `R::default()` for a panic — `None` for a
    /// query callback, so Ghostty emits no reply on behalf of a broken sink.
    fn guard<R: Default>(&self, effect: impl FnOnce() -> R) -> R {
        match catch_unwind(AssertUnwindSafe(effect)) {
            Ok(value) => value,
            Err(payload) => {
                // The first panic is the one with a cause.
                let first = self
                    .0
                    .take()
                    .unwrap_or_else(|| panic_message(payload.as_ref()));
                self.0.set(Some(first));
                R::default()
            }
        }
    }

    fn take(&self) -> Option<Box<str>> {
        self.0.take()
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> Box<str> {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).into()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str().into()
    } else {
        "unknown panic payload".into()
    }
}

/// Spots codepoints Ghostty attaches to an existing cell, carrying a partial
/// scalar across feeds.
#[derive(Debug, Default)]
struct ZeroWidthScan {
    partial: [u8; 4],
    len: u8,
}

impl ZeroWidthScan {
    /// Whether `bytes` completed a zero-width scalar. Escape payloads are
    /// scanned too: a false positive costs one render-state rebuild.
    fn scan(&mut self, bytes: &[u8]) -> bool {
        let mut found = false;
        let mut rest = bytes;
        loop {
            if self.len == 0 {
                // ASCII cannot lead a sequence, so the common chunk is skipped.
                let Some(offset) = rest.iter().position(|byte| *byte >= 0x80) else {
                    return found;
                };
                rest = &rest[offset..];
            }
            let Some((&byte, tail)) = rest.split_first() else {
                return found;
            };
            rest = tail;
            if self.len > 0 {
                if byte & 0xC0 == 0x80 {
                    self.partial[usize::from(self.len)] = byte;
                    self.len += 1;
                    if usize::from(self.len) == Self::sequence_len(self.partial[0]) {
                        found |= self.take();
                    }
                    continue;
                }
                // A truncated sequence: the terminal resynchronizes here too.
                self.len = 0;
            }
            if Self::sequence_len(byte) > 1 {
                self.partial[0] = byte;
                self.len = 1;
            }
        }
    }

    fn sequence_len(lead: u8) -> usize {
        match lead {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 1,
        }
    }

    fn take(&mut self) -> bool {
        let len = usize::from(self.len);
        self.len = 0;
        std::str::from_utf8(&self.partial[..len])
            .ok()
            .and_then(|text| text.chars().next())
            // Ghostty gives every codepoint through U+00FF width one, whatever
            // the table says.
            .is_some_and(|scalar| scalar > '\u{ff}' && codepoint_width(scalar) == 0)
    }
}

/// Owns the Ghostty terminal and its render state: it contains `Rc`, so it
/// belongs to one dedicated VT thread.
pub struct VtEngine<S> {
    terminal: Terminal<'static, 'static>,
    render: RenderState<'static>,
    rows: render::RowIterator<'static>,
    cells: render::CellIterator<'static>,
    size: GridSize,
    continuation: ContinuationLimit,
    scratch: String,
    /// What the last search needed, rather than the buffer that held it. The
    /// buffer is the whole scrollback as text - megabytes - and keeping it
    /// would leave every session that has been searched once holding that for
    /// the rest of its life, against a daemon memory budget that does not
    /// count it. The hint costs a word and still spares the second format
    /// pass that discovering the size again would need.
    search_hint: usize,
    frame: RepaintFrame,
    /// A clean row is served from its own buffer, and the first frame and the
    /// one after a resize have nothing behind them.
    render_all: bool,
    zero_width: ZeroWidthScan,
    /// `Terminal.print`'s zero-width attach path — taken while mode 2027 is off
    /// — omits the `cursorMarkDirty` its sibling does (ghostty-org/ghostty
    /// `src/terminal/Terminal.zig`), so the next repaint rebuilds the render
    /// state. Delete once that path marks the row.
    zero_width_stale: bool,
    previous: RowFrame,
    /// A `BEL` during a sync episode reaches the user only through a repaint.
    bell: Rc<Cell<bool>>,
    title: Option<Arc<str>>,
    sink: Rc<S>,
    panicked: CaughtPanic,
}

impl<S: EffectSink + 'static> VtEngine<S> {
    pub fn new(
        size: GridSize,
        scrollback: ScrollbackLimit,
        continuation: ContinuationLimit,
        sink: Rc<S>,
    ) -> Result<Self, VtError> {
        let mut terminal = Terminal::new(size.cols, size.rows).map_err(ghostty)?;
        terminal
            .set_scrollback_max_bytes(Some(scrollback.0))
            .map_err(ghostty)?;
        // `BlockHollow` is unreachable through DECSCUSR: a sentinel meaning the
        // session expressed no cursor preference.
        terminal
            .set_default_cursor_style(Some(GhosttyCursorStyle::BlockHollow))
            .map_err(ghostty)?;
        let panicked = CaughtPanic::default();
        let pty_sink = Rc::clone(&sink);
        let pty_guard = panicked.clone();
        terminal
            .on_pty_write(move |_terminal, bytes| pty_guard.guard(|| pty_sink.pty_write(bytes)))
            .map_err(ghostty)?;
        let bell = Rc::new(Cell::new(false));
        let bell_flag = Rc::clone(&bell);
        let bell_guard = panicked.clone();
        terminal
            .on_bell(move |_terminal| bell_guard.guard(|| bell_flag.set(true)))
            .map_err(ghostty)?;
        let enquiry_sink = Rc::clone(&sink);
        let enquiry_guard = panicked.clone();
        terminal
            .on_enquiry(move |_terminal| {
                enquiry_guard.guard(|| {
                    enquiry_sink.enquiry();
                    Some("braid")
                })
            })
            .map_err(ghostty)?;
        let xtversion_sink = Rc::clone(&sink);
        let xtversion_guard = panicked.clone();
        terminal
            .on_xtversion(move |_terminal| {
                xtversion_guard.guard(|| {
                    xtversion_sink.xtversion();
                    Some(concat!("braid ", env!("CARGO_PKG_VERSION")))
                })
            })
            .map_err(ghostty)?;
        // Replaces libghostty-vt's own answer rather than supplying a missing
        // one: see [`DEVICE_ATTRIBUTES`] for why braid owns what this claims.
        terminal
            .on_device_attributes(move |_terminal| Some(DEVICE_ATTRIBUTES))
            .map_err(ghostty)?;
        let render = RenderState::new().map_err(ghostty)?;
        let rows = render::RowIterator::new().map_err(ghostty)?;
        let cells = render::CellIterator::new().map_err(ghostty)?;
        Ok(Self {
            terminal,
            render,
            rows,
            cells,
            size,
            continuation,
            scratch: String::new(),
            search_hint: 0,
            frame: RepaintFrame {
                size,
                rows: vec![RowFrame::default(); usize::from(size.rows)],
                cursor: None,
                cursor_visible: true,
                cursor_shape: CursorShape::Unset,
                cursor_blinking: false,
                modes: ModeSet::empty(),
                sticky: StickyState::default(),
                dirty: RowMask::with_rows(size.rows),
            },
            render_all: true,
            zero_width: ZeroWidthScan::default(),
            zero_width_stale: false,
            previous: RowFrame::default(),
            bell,
            title: None,
            sink,
            panicked,
        })
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), VtError> {
        if bytes.len() > self.continuation.0 {
            return Err(VtError::ContinuationLimit);
        }
        self.terminal.vt_write(bytes);
        self.zero_width_stale |= self.zero_width.scan(bytes);
        match self.panicked.take() {
            Some(message) => Err(VtError::SinkPanic(message)),
            None => Ok(()),
        }
    }

    pub fn resize(&mut self, size: GridSize) -> Result<(), VtError> {
        self.terminal
            .resize(size.cols, size.rows, 0, 0)
            .map_err(ghostty)?;
        self.size = size;
        // Every row buffer describes the old grid, so none of them may be kept.
        self.render_all = true;
        Ok(())
    }

    pub fn repaint(&mut self) -> Result<&RepaintFrame, VtError> {
        // The snapshot below holds the render state borrow; read modes first.
        let modes = self.modes()?;
        let kitty_keyboard = self
            .terminal
            .kitty_keyboard_flags()
            .map_err(ghostty)?
            .bits();
        // Ghostty reports a title never set and one set empty the same way.
        let title = self.terminal.title().map_err(ghostty)?;
        if title.is_empty() {
            self.title = None;
        } else if self.title.as_deref() != Some(title) {
            self.title = Some(Arc::from(title));
        }
        // Only a rebuild re-reads a mutation the screen never flagged.
        let rebuilt = std::mem::take(&mut self.zero_width_stale);
        if rebuilt {
            self.render = RenderState::new().map_err(ghostty)?;
        }
        let size = self.size;
        let snapshot = self.render.update(&self.terminal).map_err(ghostty)?;
        let cursor = snapshot
            .cursor_viewport()
            .map_err(ghostty)?
            .map(|position| (position.x, position.y));
        let cursor_visible = snapshot.cursor_visible().map_err(ghostty)?;
        let cursor_blinking = snapshot.cursor_blinking().map_err(ghostty)?;
        // The sentinel from `new`: the session chose no shape.
        #[expect(clippy::match_same_arms, reason = "upstream enum is non-exhaustive")]
        let cursor_shape = match snapshot.cursor_visual_style().map_err(ghostty)? {
            CursorVisualStyle::BlockHollow => CursorShape::Unset,
            CursorVisualStyle::Block => CursorShape::Block,
            CursorVisualStyle::Underline => CursorShape::Underline,
            CursorVisualStyle::Bar => CursorShape::Bar,
            _ => CursorShape::Block,
        };
        // A resize or a screen swap does not mark rows individually.
        let redraw_all =
            self.render_all || snapshot.dirty().map_err(ghostty)? == render::Dirty::Full;
        // A rebuild damages every row because the state is new, not because the
        // screen moved, so content decides instead.
        let compare = rebuilt && !self.render_all;

        self.frame.size = size;
        self.frame.cursor = cursor;
        self.frame.cursor_visible = cursor_visible;
        self.frame.cursor_shape = cursor_shape;
        self.frame.cursor_blinking = cursor_blinking;
        self.frame.modes = modes;
        // Field by field: a fresh value reallocates the deferred-OSC buffer.
        self.frame.sticky.title = self.title.clone();
        self.frame.sticky.kitty_keyboard = kitty_keyboard;
        self.frame.sticky.bell = self.bell.replace(false);
        self.frame.dirty.reset(size.rows);

        let mut index = 0_u16;
        let mut row_iter = self.rows.update(&snapshot).map_err(ghostty)?;
        while let Some(row) = row_iter.next() {
            let damaged = redraw_all || row.dirty().map_err(ghostty)?;
            if usize::from(index) == self.frame.rows.len() {
                self.frame.rows.push(RowFrame::default());
            }
            // Re-rendering a clean row at the 16 ms floor on a 200x60 grid is
            // twelve thousand row walks a second of FFI on the PTY's thread.
            if damaged {
                // `is_styled` may report false positives but never false
                // negatives.
                let styled = row
                    .raw_row()
                    .map_err(ghostty)?
                    .is_styled()
                    .map_err(ghostty)?;
                let frame = &mut self.frame.rows[usize::from(index)];
                if compare {
                    std::mem::swap(frame, &mut self.previous);
                }
                fill_row(frame, &mut self.scratch, &mut self.cells, row, styled)?;
                if !compare || *frame != self.previous {
                    self.frame.dirty.set(index);
                }
                row.set_dirty(false).map_err(ghostty)?;
            }
            index += 1;
        }
        self.render_all = false;
        // A shrunk grid must not leave rows the terminal no longer has.
        self.frame.rows.truncate(usize::from(index));
        snapshot.set_dirty(render::Dirty::Clean).map_err(ghostty)?;
        Ok(&self.frame)
    }

    /// Lines of scrollback and viewport matching `pattern`, newest first. A
    /// plain substring match: a regex engine would be a parser reachable from
    /// the wire.
    pub fn search(&mut self, pattern: &str, limit: usize) -> Result<Vec<ScrollbackMatch>, VtError> {
        let mut matches = Vec::new();
        if limit == 0 {
            return Ok(matches);
        }
        // A snapshot selection, never installed: a search must not disturb what
        // the user selected.
        let Some(selection) = self.terminal.select_all().map_err(ghostty)? else {
            return Ok(matches);
        };
        let options = || {
            FormatOptions::new()
                .with_emit_format(Format::Plain)
                .with_trim(true)
                .with_selection(&selection)
        };
        // Sized from the last search rather than grown from nothing: an empty
        // buffer always answers `OutOfSpace`, so a session's first search is
        // two format passes over the whole scrollback and every one after it
        // is one. `vec![0; n]` is `calloc`, so the pages cost nothing until
        // Ghostty writes them.
        let mut buffer = vec![0; self.search_hint];
        let written = match self.terminal.format_selection_buf(options(), &mut buffer) {
            Err(GhosttyError::OutOfSpace { required }) => {
                if required > SEARCH_BUFFER_MAX {
                    return Err(VtError::SearchTooLarge);
                }
                buffer.resize(required, 0);
                self.terminal
                    .format_selection_buf(options(), &mut buffer)
                    .map_err(ghostty)?
            }
            other => other.map_err(ghostty)?,
        };
        self.search_hint = buffer.len();
        let Some(written) = written else {
            return Ok(matches);
        };
        let text = std::str::from_utf8(&buffer[..written]).map_err(ghostty)?;
        for (distance, line) in text.lines().rev().enumerate() {
            // Ghostty pads a row to the grid width; the user saw no trailing run
            // of spaces.
            let line = line.trim_end();
            if !line.contains(pattern) {
                continue;
            }
            // One line costs at least its newline, so a buffer bounded by
            // `SEARCH_BUFFER_MAX` cannot hold more lines than a `u32` counts.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "bounded by the buffer ceiling"
            )]
            let distance = distance as u32;
            matches.push(ScrollbackMatch {
                distance,
                line: line.to_owned(),
            });
            if matches.len() == limit {
                break;
            }
        }
        Ok(matches)
    }

    fn modes(&self) -> Result<ModeSet, VtError> {
        let mut modes = ModeSet::empty();
        for (index, number) in REPAINT_MODES.into_iter().enumerate() {
            let on = self
                .terminal
                .mode(Mode::new(number, ModeKind::Dec))
                .map_err(ghostty)?;
            modes.set(index, on);
        }
        Ok(modes)
    }

    pub const fn size(&self) -> GridSize {
        self.size
    }

    /// Deliberately not `repaint()`: this touches no dirty flag, so the actor
    /// may call it per PTY write without making damage depend on how often.
    pub fn cursor_cue(&self) -> Result<CursorCue, VtError> {
        Ok(CursorCue {
            col: self.terminal.cursor_x().map_err(ghostty)?,
            pending_wrap: self.terminal.is_cursor_pending_wrap().map_err(ghostty)?,
            visible: self.terminal.is_cursor_visible().map_err(ghostty)?,
            alternate: self.terminal.active_screen().map_err(ghostty)? == Screen::Alternate,
            mouse_tracking: self.terminal.is_mouse_tracking().map_err(ghostty)?,
        })
    }

    /// The engine owns a reference so the effect callbacks outlive the caller's.
    pub fn sink(&self) -> &S {
        &self.sink
    }
}

/// Rebuild one row in place. Columns, text bytes and style-run bytes are three
/// counts: a wide glyph is one cluster over two columns, a combining mark
/// several scalars over one.
fn fill_row(
    frame: &mut RowFrame,
    scratch: &mut String,
    cells: &mut render::CellIterator<'static>,
    row: &render::RowIteration<'static, '_>,
    styled: bool,
) -> Result<(), VtError> {
    frame.text.clear();
    frame.runs.clear();
    frame.cells = 0;
    let mut open: Option<(CellStyle, u16, u32)> = None;
    let mut cell_iter = cells.update(row).map_err(ghostty)?;
    while let Some(cell) = cell_iter.next() {
        let wide = cell.raw_cell().map_err(ghostty)?.wide().map_err(ghostty)?;
        // Emitting anything for the trailing half of a wide glyph drifts the
        // row one column right per repaint.
        let written = if wide == CellWide::SpacerTail {
            0
        } else {
            // The buffer cannot be `frame.text`: the C encoder writes at offset
            // zero, so appending to a row in progress truncates it.
            scratch.clear();
            cell.graphemes_utf8(scratch).map_err(ghostty)?;
            if scratch.is_empty() {
                frame.text.push(' ');
                1
            } else {
                frame.text.push_str(scratch);
                // A run whose bytes disagree with its text is cut wrong.
                u32::try_from(scratch.len()).map_err(|_| VtError::ClusterTooLarge)?
            }
        };
        frame.cells += 1;
        // The glyph beside a spacer is what the terminal shows there, so the
        // spacer extends its run rather than opening one.
        if wide == CellWide::SpacerTail
            && let Some((_, run_cells, _)) = &mut open
        {
            *run_cells += 1;
            continue;
        }
        // Every cell on a screen with no styling is default anyway, and reading
        // a style is an FFI call per cell.
        let style = if styled {
            cell_style(cell.style().map_err(ghostty)?)
        } else {
            CellStyle::default()
        };
        match &mut open {
            // A run is also where a row too wide for one screen piece is cut,
            // so it is bounded in bytes whatever the style does.
            Some((current, run_cells, bytes))
                if *current == style && *bytes + written <= MAX_RUN_BYTES =>
            {
                *run_cells += 1;
                *bytes += written;
            }
            Some((current, run_cells, bytes)) => {
                frame.runs.push(StyleRun {
                    cells: *run_cells,
                    bytes: *bytes,
                    style: *current,
                });
                *current = style;
                *run_cells = 1;
                *bytes = written;
            }
            None => open = Some((style, 1, written)),
        }
    }
    if let Some((style, run_cells, bytes)) = open {
        frame.runs.push(StyleRun {
            cells: run_cells,
            bytes,
            style,
        });
    }
    // Only the last one: any before it are boundaries a wide row is cut at.
    if frame.runs.last().is_some_and(|run| run.style.is_default()) {
        frame.runs.pop();
    }
    Ok(())
}

fn ghostty(error: impl std::fmt::Display) -> VtError {
    VtError::Ghostty(error.to_string())
}

#[expect(clippy::match_same_arms, reason = "upstream enum is non-exhaustive")]
fn cell_style(style: Style) -> CellStyle {
    CellStyle {
        fg: style_color(style.fg_color),
        bg: style_color(style.bg_color),
        underline_color: style_color(style.underline_color),
        attrs: StyleAttrs::NONE
            .with(StyleAttrs::BOLD, style.bold)
            .with(StyleAttrs::ITALIC, style.italic)
            .with(StyleAttrs::FAINT, style.faint)
            .with(StyleAttrs::BLINK, style.blink)
            .with(StyleAttrs::INVERSE, style.inverse)
            .with(StyleAttrs::INVISIBLE, style.invisible)
            .with(StyleAttrs::STRIKETHROUGH, style.strikethrough)
            .with(StyleAttrs::OVERLINE, style.overline),
        underline: match style.underline {
            Underline::None => UnderlineStyle::None,
            Underline::Single => UnderlineStyle::Single,
            Underline::Double => UnderlineStyle::Double,
            Underline::Curly => UnderlineStyle::Curly,
            Underline::Dotted => UnderlineStyle::Dotted,
            Underline::Dashed => UnderlineStyle::Dashed,
            // Non-exhaustive upstream: a plain underline beats no decoration.
            _ => UnderlineStyle::Single,
        },
    }
}

/// Palette indices stay indices: the palette is the server's, and resolved RGB
/// would repaint the user's terminal in the server's theme.
fn style_color(color: GhosttyColor) -> StyleColor {
    match color {
        GhosttyColor::None => StyleColor::Default,
        GhosttyColor::Palette(index) => StyleColor::Palette(index.0),
        GhosttyColor::Rgb(rgb) => StyleColor::Rgb(rgb.r, rgb.g, rgb.b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct TestEffects {
        pty: RefCell<Vec<u8>>,
        enquiries: Cell<usize>,
        xtversions: Cell<usize>,
    }

    impl EffectSink for TestEffects {
        fn pty_write(&self, bytes: &[u8]) {
            self.pty.borrow_mut().extend_from_slice(bytes);
        }

        fn enquiry(&self) {
            self.enquiries.set(self.enquiries.get() + 1);
        }

        fn xtversion(&self) {
            self.xtversions.set(self.xtversions.get() + 1);
        }
    }

    fn with_sink<S: EffectSink + 'static>(
        cols: u16,
        rows: u16,
        scrollback: usize,
        sink: Rc<S>,
    ) -> VtEngine<S> {
        VtEngine::new(
            GridSize { cols, rows },
            ScrollbackLimit(scrollback),
            ContinuationLimit(1024),
            sink,
        )
        .expect("terminal should initialize")
    }

    fn engine(cols: u16, rows: u16) -> VtEngine<TestEffects> {
        with_sink(cols, rows, 16, Rc::new(TestEffects::default()))
    }
    fn text_of(frame: &RepaintFrame) -> Vec<&str> {
        frame.rows.iter().map(|row| row.text.as_str()).collect()
    }

    #[test]
    fn feeds_ansi_and_extracts_owned_rows() {
        let mut engine = engine(8, 2);
        engine
            .feed(b"hello\x1b[2;1Hworld")
            .expect("ANSI input should parse");
        let frame = engine.repaint().expect("render snapshot should succeed");

        assert_eq!(frame.size, GridSize { cols: 8, rows: 2 });
        assert_eq!(text_of(frame), vec!["hello   ", "world   "]);
        assert_eq!(frame.cursor, Some((5, 1)));
        assert!(frame.cursor_visible);
    }

    #[test]
    fn the_cursor_cue_follows_the_screen() {
        let mut engine = engine(8, 2);
        engine.feed(b"abc").expect("text should parse");
        assert_eq!(
            engine.cursor_cue().expect("cue"),
            CursorCue {
                col: 3,
                pending_wrap: false,
                visible: true,
                alternate: false,
                mouse_tracking: false,
            }
        );

        engine
            .feed(b"\x1b[?1049h")
            .expect("alt screen should parse");
        assert!(engine.cursor_cue().expect("cue").alternate);
        engine
            .feed(b"\x1b[?1049l")
            .expect("alt screen should parse");
        engine.feed(b"\x1b[?1000h").expect("mouse should parse");
        assert!(engine.cursor_cue().expect("cue").mouse_tracking);
        engine.feed(b"\x1b[?25l").expect("cursor hide should parse");
        assert!(!engine.cursor_cue().expect("cue").visible);
    }

    #[test]
    fn reading_a_cue_leaves_damage_alone() {
        let mut engine = engine(8, 2);
        engine.repaint().expect("first frame");
        engine.feed(b"hi").expect("text should parse");
        for _ in 0..3 {
            engine.cursor_cue().expect("cue");
        }
        let frame = engine.repaint().expect("frame");
        assert!(frame.dirty.iter().any(|row| row == 0));
    }

    #[test]
    fn registers_synchronous_effects() {
        let sink = Rc::new(TestEffects::default());
        let mut engine = with_sink(8, 2, 0, Rc::clone(&sink));

        engine.feed(b"\x07\x1b]2;title\x1b\\\x05\x1b[>q").unwrap();

        assert_eq!(sink.enquiries.get(), 1);
        assert_eq!(sink.xtversions.get(), 1);
        assert!(!sink.pty.borrow().is_empty());

        let sticky = engine.repaint().expect("frame").sticky.clone();
        assert!(sticky.bell);
        assert_eq!(sticky.title.as_deref(), Some("title"));
        // The bell rode out with the screen that carried it.
        assert!(!engine.repaint().expect("frame").sticky.bell);
    }

    /// The exact bytes braid answers a Device Attributes query with.
    ///
    /// Pinned rather than probed for shape: the server cuts an answered query
    /// out of what a client is sent, so this reply is the only one the
    /// application will ever see and a libghostty-vt upgrade that moved it
    /// would change what every session claims to be. `62` is VT220, `6` is
    /// selective erase and `22` is ANSI colour; a `3` or a `4` here would be
    /// `ReGIS` or Sixel, promising an image this wire has no blit for.
    #[test]
    fn the_device_attributes_replies_are_the_ones_braid_pins() {
        for (query, expected) in [
            (&b"\x1b[c"[..], &b"\x1b[?62;6;22c"[..]),
            (b"\x1b[>c", b"\x1b[>1;0;0c"),
            (b"\x1b[=c", b"\x1bP!|00000000\x1b\\"),
        ] {
            let sink = Rc::new(TestEffects::default());
            let mut engine = with_sink(8, 2, 16, Rc::clone(&sink));
            engine.feed(query).expect("a DA query parses");
            assert_eq!(
                &*sink.pty.borrow(),
                expected,
                "{query:?} is answered with something other than what braid pins"
            );
        }
    }

    /// A wide glyph is one cluster over two columns, and its trailing column
    /// carries no text at all.
    ///
    /// Emitting a space there — which is what an empty cell looks like —
    /// pushed the rest of the row one column right per repaint, so a screen
    /// with CJK on it drifted a little further every reconnect.
    #[test]
    fn a_row_maps_clusters_to_columns_not_characters() {
        for (cols, input, text, cells) in [
            (10, "\u{4f60}\u{597d} ok", "\u{4f60}\u{597d} ok   ", 10),
            (4, "e\u{301}x", "e\u{301}x  ", 4),
        ] {
            let mut engine = engine(cols, 1);
            engine.feed(input.as_bytes()).expect("text should parse");
            let row = &engine.repaint().expect("frame").rows[0];
            assert_eq!((row.text.as_str(), row.cells), (text, cells), "{input:?}");
        }
    }

    fn feed_in_chunks(engine: &mut VtEngine<TestEffects>, chunks: &[&[u8]]) -> String {
        for chunk in chunks {
            engine.feed(chunk).expect("chunk should parse");
            engine.repaint().expect("frame");
        }
        engine.repaint().expect("frame").rows[0].text.clone()
    }

    /// A PTY read boundary falls wherever the chunk size puts it.
    #[test]
    fn state_spanning_a_write_boundary_survives_a_repaint_in_the_gap() {
        let cases: [(&str, &[&[u8]]); 8] = [
            (
                "wide glyph split mid-scalar",
                &[b"ab", b"\xe4", b"\xb8\x96", b"cd"],
            ),
            (
                "narrow glyph split mid-scalar",
                &[b"ab", b"\xc3", b"\xa9", b"cd"],
            ),
            (
                "combining mark split mid-scalar",
                &[b"cafe", b"\xcc", b"\x81"],
            ),
            ("CSI split mid-sequence", &[b"ab\x1b[", b"1;3H", b"Z"]),
            ("OSC split mid-sequence", &[b"\x1b]0;ti", b"tle\x07", b"ab"]),
            (
                "ZWJ family split mid-sequence",
                &[
                    "\u{1f468}".as_bytes(),
                    "\u{200d}".as_bytes(),
                    "\u{1f469}".as_bytes(),
                    "\u{200d}".as_bytes(),
                    "\u{1f467}".as_bytes(),
                ],
            ),
            (
                "ZWJ left dangling at the boundary",
                &["\u{1f468}".as_bytes(), "\u{200d}".as_bytes()],
            ),
            (
                "variation selector split off its emoji",
                &["\u{2764}".as_bytes(), "\u{fe0f}".as_bytes()],
            ),
        ];
        for (label, chunks) in cases {
            let mut split = engine(12, 2);
            let split = feed_in_chunks(&mut split, chunks);

            let mut whole = engine(12, 2);
            let joined: Vec<u8> = chunks.concat();
            whole.feed(&joined).expect("stream should parse");
            let whole = whole.repaint().expect("frame").rows[0].text.clone();

            assert_eq!(split, whole, "{label}");
        }
    }

    /// Only the row that moved may come back damaged, or every combining script
    /// costs a full screen per PTY read.
    #[test]
    fn zero_width_damage_is_not_a_full_screen_repaint() {
        let mut engine = engine(8, 3);
        engine.feed(b"one\r\ntwo\r\nthree").expect("text");
        engine.repaint().expect("frame");
        engine.feed("\u{301}".as_bytes()).expect("mark");
        let frame = engine.repaint().expect("frame");
        assert_eq!(frame.rows[2].text, "three\u{301}   ");
        assert_eq!(frame.rows[2].cells, 8, "a mark is not a column");
        assert_eq!(frame.dirty.iter().collect::<Vec<_>>(), vec![2]);
        assert!(engine.repaint().expect("frame").dirty.is_empty());
    }

    /// A byte budget read as a line count configures millions of rows.
    #[test]
    fn scrollback_limit_is_a_byte_budget() {
        let engine = with_sink(8, 2, 4 * 1024 * 1024, Rc::new(TestEffects::default()));
        assert_eq!(
            engine.terminal.scrollback_max_bytes().unwrap(),
            Some(4 * 1024 * 1024)
        );
    }

    #[test]
    fn styles_become_runs_measured_in_cells_and_a_plain_row_emits_none() {
        let mut styled = engine(8, 1);
        styled.feed(b"\x1b[31mAB\x1b[0mCD").unwrap();
        let row = &styled.repaint().unwrap().rows[0];
        assert_eq!(row.text, "ABCD    ");
        assert_eq!(row.runs.len(), 1);
        assert_eq!(row.runs[0].cells, 2);
        assert_eq!(row.runs[0].style.fg, StyleColor::Palette(1));
        // The trailing default span is implied, never encoded.
        assert_eq!(row.styled_cells(), 2);

        let mut plain = engine(8, 1);
        plain.feed(b"plain").unwrap();
        assert!(plain.repaint().unwrap().rows[0].runs.is_empty());
    }

    #[test]
    fn attributes_and_true_colour_survive() {
        let mut engine = engine(4, 1);
        engine.feed(b"\x1b[1;3;4;9;38;2;10;20;30mX").unwrap();
        let style = engine.repaint().unwrap().rows[0].runs[0].style;
        assert_eq!(style.fg, StyleColor::Rgb(10, 20, 30));
        assert!(style.attrs.contains(StyleAttrs::BOLD));
        assert!(style.attrs.contains(StyleAttrs::ITALIC));
        assert!(style.attrs.contains(StyleAttrs::STRIKETHROUGH));
        assert_eq!(style.underline, UnderlineStyle::Single);
    }

    #[test]
    fn modes_the_application_set_are_captured() {
        let mut engine = engine(8, 2);
        engine.feed(b"\x1b[?1049h\x1b[?2004h\x1b[?1006h").unwrap();
        let modes = engine.repaint().unwrap().modes;
        let on: Vec<u16> = modes
            .iter()
            .filter_map(|(mode, enabled)| enabled.then_some(mode))
            .collect();
        assert!(on.contains(&1049), "alt screen: {on:?}");
        assert!(on.contains(&2004), "bracketed paste: {on:?}");
        assert!(on.contains(&1006), "sgr mouse: {on:?}");
        assert!(!on.contains(&1003), "any-event mouse must stay off: {on:?}");
    }

    /// The unset case is load-bearing: a session that never issued DECSCUSR
    /// must not be reported as a steady block.
    #[test]
    fn cursor_shape_and_blink_follow_decscusr() {
        let mut engine = engine(8, 1);
        assert_eq!(engine.repaint().unwrap().cursor_shape, CursorShape::Unset);
        engine.feed(b"\x1b[3 q").unwrap();
        let frame = engine.repaint().unwrap();
        assert_eq!(frame.cursor_shape, CursorShape::Underline);
        assert!(frame.cursor_blinking);
        engine.feed(b"\x1b[6 q").unwrap();
        let frame = engine.repaint().unwrap();
        assert_eq!(frame.cursor_shape, CursorShape::Bar);
        assert!(!frame.cursor_blinking);
        // DECSCUSR 0 gives the choice back, and so must the frame.
        engine.feed(b"\x1b[0 q").unwrap();
        assert_eq!(engine.repaint().unwrap().cursor_shape, CursorShape::Unset);
    }

    /// A row the terminal never marked is served from its own reused buffer.
    #[test]
    fn only_rows_that_changed_are_reported_dirty_and_clean_rows_are_reused() {
        let mut engine = engine(8, 3);
        engine.feed(b"one\r\ntwo\r\nthree").unwrap();
        assert_eq!(engine.repaint().unwrap().dirty.iter().count(), 3);
        engine.feed(b"\x1b[2;1HTWO").unwrap();
        let frame = engine.repaint().unwrap();
        let dirty: Vec<u16> = frame.dirty.iter().collect();
        // Damage may over-report — Ghostty also dirties the row the cursor left.
        assert!(dirty.contains(&1), "{dirty:?}");
        assert!(!dirty.contains(&0), "{dirty:?}");
        assert_eq!(frame.rows[0].text, "one     ");

        // Nothing is damaged here: every row comes from the previous frame.
        let frame = engine.repaint().unwrap();
        assert!(frame.dirty.is_empty());
        assert_eq!(text_of(frame), vec!["one     ", "TWO     ", "three   "]);
    }

    #[test]
    fn a_resize_renders_every_row_again() {
        let mut engine = engine(8, 2);
        engine.feed(b"one\r\ntwo").unwrap();
        engine.repaint().unwrap();
        engine.resize(GridSize { cols: 4, rows: 2 }).unwrap();
        assert_eq!(text_of(engine.repaint().unwrap()), vec!["one ", "two "]);
    }

    #[test]
    fn row_mask_unions_and_clears() {
        let mut mask = RowMask::with_rows(70);
        mask.set(0);
        mask.set(69);
        let mut other = RowMask::with_rows(70);
        other.set(5);
        mask.union(&other);
        assert_eq!(mask.iter().collect::<Vec<_>>(), vec![0, 5, 69]);
        mask.clear_all();
        assert!(mask.is_empty());
    }

    /// The shared helper keeps sixteen bytes of history, which is nothing to
    /// search; `lines` of it are scrolled past the viewport.
    fn deep_engine(cols: u16, rows: u16, lines: u32) -> VtEngine<TestEffects> {
        let mut engine = with_sink(cols, rows, 64 * 1024, Rc::new(TestEffects::default()));
        fill(&mut engine, lines);
        engine
    }

    fn fill(engine: &mut VtEngine<TestEffects>, lines: u32) {
        for n in 0..lines {
            engine
                .feed(format!("line{n}\r\n").as_bytes())
                .expect("text should parse");
        }
    }

    #[test]
    fn a_line_scrolled_out_of_the_viewport_is_still_found() {
        let mut engine = deep_engine(16, 4, 40);
        engine.feed(b"prompt$").expect("text should parse");

        let hits = engine.search("line0", 8).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, "line0");
        assert!(
            hits[0].distance > u32::from(engine.size().rows),
            "line0 is behind the viewport, not in it"
        );

        assert_eq!(
            engine.search("prompt$", 8).expect("search"),
            vec![ScrollbackMatch {
                distance: 0,
                line: "prompt$".to_owned(),
            }],
        );
    }

    #[test]
    fn results_come_back_newest_first_and_stop_at_the_limit() {
        let mut engine = deep_engine(16, 4, 40);
        engine.feed(b"prompt$").expect("text should parse");

        // `line3` also matches every one of `line30`..`line39`.
        let hits = engine.search("line3", 2).expect("search");
        assert_eq!(
            hits,
            vec![
                ScrollbackMatch {
                    distance: 1,
                    line: "line39".to_owned(),
                },
                ScrollbackMatch {
                    distance: 2,
                    line: "line38".to_owned(),
                },
            ],
        );
        assert!(engine.search("LINE", 8).expect("search").is_empty());
        assert!(engine.search("line0", 0).expect("search").is_empty());
    }

    /// The selection a search formats is one Ghostty never installs, so it must
    /// leave neither the screen nor its damage behind.
    #[test]
    fn a_search_leaves_the_next_repaint_alone() {
        let mut engine = deep_engine(16, 4, 40);
        engine.feed(b"prompt$").expect("text should parse");
        let mut expected = engine.repaint().expect("frame").clone();

        engine.search("line", 8).expect("search");

        expected.dirty.clear_all();
        assert_eq!(engine.repaint().expect("frame"), &expected);
    }

    #[test]
    fn a_match_keeps_its_wide_glyphs_and_combining_marks() {
        let mut engine = deep_engine(16, 2, 0);
        engine.feed("世界 ok\r\n".as_bytes()).expect("text");
        engine.feed("e\u{301}tude\r\n".as_bytes()).expect("text");
        fill(&mut engine, 8);

        let hits = engine.search("世", 4).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, "世界 ok");

        let hits = engine.search("e\u{301}tu", 4).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, "e\u{301}tude");
    }

    /// The buffer goes and its size stays: a session searched once must not
    /// hold the whole scrollback as text for the rest of its life, and the
    /// next search must still not pay a format pass to rediscover the size.
    #[test]
    fn a_search_keeps_the_size_it_needed_rather_than_the_buffer() {
        let mut engine = deep_engine(16, 4, 40);
        let first = engine.search("line", 8).expect("search");
        let sized = engine.search_hint;
        assert!(sized > 0, "the first search is what discovers the size");

        let again = engine.search("line", 8).expect("search");
        assert_eq!(
            engine.search_hint, sized,
            "the second search fit the size the first recorded, so it took one pass"
        );
        assert_eq!(first.len(), again.len());
    }
}
