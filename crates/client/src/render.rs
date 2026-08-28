#![forbid(unsafe_code)]

//! Server screen to terminal bytes. Style arrives as typed runs and is
//! rendered into SGR here, so row text can never carry an escape through.

use braid_proto::screen::MAX_CLUSTER_BYTES;
use braid_proto::{
    ByteOff, CellStyle, CursorShape, Generation, GridSize, MAX_TITLE, ModeSet, REPAINT_MODES,
    RESET_ON_EXIT, RowFrame, RowSpan, ScreenHeader, ScreenPart, ScreenVersion, ScrollBand,
    StickyState, StyleAttrs, StyleColor, UnderlineStyle,
};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use unicode_width::UnicodeWidthChar;

/// `ST` not `CAN`: a `CAN` with nothing in progress prints a cell on libghostty.
const ANSI_CANCEL: &[u8] = b"\x1b\\";
const ANSI_SGR_RESET: &[u8] = b"\x1b[0m";
const ANSI_ERASE_LINE: &[u8] = b"\x1b[K";
/// ED 2, never ED 3: the viewport is cleared and scrollback preserved.
const ANSI_CLEAR_VIEWPORT: &[u8] = b"\x1b[2J\x1b[H";
/// Synchronized output; a terminal that does not know 2026 ignores both halves.
const ANSI_SYNC_BEGIN: &[u8] = b"\x1b[?2026h";
pub(crate) const ANSI_SYNC_END: &[u8] = b"\x1b[?2026l";

/// Exported for the two exit paths that cannot reach a [`Screen`]: a signal
/// handler that must not block on the display lock, and a panic hook.
pub(crate) const RESET_TAIL: &[u8] = b"\x1b[0m\x1b[?25h\x1b[0 q";

/// Rows are kept here rather than inferred from terminal output: passthrough is
/// byte-exact and cannot reconstruct the server's screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedScreen {
    pub generation: Generation,
    /// `None` while pieces are still arriving: a version that advanced early
    /// would have the server clear damage for rows that never landed.
    pub version: Option<ScreenVersion>,
    pub size: GridSize,
    pub cursor: Option<(u16, u16)>,
    pub cursor_visible: bool,
    pub cursor_shape: CursorShape,
    pub cursor_blinking: bool,
    pub modes: ModeSet,
    pub sticky: StickyState,
    pub rows: Vec<RowFrame>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartMismatch {
    NoScreen,
    WrongBase,
    /// The grid is taller than this terminal, so the region a band scrolls
    /// inside would be clamped and move the rows by the wrong amount.
    Unscrollable,
    /// A tail named a row, or a row width, the head's grid does not hold.
    OutsideGrid,
}

/// Acknowledging a screen that crossed a prediction has the server clear damage
/// for a row still showing a character it never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predictions {
    Settled,
    Drawn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assembled {
    pub generation: Generation,
    pub version: ScreenVersion,
    pub next_off: ByteOff,
}

/// The real bound is the piece count only the head declares, so a constant
/// stands in: sixteen pieces is around eighteen kilobytes of reordering.
const HELD_TAILS: usize = 16;

/// Its buffers live in [`Painter`]: this is built and dropped at up to 30 Hz.
struct Assembly {
    named: (Generation, ScreenVersion),
    head: Option<Head>,
    predicted: bool,
}

impl Assembly {
    const fn new(named: (Generation, ScreenVersion)) -> Self {
        Self {
            named,
            head: None,
            predicted: false,
        }
    }
}

struct Head {
    next_off: ByteOff,
    coverage: Coverage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Coverage {
    Delta,
    Whole,
}

impl Coverage {
    fn slots(self, rows: &mut Vec<bool>) -> Option<&mut Vec<bool>> {
        match self {
            Self::Delta => None,
            Self::Whole => Some(rows),
        }
    }
}

/// Kept together because the function applying one would otherwise take six.
struct HeadPart {
    header: ScreenHeader,
    base: Option<ScreenVersion>,
    scroll: Option<ScrollBand>,
    pieces: u16,
    rows: Vec<RowSpan>,
}

/// Two variants rather than a `bool`: the empty slice a fully-absorbed echo
/// hands [`Screen::observe`] must not answer for passthrough it never saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ShownSinceScreen {
    #[default]
    Nothing,
    Passthrough,
}

#[derive(Default)]
pub struct Screen {
    confirmed: Option<ConfirmedScreen>,
    pending: Option<Assembly>,
    /// Passthrough is byte-exact, so these bytes are the only witness for the
    /// modes, title and keyboard flags they set.
    observed: Observed,
    /// Cleared when a transport is replaced: the terminal may have missed mode
    /// changes, so the next screen restates every mode.
    trusted: bool,
    /// A whole screen may diff against the rows this client holds only while
    /// they still describe the terminal; a delta needs no such state.
    shown: ShownSinceScreen,
    painter: Painter,
}

/// All of it is reused: a full-screen application drives this at up to 30 Hz.
#[derive(Default)]
struct Painter {
    /// A screen cut into pieces is one frame; the flush is what bounds it.
    frame_open: bool,
    /// Comes back holding the buffers of the row it replaced, so the intra-row
    /// delta path allocates once for the session.
    scratch: RowFrame,
    /// A duplicate must not complete a screen still missing a piece.
    applied: Vec<bool>,
    /// One slot per row, consulted only under [`Coverage::Whole`].
    covered: Vec<bool>,
    /// Tails that overtook the head, bounded by [`HELD_TAILS`].
    held: Vec<(u16, Vec<RowSpan>)>,
    /// A row is only a row once every chunk of it is in hand.
    chunks: Vec<RowSpan>,
}

impl Screen {
    #[must_use]
    pub fn confirmed(&self) -> Option<&ConfirmedScreen> {
        self.confirmed.as_ref()
    }

    /// Forget what the terminal is believed to show, without repainting.
    pub fn invalidate(&mut self) {
        self.trusted = false;
        self.abandon();
    }

    fn abandon(&mut self) {
        self.pending = None;
        self.painter.held.clear();
        self.painter.chunks.clear();
    }

    /// Every byte the session sends must pass here and nothing this module
    /// writes; otherwise an application on the alternate screen is left there.
    pub fn observe(&mut self, bytes: &[u8]) {
        self.observed.feed(bytes);
        if !bytes.is_empty() {
            self.shown = ShownSinceScreen::Passthrough;
        }
    }

    /// Rows paint as they come while the version waits for the last piece, so a
    /// lost piece costs its own rows rather than the screen. Nothing retransmits.
    pub fn part<W: Write>(
        &mut self,
        output: &mut W,
        part: ScreenPart,
        terminal_rows: u16,
        predictions: Predictions,
    ) -> io::Result<Result<Option<Assembled>, PartMismatch>> {
        let named = match &part {
            ScreenPart::Head { header, .. } => (header.generation, header.version),
            ScreenPart::Tail {
                generation,
                version,
                ..
            } => (*generation, *version),
        };
        if self.superseded(named) {
            return Ok(Ok(None));
        }
        if self
            .pending
            .as_ref()
            .is_none_or(|assembly| assembly.named != named)
        {
            // The buffers a screen's pieces accumulate in outlive the assembly.
            self.abandon();
        }
        let assembly = self.pending.get_or_insert_with(|| Assembly::new(named));
        if predictions == Predictions::Drawn {
            assembly.predicted = true;
        }
        match part {
            ScreenPart::Head {
                header,
                base,
                scroll,
                pieces,
                rows,
            } => {
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|assembly| assembly.head.is_some())
                {
                    return Ok(Ok(None));
                }
                let head = match self.head(
                    output,
                    HeadPart {
                        header,
                        base,
                        scroll,
                        pieces,
                        rows,
                    },
                    terminal_rows,
                    predictions,
                )? {
                    Ok(head) => head,
                    Err(mismatch) => {
                        self.abandon();
                        return Ok(Err(mismatch));
                    }
                };
                if let Err(mismatch) = self.absorb_held(output, head)? {
                    return Ok(Err(mismatch));
                }
            }
            ScreenPart::Tail {
                pieces,
                index,
                rows,
                ..
            } => {
                let Some(assembly) = self.pending.as_mut() else {
                    return Ok(Ok(None));
                };
                let Some(head) = assembly.head.as_ref() else {
                    let held = &mut self.painter.held;
                    if held.len() < HELD_TAILS && !held.iter().any(|(slot, _)| *slot == index) {
                        held.push((index, rows));
                    }
                    return Ok(Ok(None));
                };
                let coverage = head.coverage;
                // A piece count disagreeing with the head's is a different cut.
                let slot = usize::from(index);
                if usize::from(pieces) != self.painter.applied.len()
                    || self.painter.applied.get(slot).copied() != Some(false)
                {
                    return Ok(Ok(None));
                }
                let Some(screen) = self.confirmed.as_mut() else {
                    return Ok(Ok(None));
                };
                if !rows_fit(&rows, screen.rows.len(), screen.size.cols) {
                    return Ok(Err(PartMismatch::OutsideGrid));
                }
                let rows = hold_chunks(rows, &mut self.painter.chunks);
                write_piece(output, screen, rows, coverage, &mut self.painter)?;
                self.painter.applied[slot] = true;
            }
        }
        self.settle(output)
    }

    /// Apply the first piece, which is the only one that names a grid.
    fn head<W: Write>(
        &mut self,
        output: &mut W,
        part: HeadPart,
        terminal_rows: u16,
        predictions: Predictions,
    ) -> io::Result<Result<Head, PartMismatch>> {
        let HeadPart {
            header,
            base,
            scroll,
            pieces,
            rows,
        } = part;
        let mut screen = match (base, self.confirmed.take()) {
            (Some(_), None) => return Ok(Err(PartMismatch::NoScreen)),
            (Some(base), Some(screen)) => {
                match self.head_on_base(
                    output,
                    screen,
                    &header,
                    base,
                    scroll,
                    &rows,
                    terminal_rows,
                )? {
                    Ok(screen) => screen,
                    Err((screen, mismatch)) => {
                        self.confirmed = Some(screen);
                        return Ok(Err(mismatch));
                    }
                }
            }
            // Such a screen restates every row behind the band anyway.
            (None, previous) => {
                match self.head_whole(output, &header, &rows, previous, predictions)? {
                    Ok(screen) => screen,
                    Err(previous) => {
                        self.confirmed = previous;
                        return Ok(Err(PartMismatch::OutsideGrid));
                    }
                }
            }
        };
        let coverage = match base {
            Some(_) => Coverage::Delta,
            None => Coverage::Whole,
        };
        let head = Head {
            next_off: header.next_off,
            coverage,
        };
        let Painter {
            applied,
            covered,
            chunks,
            scratch,
            ..
        } = &mut self.painter;
        applied.clear();
        applied.resize(usize::from(pieces), false);
        covered.clear();
        if coverage == Coverage::Whole {
            covered.resize(usize::from(header.size.rows), false);
        }
        let rows = hold_chunks(rows, chunks);
        write_part_rows(output, &mut screen, rows, coverage.slots(covered), scratch)?;
        screen.generation = header.generation;
        screen.size = header.size;
        screen.cursor = header.cursor;
        screen.cursor_visible = header.cursor_visible;
        screen.cursor_shape = header.cursor_shape;
        screen.cursor_blinking = header.cursor_blinking;
        screen.modes = header.modes;
        screen.sticky = header.sticky;
        // From the model, not the header: a pending wrap re-arms by rewriting.
        write_cursor(output, &screen)?;
        if let Some(first) = applied.first_mut() {
            *first = true;
        }
        self.confirmed = Some(screen);
        self.trusted = true;
        self.shown = ShownSinceScreen::Nothing;
        self.observed.settled();
        Ok(Ok(head))
    }

    /// Returns the screen on refusal: `confirmed` must be left as it was found.
    #[allow(clippy::too_many_arguments)]
    fn head_on_base<W: Write>(
        &mut self,
        output: &mut W,
        mut screen: ConfirmedScreen,
        header: &ScreenHeader,
        base: ScreenVersion,
        scroll: Option<ScrollBand>,
        rows: &[RowSpan],
        terminal_rows: u16,
    ) -> io::Result<Result<ConfirmedScreen, (ConfirmedScreen, PartMismatch)>> {
        if let Err(mismatch) = base_fits(&screen, self.trusted, header, base, scroll, terminal_rows)
            .and_then(|()| {
                rows_fit(rows, screen.rows.len(), screen.size.cols)
                    .then_some(())
                    .ok_or(PartMismatch::OutsideGrid)
            })
        {
            return Ok(Err((screen, mismatch)));
        }
        let believed = self.observed.believed(&screen);
        open_frame(output, &mut self.painter.frame_open)?;
        write_modes(output, header.modes, Some(screen.modes))?;
        write_sticky(output, &header.sticky, Some(&believed))?;
        if let Some(band) = scroll {
            write_scroll(output, &mut screen, band)?;
        }
        Ok(Ok(screen))
    }

    /// Painted as the difference against the rows this client holds while they
    /// still describe the terminal: erasing costs a full grid of writes on
    /// every repaint, and a repaint is what answers every lost datagram.
    fn head_whole<W: Write>(
        &mut self,
        output: &mut W,
        header: &ScreenHeader,
        rows: &[RowSpan],
        previous: Option<ConfirmedScreen>,
        predictions: Predictions,
    ) -> io::Result<Result<ConfirmedScreen, Option<ConfirmedScreen>>> {
        if !rows_fit(rows, usize::from(header.size.rows), header.size.cols) {
            return Ok(Err(previous));
        }
        let believed = self
            .trusted
            .then_some(previous.as_ref())
            .flatten()
            .map(|screen| (screen.modes, self.observed.believed(screen)));
        let base = previous.filter(|screen| {
            self.trusted
                && self.shown == ShownSinceScreen::Nothing
                && predictions == Predictions::Settled
                && screen.size == header.size
                && screen.rows.len() == usize::from(header.size.rows)
        });
        open_frame(output, &mut self.painter.frame_open)?;
        write_modes(
            output,
            header.modes,
            believed.as_ref().map(|(modes, _)| *modes),
        )?;
        write_sticky(
            output,
            &header.sticky,
            believed.as_ref().map(|(_, sticky)| sticky),
        )?;
        let rows = if let Some(screen) = base {
            screen.rows
        } else {
            output.write_all(ANSI_SGR_RESET)?;
            // A row no piece arrives for must not be one the client holds.
            output.write_all(ANSI_CLEAR_VIEWPORT)?;
            vec![RowFrame::default(); usize::from(header.size.rows)]
        };
        Ok(Ok(ConfirmedScreen {
            generation: header.generation,
            version: None,
            size: header.size,
            cursor: header.cursor,
            cursor_visible: header.cursor_visible,
            cursor_shape: header.cursor_shape,
            cursor_blinking: header.cursor_blinking,
            modes: header.modes,
            sticky: header.sticky.clone(),
            rows,
        }))
    }

    /// Paint the tails that overtook the head now that a grid names them.
    fn absorb_held<W: Write>(
        &mut self,
        output: &mut W,
        head: Head,
    ) -> io::Result<Result<(), PartMismatch>> {
        if self.pending.is_none() {
            return Ok(Ok(()));
        }
        // Drained into a local because painting reaches the painter it lives in.
        let mut orphans = std::mem::take(&mut self.painter.held);
        let mut refused = None;
        if let Some(screen) = self.confirmed.as_mut() {
            for (index, rows) in orphans.drain(..) {
                let slot = usize::from(index);
                if self.painter.applied.get(slot).copied() != Some(false) {
                    continue;
                }
                if !rows_fit(&rows, screen.rows.len(), screen.size.cols) {
                    refused = Some(PartMismatch::OutsideGrid);
                    break;
                }
                let rows = hold_chunks(rows, &mut self.painter.chunks);
                write_piece(output, screen, rows, head.coverage, &mut self.painter)?;
                self.painter.applied[slot] = true;
            }
        }
        self.painter.held = orphans;
        if let Some(assembly) = self.pending.as_mut() {
            assembly.head = Some(head);
        }
        Ok(refused.map_or(Ok(()), Err))
    }

    fn settle<W: Write>(
        &mut self,
        output: &mut W,
    ) -> io::Result<Result<Option<Assembled>, PartMismatch>> {
        let Some(assembly) = self.pending.as_mut() else {
            return Ok(Ok(None));
        };
        let Assembly {
            named,
            head,
            predicted,
        } = assembly;
        let Some(head) = head.as_ref() else {
            return Ok(Ok(None));
        };
        let coverage = head.coverage;
        if !self.painter.applied.iter().all(|piece| *piece) {
            return Ok(Ok(None));
        }
        if !self.painter.chunks.is_empty() {
            let Some(screen) = self.confirmed.as_mut() else {
                return Ok(Ok(None));
            };
            let Painter {
                frame_open,
                scratch,
                covered,
                chunks,
                ..
            } = &mut self.painter;
            // Ends at the header's cursor, not at the end of the last row's text.
            open_frame(output, frame_open)?;
            write_joined_rows(output, screen, chunks, coverage.slots(covered), scratch)?;
            write_cursor(output, screen)?;
        }
        // A row whose chunks did not add up is one this client is not holding.
        if coverage
            .slots(&mut self.painter.covered)
            .is_some_and(|rows| rows.iter().any(|row| !*row))
        {
            return Ok(Ok(None));
        }
        let (generation, version) = *named;
        let next_off = head.next_off;
        let predicted = *predicted;
        self.abandon();
        close_frame(output, &mut self.painter.frame_open)?;
        let Some(screen) = self.confirmed.as_mut() else {
            return Ok(Ok(None));
        };
        // Once every row is on: these are events the byte stream carried rather
        // than state a screen restates, so replaying marks prompts twice.
        for entry in &screen.sticky.deferred {
            // Always `ST`: the body was kept alone, UTF-8 and control-free.
            write!(output, "\x1b]{entry}\x1b\\")?;
        }
        if predicted {
            return Ok(Ok(None));
        }
        screen.version = Some(version);
        Ok(Ok(Some(Assembled {
            generation,
            version,
            next_off,
        })))
    }

    /// A straggler would paint its rows over the screen that replaced it.
    fn superseded(&self, named: (Generation, ScreenVersion)) -> bool {
        if self
            .pending
            .as_ref()
            .is_some_and(|assembly| assembly.named > named)
        {
            return true;
        }
        self.confirmed.as_ref().is_some_and(|screen| {
            screen
                .version
                .is_some_and(|version| (screen.generation, version) >= named)
        })
    }

    /// An unended frame holds the display until the terminal's 2026 timeout.
    pub(crate) fn end_frame<W: Write>(&mut self, output: &mut W) -> io::Result<()> {
        close_frame(output, &mut self.painter.frame_open)
    }

    /// The reset owed is the union of what a repaint painted and what the byte
    /// stream turned on; autowrap and grapheme clustering are defaults to keep.
    pub fn teardown<W: Write>(&mut self, output: &mut W) -> io::Result<()> {
        // Ahead of the resets, so none lands inside a frame nothing will end.
        close_frame(output, &mut self.painter.frame_open)?;
        let confirmed = self.confirmed.take();
        let lit = ModeSet::from_bits(
            self.observed.lit.bits() | confirmed.as_ref().map_or(0, |screen| screen.modes.bits()),
        );
        for (index, (mode, on)) in lit.iter().enumerate() {
            if on && RESET_ON_EXIT.get(index) {
                write!(output, "\x1b[?{mode}l")?;
            }
        }
        let kitty = confirmed.map_or(0, |screen| screen.sticky.kitty_keyboard);
        if kitty != 0 || self.observed.kitty.is_some_and(|flags| flags != 0) {
            output.write_all(b"\x1b[=0;1u")?;
        }
        output.write_all(RESET_TAIL)?;
        self.trusted = false;
        self.abandon();
        self.observed = Observed::default();
        output.flush()
    }
}

/// [`ANSI_CANCEL`] leads the frame rather than every piece: it abandons a
/// sequence the byte stream left dangling, and passthrough cannot run inside one.
fn open_frame<W: Write>(output: &mut W, open: &mut bool) -> io::Result<()> {
    if *open {
        return Ok(());
    }
    output.write_all(ANSI_CANCEL)?;
    output.write_all(ANSI_SYNC_BEGIN)?;
    *open = true;
    Ok(())
}

fn close_frame<W: Write>(output: &mut W, open: &mut bool) -> io::Result<()> {
    if std::mem::take(open) {
        output.write_all(ANSI_SYNC_END)?;
    }
    Ok(())
}

/// A bounded region and index sequences rather than a repaint; a whole-terminal
/// band puts the rows leaving the top into the user's own scrollback. The
/// decoder proved `top < bottom <= rows` and `0 < lines <= bottom - top`.
fn write_scroll<W: Write>(
    output: &mut W,
    screen: &mut ConfirmedScreen,
    band: ScrollBand,
) -> io::Result<()> {
    let lines = usize::from(band.lines);
    if let Some(rows) = screen
        .rows
        .get_mut(usize::from(band.top)..usize::from(band.bottom))
        && lines <= rows.len()
    {
        rows.rotate_left(lines);
        for row in rows.iter_mut().rev().take(lines) {
            *row = RowFrame::default();
        }
    }
    let moved = write_band(output, band);
    // Unconditional: a scroll region outlives this client, so even a failed
    // band owes the terminal its whole screen back.
    let restored = output.write_all(b"\x1b[r");
    moved.and(restored)
}

fn write_band<W: Write>(output: &mut W, band: ScrollBand) -> io::Result<()> {
    // An index sequence fills the row it reveals with the current background.
    output.write_all(ANSI_SGR_RESET)?;
    write!(output, "\x1b[{};{}r", u32::from(band.top) + 1, band.bottom)?;
    write!(output, "\x1b[{};1H", band.bottom)?;
    for _ in 0..band.lines {
        output.write_all(b"\x1bD")?;
    }
    Ok(())
}

fn base_fits(
    screen: &ConfirmedScreen,
    trusted: bool,
    header: &ScreenHeader,
    base: ScreenVersion,
    scroll: Option<ScrollBand>,
    terminal_rows: u16,
) -> Result<(), PartMismatch> {
    if !trusted
        || screen.generation != header.generation
        || screen.version != Some(base)
        || screen.size != header.size
    {
        return Err(PartMismatch::WrongBase);
    }
    // A terminal clamps a region to its own height, so a grid taller than this
    // one — a local shrink not yet answered — would move unseen rows.
    if scroll.is_some() && screen.size.rows > terminal_rows {
        return Err(PartMismatch::Unscrollable);
    }
    Ok(())
}

/// A tail's rows were decoded against `u16::MAX` columns, so this is the only
/// place that can refuse one.
fn rows_fit(rows: &[RowSpan], held: usize, cols: u16) -> bool {
    rows.iter().all(|row| {
        usize::from(row.row) < held
            && row.frame.cells <= cols
            // What a row's chunks sum to is checked where they are joined.
            && (row.chunk
                || usize::from(row.col) + usize::from(row.frame.cells) <= usize::from(cols))
    })
}

/// Past the bound chunks are dropped, which costs what a lost piece already
/// costs: the screen is never acknowledged and the rows are named again.
const HELD_CHUNK_BYTES: usize = 1024 * 1024;

fn hold_chunks(rows: Vec<RowSpan>, chunks: &mut Vec<RowSpan>) -> Vec<RowSpan> {
    if rows.iter().all(|row| !row.chunk) {
        return rows;
    }
    let mut whole = Vec::with_capacity(rows.len());
    let mut held: usize = chunks.iter().map(|span| span.frame.text.len()).sum();
    for row in rows {
        if !row.chunk {
            whole.push(row);
            continue;
        }
        held += row.frame.text.len();
        if held > HELD_CHUNK_BYTES {
            continue;
        }
        chunks.push(row);
    }
    whole
}

/// A chunk boundary is a style-run boundary, so text, runs and columns all
/// concatenate. `(row, column)` is the only ordering the wire states.
fn write_joined_rows<W: Write>(
    output: &mut W,
    screen: &mut ConfirmedScreen,
    chunks: &mut Vec<RowSpan>,
    covered: Option<&mut Vec<bool>>,
    scratch: &mut RowFrame,
) -> io::Result<()> {
    chunks.sort_by_key(|span| (span.row, span.col));
    let mut joined: Vec<RowSpan> = Vec::new();
    for span in chunks.drain(..) {
        match joined.last_mut() {
            Some(last) if last.row == span.row => {
                // A gap in either extent is a row this client cannot rebuild;
                // the flag keeps it out of the paint rather than holing it.
                if last.chunk
                    || usize::from(last.col) + usize::from(last.frame.cells)
                        != usize::from(span.col)
                    || last.byte as usize + last.frame.text.len() != span.byte as usize
                {
                    last.chunk = true;
                    continue;
                }
                last.frame.text.push_str(&span.frame.text);
                last.frame.runs.extend_from_slice(&span.frame.runs);
                last.frame.cells = last.frame.cells.saturating_add(span.frame.cells);
                // The erase belongs to the last chunk of the row.
                last.clear_tail = span.clear_tail;
            }
            _ => joined.push(RowSpan {
                chunk: false,
                ..span
            }),
        }
    }
    // A row that fails here stays uncovered, so the screen is never confirmed.
    joined.retain(|span| {
        let frame = &span.frame;
        !span.chunk
            && usize::from(span.row) < screen.rows.len()
            && usize::from(span.col) + usize::from(frame.cells) <= usize::from(screen.size.cols)
            && frame.text.len() <= usize::from(frame.cells) * MAX_CLUSTER_BYTES
            && frame.styled_bytes() <= frame.text.len()
            && frame.styled_cells() <= u32::from(frame.cells)
    });
    write_part_rows(output, screen, joined, covered, scratch)
}

/// A span is a patch, not a row: what reaches the terminal is the columns in
/// which the patched row differs from the one already on it.
fn write_part_rows<W: Write>(
    output: &mut W,
    screen: &mut ConfirmedScreen,
    rows: Vec<RowSpan>,
    mut covered: Option<&mut Vec<bool>>,
    scratch: &mut RowFrame,
) -> io::Result<()> {
    for span in rows {
        let index = usize::from(span.row);
        let Some(current) = screen.rows.get(index) else {
            continue;
        };
        let clear_tail = span.clear_tail;
        // A span this client cannot place leaves the row uncovered.
        if splice_into(scratch, current, span).is_none() {
            continue;
        }
        if let Some(slot) = covered.as_deref_mut().and_then(|rows| rows.get_mut(index)) {
            *slot = true;
        }
        let patch = row_patch(current, scratch, clear_tail);
        write_patch(output, index, scratch, patch)?;
        // The row this replaces hands its buffers back.
        std::mem::swap(&mut screen.rows[index], scratch);
    }
    Ok(())
}

/// A span names where it lands in both extents, and both are boundaries of the
/// row the server built it against, so that is the whole of the check. `into`
/// is written rather than returned because the caller swaps it in.
fn splice_into(into: &mut RowFrame, row: &RowFrame, span: RowSpan) -> Option<()> {
    let RowSpan {
        col,
        byte,
        clear_tail,
        frame,
        ..
    } = span;
    let byte = byte as usize;
    let first = boundary(row, col, byte)?;
    let past_col = col.checked_add(frame.cells)?;
    let past_byte = byte.checked_add(frame.text.len())?;
    // An erase is the one case an empty span carries information.
    let end = if clear_tail {
        None
    } else {
        boundary(row, past_col, past_byte)
    };
    match end {
        Some(end) => {
            // Read out before `into` is touched: a refusal must leave the row.
            let head = row.text.get(..byte)?;
            let tail = row.text.get(past_byte..)?;
            let head_runs = row.runs.get(..first)?;
            let tail_runs = row.runs.get(end..)?;
            into.text.clear();
            into.text.push_str(head);
            into.text.push_str(&frame.text);
            into.text.push_str(tail);
            into.runs.clear();
            into.runs.extend_from_slice(head_runs);
            into.runs.extend_from_slice(&frame.runs);
            into.runs.extend_from_slice(tail_runs);
            into.cells = row.cells;
        }
        // Reaching the row's end is a run range that ran to the last run.
        None if first == 0 && byte == 0 => *into = frame,
        None => {
            let head = row.text.get(..byte)?;
            let head_runs = row.runs.get(..first)?;
            into.text.clear();
            into.text.push_str(head);
            into.text.push_str(&frame.text);
            into.runs.clear();
            into.runs.extend_from_slice(head_runs);
            into.runs.extend_from_slice(&frame.runs);
            into.cells = past_col;
        }
    }
    Some(())
}

/// A run boundary is the only offset in a row where both a column and a byte
/// position are known, which is why the wire names spans at one and nowhere else.
fn boundary(row: &RowFrame, col: u16, byte: usize) -> Option<usize> {
    if byte > row.text.len() || !row.text.is_char_boundary(byte) {
        return None;
    }
    let mut at = 0_usize;
    let mut cells = 0_u16;
    for (index, run) in row.runs.iter().enumerate() {
        if cells == col && at == byte {
            return Some(index);
        }
        if cells > col || at > byte {
            return None;
        }
        cells = cells.checked_add(run.cells)?;
        at = at.checked_add(run.bytes as usize)?;
    }
    (cells == col && at == byte).then_some(row.runs.len())
}

/// Leaves the cursor where the header put it: a flush between pieces still
/// shows a screen someone is looking at.
fn write_piece<W: Write>(
    output: &mut W,
    screen: &mut ConfirmedScreen,
    rows: Vec<RowSpan>,
    coverage: Coverage,
    painter: &mut Painter,
) -> io::Result<()> {
    let Painter {
        frame_open,
        scratch,
        covered,
        ..
    } = painter;
    open_frame(output, frame_open)?;
    write_part_rows(output, screen, rows, coverage.slots(covered), scratch)?;
    write_cursor(output, screen)
}

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

/// A longer sequence is dropped rather than buffered, which keeps a stream that
/// never terminates one from growing this without bound.
const SCAN_LIMIT: usize = MAX_TITLE + 2;

/// A mode tracker, not an emulator: it recognises the sequences whose effect
/// outlives the session and consumes the rest far enough to find their end.
#[derive(Default)]
struct Observed {
    /// Never cleared: a DECRST for a mode already off is a no-op, and a missing
    /// one leaves the shell answering keystrokes with mouse escapes.
    lit: ModeSet,
    /// Set since the last screen. A header describes the moment the server took
    /// it, so a screen's diff against the confirmed one is stale exactly here.
    title: Option<Arc<str>>,
    kitty: Option<u8>,
    /// Popping the last restores the entry the last screen set.
    pushed: u16,
    scan: Scan,
    /// The sequence being scanned, minus its introducer.
    partial: Vec<u8>,
    /// The sequence outgrew `partial` and is consumed for its end alone.
    truncated: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Scan {
    #[default]
    Ground,
    Escape,
    Csi,
    Osc,
    /// An OSC that has seen `ESC`: only `\` ends it.
    OscEnd,
    /// Skipped whole: its body would otherwise read as sequences of its own.
    Skip,
    SkipEnd,
}

impl Observed {
    /// Stepping byte by byte costs 65536 dispatches per max-size chunk under
    /// the display mutex; skipping to the next `ESC` is a `memchr` in disguise.
    fn feed(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            if self.scan == Scan::Ground {
                let Some(escape) = rest.iter().position(|&byte| byte == ESC) else {
                    return;
                };
                self.scan = Scan::Escape;
                rest = &rest[escape + 1..];
            } else {
                self.step(rest[0]);
                rest = &rest[1..];
            }
        }
    }

    fn step(&mut self, byte: u8) {
        match self.scan {
            Scan::Ground => {
                if byte == ESC {
                    self.scan = Scan::Escape;
                }
            }
            Scan::Escape => self.introduce(byte),
            Scan::Csi => match byte {
                // Parameters and intermediates, then the final byte.
                0x20..=0x3f => self.push(byte),
                0x40..=0x7e => {
                    self.csi(byte);
                    self.end();
                }
                ESC => self.scan = Scan::Escape,
                // Any other C0 abandons the sequence where it stands.
                _ => self.end(),
            },
            Scan::Osc => match byte {
                BEL => {
                    self.osc();
                    self.end();
                }
                ESC => self.scan = Scan::OscEnd,
                _ => self.push(byte),
            },
            Scan::OscEnd => {
                if byte == b'\\' {
                    self.osc();
                    self.end();
                } else {
                    // An `ESC` anything-else abandons the string, as the
                    // terminal reading these same bytes does.
                    self.end();
                    self.introduce(byte);
                }
            }
            Scan::Skip => match byte {
                BEL => self.end(),
                ESC => self.scan = Scan::SkipEnd,
                _ => {}
            },
            Scan::SkipEnd => {
                self.end();
                if byte != b'\\' {
                    self.introduce(byte);
                }
            }
        }
    }

    fn introduce(&mut self, byte: u8) {
        self.partial.clear();
        self.truncated = false;
        self.scan = match byte {
            b'[' => Scan::Csi,
            b']' => Scan::Osc,
            b'P' | b'X' | b'^' | b'_' => Scan::Skip,
            ESC => Scan::Escape,
            // A two-byte escape: nothing tracked here arrives as one.
            _ => Scan::Ground,
        };
    }

    fn push(&mut self, byte: u8) {
        if self.partial.len() < SCAN_LIMIT {
            self.partial.push(byte);
        } else {
            self.truncated = true;
        }
    }

    fn end(&mut self) {
        self.scan = Scan::Ground;
        self.partial.clear();
        self.truncated = false;
    }

    fn csi(&mut self, final_byte: u8) {
        if self.truncated {
            return;
        }
        let Some((&prefix, params)) = self.partial.split_first() else {
            return;
        };
        match (prefix, final_byte) {
            // Only DECSET: a mode turned off needs no undoing.
            (b'?', b'h') => {
                for value in numbers(params) {
                    if let Some(index) = REPAINT_MODES
                        .iter()
                        .position(|mode| u32::from(*mode) == value)
                    {
                        self.lit.set(index, true);
                    }
                }
            }
            (b'=', b'u') => {
                let mut values = numbers(params);
                let flags = kitty_flags(values.next().unwrap_or(0));
                let current = self.kitty.unwrap_or(0);
                // `CSI = flags ; mode u`: 2 sets the named bits and 3 clears
                // them; any other mode replaces the entry outright.
                self.kitty = Some(match values.next().unwrap_or(1) {
                    2 => current | flags,
                    3 => current & !flags,
                    _ => flags,
                });
            }
            (b'>', b'u') => {
                self.pushed = self.pushed.saturating_add(1);
                self.kitty = Some(kitty_flags(numbers(params).next().unwrap_or(0)));
            }
            (b'<', b'u') => {
                let count = numbers(params).next().unwrap_or(1).max(1);
                self.pushed = self
                    .pushed
                    .saturating_sub(u16::try_from(count).unwrap_or(u16::MAX));
                if self.pushed == 0 {
                    self.kitty = None;
                }
            }
            _ => {}
        }
    }

    /// OSC 0 and OSC 2 both set the window title.
    fn osc(&mut self) {
        if self.truncated {
            return;
        }
        let Some(separator) = self.partial.iter().position(|byte| *byte == b';') else {
            return;
        };
        let (kind, text) = self.partial.split_at(separator);
        if kind != b"0" && kind != b"2" {
            return;
        }
        // Never written back out, so a title that is not text is dropped.
        if let Ok(title) = str::from_utf8(&text[1..]) {
            self.title = Some(Arc::from(title));
        }
    }

    /// The confirmed screen overridden by whatever the byte stream said since.
    fn believed(&self, screen: &ConfirmedScreen) -> StickyState {
        let mut sticky = screen.sticky.clone();
        if let Some(title) = &self.title {
            sticky.title = Some(Arc::clone(title));
        }
        if let Some(kitty) = self.kitty {
            sticky.kitty_keyboard = kitty;
        }
        sticky
    }

    /// `lit` is not spent: it is what teardown owes a reset for.
    fn settled(&mut self) {
        self.title = None;
        self.kitty = None;
    }
}

/// Decimal parameters of a control sequence, an omitted one reading as zero.
fn numbers(params: &[u8]) -> impl Iterator<Item = u32> + '_ {
    params.split(|byte| *byte == b';').map(|part| {
        part.iter()
            .take_while(|byte| byte.is_ascii_digit())
            .fold(0_u32, |value, digit| {
                value
                    .saturating_mul(10)
                    .saturating_add(u32::from(*digit - b'0'))
            })
    })
}

/// Kitty keyboard flags are five bits. A value that does not fit is kept as
/// "something is on" rather than dropped: teardown still owes it a reset.
fn kitty_flags(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

/// `previous` is what the terminal is believed to show; `None` restates all.
fn write_sticky<W: Write>(
    output: &mut W,
    sticky: &StickyState,
    previous: Option<&StickyState>,
) -> io::Result<()> {
    if sticky.bell {
        output.write_all(b"\x07")?;
    }
    if previous.is_none_or(|previous| previous.title != sticky.title) {
        // The title is refused at decode if it carries a control byte.
        write!(
            output,
            "\x1b]2;{}\x1b\\",
            sticky.title.as_deref().unwrap_or("")
        )?;
    }
    if previous.is_none_or(|previous| previous.kitty_keyboard != sticky.kitty_keyboard) {
        // `CSI = flags ; 1 u` sets the current stack entry outright, which is
        // the only idempotent form: pushing would grow the stack per repaint.
        write!(output, "\x1b[={};1u", sticky.kitty_keyboard)?;
    }
    Ok(())
}

/// `None` means the terminal's state is unknown and every mode is restated.
fn write_modes<W: Write>(
    output: &mut W,
    modes: ModeSet,
    previous: Option<ModeSet>,
) -> io::Result<()> {
    for (index, (mode, on)) in modes.iter().enumerate() {
        if previous.is_some_and(|previous| previous.get(index) == on) {
            continue;
        }
        write!(output, "\x1b[?{}{}", mode, if on { 'h' } else { 'l' })?;
    }
    Ok(())
}

/// Also the two pieces of cursor state a `CUP` on its own destroys.
fn write_cursor<W: Write>(output: &mut W, screen: &ConfirmedScreen) -> io::Result<()> {
    if let Some(saved) = screen.sticky.saved_cursor {
        // `ESC 7` saves whatever is current, so it is made current first.
        output.write_all(ANSI_SGR_RESET)?;
        write_cup(output, Some(saved))?;
        output.write_all(b"\x1b7")?;
    }
    output.write_all(ANSI_SGR_RESET)?;
    write!(
        output,
        "\x1b[{} q",
        screen.cursor_shape.decscusr(screen.cursor_blinking)
    )?;
    output.write_all(if screen.cursor_visible {
        b"\x1b[?25h".as_slice()
    } else {
        b"\x1b[?25l".as_slice()
    })?;
    write_cup(output, screen.cursor)?;
    if screen.sticky.pending_wrap {
        write_pending_wrap(output, screen)?;
    }
    Ok(())
}

/// No sequence sets a pending wrap and the `CUP` above cleared it, so the cell
/// is rewritten; without this the next character overwrites the last column.
fn write_pending_wrap<W: Write>(output: &mut W, screen: &ConfirmedScreen) -> io::Result<()> {
    let Some((col, row)) = screen.cursor else {
        return Ok(());
    };
    // Rewriting a cell anywhere else leaves the cursor past the session's.
    if usize::from(col) + 1 != usize::from(screen.size.cols) {
        return Ok(());
    }
    let Some(frame) = screen.rows.get(usize::from(row)) else {
        return Ok(());
    };
    // A glyph in the wrong cell costs the row; a re-earned wrap costs a cell.
    let Some((text, style)) = cell_at(frame, col) else {
        return Ok(());
    };
    write_sgr(output, &style)?;
    output.write_all(text.as_bytes())
}

/// A cursor outside the grid is refused at decode, so a clamp here would only
/// hide a server-side desync.
fn write_cup<W: Write>(output: &mut W, cursor: Option<(u16, u16)>) -> io::Result<()> {
    if let Some((x, y)) = cursor {
        // Ghostty reports viewport coordinates from zero; ANSI CUP is one-based.
        write!(output, "\x1b[{};{}H", u32::from(y) + 1, u32::from(x) + 1)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Patch {
    Nothing,
    /// Paint `[from, to)` at `col`, erasing what follows when `erase`.
    Columns {
        col: u16,
        from: usize,
        to: usize,
        erase: bool,
    },
    /// No column can be trusted: home, erase, repaint.
    Whole,
}

/// [`write_sgr`] leads every run with a reset, so a 200-column row reissued for
/// one changed cell is 250 bytes where the cell is ten — most of a 30 Hz budget.
fn row_patch(old: &RowFrame, new: &RowFrame, clear_tail: bool) -> Patch {
    if old == new {
        return Patch::Nothing;
    }
    let (Some(was), Some(now)) = (painted_cells(old), painted_cells(new)) else {
        return Patch::Whole;
    };
    let mut before = Cells::new(old);
    let mut after = Cells::new(new);
    let mut first: Option<(u16, usize)> = None;
    let mut last = 0_usize;
    while !before.done() || !after.done() {
        if before.col == after.col && before.peek() == after.peek() {
            before.step();
            after.step();
            continue;
        }
        first.get_or_insert((after.col, after.byte));
        // Off a shared column the two rows are not comparable — a wide glyph on
        // one side straddles a boundary on the other — so the lagging walk moves.
        if before.col <= after.col {
            before.step();
        }
        if after.col <= before.col || before.done() {
            after.step();
        }
        last = after.byte;
    }
    // `clear_tail` is the server saying the row got shorter.
    let erase = clear_tail || was > now;
    let Some((col, from)) = first else {
        return Patch::Nothing;
    };
    let to = if erase { new.painted_bytes() } else { last };
    Patch::Columns {
        col,
        from,
        to: to.max(from),
        erase,
    }
}

fn write_patch<W: Write>(
    output: &mut W,
    index: usize,
    row: &RowFrame,
    patch: Patch,
) -> io::Result<()> {
    match patch {
        Patch::Nothing => Ok(()),
        Patch::Whole => write_row(output, index, row),
        Patch::Columns {
            col,
            from,
            to,
            erase,
        } => {
            write!(output, "\x1b[{};{}H", index + 1, u32::from(col) + 1)?;
            write_row_text(output, row, from, to, None)?;
            if erase {
                // `\x1b[K` paints with the current background, so a coloured
                // row erased under its own style grows a coloured tail.
                output.write_all(ANSI_SGR_RESET)?;
                output.write_all(ANSI_ERASE_LINE)?;
            }
            Ok(())
        }
    }
}

/// The erase precedes the text and under a reset style, at column one, which
/// keeps paint off the last column where a pending wrap lives.
fn write_row<W: Write>(output: &mut W, index: usize, row: &RowFrame) -> io::Result<()> {
    write!(output, "\x1b[{};1H", index + 1)?;
    output.write_all(ANSI_SGR_RESET)?;
    output.write_all(ANSI_ERASE_LINE)?;
    write_row_text(
        output,
        row,
        0,
        row.painted_bytes(),
        Some(CellStyle::default()),
    )
}

/// `current` is the style in effect where the write begins; `None` is what a
/// `CUP` into the middle of a row leaves.
fn write_row_text<W: Write>(
    output: &mut W,
    row: &RowFrame,
    from: usize,
    to: usize,
    mut current: Option<CellStyle>,
) -> io::Result<()> {
    let text = row.text.as_bytes();
    let to = to.min(text.len());
    let mut at = 0_usize;
    for run in &row.runs {
        if at >= to {
            break;
        }
        let end = at
            .saturating_add(usize::try_from(run.bytes).unwrap_or(usize::MAX))
            .min(to);
        if end > from {
            if current != Some(run.style) {
                write_sgr(output, &run.style)?;
                current = Some(run.style);
            }
            output.write_all(&text[at.max(from)..end])?;
        }
        at = end;
    }
    // Every cell past the last run carries the default style.
    if at < to {
        if current.is_none_or(|style| !style.is_default()) {
            output.write_all(ANSI_SGR_RESET)?;
        }
        output.write_all(&text[at.max(from)..to])?;
    }
    Ok(())
}

/// A ZWJ family is one cell to libghostty and three leading characters here,
/// which is why nothing below trusts this without the session's own count.
fn lead_cells(c: char) -> u16 {
    match UnicodeWidthChar::width(c) {
        Some(0) => 0,
        Some(2) => 2,
        // A control byte never reaches row text; an unrenderable cell was a space.
        _ => 1,
    }
}

fn text_cells(text: &str) -> u32 {
    text.chars().map(|c| u32::from(lead_cells(c))).sum()
}

/// A style run's `cells` is what libghostty counted and the only checkpoint a
/// row carries; past the last run there is none, so only ASCII is walked there.
/// What this refuses is repainted from column one.
fn painted_cells(row: &RowFrame) -> Option<u16> {
    let mut at = 0_usize;
    let mut cells = 0_u16;
    for run in &row.runs {
        let end = at.checked_add(run.bytes as usize)?;
        if text_cells(row.text.get(at..end)?) != u32::from(run.cells) {
            return None;
        }
        cells = cells.checked_add(run.cells)?;
        at = end;
    }
    let tail = row.text.get(at..row.painted_bytes()).unwrap_or_default();
    if !tail.is_ascii() {
        return None;
    }
    let cells = cells.checked_add(u16::try_from(tail.len()).ok()?)?;
    (cells <= row.cells).then_some(cells)
}

/// Only built for a row [`painted_cells`] agreed with, so its columns are the
/// session's and not this side's guess.
struct Cells<'a> {
    row: &'a RowFrame,
    painted: usize,
    byte: usize,
    col: u16,
    /// The run covering `byte`, and the byte it ends at.
    run: usize,
    run_end: usize,
}

impl<'a> Cells<'a> {
    fn new(row: &'a RowFrame) -> Self {
        Self {
            row,
            painted: row.painted_bytes(),
            byte: 0,
            col: 0,
            run: 0,
            run_end: row.runs.first().map_or(0, |run| run.bytes as usize),
        }
    }

    fn done(&self) -> bool {
        self.byte >= self.painted
    }

    /// A column past the painted text is a blank the encoder dropped; comparing
    /// two of those lets a shortened row find where it stopped matching.
    fn peek(&self) -> (&'a str, u16, CellStyle) {
        if self.done() {
            return (" ", 1, CellStyle::default());
        }
        let rest = &self.row.text[self.byte..self.painted];
        let mut end = 0_usize;
        let mut cells = 0_u16;
        for c in rest.chars() {
            let width = lead_cells(c);
            if end > 0 && width > 0 {
                break;
            }
            end += c.len_utf8();
            cells += width;
        }
        let style = self
            .row
            .runs
            .get(self.run)
            .map_or_else(CellStyle::default, |run| run.style);
        (&rest[..end], cells, style)
    }

    fn step(&mut self) {
        if self.done() {
            self.col = self.col.saturating_add(1);
            return;
        }
        let (text, cells, _) = self.peek();
        self.byte += text.len();
        self.col = self.col.saturating_add(cells);
        while self.run < self.row.runs.len() && self.byte >= self.run_end {
            self.run += 1;
            self.run_end += self
                .row
                .runs
                .get(self.run)
                .map_or(0, |run| run.bytes as usize);
        }
    }
}

fn cell_at(row: &RowFrame, col: u16) -> Option<(&str, CellStyle)> {
    painted_cells(row)?;
    let mut cells = Cells::new(row);
    while cells.col < col && !cells.done() {
        cells.step();
    }
    if cells.done() && cells.col <= col {
        // The dropped blank written back re-arms a wrap on a row that ended in one.
        return Some((" ", CellStyle::default()));
    }
    if cells.col != col {
        return None;
    }
    let (text, _, style) = cells.peek();
    Some((text, style))
}

/// Leading with a reset makes it independent of what preceded it; a difference
/// would need an "off" code per attribute, and a missed one smears down the row.
fn write_sgr<W: Write>(output: &mut W, style: &CellStyle) -> io::Result<()> {
    output.write_all(b"\x1b[0")?;
    for (flag, code) in [
        (StyleAttrs::BOLD, ";1"),
        (StyleAttrs::FAINT, ";2"),
        (StyleAttrs::ITALIC, ";3"),
        (StyleAttrs::BLINK, ";5"),
        (StyleAttrs::INVERSE, ";7"),
        (StyleAttrs::INVISIBLE, ";8"),
        (StyleAttrs::STRIKETHROUGH, ";9"),
        (StyleAttrs::OVERLINE, ";53"),
    ] {
        if style.attrs.contains(flag) {
            output.write_all(code.as_bytes())?;
        }
    }
    let underline = match style.underline {
        UnderlineStyle::None => "",
        UnderlineStyle::Single => ";4",
        // ECMA-48 assigns 21 to a double underline but xterm and a long tail of
        // emulators read it as SGR 22, which after the leading reset unsets bold.
        UnderlineStyle::Double => ";4:2",
        UnderlineStyle::Curly => ";4:3",
        UnderlineStyle::Dotted => ";4:4",
        UnderlineStyle::Dashed => ";4:5",
    };
    output.write_all(underline.as_bytes())?;
    write_color(output, style.fg, 38)?;
    write_color(output, style.bg, 48)?;
    write_color(output, style.underline_color, 58)?;
    output.write_all(b"m")
}

/// Palette indices are emitted as indices (`38;5;n`), never expanded to RGB:
/// the index must resolve against the *user's* palette, not the server's.
fn write_color<W: Write>(output: &mut W, color: StyleColor, selector: u8) -> io::Result<()> {
    match color {
        StyleColor::Default => Ok(()),
        StyleColor::Palette(index) => write!(output, ";{selector};5;{index}"),
        StyleColor::Rgb(r, g, b) => write!(output, ";{selector};2;{r};{g};{b}"),
    }
}

/// Unbounded retry with no feedback is indistinguishable from a hang.
pub struct StatusLine {
    /// The row `clear` owes an erase to: a resize between the two would erase a
    /// row the session owns and strand the indicator on the one it drew.
    shown: Option<GridSize>,
}

impl StatusLine {
    #[must_use]
    pub const fn new() -> Self {
        Self { shown: None }
    }

    #[must_use]
    pub const fn is_shown(&self) -> bool {
        self.shown.is_some()
    }

    /// DECSC/DECRC would clobber the one saved-cursor slot the remote
    /// application is entitled to, and this row is redrawn once a second.
    pub fn show<W: Write>(
        &mut self,
        output: &mut W,
        size: GridSize,
        cursor: Option<(u16, u16)>,
        elapsed: Duration,
        dropped: bool,
    ) -> io::Result<()> {
        let mut text = format!(
            "[brd] disconnected {}s ago \u{2014} Ctrl-] . to quit",
            elapsed.as_secs()
        );
        if dropped {
            text.push_str(" \u{2014} input buffer full, keystrokes dropped");
        }
        write!(output, "\x1b[{};1H", size.rows)?;
        output.write_all(b"\x1b[0m\x1b[7m")?;
        let mut encoded = [0_u8; 4];
        for character in text.chars().take(usize::from(size.cols)) {
            output.write_all(character.encode_utf8(&mut encoded).as_bytes())?;
        }
        output.write_all(b"\x1b[0m\x1b[K")?;
        write_cup(output, cursor)?;
        output.flush()?;
        self.shown = Some(size);
        Ok(())
    }

    /// The row underneath comes back with the caller's repaint, not with this.
    pub fn clear<W: Write>(
        &mut self,
        output: &mut W,
        cursor: Option<(u16, u16)>,
    ) -> io::Result<()> {
        let Some(size) = self.shown.take() else {
            return Ok(());
        };
        write!(output, "\x1b[{};1H", size.rows)?;
        output.write_all(b"\x1b[0m\x1b[K")?;
        write_cup(output, cursor)?;
        output.flush()
    }
}

impl Default for StatusLine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use braid_proto::{
        MIN_DATAGRAM_FRAME, RowUpdate, ServerMessage, StyleRun, Version, encode_screen_parts,
    };

    /// Bytes of length an encoded frame carries in front of its payload.
    const PREFIX: usize = 4;

    /// One column of a table-driven case: literal sequences or row texts.
    type Strs = &'static [&'static str];
    /// Screen modes, screen kitty flags, passthrough, sequences the exit owes,
    /// sequences it must leave alone.
    type TeardownCase = (&'static [usize], u8, &'static [u8], Strs, Strs);
    /// Rows before, the band, the row the delta names, rows after, the region
    /// sequence, and the rows that must not be repainted.
    type BandCase = (
        Strs,
        ScrollBand,
        (u16, &'static str),
        Strs,
        &'static str,
        Strs,
    );
    /// Why the model stopped describing the terminal, how to retire it, the
    /// grid the next screen names, its predictions, and whether it is confirmed.
    type RetiredCase = (&'static str, fn(&mut Screen), GridSize, Predictions, bool);

    /// A whole screen in one piece; rows are positional.
    fn whole(header: ScreenHeader, rows: Vec<RowFrame>) -> ScreenPart {
        ScreenPart::Head {
            header,
            base: None,
            scroll: None,
            pieces: 1,
            rows: rows
                .into_iter()
                .enumerate()
                .map(|(row, frame)| RowSpan {
                    row: u16::try_from(row).expect("a short screen"),
                    chunk: false,
                    col: 0,
                    byte: 0,
                    clear_tail: false,
                    frame,
                })
                .collect(),
        }
    }

    fn on_base(
        header: ScreenHeader,
        base: ScreenVersion,
        scroll: Option<ScrollBand>,
        rows: Vec<RowSpan>,
    ) -> ScreenPart {
        ScreenPart::Head {
            header,
            base: Some(base),
            scroll,
            pieces: 1,
            rows,
        }
    }

    fn header(size: GridSize) -> ScreenHeader {
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

    fn at(size: GridSize, version: ScreenVersion) -> ScreenHeader {
        ScreenHeader {
            version,
            ..header(size)
        }
    }

    /// A row of narrow characters, where columns and characters agree.
    fn plain(text: &str) -> RowFrame {
        RowFrame {
            cells: u16::try_from(text.chars().count()).expect("a short row"),
            text: text.into(),
            runs: Vec::new(),
        }
    }

    fn run(cells: u16, bytes: u32, style: CellStyle) -> StyleRun {
        StyleRun {
            cells,
            bytes,
            style,
        }
    }

    fn red() -> CellStyle {
        CellStyle {
            bg: StyleColor::Palette(1),
            ..CellStyle::default()
        }
    }

    fn row(index: u16, text: &str) -> RowSpan {
        RowSpan {
            row: index,
            chunk: false,
            col: 0,
            byte: 0,
            clear_tail: false,
            frame: plain(text),
        }
    }

    /// Both offsets are boundaries of the row the span lands on, because a
    /// style run is the only place either one is known.
    fn span(index: u16, col: u16, byte: u32, frame: RowFrame, clear_tail: bool) -> RowSpan {
        RowSpan {
            row: index,
            chunk: false,
            col,
            byte,
            clear_tail,
            frame,
        }
    }

    /// The shape every row has once the encoder dropped its trailing blanks.
    fn trimmed(text: &str, cells: u16) -> RowFrame {
        RowFrame {
            cells,
            text: text.into(),
            runs: Vec::new(),
        }
    }

    /// A styled prefix and an unstyled tail, which is what makes a partial span
    /// placeable at all.
    fn styled(text: &str, cells: u16, prefix: (u16, u32)) -> RowFrame {
        RowFrame {
            cells,
            text: text.into(),
            runs: vec![run(prefix.0, prefix.1, red())],
        }
    }

    fn piece_head(
        size: GridSize,
        version: ScreenVersion,
        base: Option<ScreenVersion>,
        pieces: u16,
        rows: Vec<RowSpan>,
    ) -> ScreenPart {
        ScreenPart::Head {
            header: at(size, version),
            base,
            scroll: None,
            pieces,
            rows,
        }
    }

    fn piece_tail(
        version: ScreenVersion,
        pieces: u16,
        index: u16,
        rows: Vec<RowSpan>,
    ) -> ScreenPart {
        ScreenPart::Tail {
            generation: Generation::initial(),
            version,
            pieces,
            index,
            rows,
        }
    }

    fn feed(
        screen: &mut Screen,
        output: &mut Vec<u8>,
        part: ScreenPart,
        terminal_rows: u16,
    ) -> Result<Option<Assembled>, PartMismatch> {
        screen
            .part(output, part, terminal_rows, Predictions::Settled)
            .expect("a piece renders")
    }

    /// Render one whole screen and return what the terminal was sent.
    fn paint_head(screen: &mut Screen, header: ScreenHeader, rows: Vec<RowFrame>) -> String {
        let terminal_rows = header.size.rows;
        let mut output = Vec::new();
        let assembled = feed(screen, &mut output, whole(header, rows), terminal_rows)
            .expect("a whole screen applies");
        assert!(assembled.is_some(), "one piece is a whole screen");
        String::from_utf8(output).expect("rendered output is UTF-8")
    }

    fn paint(screen: &mut Screen, size: GridSize, rows: Vec<RowFrame>) -> String {
        paint_head(screen, header(size), rows)
    }

    /// The version a second screen carries; the first is what it names as base.
    fn next() -> ScreenVersion {
        ScreenVersion::initial().next()
    }

    /// The screen after the one [`paint`] left behind.
    fn repaint(screen: &mut Screen, size: GridSize, rows: Vec<RowFrame>) -> String {
        paint_head(screen, at(size, next()), rows)
    }

    /// A delta against the screen [`paint`] left behind.
    fn delta(size: GridSize, scroll: Option<ScrollBand>, rows: Vec<RowSpan>) -> ScreenPart {
        on_base(at(size, next()), ScreenVersion::initial(), scroll, rows)
    }

    fn assembled(version: ScreenVersion) -> Assembled {
        Assembled {
            generation: Generation::initial(),
            version,
            next_off: ByteOff::zero(),
        }
    }

    fn rows_of(screen: &Screen) -> Vec<String> {
        screen
            .confirmed()
            .expect("a confirmed screen")
            .rows
            .iter()
            .map(|row| row.text.clone())
            .collect()
    }

    /// A row too wide for one datagram: `runs` style runs of ten columns each.
    /// One style throughout, so a joined row that lost or reordered a chunk
    /// cannot look contiguous; true colour because only a twenty-byte run
    /// overruns a piece at these widths.
    fn wide_row(runs: usize) -> RowFrame {
        let mut text = String::with_capacity(runs * 10);
        for index in 0..runs {
            let glyph = char::from(b'a' + u8::try_from(index % 26).expect("a letter"));
            for _ in 0..10 {
                text.push(glyph);
            }
        }
        RowFrame {
            cells: u16::try_from(runs * 10).expect("a wide row"),
            text,
            runs: (0..runs).map(|_| run(10, 10, truecolour())).collect(),
        }
    }

    /// The widest a style run encodes: three explicit RGB colours.
    fn truecolour() -> CellStyle {
        CellStyle {
            fg: StyleColor::Rgb(1, 2, 3),
            bg: StyleColor::Rgb(4, 5, 6),
            underline_color: StyleColor::Rgb(7, 8, 9),
            ..CellStyle::default()
        }
    }

    /// Cut a whole screen the way the server does and decode the pieces the way
    /// the client sees them: the real encoder and the real wire.
    fn cut(header: &ScreenHeader, rows: &[RowFrame]) -> Vec<ScreenPart> {
        let named = rows.iter().enumerate().map(|(row, frame)| {
            RowUpdate::whole(u16::try_from(row).expect("a short screen"), frame)
        });
        encode_screen_parts(header, None, None, named, MIN_DATAGRAM_FRAME)
            .expect("a screen that fits once it is cut")
            .iter()
            .map(|frame| {
                assert!(
                    frame.len() <= MIN_DATAGRAM_FRAME,
                    "a piece of {} bytes does not fit the path",
                    frame.len()
                );
                match ServerMessage::decode(&frame[PREFIX..], Version::LOCAL)
                    .expect("a piece this encoder wrote")
                {
                    ServerMessage::Screen { part } => part,
                    other => panic!("a piece is not a screen: {other:?}"),
                }
            })
            .collect()
    }

    /// A writer that refuses one exact sequence and records the rest.
    struct Flaky {
        seen: Vec<u8>,
        refuse: &'static [u8],
    }

    impl Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf == self.refuse {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.seen.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Walking characters and columns together would draw a space for the
    /// trailing half of every wide glyph; a combining mark belongs to the cell
    /// before it, so a run of one cell can be several characters wide.
    #[test]
    fn a_style_run_ends_where_the_cells_it_names_end() {
        for (cols, frame, inside, after) in [
            (
                8,
                RowFrame {
                    text: "\u{4f60}\u{597d}ok".into(),
                    runs: vec![run(4, 6, red())],
                    cells: 6,
                },
                "\u{4f60}\u{597d}",
                "ok",
            ),
            (
                4,
                RowFrame {
                    text: "e\u{301}x".into(),
                    runs: vec![run(1, 3, red())],
                    cells: 2,
                },
                "e\u{301}",
                "x",
            ),
        ] {
            let rendered = paint(
                &mut Screen::default(),
                GridSize { cols, rows: 1 },
                vec![frame],
            );
            assert_eq!(rendered.matches(inside).count(), 1, "{rendered:?}");
            let rest = &rendered[rendered.find(";48;5;1").expect("background colour")..];
            assert!(
                rest.find("\x1b[0m").expect("the run ends")
                    < rest.find(after).expect("the cells it does not cover"),
                "the run must end before the cells it does not cover: {rendered:?}"
            );
        }
    }

    /// `\x1b[K` paints with the *current* background, so the erase a shortened
    /// row still owes is owed under a reset.
    #[test]
    fn a_coloured_row_that_got_shorter_leaves_no_tail() {
        let size = GridSize { cols: 8, rows: 1 };
        let mut screen = Screen::default();
        paint(
            &mut screen,
            size,
            vec![RowFrame {
                text: "hihihihi".into(),
                runs: vec![run(8, 8, red())],
                cells: 8,
            }],
        );

        let rendered = paint_head(
            &mut screen,
            at(size, ScreenVersion::initial().next()),
            vec![RowFrame {
                text: "hi".into(),
                runs: vec![run(2, 2, red())],
                cells: 8,
            }],
        );
        let erase = rendered
            .find("\x1b[K")
            .expect("the shortened row is erased");
        assert!(
            rendered[..erase].ends_with("\x1b[0m"),
            "the erase is written under a reset style: {rendered:?}"
        );
    }

    /// A ZWJ family is two columns to libghostty and six to this side's table,
    /// so no column can be placed and the row is repainted from column one.
    #[test]
    fn a_row_whose_widths_do_not_add_up_is_repainted_from_column_one() {
        let size = GridSize { cols: 3, rows: 1 };
        let family = |tail: &str| RowFrame {
            text: format!("\u{1f468}\u{200d}\u{1f469}{tail}"),
            runs: vec![run(2, 11, red())],
            cells: 3,
        };
        let mut screen = Screen::default();
        paint(&mut screen, size, vec![family("x")]);

        let rendered = repaint(&mut screen, size, vec![family("y")]);
        let erase = rendered.find("\x1b[K").expect("the row is repainted whole");
        assert!(
            rendered[..erase].ends_with("\x1b[1;1H\x1b[0m"),
            "a row no column of can be placed is painted from column one: {rendered:?}"
        );
        let colour = rendered.find(";48;5;1").expect("background colour");
        assert!(
            erase < colour,
            "erase must precede any background: {rendered:?}"
        );
    }

    #[test]
    fn styles_are_emitted_once_per_run() {
        let rendered = paint(
            &mut Screen::default(),
            GridSize { cols: 4, rows: 1 },
            vec![RowFrame {
                text: "aabb".into(),
                runs: vec![
                    run(2, 2, red()),
                    run(
                        2,
                        2,
                        CellStyle {
                            attrs: StyleAttrs::BOLD,
                            ..CellStyle::default()
                        },
                    ),
                ],
                cells: 4,
            }],
        );
        assert_eq!(rendered.matches("\x1b[0;48;5;1m").count(), 1);
        assert_eq!(rendered.matches("\x1b[0;1m").count(), 1);
    }

    #[test]
    fn modes_are_restated_once_and_then_only_when_they_change() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 4, rows: 1 };
        let version = ScreenVersion::initial();
        let mut first = header(size);
        first.modes.set(13, true); // 1049
        let rendered = paint_head(&mut screen, first, vec![RowFrame::default()]);
        assert!(rendered.contains("\x1b[?1049h"));
        assert!(rendered.contains("\x1b[?2004l"));

        let mut second = at(size, version.next());
        second.modes.set(13, true);
        let rendered = paint_head(&mut screen, second, vec![RowFrame::default()]);
        assert!(!rendered.contains("\x1b[?1049"), "{rendered:?}");

        // A replaced transport may have dropped mode changes on the floor.
        screen.invalidate();
        let mut third = at(size, version.next().next());
        third.modes.set(13, true);
        let rendered = paint_head(&mut screen, third, vec![RowFrame::default()]);
        assert!(rendered.contains("\x1b[?1049h"), "{rendered:?}");
    }

    /// The first repaint after a reconnect is where a title, a bell and a
    /// keyboard stack carried only by passthrough would be lost permanently.
    /// The byte stream is the only witness for a title set after the last
    /// screen, which is what the next screen's diff is taken against.
    #[test]
    fn a_screen_restates_the_sticky_state_the_terminal_is_not_already_holding() {
        let size = GridSize { cols: 4, rows: 1 };
        let sticky = |bell| StickyState {
            title: Some("build".into()),
            kitty_keyboard: 3,
            bell,
            ..StickyState::default()
        };
        for (passthrough, restated) in [(&b""[..], false), (b"\x1b]0;make: *** \x07", true)] {
            let mut screen = Screen::default();
            let mut first = header(size);
            first.sticky = sticky(true);
            let rendered = paint_head(&mut screen, first, vec![RowFrame::default()]);
            for owed in ["\x1b]2;build\x1b\\", "\x1b[=3;1u", "\u{7}"] {
                assert!(rendered.contains(owed), "{owed:?} in {rendered:?}");
            }

            screen.observe(passthrough);
            let mut second = at(size, next());
            second.sticky = sticky(false);
            let rendered = paint_head(&mut screen, second, vec![RowFrame::default()]);
            assert_eq!(
                rendered.contains("\x1b]2;build\x1b\\"),
                restated,
                "{rendered:?}"
            );
            assert!(!rendered.contains("\x1b[=3;1u"), "{rendered:?}");
            // A bell is an event rather than state: it must not ring again.
            assert!(!rendered.contains('\u{7}'), "{rendered:?}");
        }
    }

    /// Leaving without a reset hands the user a shell answering keystrokes with
    /// mouse escapes; autowrap is the terminal's own default, whoever lit it.
    #[test]
    fn teardown_resets_the_union_of_what_a_repaint_and_the_stream_lit() {
        let size = GridSize { cols: 4, rows: 1 };
        let cases: [TeardownCase; 3] = [
            (
                &[13, 3, 1],
                1,
                b"",
                &["\x1b[?1049l", "\x1b[?1000l", "\x1b[=0;1u", "\x1b[?25h"],
                &["\x1b[?7l"],
            ),
            // `vim` on a session that never disconnected: no repaint, ever.
            (
                &[],
                0,
                b"\x1b[?1049h\x1b[?1002h\x1b[?2004h\x1b[?7h",
                &["\x1b[?1049l", "\x1b[?1002l", "\x1b[?2004l"],
                &["\x1b[?7l"],
            ),
            (
                &[3],
                0,
                b"\x1b[?1049h\x1b[>5u",
                &["\x1b[?1000l", "\x1b[?1049l", "\x1b[=0;1u"],
                &[],
            ),
        ];
        for (modes, kitty, stream, reset, kept) in cases {
            let mut screen = Screen::default();
            if !modes.is_empty() || kitty != 0 {
                let mut frame = header(size);
                for &index in modes {
                    frame.modes.set(index, true);
                }
                frame.sticky.kitty_keyboard = kitty;
                paint_head(&mut screen, frame, vec![RowFrame::default()]);
            }
            screen.observe(stream);

            let mut output = Vec::new();
            screen.teardown(&mut output).unwrap();
            assert!(output.ends_with(RESET_TAIL), "{output:?}");
            let rendered = String::from_utf8(output).unwrap();
            for expected in reset {
                assert!(rendered.contains(expected), "{expected:?} in {rendered:?}");
            }
            for forbidden in kept {
                assert!(
                    !rendered.contains(forbidden),
                    "{forbidden:?} in {rendered:?}"
                );
            }
        }
    }

    /// `RawMode::drop` restores termios and nothing else.
    #[test]
    fn teardown_resets_a_terminal_no_screen_ever_reached() {
        let mut output = Vec::new();
        Screen::default().teardown(&mut output).unwrap();
        assert_eq!(output, RESET_TAIL);
    }

    /// An unset shape sends the reset rather than a steady block, because the
    /// user's own cursor configuration is the fallback.
    #[test]
    fn the_cursor_shape_and_blink_reach_the_terminal() {
        let size = GridSize { cols: 4, rows: 1 };
        for (shape, blinking, expected) in [
            (CursorShape::Bar, true, "\x1b[5 q"),
            (CursorShape::Unset, false, "\x1b[0 q"),
        ] {
            let mut frame = header(size);
            frame.cursor_shape = shape;
            frame.cursor_blinking = blinking;
            let rendered = paint_head(&mut Screen::default(), frame, vec![RowFrame::default()]);
            assert!(rendered.contains(expected), "{rendered:?}");
            assert_eq!(rendered.matches(" q").count(), 1, "{rendered:?}");
            assert!(rendered.contains("\x1b[?25h"), "{rendered:?}");
        }
    }

    #[test]
    fn a_delta_on_the_confirmed_screen_repaints_only_its_rows() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 4, rows: 2 };
        paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);

        let mut output = Vec::new();
        let mut header = at(size, ScreenVersion::initial().next());
        header.cursor = Some((1, 1));
        feed(
            &mut screen,
            &mut output,
            on_base(header, ScreenVersion::initial(), None, vec![row(1, "cccc")]),
            size.rows,
        )
        .expect("delta should apply")
        .expect("a single piece completes the screen");
        let confirmed = screen.confirmed().expect("a confirmed screen");
        assert_eq!(confirmed.version, Some(ScreenVersion::initial().next()));
        assert_eq!(confirmed.rows[0].text, "aaaa");
        assert_eq!(confirmed.rows[1].text, "cccc");
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("cccc"));
        assert!(
            !rendered.contains("aaaa"),
            "clean rows must not be repainted"
        );
        // `CAN` is a cell on libghostty when there is nothing to cancel.
        assert!(rendered.starts_with("\x1b\\"), "{rendered:?}");
        assert!(!rendered.contains('\u{18}'), "{rendered:?}");
    }

    /// Nothing a piece names is clamped: acknowledging a screen this client
    /// could not paint has the server clear damage for a row still showing
    /// something else, which is permanent corruption with no error path.
    #[test]
    fn a_piece_that_does_not_fit_is_refused_and_leaves_the_screen_alone() {
        let size = GridSize { cols: 4, rows: 2 };
        let band = ScrollBand {
            top: 0,
            bottom: 2,
            lines: 1,
        };
        // The last is a grid taller than the terminal — the window between a
        // local shrink and the resize answering it — which clamps the region.
        let cases: [(PartMismatch, bool, u16, ScreenPart); 5] = [
            (
                PartMismatch::OutsideGrid,
                false,
                size.rows,
                whole(
                    header(size),
                    vec![plain("aaaa"), plain("bbbb"), plain("cccc")],
                ),
            ),
            (
                PartMismatch::NoScreen,
                false,
                size.rows,
                delta(size, None, Vec::new()),
            ),
            (
                PartMismatch::WrongBase,
                true,
                size.rows,
                on_base(at(size, next()), next().next(), None, Vec::new()),
            ),
            (
                PartMismatch::OutsideGrid,
                true,
                size.rows,
                delta(size, None, vec![row(5, "dddd")]),
            ),
            (
                PartMismatch::Unscrollable,
                true,
                1,
                delta(size, Some(band), vec![row(1, "eeee")]),
            ),
        ];
        for (mismatch, painted, terminal_rows, part) in cases {
            let mut screen = Screen::default();
            if painted {
                paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);
            }
            let mut output = Vec::new();
            assert_eq!(
                feed(&mut screen, &mut output, part, terminal_rows),
                Err(mismatch)
            );
            assert!(output.is_empty(), "{mismatch:?} wrote {output:?}");
            assert_eq!(
                screen.confirmed().and_then(|screen| screen.version),
                painted.then(ScreenVersion::initial),
                "a refused piece moved the version"
            );
        }

        let mut screen = Screen::default();
        paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);
        assert!(
            feed(
                &mut screen,
                &mut Vec::new(),
                delta(size, Some(band), vec![row(1, "eeee")]),
                size.rows,
            )
            .expect("the same band applies when the terminal holds the grid")
            .is_some(),
            "the band is refused for the terminal's height and nothing else"
        );
    }

    /// Almost nothing scrolls the whole viewport — `less` has a prompt, `vim` a
    /// status line — so a row outside the band must not move.
    #[test]
    fn a_scroll_band_moves_only_its_own_rows_and_restores_the_region() {
        let cases: [BandCase; 2] = [
            (
                &["aaa", "bbb", "ccc"],
                ScrollBand {
                    top: 0,
                    bottom: 3,
                    lines: 1,
                },
                (2, "ddd"),
                &["bbb", "ccc", "ddd"],
                "\x1b[1;3r\x1b[3;1H\x1bD",
                &["bbb", "ccc"],
            ),
            (
                &["aaa", "bbb", "ccc", "ddd"],
                ScrollBand {
                    top: 1,
                    bottom: 3,
                    lines: 1,
                },
                (2, "eee"),
                &["aaa", "ccc", "eee", "ddd"],
                "\x1b[2;3r\x1b[3;1H\x1bD",
                &["aaa", "ddd"],
            ),
        ];
        for (before, band, update, after, region, untouched) in cases {
            let size = GridSize {
                cols: 3,
                rows: u16::try_from(before.len()).expect("a short screen"),
            };
            let mut screen = Screen::default();
            paint(
                &mut screen,
                size,
                before.iter().copied().map(plain).collect(),
            );

            let mut output = Vec::new();
            feed(
                &mut screen,
                &mut output,
                delta(size, Some(band), vec![row(update.0, update.1)]),
                size.rows,
            )
            .expect("delta should apply")
            .expect("a single piece completes the screen");
            assert_eq!(rows_of(&screen), after);
            let rendered = String::from_utf8(output).unwrap();
            assert!(
                rendered.contains(region),
                "the region is the band and nothing else: {rendered:?}"
            );
            assert!(
                rendered.contains("\x1b[r"),
                "the full-screen region is restored: {rendered:?}"
            );
            assert!(!rendered.contains("\x1b[3J"), "ED 3 destroys scrollback");
            for text in untouched {
                assert!(
                    !rendered.contains(text),
                    "rows the scroll moved are not repainted: {rendered:?}"
                );
            }
            assert!(rendered.contains(update.1), "{rendered:?}");
        }
    }

    /// A scroll region outlives this client, so even a write that failed part
    /// way through moving the band still owes the restore.
    #[test]
    fn a_scroll_region_is_restored_even_when_the_band_could_not_be_written() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 3, rows: 3 };
        paint(
            &mut screen,
            size,
            vec![plain("aaa"), plain("bbb"), plain("ccc")],
        );
        let mut output = Flaky {
            seen: Vec::new(),
            refuse: b"\x1bD",
        };
        let confirmed = screen.confirmed.as_mut().expect("a confirmed screen");
        let band = ScrollBand {
            top: 0,
            bottom: 3,
            lines: 1,
        };
        assert!(
            write_scroll(&mut output, confirmed, band).is_err(),
            "the refused index sequence is reported"
        );
        let rendered = String::from_utf8(output.seen).expect("rendered output is UTF-8");
        assert!(
            rendered.ends_with("\x1b[r"),
            "a failed band still hands the terminal its whole screen back: {rendered:?}"
        );
    }

    /// The client writes the byte stream in chunks the session did not choose,
    /// so a sequence is routinely split across two of them; a DCS body is
    /// skipped whole rather than read as sequences of its own; and an `ESC`
    /// anything-else abandons a string, as the terminal reading these same
    /// bytes does. Whatever the shape, the exit still owes the reset.
    #[test]
    fn a_mode_the_byte_stream_lit_is_owed_a_reset_however_it_arrived() {
        for (why, chunks, owed) in [
            (
                "split across three writes",
                &[&b"text \x1b[?10"[..], b"49", b"h more text"][..],
                "\x1b[?1049l",
            ),
            (
                "behind a DCS body",
                &[&b"\x1bP+q544e;3236\x1b\\\x1b[?1000h"[..]][..],
                "\x1b[?1000l",
            ),
            (
                "behind an OSC the terminal would have abandoned",
                &[&b"\x1b]2;unfinished\x1b[?1049h"[..]][..],
                "\x1b[?1049l",
            ),
            (
                "a kitty stack entry set outright",
                &[&b"\x1b[=3;1u"[..]][..],
                "\x1b[=0;1u",
            ),
        ] {
            let mut screen = Screen::default();
            for chunk in chunks {
                screen.observe(chunk);
            }
            let mut output = Vec::new();
            screen.teardown(&mut output).unwrap();
            let rendered = String::from_utf8(output).unwrap();
            assert!(rendered.contains(owed), "{why}: {rendered:?}");
        }
    }

    /// A hostile stream must not grow the scanner by never terminating one.
    #[test]
    fn an_unterminated_sequence_cannot_grow_the_scanner() {
        let mut output = Vec::new();
        let mut screen = Screen::default();
        screen.observe(b"\x1b[?");
        for _ in 0..64 {
            screen.observe(&[b'1'; 4096]);
        }
        assert!(screen.observed.partial.len() <= SCAN_LIMIT);
        // A sequence dropped for its size does not derail the ones after it.
        screen.observe(b"h\x1b[?1000h");
        screen.teardown(&mut output).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("\x1b[?1000l"), "{rendered:?}");
    }

    /// A pop hands back the entry the last screen set.
    #[test]
    fn the_keyboard_stack_the_byte_stream_pushed_is_observed() {
        let mut screen = Screen::default();
        screen.observe(b"\x1b[>5u");
        assert_eq!(screen.observed.kitty, Some(5));
        screen.observe(b"\x1b[<u");
        assert_eq!(screen.observed.kitty, None);
    }

    /// A string ends where the terminal ends it, and the sequence hiding behind
    /// an early `ESC` is one the terminal acts on.
    #[test]
    fn a_title_is_taken_only_from_a_string_the_terminal_would_have_ended() {
        // The last two carry a mode behind the string, and it is still seen.
        for (stream, title, lit) in [
            (
                &b"\x1b]2;from a string terminator\x1b\\"[..],
                Some("from a string terminator"),
                false,
            ),
            (b"\x1b]0;from a bell\x07", Some("from a bell"), false),
            // A DCS body is skipped whole: its terminator ends the string
            // rather than a sequence of its own.
            (b"\x1bP+q544e;3236\x1b\\\x1b[?1000h", None, true),
            (b"\x1b]2;unfinished\x1b[?1049h", None, true),
        ] {
            let mut screen = Screen::default();
            screen.observe(stream);
            assert_eq!(screen.observed.title.as_deref(), title, "{stream:?}");
            assert_eq!(screen.observed.lit != ModeSet::empty(), lit, "{stream:?}");
        }
    }

    #[test]
    fn the_status_line_names_the_quit_key_and_restores_the_cursor() {
        let mut output = Vec::new();
        let mut status = StatusLine::new();
        let size = GridSize { cols: 80, rows: 24 };
        status
            .show(
                &mut output,
                size,
                Some((7, 3)),
                Duration::from_secs(47),
                false,
            )
            .unwrap();
        let rendered = String::from_utf8(std::mem::take(&mut output)).unwrap();
        assert!(rendered.contains("disconnected 47s ago"), "{rendered:?}");
        assert!(rendered.contains("Ctrl-] . to quit"));
        assert!(rendered.starts_with("\x1b[24;1H"), "{rendered:?}");
        // DECSC/DECRC would clobber the one saved-cursor slot the remote
        // application is entitled to, and this row is drawn once a second.
        assert!(
            !rendered.contains("\x1b7") && !rendered.contains("\x1b8"),
            "{rendered:?}"
        );
        assert!(rendered.ends_with("\x1b[4;8H"), "{rendered:?}");
        assert!(status.is_shown());

        // The row erased is the one drawn on, whatever the grid is now.
        status.clear(&mut output, Some((7, 3))).unwrap();
        let rendered = String::from_utf8(std::mem::take(&mut output)).unwrap();
        assert!(rendered.starts_with("\x1b[24;1H"), "{rendered:?}");
        assert!(!status.is_shown());
        // Clearing twice must not emit a second time.
        status.clear(&mut output, None).unwrap();
        assert!(output.is_empty());
    }

    /// The pending-input buffer is the one place this client throws a keystroke
    /// away, so the indicator says so rather than let it happen silently.
    #[test]
    fn the_status_line_says_when_input_is_being_dropped() {
        let mut output = Vec::new();
        let mut status = StatusLine::new();
        status
            .show(
                &mut output,
                GridSize {
                    cols: 120,
                    rows: 24,
                },
                None,
                Duration::from_secs(1),
                true,
            )
            .unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("keystrokes dropped"), "{rendered:?}");
    }

    /// The fast path and the per-byte path must be indistinguishable: a scanner
    /// that disagrees with itself loses a mode the terminal is left holding.
    #[test]
    fn skipping_a_run_of_text_sees_what_stepping_it_would_have() {
        let stream: &[u8] = b"plain text \x1b[?1049h more \x1b]2;title\x07 \
\x1b[?1000h\x1bP+q544e\x1b\\ tail \x1b[>5u\x1b\x1b[?2004h";
        let mut stepped = Observed::default();
        for byte in stream {
            stepped.step(*byte);
        }
        assert_ne!(stepped.lit, ModeSet::empty(), "the stream turned modes on");

        let mut fed = Observed::default();
        fed.feed(stream);
        assert_eq!(fed.lit, stepped.lit);
        assert_eq!(fed.title, stepped.title);
        assert_eq!(fed.kitty, stepped.kitty);
        assert!(fed.scan == stepped.scan);

        // Every split, because a chunk boundary is the one place a state that
        // the fast path carries across a call can be dropped.
        for split in 0..stream.len() {
            let mut halves = Observed::default();
            halves.feed(&stream[..split]);
            halves.feed(&stream[split..]);
            assert_eq!(halves.lit, stepped.lit, "split at {split}");
            assert_eq!(halves.title, stepped.title, "split at {split}");
            assert_eq!(halves.kitty, stepped.kitty, "split at {split}");
        }
    }

    /// A screen is acknowledged once every piece of it is in, whatever order
    /// they arrived in: never early, never for a cut that left a row uncovered,
    /// never again for a straggler, and never for a row the grid cannot hold.
    #[test]
    fn a_screen_is_acknowledged_once_every_piece_of_it_is_in() {
        let three = GridSize { cols: 4, rows: 3 };
        let two = GridSize { cols: 4, rows: 2 };
        let version = ScreenVersion::initial();
        // Why, the grid, each piece in arrival order with what it returns, the
        // rows the screen ends up holding, and whether it was acknowledged.
        let cases = [
            (
                "in order, then a straggling duplicate of the last piece",
                three,
                vec![
                    (
                        piece_head(three, version, None, 2, vec![row(0, "aaaa")]),
                        Ok(None),
                    ),
                    (
                        piece_tail(version, 2, 1, vec![row(1, "bbbb"), row(2, "cccc")]),
                        Ok(Some(assembled(version))),
                    ),
                    (piece_tail(version, 2, 1, vec![row(1, "bbbb")]), Ok(None)),
                ],
                &["aaaa", "bbbb", "cccc"][..],
                true,
            ),
            (
                "a tail that overtook the head, which is what names the grid",
                two,
                vec![
                    (piece_tail(version, 2, 1, vec![row(1, "bbbb")]), Ok(None)),
                    (
                        piece_head(two, version, None, 2, vec![row(0, "aaaa")]),
                        Ok(Some(assembled(version))),
                    ),
                ],
                &["aaaa", "bbbb"][..],
                true,
            ),
            (
                // A tail's rows were decoded with no grid to bound them, so
                // this is the only place that can refuse one.
                "a tail naming a row, and then a row width, past the grid",
                two,
                vec![
                    (
                        piece_head(two, version, None, 2, vec![row(0, "aaaa"), row(1, "bbbb")]),
                        Ok(None),
                    ),
                    (
                        piece_tail(version, 2, 1, vec![row(9, "cccc")]),
                        Err(PartMismatch::OutsideGrid),
                    ),
                    (
                        piece_tail(
                            version,
                            2,
                            1,
                            vec![span(0, 0, 0, trimmed("cccc", 9), false)],
                        ),
                        Err(PartMismatch::OutsideGrid),
                    ),
                ],
                &["aaaa", "bbbb"][..],
                false,
            ),
            (
                "a whole screen whose pieces between them never name row 2",
                three,
                vec![
                    (
                        piece_head(three, version, None, 2, vec![row(0, "aaaa")]),
                        Ok(None),
                    ),
                    (piece_tail(version, 2, 1, vec![row(1, "bbbb")]), Ok(None)),
                ],
                &["aaaa", "bbbb", ""][..],
                false,
            ),
        ];
        for (why, size, pieces, rows, acknowledged) in cases {
            let mut screen = Screen::default();
            let mut output = Vec::new();
            for (index, (part, expected)) in pieces.into_iter().enumerate() {
                assert_eq!(
                    feed(&mut screen, &mut output, part, size.rows),
                    expected,
                    "{why}: piece {index}"
                );
            }
            assert_eq!(rows_of(&screen), rows, "{why}");
            assert_eq!(
                screen.confirmed().expect("a confirmed screen").version,
                acknowledged.then_some(version),
                "{why}"
            );
            let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
            for text in rows.iter().filter(|text| !text.is_empty()) {
                assert!(rendered.contains(text), "{why}: {rendered:?}");
            }
        }
    }

    /// A lost piece costs its own rows and not the screen: the version stays
    /// where it was and the server keeps the damage it was never told about.
    #[test]
    fn a_screen_missing_a_piece_paints_what_arrived_and_confirms_nothing() {
        let size = GridSize { cols: 4, rows: 2 };
        let mut screen = Screen::default();
        paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);
        let mut output = Vec::new();
        assert_eq!(
            feed(
                &mut screen,
                &mut output,
                piece_head(
                    size,
                    next(),
                    Some(ScreenVersion::initial()),
                    2,
                    vec![row(0, "xxxx")],
                ),
                size.rows,
            ),
            Ok(None)
        );
        let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
        assert!(
            rendered.contains("xxxx"),
            "the rows that arrived are painted"
        );
        assert_eq!(rows_of(&screen), ["xxxx", "bbbb"]);
        assert_eq!(
            screen.confirmed().expect("a confirmed screen").version,
            Some(ScreenVersion::initial()),
            "an incomplete screen does not move the version"
        );
    }

    /// Abandoning an incomplete screen costs nothing: the rows already painted
    /// stay painted, and the server carries the damage for the lost version.
    #[test]
    fn a_newer_screen_abandons_an_incomplete_one_without_losing_its_rows() {
        let size = GridSize { cols: 3, rows: 3 };
        let mut screen = Screen::default();
        paint(
            &mut screen,
            size,
            vec![plain("aaa"), plain("bbb"), plain("ccc")],
        );
        let mut output = Vec::new();
        let base = ScreenVersion::initial();
        feed(
            &mut screen,
            &mut output,
            piece_head(size, base.next(), Some(base), 2, vec![row(0, "xxx")]),
            size.rows,
        )
        .expect("the head applies");

        let newer = base.next().next();
        assert_eq!(
            feed(
                &mut screen,
                &mut output,
                piece_head(size, newer, Some(base), 1, vec![row(1, "yyy")]),
                size.rows,
            ),
            Ok(Some(assembled(newer)))
        );
        assert_eq!(rows_of(&screen), ["xxx", "yyy", "ccc"]);
    }

    /// Every lost datagram is answered with a whole screen, so erasing each
    /// time is a grid of writes against a terminal already showing most of it.
    #[test]
    fn a_whole_screen_against_a_model_that_still_describes_the_terminal_writes_only_what_changed() {
        let size = GridSize { cols: 4, rows: 2 };
        let mut screen = Screen::default();
        let first = paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);
        assert!(
            first.contains("\x1b[2J\x1b[H"),
            "a screen with no model behind it erases: {first:?}"
        );

        let rendered = repaint(&mut screen, size, vec![plain("aaaa"), plain("cccc")]);
        assert!(
            !rendered.contains("\x1b[2J"),
            "the model still describes the terminal: {rendered:?}"
        );
        assert!(
            !rendered.contains("aaaa"),
            "an unchanged row costs nothing: {rendered:?}"
        );
        assert!(rendered.contains("cccc"), "{rendered:?}");
        assert_eq!(rows_of(&screen), ["aaaa", "cccc"]);
    }

    /// The diff is sound only while the rows this client holds still describe
    /// the terminal; each case below retires them for a different reason.
    #[test]
    fn a_model_that_stopped_describing_the_terminal_forces_the_erase_back() {
        let size = GridSize { cols: 4, rows: 2 };
        let cases: [RetiredCase; 5] = [
            (
                "passthrough wrote rows this model never saw",
                |screen| screen.observe(b"progress: 40%\r"),
                size,
                Predictions::Settled,
                true,
            ),
            (
                "an absorbed echo cannot answer for the passthrough before it",
                |screen| {
                    screen.observe(b"progress: 40%\r");
                    screen.observe(b"");
                },
                size,
                Predictions::Settled,
                true,
            ),
            (
                "a prediction drew a character the server never sent",
                |_| {},
                size,
                Predictions::Drawn,
                false,
            ),
            (
                "the grid moved, so the model indexes a screen that is gone",
                |_| {},
                GridSize { cols: 5, rows: 2 },
                Predictions::Settled,
                true,
            ),
            (
                "a replaced transport may have dropped what the session wrote",
                Screen::invalidate,
                size,
                Predictions::Settled,
                true,
            ),
        ];
        for (why, retire, grid, predictions, acknowledged) in cases {
            let mut screen = Screen::default();
            paint(&mut screen, size, vec![plain("aaaa"), plain("bbbb")]);
            retire(&mut screen);

            let mut output = Vec::new();
            let done = screen
                .part(
                    &mut output,
                    whole(at(grid, next()), vec![plain("aaaa"), plain("cccc")]),
                    grid.rows,
                    predictions,
                )
                .expect("a screen renders")
                .expect("a whole screen applies");
            assert_eq!(done.is_some(), acknowledged, "{why}");
            let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
            assert!(rendered.contains("\x1b[2J\x1b[H"), "{why}: {rendered:?}");
            assert!(
                rendered.contains("aaaa") && rendered.contains("cccc"),
                "{why}: every row is repainted over the erase: {rendered:?}"
            );
        }
    }

    /// A chunk is a fragment starting at a column nothing on the wire names, so
    /// a row is only a row once every chunk of it is in hand — joined in the
    /// order the encoder cut them, not the order the path delivered them.
    #[test]
    fn a_row_cut_across_pieces_is_painted_once_and_whole_in_piece_order() {
        // (grid columns, style runs in the wide row, least pieces, reversed)
        for (cols, runs, least, reversed) in [(400_u16, 40_usize, 3, false), (800, 80, 4, true)] {
            let size = GridSize { cols, rows: 2 };
            let wide = wide_row(runs);
            // Row 0, which is not the row the chunks join into: a paint that
            // forgot to put the cursor back cannot land here by coincidence.
            let mut head = header(size);
            head.cursor = Some((5, 0));
            let pieces = cut(&head, &[plain("aaaa"), wide.clone()]);
            assert!(
                pieces.len() >= least,
                "a {cols}-column row fit {} pieces",
                pieces.len()
            );

            let mut screen = Screen::default();
            let mut output = Vec::new();
            assert_eq!(
                feed(&mut screen, &mut output, pieces[0].clone(), size.rows),
                Ok(None),
                "the head completed a screen still missing pieces"
            );
            let mut rest: Vec<ScreenPart> = pieces[1..].to_vec();
            if reversed {
                rest.reverse();
            }
            let last = rest.len() - 1;
            for (index, part) in rest.into_iter().enumerate() {
                if index == last {
                    let painted =
                        String::from_utf8(output.clone()).expect("rendered output is UTF-8");
                    assert!(
                        !painted.contains(&wide.text[..10]),
                        "a chunk is not painted where it arrives"
                    );
                    assert_eq!(
                        screen.confirmed().expect("a confirmed screen").version,
                        None,
                        "a screen missing a chunk of a row is never assembled"
                    );
                }
                let done = feed(&mut screen, &mut output, part, size.rows)
                    .expect("a piece applies")
                    .is_some();
                assert_eq!(done, index == last, "piece {index} of {cols} columns");
            }

            let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
            assert!(
                rendered.contains(&wide.text),
                "the joined row reaches the terminal whole"
            );
            assert_eq!(
                rendered.matches("\x1b[2;1H").count(),
                1,
                "the cut row is painted once"
            );
            // The joined rows land inside the one frame the whole screen is,
            // and it ends where the header put the cursor.
            let text = rendered.find(&wide.text).expect("the joined row");
            let begin = rendered[..text]
                .rfind("\x1b[?2026h")
                .expect("a synchronized frame");
            assert!(
                rendered[..text]
                    .rfind("\x1b[?2026l")
                    .is_none_or(|end| end < begin),
                "the joined row is painted inside a frame still open"
            );
            assert!(
                rendered.ends_with("\x1b[1;6H\x1b[?2026l"),
                "the frame ends at the cursor the header named: {:?}",
                rendered.get(rendered.len().saturating_sub(32)..)
            );
            assert_eq!(rows_of(&screen)[1], wide.text);
        }
    }

    /// A screen is one synchronized frame however many pieces it was cut into:
    /// ending it between pieces publishes a screen half of which had not
    /// arrived, and costs a `write(2)` and a terminal wakeup per piece besides.
    #[test]
    fn a_screen_is_one_synchronized_frame_whatever_it_was_cut_into() {
        let size = GridSize { cols: 800, rows: 2 };
        let pieces = cut(&header(size), &[plain("aaaa"), wide_row(60)]);
        assert!(pieces.len() > 2, "a screen of one piece proves nothing");
        let last = pieces.len() - 1;

        let mut screen = Screen::default();
        let mut output = Vec::new();
        for part in &pieces[..last] {
            assert!(
                feed(&mut screen, &mut output, part.clone(), size.rows)
                    .expect("a piece applies")
                    .is_none(),
                "a screen missing a piece is not assembled"
            );
        }
        let held = String::from_utf8(output.clone()).expect("rendered output is UTF-8");
        assert_eq!(
            held.matches("\x1b[?2026h").count(),
            1,
            "one frame for the pieces so far"
        );
        assert_eq!(
            held.matches("\x1b[?2026l").count(),
            0,
            "a screen still arriving does not publish itself"
        );

        assert!(
            feed(&mut screen, &mut output, pieces[last].clone(), size.rows)
                .expect("the last piece applies")
                .is_some(),
            "every piece is in"
        );
        let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
        assert_eq!(
            rendered.matches("\x1b[?2026h").count(),
            1,
            "{} pieces, one frame",
            pieces.len()
        );
        assert_eq!(
            rendered.matches("\x1b[?2026l").count(),
            1,
            "the frame ends once, when the screen is whole"
        );
        assert!(rendered.ends_with("\x1b[?2026l"), "and ends it last");

        // The flush is what bounds an open frame: a piece that never arrives
        // must not leave the terminal holding one nothing will ever end.
        let mut unfinished = Screen::default();
        let mut abandoned = Vec::new();
        for part in &pieces[..last] {
            feed(&mut unfinished, &mut abandoned, part.clone(), size.rows)
                .expect("a piece applies");
        }
        unfinished
            .end_frame(&mut abandoned)
            .expect("the frame closes on demand");
        assert!(
            abandoned.ends_with(b"\x1b[?2026l"),
            "a flush closes the frame a lost piece left open"
        );
    }

    /// Each chunk fits the grid on its own, so the only place a row that does
    /// not can be caught is where they are joined.
    #[test]
    fn a_chunked_row_wider_than_the_grid_is_dropped_and_never_acknowledged() {
        let size = GridSize { cols: 400, rows: 2 };
        // Six hundred columns against a four-hundred-column grid, cut into
        // chunks of 370 and 230: every chunk passes, their sum does not.
        let wide = wide_row(60);
        let pieces = cut(&header(size), &[plain("aaaa"), wide.clone()]);
        assert!(pieces.len() >= 3, "the row was not cut");

        let mut screen = Screen::default();
        let mut output = Vec::new();
        for (index, part) in pieces.iter().cloned().enumerate() {
            assert_eq!(
                feed(&mut screen, &mut output, part, size.rows),
                Ok(None),
                "piece {index} acknowledged a screen holding a row it could not join"
            );
        }
        let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
        assert_eq!(
            rendered.matches("\x1b[2;1H").count(),
            0,
            "a row wider than the grid is never painted"
        );
        assert_eq!(
            screen.confirmed().expect("a confirmed screen").version,
            None
        );
        assert_eq!(
            rows_of(&screen)[1],
            "",
            "the model does not hold a row the client refused"
        );
    }

    /// The columns before a span are the client's own: repainting from column
    /// one would cost the whole row to say a few cells. `\x1b[K` past a span
    /// still reaching the last column wipes cells the server never named, so
    /// only `clear_tail` erases.
    #[test]
    fn a_partial_span_patches_its_own_columns_and_erases_only_on_clear_tail() {
        let size = GridSize { cols: 8, rows: 1 };
        for (text, clear_tail, held, painted, erases) in [
            (
                "XY",
                true,
                "abcdXY",
                "\x1b[1;5H\x1b[0mXY\x1b[0m\x1b[K",
                true,
            ),
            ("XYZW", false, "abcdXYZW", "\x1b[1;5H\x1b[0mXYZW", false),
        ] {
            let mut screen = Screen::default();
            paint(&mut screen, size, vec![styled("abcdefgh", 8, (4, 4))]);

            let mut output = Vec::new();
            feed(
                &mut screen,
                &mut output,
                delta(
                    size,
                    None,
                    vec![span(0, 4, 4, trimmed(text, 4), clear_tail)],
                ),
                size.rows,
            )
            .expect("the delta applies")
            .expect("a single piece completes the screen");
            assert_eq!(rows_of(&screen), [held]);
            let rendered = String::from_utf8(output).expect("rendered output is UTF-8");
            assert!(
                rendered.contains(painted),
                "the span is written at the column it named: {rendered:?}"
            );
            assert_eq!(
                rendered.contains("\x1b[K"),
                erases,
                "only a shortened row is erased, and under a reset: {rendered:?}"
            );
            assert!(
                !rendered.contains("abcd"),
                "the columns before the span are never rewritten: {rendered:?}"
            );
        }
    }

    /// `write_sgr` is thirty bytes for a true-colour run, so a 200-column row
    /// reissued for one cell is most of a 30 Hz repaint's local write budget.
    #[test]
    fn an_intra_row_diff_writes_only_the_columns_that_changed() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 8, rows: 1 };
        paint(&mut screen, size, vec![plain("abcdefgh")]);

        let rendered = repaint(&mut screen, size, vec![plain("abXdefgh")]);
        assert_eq!(rows_of(&screen), ["abXdefgh"]);
        assert!(
            rendered.contains("\x1b[1;3H\x1b[0mX"),
            "the one changed cell is written at its own column: {rendered:?}"
        );
        assert!(
            !rendered.contains("defgh"),
            "the columns after it are left alone: {rendered:?}"
        );
        assert!(
            !rendered.contains("\x1b[K"),
            "a row that did not get shorter erases nothing: {rendered:?}"
        );
    }

    /// A diff that walked characters as columns lands every write two columns
    /// early per wide glyph before it, which is how `"你好世界tail"` came back
    /// as `"你 好 世 界 tail"`.
    #[test]
    fn an_intra_row_diff_of_a_wide_row_lands_on_the_session_s_columns() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 12, rows: 1 };
        // Styled because a run's `cells` is the only checkpoint a row has.
        let row = |fourth| RowFrame {
            text: format!("\u{4f60}\u{597d}\u{4e16}{fourth}tail"),
            runs: vec![run(8, 12, red())],
            cells: 12,
        };
        paint(&mut screen, size, vec![row('\u{754c}')]);

        let rendered = repaint(&mut screen, size, vec![row('\u{583a}')]);
        assert_eq!(rows_of(&screen), ["\u{4f60}\u{597d}\u{4e16}\u{583a}tail"]);
        assert_eq!(
            rendered,
            "\x1b\\\x1b[?2026h\x1b[1;7H\x1b[0;48;5;1m\u{583a}\x1b[0m\x1b[2 q\x1b[?25h\
             \x1b[1;1H\x1b[?2026l",
            "the fourth wide glyph is column seven, not column four, and it is \
             the only cell written"
        );
    }

    /// A screen cannot restate an OSC, so the ones the byte stream carried ride
    /// along with it and are replayed once the rows are on.
    #[test]
    fn deferred_sequences_are_replayed_in_order_and_terminated_with_st() {
        let mut screen = Screen::default();
        let size = GridSize { cols: 4, rows: 1 };
        let mut frame = header(size);
        frame.sticky = StickyState {
            deferred: vec!["52;c;aGk=".into(), "133;A".into()],
            ..StickyState::default()
        };
        let rendered = paint_head(&mut screen, frame, vec![plain("abcd")]);
        let clipboard = rendered
            .find("\x1b]52;c;aGk=\x1b\\")
            .expect("the clipboard write is replayed");
        let mark = rendered
            .find("\x1b]133;A\x1b\\")
            .expect("the prompt mark is replayed");
        assert!(clipboard < mark, "in the order they were carried");
        assert!(
            rendered.find("abcd").is_some_and(|row| row < clipboard),
            "and after the screen they could not be part of: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{7}'),
            "always ST, never BEL: {rendered:?}"
        );
    }

    /// A cursor in the last column with a wrap owed and one that merely arrived
    /// there put the next character in different rows, and `CUP` clears the flag.
    #[test]
    fn a_pending_wrap_is_re_armed_by_rewriting_the_cell_under_the_cursor() {
        let size = GridSize { cols: 4, rows: 1 };
        let painted = |pending| {
            let mut frame = header(size);
            frame.cursor = Some((3, 0));
            frame.sticky = StickyState {
                pending_wrap: pending,
                ..StickyState::default()
            };
            paint_head(&mut Screen::default(), frame, vec![plain("abcd")])
        };

        let armed = painted(true);
        assert!(
            armed.ends_with("\x1b[1;4H\x1b[0md\x1b[?2026l"),
            "the last column is written again after the cursor lands: {armed:?}"
        );
        let plain = painted(false);
        assert!(
            plain.ends_with("\x1b[1;4H\x1b[?2026l"),
            "a cursor with no wrap owed writes no cell: {plain:?}"
        );
    }

    /// The server leaves the saved cursor unset — libghostty exposes no DECSC
    /// accessor — so the field is only ever exercised here.
    #[test]
    fn a_saved_cursor_is_restated_before_the_live_one_and_a_missing_one_is_silent() {
        let size = GridSize { cols: 4, rows: 2 };
        let painted = |saved| {
            let mut frame = header(size);
            frame.cursor = Some((1, 1));
            frame.sticky = StickyState {
                saved_cursor: saved,
                ..StickyState::default()
            };
            paint_head(
                &mut Screen::default(),
                frame,
                vec![plain("abcd"), plain("efgh")],
            )
        };

        let restored = painted(Some((2, 0)));
        let save = restored
            .find("\x1b[1;3H\x1b7")
            .expect("the saved position is made current and then saved");
        let live = restored
            .rfind("\x1b[2;2H")
            .expect("the live cursor is put back after it");
        assert!(save < live, "{restored:?}");
        assert!(
            !painted(None).contains("\x1b7"),
            "an unset saved cursor claims nothing"
        );
    }
}
