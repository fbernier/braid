#![forbid(unsafe_code)]

//! What the attached client has confirmed, and what it is still missing.
//!
//! The base is the *confirmed* screen, not the previous frame: paced at SRTT/2
//! with one screen outstanding, a client may have answered none of the last ten.

use braid_proto::{Generation, RowFrame, RowUpdate, ScreenHeader, ScreenVersion, ScrollBand};
use braid_vt::{RepaintFrame, RowMask};

/// `rows` is reused across calls, so a 30 Hz sync burst allocates nothing once
/// the buffers are warm.
pub struct Plan {
    pub full: bool,
    /// The screen a delta applies to. Meaningful only when `!full`.
    pub base: ScreenVersion,
    /// The rows that moved and how far, applied before `rows`.
    pub scroll: Option<ScrollBand>,
    /// Strictly ascending by row, and only when `!full`.
    pub rows: Vec<PlannedRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedRow {
    pub row: u16,
    pub sending: RowPlan,
}

impl PlannedRow {
    /// `frame` is the row itself, which this ledger names but does not hold:
    /// the encoder borrows the emulator's buffers rather than a copy of them.
    #[must_use]
    pub fn update<'a>(&self, frame: &'a RowFrame) -> RowUpdate<'a> {
        match self.sending {
            RowPlan::Whole => RowUpdate::whole(self.row, frame),
            RowPlan::Span { runs, clear_tail } => RowUpdate {
                row: self.row,
                frame,
                runs,
                clear_tail,
            },
        }
    }
}

/// A partial update patches the row the client is already holding, so it is
/// applicable only where this ledger knows what that row is: patching a base
/// the client does not hold leaves a row wrong in a way no later comparison
/// can find.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowPlan {
    Whole,
    /// The half-open style-run range in which the row differs from the
    /// confirmed one.
    Span {
        runs: (usize, usize),
        /// Erase from the end of the span to the end of the line.
        clear_tail: bool,
    },
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            full: true,
            base: ScreenVersion::initial(),
            scroll: None,
            rows: Vec::new(),
        }
    }
}

pub struct ScreenLedger {
    confirmed: Option<(Generation, ScreenVersion)>,
    /// The rows a delta is a difference against.
    confirmed_rows: Vec<RowFrame>,
    pending: Option<(Generation, ScreenVersion)>,
    /// The rows the screen in flight leaves the client holding, promoted on
    /// confirm: the frame verbatim, since whole rows, bands and spans all
    /// reconstruct the frame exactly from the base they name.
    pending_rows: Vec<RowFrame>,
    /// Rows dirtied since the confirmed screen that no screen in flight
    /// carries. Ghostty clears its own dirty bits on every repaint, so damage
    /// that must outlive an unacknowledged frame accumulates here instead.
    damage: RowMask,
    /// The damage the screen in flight took with it, held back rather than
    /// dropped so releasing that screen costs a retransmit and never a row.
    in_flight_damage: RowMask,
    /// Rows carried by a screen the client has not confirmed. A row that
    /// changed and changed back equals the confirmed screen but not what the
    /// client painted from a screen it never acknowledged, so content
    /// comparison alone would leave it stale forever.
    sent_unconfirmed: RowMask,
    /// The row list a band rebuilds into, held rather than reallocated on a
    /// path that runs thirty times a second.
    named: Vec<PlannedRow>,
    plan: Plan,
}

impl Default for ScreenLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenLedger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            confirmed: None,
            confirmed_rows: Vec::new(),
            pending: None,
            pending_rows: Vec::new(),
            damage: RowMask::default(),
            in_flight_damage: RowMask::default(),
            sent_unconfirmed: RowMask::default(),
            named: Vec::new(),
            plan: Plan::default(),
        }
    }

    /// Take Ghostty's damage for this frame, which bounds the rows a delta
    /// has to compare.
    pub fn note_damage(&mut self, dirty: &RowMask) {
        self.damage.union(dirty);
    }

    /// Nothing the client holds can serve as a base any more: a new attachment
    /// has never seen this screen, and a resize moved every row.
    pub fn invalidate(&mut self, rows: u16) {
        self.confirmed = None;
        self.confirmed_rows.clear();
        self.pending = None;
        self.damage = RowMask::filled(rows);
        self.in_flight_damage.reset(rows);
        self.sent_unconfirmed.reset(rows);
    }

    /// Decide what to send for `frame`, record it as sent under the header's
    /// version, and snapshot the rows so [`confirm`](Self::confirm) can
    /// promote them.
    ///
    /// The generation comes from the header because it is the pair
    /// `(generation, version)` the client echoes back.
    pub fn plan(&mut self, frame: &RepaintFrame, header: &ScreenHeader) -> &Plan {
        // The sink's single screen slot has already dropped the superseded
        // payload, so its damage comes back here.
        self.release_in_flight();
        self.plan.rows.clear();
        self.plan.scroll = None;
        self.plan.base = ScreenVersion::initial();
        self.plan.full = !self.plan_delta(frame, header);
        if self.plan.full {
            self.plan.rows.clear();
            self.plan.scroll = None;
            // A grid too tall to index with `u16` can never serve as a delta
            // base, so there is nothing to carry for it.
            if let Ok(count) = u16::try_from(frame.rows.len()) {
                self.carry_every(count);
            }
        } else {
            // Unioned, never replaced: several screens can go out between two
            // confirmations, and each leaves its own rows on the client.
            for named in &self.plan.rows {
                self.sent_unconfirmed.set(named.row);
            }
        }
        self.pending = Some((header.generation, header.version));
        // Moved rather than cloned: a derived `clone_from` is one allocation a
        // frame, thirty a second in the mode this exists for. The buffer
        // coming back is empty by construction.
        std::mem::swap(&mut self.damage, &mut self.in_flight_damage);
        self.damage.clear_all();
        snapshot(&mut self.pending_rows, &frame.rows);
        &self.plan
    }

    /// Fill in the delta half of the plan, or report that a whole screen is
    /// the only applicable answer.
    fn plan_delta(&mut self, frame: &RepaintFrame, header: &ScreenHeader) -> bool {
        let Some((generation, base)) = self.confirmed else {
            return false;
        };
        // A base from a generation this screen replaced names rows the client
        // no longer holds, and one of another height cannot be indexed at all.
        if generation != header.generation || self.confirmed_rows.len() != frame.rows.len() {
            return false;
        }
        let Ok(count) = u16::try_from(frame.rows.len()) else {
            return false;
        };
        self.plan.base = base;
        // A row the client may hold differently is worth naming on a frame
        // that dirtied nothing at all.
        if self.damage.is_empty() && self.sent_unconfirmed.is_empty() {
            return true;
        }
        // Ghostty marks a row dirty when it is rewritten with identical
        // content, so the mask decides what to look at and the comparison
        // decides what to send.
        for row in self.damage.iter_either(&self.sent_unconfirmed) {
            if row >= count {
                break;
            }
            let index = usize::from(row);
            let frame_row = &frame.rows[index];
            // A carried row is named because the client may be holding it
            // differently, so the confirmed screen is not a base a partial
            // update could patch and the whole row is the only sound answer.
            let sending = if self.sent_unconfirmed.get(row) {
                RowPlan::Whole
            } else if let Some(runs) = frame_row.changed_span(&self.confirmed_rows[index]) {
                partial(frame_row, runs)
            } else {
                continue;
            };
            self.plan.rows.push(PlannedRow { row, sending });
        }
        // A band carries its own row list, so it can only pay against a
        // difference of at least two rows.
        if self.plan.rows.len() > 1
            && let Some(found) = band(
                &self.confirmed_rows,
                &frame.rows,
                count,
                &self.plan.rows,
                &self.sent_unconfirmed,
            )
        {
            self.scroll_to(found);
        }
        // A delta naming every row costs a row index more than the screen it
        // replaces.
        self.plan.rows.len() < frame.rows.len()
    }

    /// Rewrite the plan around the band that moved: what survives is the rows
    /// the band reveals, the rows outside it that were already named, and the
    /// rows inside it inheriting one the client may be holding differently.
    fn scroll_to(&mut self, band: ScrollBand) {
        self.plan.scroll = Some(band);
        let revealed = band.bottom - band.lines;
        let carried = &self.sent_unconfirmed;
        self.named.clear();
        self.named.extend(
            self.plan
                .rows
                .iter()
                .copied()
                .filter(|one| one.row < band.top),
        );
        self.named.extend(
            (band.top..revealed)
                .filter(|row| carried.get(row + band.lines))
                .map(|row| PlannedRow {
                    row,
                    sending: RowPlan::Whole,
                }),
        );
        // The rows a band reveals are the terminal's own blank lines, which
        // this ledger holds no representation of, so they are named rather
        // than compared.
        self.named
            .extend((revealed..band.bottom).map(|row| PlannedRow {
                row,
                sending: RowPlan::Whole,
            }));
        self.named.extend(
            self.plan
                .rows
                .iter()
                .copied()
                .filter(|one| one.row >= band.bottom),
        );
        std::mem::swap(&mut self.plan.rows, &mut self.named);
        // Every row of the band moves, so a band the client never answers
        // leaves all of it - and only it - in doubt.
        for row in band.top..band.bottom {
            self.sent_unconfirmed.set(row);
        }
    }

    /// Record the screen a client says it is showing, and report whether the
    /// acknowledgement was taken.
    ///
    /// Only the screen actually pushed last can be confirmed: an ack that
    /// lagged behind a later push names rows this server no longer tracks
    /// separately, and honouring it would clear damage the client never got.
    pub fn confirm(&mut self, generation: Generation, version: ScreenVersion) -> bool {
        if self.pending != Some((generation, version)) {
            return false;
        }
        self.pending = None;
        self.in_flight_damage.clear_all();
        self.sent_unconfirmed.clear_all();
        // The buffer the confirmed rows vacate becomes the next snapshot's,
        // which is what keeps a sync burst allocation-free.
        std::mem::swap(&mut self.confirmed_rows, &mut self.pending_rows);
        self.confirmed = Some((generation, version));
        true
    }

    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.pending.is_some()
    }

    /// Give up on the screen in flight without confirming it. The damage it
    /// carried comes back, so the client is sent those rows again.
    pub fn release_in_flight(&mut self) {
        if self.pending.take().is_some() {
            self.damage.union(&self.in_flight_damage);
            self.in_flight_damage.clear_all();
        }
    }

    /// Mark every row as one the client may be holding differently, setting
    /// into the buffer already here rather than allocating a filled mask.
    fn carry_every(&mut self, rows: u16) {
        for row in 0..rows {
            self.sent_unconfirmed.set(row);
        }
    }
}

fn partial(frame: &RowFrame, runs: (usize, usize)) -> RowPlan {
    RowPlan::Span {
        runs,
        // A range reaching the last run carries the row to its painted end, so
        // whatever the client holds past that end is stale. Set on every such
        // range rather than only on a row that got shorter: a `RowFrame`
        // counts columns but not painted ones, and the flag costs no wire
        // bytes in a row head that is written either way.
        clear_tail: runs.1 == frame.runs.len(),
    }
}

/// The band of rows that moved, when moving it costs less than naming those
/// rows outright.
///
/// A band rather than the viewport, because almost nothing scrolls the whole
/// viewport: `less` keeps a `:` prompt, `vim` a status line, `tmux` a status
/// bar. `named` is what the delta costs without a band, and a band has to beat
/// it; a shift of `lines` always costs at least `lines`, so the search walks
/// shifts upwards and stops once the best band it holds is no dearer than the
/// shift it is about to try.
fn band(
    confirmed: &[RowFrame],
    frame: &[RowFrame],
    count: u16,
    named: &[PlannedRow],
    carried: &RowMask,
) -> Option<ScrollBand> {
    let limit = u16::try_from(named.len()).unwrap_or(u16::MAX).min(count);
    let mut best: Option<(usize, ScrollBand)> = None;
    for lines in 1..limit {
        if best.is_some_and(|(lowest, _)| lowest <= usize::from(lines)) {
            break;
        }
        let last = count - lines;
        let mut row = 0;
        while row < last {
            if frame[usize::from(row)] != confirmed[usize::from(row + lines)] {
                row += 1;
                continue;
            }
            let top = row;
            while row < last && frame[usize::from(row)] == confirmed[usize::from(row + lines)] {
                row += 1;
            }
            // One past the last row that matched, plus the shift: a band ends
            // where the rows it reveals do, which makes it always taller than
            // its own shift and so one the client can apply.
            let found = ScrollBand {
                top,
                bottom: (row + lines).min(count),
                lines,
            };
            let found_cost = cost(found, named, carried);
            if best.is_none_or(|(lowest, _)| found_cost < lowest) {
                best = Some((found_cost, found));
            }
        }
    }
    best.filter(|&(lowest, _)| lowest < named.len())
        .map(|(_, found)| found)
}

/// Rows a band still has to name, against `named.len()` for naming them all.
fn cost(band: ScrollBand, named: &[PlannedRow], carried: &RowMask) -> usize {
    let revealed = band.bottom - band.lines;
    // A row inheriting one the client may hold differently inherits the doubt
    // with it, and content comparison never resolves it: this ledger's copy of
    // the row it came from is exactly what the band matched against.
    let inherited = (band.top..revealed)
        .filter(|row| carried.get(row + band.lines))
        .count();
    // Rows outside the band do not move, so what a band saves is precisely the
    // named rows it covers.
    let inside = within(named, band.top, band.bottom);
    usize::from(band.lines) + inherited + (named.len() - inside)
}

/// How many of `named`, which is strictly ascending by row, fall inside
/// `[top, bottom)`.
fn within(named: &[PlannedRow], top: u16, bottom: u16) -> usize {
    let from = named.partition_point(|one| one.row < top);
    named[from..].partition_point(|one| one.row < bottom)
}

/// Copy `rows` into a buffer that already holds a screen of the same shape.
///
/// Field by field rather than `clone_from`: a derived `clone_from` is a fresh
/// `String` per row per frame, which is 1500 allocations a second on an 80x50
/// screen at 30 Hz.
fn snapshot(into: &mut Vec<RowFrame>, rows: &[RowFrame]) {
    into.truncate(rows.len());
    let held = into.len();
    for (slot, row) in into.iter_mut().zip(rows) {
        slot.text.clear();
        slot.text.push_str(&row.text);
        slot.runs.clear();
        slot.runs.extend_from_slice(&row.runs);
        slot.cells = row.cells;
    }
    into.extend_from_slice(&rows[held..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use braid_proto::{
        ByteOff, CellStyle, CursorShape, GridSize, MAX_FRAME, ModeSet, StickyState, StyleAttrs,
        StyleColor, StyleRun, encode_screen_parts,
    };

    const COLS: u16 = 80;

    fn row(text: &str) -> RowFrame {
        RowFrame {
            text: text.into(),
            runs: Vec::new(),
            cells: COLS,
        }
    }

    /// A row of `runs` styled stretches, each of `cells` single-byte columns.
    fn styled(text: &str, runs: &[(u16, StyleColor)]) -> RowFrame {
        RowFrame {
            text: text.into(),
            runs: runs
                .iter()
                .map(|&(cells, fg)| StyleRun {
                    cells,
                    bytes: u32::from(cells),
                    style: CellStyle {
                        fg,
                        attrs: StyleAttrs::NONE,
                        ..CellStyle::default()
                    },
                })
                .collect(),
            cells: u16::try_from(text.len()).expect("row width"),
        }
    }

    /// A screen of `rows` distinguishable lines, numbered from `first`.
    fn lines(first: usize, rows: usize) -> Vec<RowFrame> {
        (first..first + rows)
            .map(|line| row(&format!("line {line}")))
            .collect()
    }

    fn frame(rows: Vec<RowFrame>) -> RepaintFrame {
        let count = u16::try_from(rows.len()).expect("grid height");
        RepaintFrame {
            size: GridSize::new(COLS, count).expect("grid"),
            rows,
            cursor: Some((0, 0)),
            cursor_visible: true,
            cursor_shape: CursorShape::Unset,
            cursor_blinking: false,
            modes: ModeSet::default(),
            sticky: StickyState::default(),
            dirty: RowMask::filled(count),
        }
    }

    fn header(generation: Generation, version: ScreenVersion, rows: u16) -> ScreenHeader {
        ScreenHeader {
            generation,
            version,
            next_off: ByteOff::zero(),
            size: GridSize::new(COLS, rows).expect("grid"),
            cursor: Some((0, 0)),
            cursor_visible: true,
            cursor_shape: CursorShape::Unset,
            cursor_blinking: false,
            modes: ModeSet::default(),
            sticky: StickyState::default(),
        }
    }

    fn dirty(rows: u16, set: &[u16]) -> RowMask {
        let mut mask = RowMask::with_rows(rows);
        for row in set {
            mask.set(*row);
        }
        mask
    }

    /// The version after the one `confirmed` leaves the client holding.
    fn second() -> ScreenVersion {
        ScreenVersion::initial().next()
    }

    /// A ledger holding `rows` as the screen the client confirmed.
    fn confirmed(rows: Vec<RowFrame>) -> (ScreenLedger, RepaintFrame) {
        let mut ledger = ScreenLedger::new();
        let screen = frame(rows);
        let height = screen.size.rows;
        ledger.invalidate(height);
        ledger.note_damage(&screen.dirty);
        let plan = ledger.plan(
            &screen,
            &header(Generation::initial(), ScreenVersion::initial(), height),
        );
        assert!(plan.full, "a client that confirmed nothing gets a screen");
        assert!(ledger.confirm(Generation::initial(), ScreenVersion::initial()));
        (ledger, screen)
    }

    /// The plan for `screen` at `version`, on the generation these tests use.
    fn plan_at<'a>(
        ledger: &'a mut ScreenLedger,
        screen: &RepaintFrame,
        version: ScreenVersion,
    ) -> &'a Plan {
        let rows = screen.size.rows;
        ledger.plan(screen, &header(Generation::initial(), version, rows))
    }

    fn named_rows(plan: &Plan) -> Vec<u16> {
        plan.rows.iter().map(|one| one.row).collect()
    }

    /// A row as the client ends up holding it: the trailing blanks
    /// `painted_bytes` drops are never sent, and the line a row is painted over
    /// is already erased.
    fn painted(row: &RowFrame) -> RowFrame {
        RowFrame {
            text: row.text[..row.painted_bytes()].to_owned(),
            runs: row.runs.clone(),
            cells: row.cells,
        }
    }

    fn holding(rows: &[RowFrame]) -> Vec<RowFrame> {
        rows.iter().map(painted).collect()
    }

    /// Apply a plan the way the client does: shift the band, then paint what
    /// the delta names. The spans go through `RowFrame::span`, so this applies
    /// exactly the chunks the encoder puts on the wire.
    fn applied(base: &[RowFrame], plan: &Plan, frame: &RepaintFrame) -> Vec<RowFrame> {
        let mut screen = holding(base);
        if let Some(band) = plan.scroll {
            let (top, bottom) = (usize::from(band.top), usize::from(band.bottom));
            screen[top..bottom].rotate_left(usize::from(band.lines));
            for slot in &mut screen[bottom - usize::from(band.lines)..bottom] {
                // A line feed inside the region reveals the terminal's own
                // blank line.
                *slot = RowFrame::default();
            }
        }
        for one in &plan.rows {
            let index = usize::from(one.row);
            let row = &frame.rows[index];
            screen[index] = match one.sending {
                RowPlan::Whole => painted(row),
                RowPlan::Span { runs, clear_tail } => {
                    patched(&screen[index], row, runs, clear_tail)
                }
            };
        }
        screen
    }

    /// One row after the client patches it with a partial update: the columns
    /// before the span stay, the span's chunks land, and what follows is either
    /// kept or erased.
    fn patched(
        held: &RowFrame,
        row: &RowFrame,
        runs: (usize, usize),
        clear_tail: bool,
    ) -> RowFrame {
        let budget = MAX_FRAME as usize;
        let (_, at) = row.span(runs, budget).start();
        let at = usize::try_from(at).expect("a row offset");
        let mut text = held.text[..at].to_owned();
        let mut spans = held.runs[..runs.0].to_vec();
        for chunk in row.span(runs, budget) {
            text.push_str(chunk.text);
            spans.extend_from_slice(chunk.runs);
        }
        if !clear_tail {
            let replaced: usize = held.runs[runs.0..runs.1]
                .iter()
                .map(|run| run.bytes as usize)
                .sum();
            text.push_str(&held.text[at + replaced..]);
            spans.extend_from_slice(&held.runs[runs.1..]);
        }
        RowFrame {
            text,
            runs: spans,
            cells: held.cells,
        }
    }

    fn viewport(rows: u16, lines: u16) -> ScrollBand {
        ScrollBand {
            top: 0,
            bottom: rows,
            lines,
        }
    }

    /// A row in three styled stretches, so that a change in the middle one is
    /// a span that neither starts at column zero nor reaches the row's end.
    fn coloured(line: usize) -> RowFrame {
        styled(
            &format!("{:<80}", format!("line {line} of a coloured screen")),
            &[
                (6, StyleColor::Palette(2)),
                (10, StyleColor::Palette(4)),
                (8, StyleColor::Palette(6)),
            ],
        )
    }

    /// The frames a plan encodes to, through the encoder the session uses.
    fn encoded(head: &ScreenHeader, plan: &Plan, frame: &RepaintFrame) -> Vec<Vec<u8>> {
        encode_screen_parts(
            head,
            Some(plan.base),
            plan.scroll,
            plan.rows
                .iter()
                .map(|one| one.update(&frame.rows[usize::from(one.row)])),
            MAX_FRAME as usize,
        )
        .expect("a delta")
    }

    /// One screen, applied both to a client that has been given every screen
    /// and to one that dropped every screen since its last acknowledgement.
    /// Both have to end up holding the frame, because the server cannot tell
    /// them apart.
    fn round(
        ledger: &mut ScreenLedger,
        clients: &mut (Vec<RowFrame>, Vec<RowFrame>),
        rows: &[RowFrame],
        version: ScreenVersion,
        acknowledged: bool,
    ) {
        let screen = frame(rows.to_vec());
        ledger.note_damage(&RowMask::filled(screen.size.rows));
        let plan = plan_at(ledger, &screen, version);
        let want = holding(&screen.rows);
        let apply = |held: &Vec<RowFrame>| {
            if plan.full {
                want.clone()
            } else {
                applied(held, plan, &screen)
            }
        };
        clients.0 = apply(&clients.0);
        assert_eq!(clients.0, want, "a client holding every screen it was sent");
        if !acknowledged {
            ledger.release_in_flight();
            return;
        }
        clients.1 = apply(&clients.1);
        assert_eq!(
            clients.1, want,
            "a client that dropped every screen since its last acknowledgement"
        );
        assert!(ledger.confirm(Generation::initial(), version));
    }

    #[test]
    fn a_confirmed_screen_becomes_the_delta_base() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[3] = row("changed");
        screen.rows[4] = row("changed too");
        ledger.note_damage(&dirty(24, &[3, 4]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert!(!plan.full);
        assert_eq!(plan.base, ScreenVersion::initial());
        assert_eq!(named_rows(plan), vec![3, 4]);
        assert_eq!(plan.scroll, None);
    }

    /// A screen from another generation is not this ledger's screen, however
    /// well the version numbers happen to line up: neither as a delta base nor
    /// as an acknowledgement.
    #[test]
    fn another_generation_is_refused_as_a_base_and_ignored_as_an_acknowledgement() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[1] = row("changed");
        ledger.note_damage(&dirty(24, &[1]));
        assert!(
            ledger
                .plan(&screen, &header(Generation::initial().next(), second(), 24))
                .full
        );

        plan_at(&mut ledger, &screen, second());
        assert!(!ledger.confirm(Generation::initial().next(), second()));
        assert!(ledger.in_flight());
    }

    /// Ghostty marks a row dirty when it is rewritten with identical content.
    /// Those rows are pure wire weight.
    #[test]
    fn a_row_rewritten_with_the_same_content_is_not_named() {
        let (mut ledger, screen) = confirmed(lines(0, 24));
        ledger.note_damage(&dirty(24, &[2, 11, 19]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert!(!plan.full);
        assert!(
            plan.rows.is_empty(),
            "damage without a content change is not a row: {:?}",
            plan.rows
        );
    }

    /// Why the scroll band is on the wire: a screen that scrolls changes every
    /// row, and naming the movement costs only the rows it reveals.
    #[test]
    fn a_viewport_scroll_names_only_the_rows_it_reveals() {
        for shift in [1_u16, 6] {
            let base = lines(0, 50);
            let (mut ledger, _) = confirmed(base.clone());
            let screen = frame(lines(usize::from(shift), 50));
            ledger.note_damage(&RowMask::filled(50));
            let plan = plan_at(&mut ledger, &screen, second());
            assert!(!plan.full, "a shift of {shift}");
            assert_eq!(plan.scroll, Some(viewport(50, shift)), "a shift of {shift}");
            assert_eq!(
                named_rows(plan),
                (50 - shift..50).collect::<Vec<_>>(),
                "a shift of {shift}"
            );
            assert_eq!(
                applied(&base, plan, &screen),
                holding(&screen.rows),
                "base + scroll + rows is the frame, for a shift of {shift}"
            );
        }
    }

    /// A viewport rule needs the *whole* viewport to shift, so one row that
    /// does not move refuses the scroll outright and names all fifty. A band
    /// keeps the part that did move.
    #[test]
    fn a_shift_broken_by_one_row_keeps_the_band_around_it() {
        let base = lines(0, 50);
        let (mut ledger, _) = confirmed(base.clone());
        let mut rows = lines(1, 50);
        rows[20] = row("interloper");
        let screen = frame(rows);
        ledger.note_damage(&RowMask::filled(50));
        let plan = plan_at(&mut ledger, &screen, second());
        assert!(
            !plan.full,
            "the larger band is worth naming: {plan:?}",
            plan = named_rows(plan)
        );
        assert_eq!(
            plan.scroll,
            Some(ScrollBand {
                top: 21,
                bottom: 50,
                lines: 1
            }),
            "the band below the interloper is the larger of the two"
        );
        assert_eq!(applied(&base, plan, &screen), holding(&screen.rows));
    }

    /// Nothing relates the two screens, so no band can pay and a delta naming
    /// every row is larger than the screen it replaces.
    #[test]
    fn a_screen_that_no_shift_relates_carries_no_band() {
        let (mut ledger, _) = confirmed(lines(0, 50));
        let mut rows = lines(100, 50);
        rows.reverse();
        let screen = frame(rows);
        ledger.note_damage(&RowMask::filled(50));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(plan.scroll, None);
        assert!(plan.full, "50 differing rows cost more than the screen");
    }

    /// Damage must survive a delta the client never confirms, or the
    /// emulator's state becomes hostage to the network.
    #[test]
    fn unconfirmed_damage_is_carried_into_the_next_delta() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[2] = row("changed");
        ledger.note_damage(&dirty(24, &[2]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(named_rows(plan), vec![2]);
        // No ack arrives; the hold times out and row 5 changes as well.
        ledger.release_in_flight();
        screen.rows[5] = row("also changed");
        ledger.note_damage(&dirty(24, &[5]));
        let plan = plan_at(&mut ledger, &screen, second().next());
        assert_eq!(named_rows(plan), vec![2, 5]);
        assert_eq!(
            plan.base,
            ScreenVersion::initial(),
            "the base stays the last screen the client actually confirmed"
        );
    }

    #[test]
    fn confirmation_clears_only_what_it_carried() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[7] = row("changed");
        ledger.note_damage(&dirty(24, &[7]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(named_rows(plan), vec![7]);
        // Row 9 changes after the delta went out but before the ack lands.
        screen.rows[9] = row("later");
        ledger.note_damage(&dirty(24, &[9]));
        assert!(ledger.confirm(Generation::initial(), second()));
        let plan = plan_at(&mut ledger, &screen, second().next());
        assert_eq!(named_rows(plan), vec![9]);
        assert_eq!(plan.base, second());
    }

    /// An ack for a screen that has already been superseded names rows this
    /// ledger no longer tracks separately.
    #[test]
    fn a_stale_acknowledgement_is_ignored() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[1] = row("first change");
        ledger.note_damage(&dirty(24, &[1]));
        plan_at(&mut ledger, &screen, second());
        screen.rows[2] = row("second change");
        ledger.note_damage(&dirty(24, &[2]));
        let third = second().next();
        plan_at(&mut ledger, &screen, third);
        assert!(
            !ledger.confirm(Generation::initial(), second()),
            "a superseded ack must not be taken"
        );
        assert!(ledger.in_flight(), "the screen actually sent still stands");
        ledger.release_in_flight();
        let plan = plan_at(&mut ledger, &screen, third.next());
        assert_eq!(
            named_rows(plan),
            vec![1, 2],
            "a superseded ack must not clear rows"
        );
        assert_eq!(
            plan.base,
            ScreenVersion::initial(),
            "the base stays the last screen the client actually confirmed"
        );
    }

    /// A row equal to the confirmed screen is not equal to what the client
    /// painted from a screen it never acknowledged.
    #[test]
    fn a_row_that_changed_and_changed_back_is_resent_until_confirmed() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        let original = screen.rows[3].clone();
        screen.rows[3] = row("changed");
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(named_rows(plan), vec![3]);
        // The ack is lost, and the application rewrites row 3 with what the
        // confirmed screen already holds.
        ledger.release_in_flight();
        screen.rows[3] = original;
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second().next());
        assert_eq!(
            named_rows(plan),
            vec![3],
            "the client may be showing the row it was sent and never confirmed"
        );
    }

    /// An ack is the client saying what it holds, which is what makes content
    /// comparison sufficient again.
    #[test]
    fn a_confirmed_screen_stops_carrying_its_rows() {
        let (mut ledger, mut screen) = confirmed(lines(0, 24));
        screen.rows[3] = row("changed");
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(named_rows(plan), vec![3]);
        assert!(ledger.confirm(Generation::initial(), second()));
        // Row 3 is rewritten with the content the client just confirmed.
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second().next());
        assert!(
            plan.rows.is_empty(),
            "a confirmed row is not carried: {:?}",
            plan.rows
        );
        assert_eq!(plan.base, second());
    }

    /// A scroll moves every row, so an unanswered one puts the whole grid in
    /// doubt - here a pager that scrolled down a line and back up again.
    #[test]
    fn a_scroll_leaves_every_row_carried() {
        let base = lines(0, 50);
        let (mut ledger, _) = confirmed(base.clone());
        let screen = frame(lines(1, 50));
        ledger.note_damage(&RowMask::filled(50));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(plan.scroll, Some(viewport(50, 1)));
        assert_eq!(named_rows(plan), vec![49]);
        // No ack, and the screen returns to exactly the confirmed content, so
        // content comparison alone would name nothing at all.
        ledger.release_in_flight();
        let restored = frame(base);
        ledger.note_damage(&RowMask::filled(50));
        let plan = plan_at(&mut ledger, &restored, second().next());
        assert!(
            plan.full,
            "all fifty rows named costs more than the screen: {:?}",
            plan.rows
        );
    }

    #[test]
    fn a_new_attachment_starts_from_a_whole_screen() {
        let (mut ledger, screen) = confirmed(lines(0, 24));
        ledger.invalidate(24);
        assert!(!ledger.in_flight());
        let plan = plan_at(&mut ledger, &screen, second());
        assert!(plan.full);
        assert!(plan.rows.is_empty());
    }

    /// The byte win the band exists for, measured through the real encoder.
    /// 80x50, 78 painted bytes a row, and a `less` prompt on the bottom line so
    /// that a viewport rule would name all 49 moved rows.
    #[test]
    fn a_one_line_scroll_costs_a_row_instead_of_a_screen() {
        let mut base: Vec<RowFrame> = (0..49).map(|line| row(&format!("{line:0>78}"))).collect();
        base.push(row(":"));
        let head = header(Generation::initial(), second(), 50);
        // What a delta without a band sends: every row that moved.
        let every_row = encode_screen_parts(
            &head,
            Some(ScreenVersion::initial()),
            None,
            base[..49]
                .iter()
                .enumerate()
                .map(|(index, frame)| RowUpdate::whole(u16::try_from(index).expect("row"), frame)),
            MAX_FRAME as usize,
        )
        .expect("a screen");

        let (mut ledger, _) = confirmed(base.clone());
        let mut rows = base.clone();
        rows[..49].rotate_left(1);
        rows[48] = row(&format!("{:0>78}", 49));
        let scrolled = frame(rows);
        ledger.note_damage(&RowMask::filled(50));
        let plan = ledger.plan(&scrolled, &head);
        assert_eq!(
            plan.scroll,
            Some(ScrollBand {
                top: 0,
                bottom: 49,
                lines: 1
            })
        );
        assert_eq!(named_rows(plan), vec![48]);
        let one_row = encoded(&head, plan, &scrolled);

        // A stream budget takes a screen whole, so this is one frame against
        // one frame.
        assert_eq!(every_row.len(), 1);
        assert_eq!(one_row.len(), 1);
        assert_eq!(every_row[0].len(), 4671);
        assert_eq!(one_row[0].len(), 165);
    }

    /// The other half of the wire win, on the case sync mode is actually made
    /// of: one keystroke into a wide styled row. With the row as the diff unit
    /// a single cell costs the whole row and every style run in it.
    #[test]
    fn a_keystroke_into_a_styled_row_costs_the_run_it_landed_in() {
        let wide = |line: usize| {
            styled(
                &format!("{line:0>200}"),
                &[
                    (50, StyleColor::Palette(1)),
                    (50, StyleColor::Palette(2)),
                    (50, StyleColor::Palette(3)),
                    (50, StyleColor::Palette(4)),
                ],
            )
        };
        let base: Vec<RowFrame> = (0..24).map(wide).collect();
        let head = ScreenHeader {
            size: GridSize::new(200, 24).expect("grid"),
            ..header(Generation::initial(), second(), 24)
        };
        let (mut ledger, _) = confirmed(base.clone());
        let mut rows = base.clone();
        rows[5].text.replace_range(60..61, "x");
        let typed = RepaintFrame {
            size: head.size,
            ..frame(rows)
        };
        ledger.note_damage(&dirty(24, &[5]));
        let plan = ledger.plan(&typed, &head);
        assert_eq!(
            plan.rows,
            vec![PlannedRow {
                row: 5,
                sending: RowPlan::Span {
                    runs: (1, 2),
                    clear_tail: false
                }
            }],
            "one run of four, and no erase: the columns past it did not move"
        );
        let run_only = encoded(&head, plan, &typed);
        let whole_row = encode_screen_parts(
            &head,
            Some(plan.base),
            None,
            std::iter::once(RowUpdate::whole(5, &typed.rows[5])),
            MAX_FRAME as usize,
        )
        .expect("a screen");

        assert_eq!(whole_row[0].len(), 329);
        assert_eq!(run_only[0].len(), 143);
    }

    /// The cases a viewport rule never fires on and the band exists for: a
    /// pager keeping a prompt on the bottom line, and `tmux` adding a header
    /// above it so that the rows that move are an interior band with live
    /// content on both sides.
    #[test]
    fn a_band_covers_only_the_rows_that_moved() {
        let cases = [
            (None, ":", ":", 0_u16, vec![48_u16]),
            (
                Some("window 0: shell"),
                "[0] 0:shell*    12:00",
                "[0] 0:shell*    12:01",
                1,
                vec![48, 49],
            ),
        ];
        for (head_row, before, after, top, want) in cases {
            let body = 49 - usize::from(top);
            let mut base: Vec<RowFrame> = head_row.iter().copied().map(row).collect();
            base.extend(lines(0, body));
            base.push(row(before));
            let mut next: Vec<RowFrame> = head_row.iter().copied().map(row).collect();
            next.extend(lines(1, body));
            next.push(row(after));

            let (mut ledger, _) = confirmed(base.clone());
            let screen = frame(next);
            ledger.note_damage(&RowMask::filled(50));
            let plan = plan_at(&mut ledger, &screen, second());
            assert_eq!(
                plan.scroll,
                Some(ScrollBand {
                    top,
                    bottom: 49,
                    lines: 1
                }),
                "the rows outside the band did not move"
            );
            assert_eq!(
                named_rows(plan),
                want,
                "the row the band reveals, plus whatever changed outside it"
            );
            assert_eq!(applied(&base, plan, &screen), holding(&screen.rows));
        }
    }

    /// A row that lost its last styled stretch owes an erase: the client is
    /// holding columns the new row no longer covers.
    #[test]
    fn a_row_that_got_shorter_erases_what_it_no_longer_covers() {
        let mut base = lines(0, 24);
        base[3] = styled(
            &format!("{:<80}", "abcdefgh"),
            &[(4, StyleColor::Palette(1)), (4, StyleColor::Palette(2))],
        );
        let (mut ledger, _) = confirmed(base.clone());
        let mut rows = base.clone();
        rows[3] = styled(&format!("{:<80}", "abcd"), &[(4, StyleColor::Palette(1))]);
        let screen = frame(rows);
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(
            plan.rows,
            vec![PlannedRow {
                row: 3,
                sending: RowPlan::Span {
                    runs: (1, 1),
                    clear_tail: true
                }
            }],
            "nothing left to send, and four columns left to erase"
        );
        assert_eq!(applied(&base, plan, &screen), holding(&screen.rows));
    }

    /// The bug this ledger exists to prevent, in its partial-row form: a row
    /// named because the client may be holding it differently has no base a
    /// span could patch.
    #[test]
    fn a_carried_row_is_never_sent_as_a_partial_update() {
        let mut base = lines(0, 24);
        base[3] = styled(
            &format!("{:<80}", "abcdefgh"),
            &[(4, StyleColor::Palette(1)), (4, StyleColor::Palette(2))],
        );
        let (mut ledger, mut screen) = confirmed(base.clone());
        screen.rows[3] = styled(
            &format!("{:<80}", "abcdEFGH"),
            &[(4, StyleColor::Palette(1)), (4, StyleColor::Palette(2))],
        );
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second());
        assert_eq!(
            plan.rows,
            vec![PlannedRow {
                row: 3,
                sending: RowPlan::Span {
                    runs: (1, 2),
                    clear_tail: true
                }
            }],
            "against a confirmed base, the second stretch is all that changed"
        );
        // The ack never comes and the row changes again.
        ledger.release_in_flight();
        screen.rows[3] = styled(
            &format!("{:<80}", "abcdWXYZ"),
            &[(4, StyleColor::Palette(1)), (4, StyleColor::Palette(2))],
        );
        ledger.note_damage(&dirty(24, &[3]));
        let plan = plan_at(&mut ledger, &screen, second().next());
        assert_eq!(
            plan.rows,
            vec![PlannedRow {
                row: 3,
                sending: RowPlan::Whole
            }],
            "a row the client may hold differently cannot be patched, only replaced"
        );
    }

    /// The property partial rows rest on: whatever a plan says, applying it
    /// leaves the client holding exactly the frame - both the client that was
    /// given every screen and the one that dropped every screen since the last
    /// it acknowledged.
    #[test]
    fn applying_a_plans_own_spans_to_the_rows_a_client_holds_rebuilds_the_frame() {
        let mut rows: Vec<RowFrame> = (0..24).map(coloured).collect();
        let (mut ledger, _) = confirmed(rows.clone());
        let mut clients = (holding(&rows), holding(&rows));
        let mut version = ScreenVersion::initial();

        // One styled cell, in a run that is not the last.
        version = version.next();
        rows[4].text.replace_range(8..9, "X");
        round(&mut ledger, &mut clients, &rows, version, true);

        // A row that lost its last stretch and one that grew a longer one,
        // on a screen the client never answers for.
        version = version.next();
        rows[6] = styled(&format!("{:<80}", "short"), &[(5, StyleColor::Palette(1))]);
        rows[7] = styled(
            &format!("{:<80}", "much longer than it was before"),
            &[(5, StyleColor::Palette(1)), (25, StyleColor::Palette(2))],
        );
        round(&mut ledger, &mut clients, &rows, version, false);

        // The repair: rows 6 and 7 are carried and go whole, row 9 is a span
        // against the base both clients still agree on.
        version = version.next();
        rows[6].text.replace_range(0..1, "S");
        rows[9].text.replace_range(8..9, "Y");
        round(&mut ledger, &mut clients, &rows, version, true);

        // And a band under a status bar, with the header above it left alone.
        version = version.next();
        rows[1..23].rotate_left(1);
        rows[22] = coloured(99);
        round(&mut ledger, &mut clients, &rows, version, true);
    }
}
