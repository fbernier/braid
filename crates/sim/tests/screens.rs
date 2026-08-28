//! The client's screen converges on the server's, for every schedule of loss:
//! the real `ScreenLedger` and wire types against a reference client that does
//! nothing but apply rows by index.

use braid_proto::{
    ByteOff, CellStyle, ClientMessage, CursorShape, Generation, GridSize, ModeSet, RowFrame,
    RowSpan, RowUpdate, ScreenHeader, ScreenPart, ScreenVersion, ScrollBand, ServerMessage,
    StickyState, StyleColor, StyleRun, Version, encode_screen_parts,
};
use braid_server::screen::ScreenLedger;
use braid_sim::fault::{Asymmetric, GilbertElliott, Perfect, Schedule};
use braid_sim::net::{Side, Sim};
use braid_sim::rng::Rng;
use braid_vt::{RepaintFrame, RowMask};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const COLS: u16 = 80;
const ROWS: u16 = 40;

fn blank() -> Vec<RowFrame> {
    vec![plain(""); usize::from(ROWS)]
}

/// The blanks a row is padded to the grid with are dropped at encode, so they
/// are the one difference between what a side holds and what it can be told.
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

/// What a client holds where nothing has been painted.
fn erased() -> RowFrame {
    painted(&plain(""))
}

fn grid() -> GridSize {
    GridSize::new(COLS, ROWS).expect("a grid")
}

fn header(generation: Generation, version: ScreenVersion, next_off: ByteOff) -> ScreenHeader {
    ScreenHeader {
        generation,
        version,
        next_off,
        size: grid(),
        cursor: Some((0, 0)),
        cursor_visible: true,
        cursor_shape: CursorShape::Unset,
        cursor_blinking: false,
        modes: ModeSet::default(),
        sticky: StickyState::default(),
    }
}

/// A deliberately tiny alphabet, so rows return to content they held before:
/// "changed and changed back" is where comparing against the confirmed screen
/// names nothing. Styled rows share one layout, so a delta names a *span*.
fn text(rng: &mut Rng) -> RowFrame {
    const LINES: [&str; 4] = [
        "$",
        "$ cargo test --workspace",
        "   Compiling braid-server v0.1.0",
        "test result: ok. 38 passed; 0 failed",
    ];
    const STATES: [&str; 4] = ["  0%", " 42%", " 99%", "done"];
    let pick = usize::try_from(rng.below(8)).expect("below eight");
    match LINES.get(pick) {
        Some(line) => plain(line),
        None => building(STATES[pick - LINES.len()]),
    }
}

/// Padded to the grid, as the emulator builds it, so a whole-row update means
/// the whole line.
fn plain(line: &str) -> RowFrame {
    RowFrame {
        text: format!("{line:<width$}", width = usize::from(COLS)),
        cells: COLS,
        runs: Vec::new(),
    }
}

/// Three runs, of which only the middle one ever holds anything different.
fn building(state: &str) -> RowFrame {
    let line = format!("[braid] {state} building");
    RowFrame {
        text: format!("{line:<width$}", width = usize::from(COLS)),
        cells: COLS,
        runs: vec![
            run(8, StyleColor::Palette(4)),
            run(4, StyleColor::Palette(2)),
            run(9, StyleColor::Palette(7)),
        ],
    }
}

/// One style run over `cells` single-byte columns.
fn run(cells: u16, fg: StyleColor) -> StyleRun {
    StyleRun {
        cells,
        bytes: u32::from(cells),
        style: CellStyle {
            fg,
            ..CellStyle::default()
        },
    }
}

/// The client: rows by index, and a count of the pieces being assembled.
#[derive(Default)]
struct Reference {
    rows: Vec<RowFrame>,
    held: Option<(Generation, ScreenVersion)>,
    assembling: Option<Assembling>,
}

struct Assembling {
    generation: Generation,
    version: ScreenVersion,
    pieces: u16,
    seen: HashSet<u16>,
    /// A delta names a subset of rows by definition; a whole screen names all.
    whole: bool,
    rows_named: HashSet<u16>,
}

impl Assembling {
    fn complete(&self) -> bool {
        if self.seen.len() != usize::from(self.pieces) {
            return false;
        }
        !self.whole || self.rows_named.len() == usize::from(ROWS)
    }
}

impl Reference {
    fn new() -> Self {
        Self {
            rows: holding(&blank()),
            held: None,
            assembling: None,
        }
    }

    fn apply(&mut self, part: ScreenPart) -> Applied {
        if self.superseded(&part) {
            return Applied::Stale;
        }
        let (generation, version, pieces, index, whole, band, rows) = match part {
            ScreenPart::Head {
                header,
                base,
                scroll,
                pieces,
                rows,
            } => {
                // A client holding another screen cannot apply a delta that
                // names this one.
                if let Some(base) = base
                    && self.held != Some((header.generation, base))
                {
                    return Applied::Mismatch;
                }
                (
                    header.generation,
                    header.version,
                    pieces,
                    0u16,
                    base.is_none(),
                    scroll,
                    rows,
                )
            }
            ScreenPart::Tail {
                generation,
                version,
                pieces,
                index,
                rows,
            } => {
                // A tail carries no grid, so there is nothing to check against.
                let Some(assembling) = &self.assembling else {
                    return Applied::Mismatch;
                };
                if (assembling.generation, assembling.version) != (generation, version) {
                    return Applied::Mismatch;
                }
                (
                    generation,
                    version,
                    pieces,
                    index,
                    assembling.whole,
                    None,
                    rows,
                )
            }
        };
        // A newer screen abandons an older incomplete one; the rows the older
        // painted stay painted, because their damage was never cleared.
        let fresh = self
            .assembling
            .as_ref()
            .is_none_or(|open| (open.generation, open.version) != (generation, version));
        if fresh {
            self.assembling = Some(Assembling {
                generation,
                version,
                pieces,
                seen: HashSet::new(),
                whole,
                rows_named: HashSet::new(),
            });
            // Once, before the rows: a screen names rows where they are
            // *after* the movement.
            if let Some(band) = band {
                self.scroll(band);
            }
        }
        let assembling = self.assembling.as_mut().expect("just installed");
        assembling.seen.insert(index);
        for span in rows {
            assert!(span.row < ROWS, "a piece named a row outside the grid");
            assembling.rows_named.insert(span.row);
            let held = &self.rows[usize::from(span.row)];
            self.rows[usize::from(span.row)] = patch(held, &span);
        }
        if !assembling.complete() {
            return Applied::Incomplete;
        }
        self.held = Some((generation, version));
        self.assembling = None;
        Applied::Complete(generation, version)
    }

    /// `[top, bottom)` shifts up by `lines`, revealing that many blank rows.
    fn scroll(&mut self, band: ScrollBand) {
        let (top, bottom) = (usize::from(band.top), usize::from(band.bottom));
        let lines = usize::from(band.lines);
        self.rows[top..bottom].rotate_left(lines);
        for row in &mut self.rows[bottom - lines..bottom] {
            *row = erased();
        }
    }

    /// A superseded piece arrives whenever a router held a screen while newer
    /// ones went by; painting it puts the terminal back with nothing to correct.
    fn superseded(&self, part: &ScreenPart) -> bool {
        let named = match part {
            ScreenPart::Head { header, .. } => (header.generation, header.version),
            ScreenPart::Tail {
                generation,
                version,
                ..
            } => (*generation, *version),
        };
        if self.held.is_some_and(|held| held >= named) {
            return true;
        }
        self.assembling
            .as_ref()
            .is_some_and(|open| (open.generation, open.version) > named)
    }
}

/// Written from what the wire says a span is: a span boundary is always a
/// style-run boundary, which makes both ends of the splice nameable.
fn patch(held: &RowFrame, span: &RowSpan) -> RowFrame {
    let at = usize::try_from(span.byte).expect("a span inside a row");
    // A span starts on a run boundary, so counting bytes stops exactly at `at`.
    let mut first = 0;
    let mut byte = 0;
    while first < held.runs.len() && byte < at {
        byte += held.runs[first].bytes as usize;
        first += 1;
    }
    // A span that runs out of runs reached the row's unstyled tail, and its end.
    let mut end = first;
    let mut covered = 0_u16;
    while end < held.runs.len() && covered < span.frame.cells {
        covered = covered.saturating_add(held.runs[end].cells);
        byte += held.runs[end].bytes as usize;
        end += 1;
    }
    let erased = span.clear_tail || covered < span.frame.cells;
    let mut text = held.text.get(..at).unwrap_or_default().to_owned();
    text.push_str(&span.frame.text);
    let mut runs = held.runs[..first].to_vec();
    runs.extend_from_slice(&span.frame.runs);
    if !erased {
        text.push_str(held.text.get(byte..).unwrap_or_default());
        runs.extend_from_slice(&held.runs[end..]);
    }
    RowFrame {
        text,
        runs,
        // A span that erased what followed left the row as wide as itself.
        cells: if erased {
            span.col.saturating_add(span.frame.cells)
        } else {
            held.cells
        },
    }
}

/// The same three answers the real client has, driving the same behaviours.
enum Applied {
    Incomplete,
    Complete(Generation, ScreenVersion),
    /// A piece of a screen already superseded: nothing wrong, nothing to ask.
    Stale,
    /// A delta on a screen this client does not hold, or a tail with no head.
    /// The answer is a repaint; without one both ends refuse each other for ever.
    Mismatch,
}

/// The session's own rule is twice the round trip; here the round is the clock.
const ACK_ROUNDS: u32 = 4;

const ROUND: Duration = Duration::from_millis(25);

/// One convergence run: the harness, the ledger, the reference client, and the
/// counters that let a caller refuse to believe a run which lost nothing.
struct Run<S: Schedule> {
    sim: Sim<S>,
    client: Reference,
    ledger: ScreenLedger,
    version: ScreenVersion,
    server: Vec<RowFrame>,
    planned: HashMap<ScreenVersion, Vec<RowFrame>>,
    pushed: u32,
    arrived: u32,
}

impl<S: Schedule> Run<S> {
    fn new(schedule: S) -> Self {
        let mut ledger = ScreenLedger::new();
        ledger.invalidate(ROWS);
        Self {
            sim: Sim::new(schedule),
            client: Reference::new(),
            ledger,
            version: ScreenVersion::initial(),
            server: blank(),
            planned: HashMap::new(),
            pushed: 0,
            arrived: 0,
        }
    }

    fn push(&mut self) {
        let (_, parts) = cut_next(&mut self.ledger, &mut self.version, &self.server);
        self.planned.insert(self.version, self.server.clone());
        for part in parts {
            assert!(
                self.sim.send(Side::Server, &part).is_some(),
                "a piece did not fit"
            );
            self.pushed += 1;
        }
    }

    fn tick(&mut self) -> bool {
        self.sim.advance(ROUND);
        self.catch_up()
    }

    /// Returns whether the client refused a piece, which costs a repaint.
    fn catch_up(&mut self) -> bool {
        let refused = self.drain();
        if refused {
            repaint(&mut self.ledger, &mut self.client);
        }
        refused
    }

    /// Pieces to the client, acknowledgements to the ledger.
    fn drain(&mut self) -> bool {
        let mut refused = false;
        for frame in self.sim.take_delivered(Side::Client) {
            self.arrived += 1;
            let ServerMessage::Screen { part } =
                ServerMessage::decode(&frame[4..], Version::LOCAL).expect("a screen")
            else {
                panic!("this run sends nothing else");
            };
            match self.client.apply(part) {
                Applied::Complete(generation, version) => {
                    let ack = ClientMessage::ScreenAck {
                        generation,
                        version,
                    }
                    .encode(Version::LOCAL)
                    .expect("an ack");
                    let _ = self.sim.send(Side::Client, &ack);
                }
                Applied::Incomplete | Applied::Stale => {}
                Applied::Mismatch => refused = true,
            }
        }
        for frame in self.sim.take_delivered(Side::Server) {
            let ClientMessage::ScreenAck {
                generation,
                version,
            } = ClientMessage::decode(&frame[4..], Version::LOCAL).expect("an ack")
            else {
                panic!("this run sends nothing else");
            };
            if !self.ledger.confirm(generation, version) {
                continue;
            }
            // The invariant the ledger rests on: from here the server computes
            // every later difference against this screen, so a differing row can
            // never be repaired. Checked here: the next write to it hides it.
            let expected = holding(&self.planned[&version]);
            let differ: Vec<u16> = (0..ROWS)
                .filter(|&row| self.client.rows[usize::from(row)] != expected[usize::from(row)])
                .collect();
            assert!(
                differ.is_empty(),
                "the server confirmed screen {version:?} but the client is not showing rows {differ:?}"
            );
        }
        refused
    }
}

/// Returns the band the plan named alongside the pieces.
fn cut_next(
    ledger: &mut ScreenLedger,
    version: &mut ScreenVersion,
    server: &[RowFrame],
) -> (Option<ScrollBand>, Vec<Vec<u8>>) {
    *version = version.next();
    let head = header(Generation::initial(), *version, ByteOff::zero());
    let frame = RepaintFrame {
        size: grid(),
        rows: server.to_vec(),
        cursor: head.cursor,
        cursor_visible: true,
        cursor_shape: CursorShape::Unset,
        cursor_blinking: false,
        modes: ModeSet::default(),
        sticky: StickyState::default(),
        dirty: RowMask::with_rows(ROWS),
    };
    let plan = ledger.plan(&frame, &head);
    let delta = (!plan.full).then(|| {
        encode_screen_parts(
            &head,
            Some(plan.base),
            plan.scroll,
            plan.rows
                .iter()
                .map(|named| named.update(&server[usize::from(named.row)])),
            braid_proto::MIN_DATAGRAM_FRAME,
        )
    });
    match delta {
        Some(Ok(parts)) => (plan.scroll, parts),
        // The session's own answer: a band survives only in a single piece, and
        // a delta of just the rows it reveals describes a screen nobody holds.
        Some(Err(_)) | None => (
            None,
            encode_screen_parts(
                &head,
                None,
                None,
                (0..ROWS).map(|row| RowUpdate::whole(row, &server[usize::from(row)])),
                braid_proto::MIN_DATAGRAM_FRAME,
            )
            .expect("a screen of this grid fits datagrams"),
        ),
    }
}

/// The client holds something this session can no longer describe a diff against.
fn repaint(ledger: &mut ScreenLedger, client: &mut Reference) {
    ledger.invalidate(ROWS);
    ledger.release_in_flight();
    client.held = None;
    client.assembling = None;
}

/// Returns the pieces pushed and the pieces that arrived, so a caller can
/// refuse to believe a run that lost nothing.
fn converges<S: Schedule>(schedule: S, seed: u64, rounds: u32) -> (u32, u32) {
    let mut run = Run::new(schedule);
    let mut rng = Rng::seeded(seed);
    let mut outstanding = 0u32;

    for round in 0..rounds {
        // Stops for the last quarter of the run, so there is something to
        // converge to.
        if round < rounds * 3 / 4 {
            let mut dirty = RowMask::with_rows(ROWS);
            for _ in 0..=rng.below(20) {
                let row = u16::try_from(rng.below(u64::from(ROWS))).expect("below ROWS");
                run.server[usize::from(row)] = text(&mut rng);
                dirty.set(row);
            }
            run.ledger.note_damage(&dirty);
        }

        // Section 2's pacing: one screen outstanding, so an acknowledgement
        // always names the screen pushed last, and an unanswered one is released.
        if run.ledger.in_flight() {
            outstanding += 1;
            if outstanding < ACK_ROUNDS {
                if run.tick() {
                    outstanding = 0;
                }
                continue;
            }
            run.ledger.release_in_flight();
        }
        outstanding = 0;
        run.push();
        run.tick();
    }

    // Long enough for the link to finish what it is carrying.
    for _ in 0..ACK_ROUNDS * 4 {
        if run.ledger.in_flight() {
            run.ledger.release_in_flight();
        }
        run.push();
        run.tick();
    }

    // The transport paces what it takes, so the last pieces may still be queued.
    run.sim.settle();
    run.catch_up();

    run.sim.assert_sound();
    assert_eq!(
        run.client.rows,
        holding(&run.server),
        "the client's screen did not converge on the server's"
    );
    (run.pushed, run.arrived)
}

#[test]
fn a_screen_converges_over_a_link_that_loses_nothing() {
    let (pushed, arrived) = converges(Perfect, 1, 60);
    assert_eq!(pushed, arrived);
}

/// The ledger's damage carry is the only thing repairing what bursts take out.
#[test]
fn a_screen_converges_over_a_link_that_loses_in_bursts() {
    let mut lost = 0;
    for seed in 0..16u64 {
        let (pushed, arrived) = converges(GilbertElliott::typical(seed), seed, 200);
        lost += pushed - arrived;
    }
    assert!(
        lost > 100,
        "only {lost} pieces were lost across sixteen runs"
    );
}

#[test]
fn a_screen_converges_over_a_link_nobody_would_use() {
    for seed in 0..8u64 {
        let (pushed, arrived) = converges(GilbertElliott::hostile(seed), 1_000 + seed, 400);
        assert!(
            arrived * 3 < pushed * 2,
            "seed {seed} was supposed to be hostile: {arrived} of {pushed} arrived"
        );
    }
}

/// Pieces lost on the way *out* while acknowledgements get back unharmed: the
/// client holds rows the confirmed screen does not. Fails if `ScreenLedger`
/// stops carrying the rows of an unconfirmed screen.
#[test]
fn a_row_that_changed_and_changed_back_still_reaches_a_client_losing_pieces() {
    for seed in 0..12u64 {
        let (pushed, arrived) = converges(
            Asymmetric {
                from_client: Perfect,
                from_server: GilbertElliott::typical(seed),
            },
            2_000 + seed,
            400,
        );
        assert!(
            arrived < pushed,
            "seed {seed} lost no pieces, so it tested nothing"
        );
    }
}

/// A row nothing else on the grid equals, so a shift is unambiguous.
fn numbered(row: u16) -> RowFrame {
    plain(&format!("row {row}"))
}

/// Every piece in order, losing nothing. Reports whether the client refused it.
fn apply_all(client: &mut Reference, parts: Vec<Vec<u8>>) -> bool {
    let mut refused = false;
    for part in parts {
        let ServerMessage::Screen { part: piece } =
            ServerMessage::decode(&part[4..], Version::LOCAL).expect("a screen")
        else {
            panic!("this run sends nothing else");
        };
        refused |= matches!(client.apply(piece), Applied::Mismatch);
    }
    refused
}

/// The whole grid damaged, so what is planned is decided by what the client
/// last confirmed. Returns the band planned and whether the client refused it.
fn replan(
    ledger: &mut ScreenLedger,
    client: &mut Reference,
    version: &mut ScreenVersion,
    screen: &[RowFrame],
) -> (Option<ScrollBand>, bool) {
    ledger.note_damage(&RowMask::filled(ROWS));
    let (band, parts) = cut_next(ledger, version, screen);
    (band, apply_all(client, parts))
}

/// The base the bands below are planned against.
fn agreed() -> (ScreenLedger, Reference, ScreenVersion, Vec<RowFrame>) {
    let mut ledger = ScreenLedger::new();
    let mut client = Reference::new();
    let mut version = ScreenVersion::initial();
    ledger.invalidate(ROWS);
    let screen: Vec<RowFrame> = (0..ROWS).map(numbered).collect();
    let (band, refused) = replan(&mut ledger, &mut client, &mut version, &screen);
    assert_eq!(
        band, None,
        "a client holding nothing is sent a whole screen"
    );
    assert!(!refused, "a whole screen needs no base");
    assert!(ledger.confirm(Generation::initial(), version));
    assert_eq!(client.rows, holding(&screen));
    (ledger, client, version, screen)
}

fn scrolled_under_the_last_row(screen: &[RowFrame]) -> Vec<RowFrame> {
    let mut rows = screen.to_vec();
    let last = rows.len() - 1;
    rows[..last].rotate_left(1);
    rows[last - 1] = numbered(ROWS);
    rows
}

const UNDER_THE_LAST_ROW: ScrollBand = ScrollBand {
    top: 0,
    bottom: ROWS - 1,
    lines: 1,
};

/// A band applied and never acknowledged leaves the ledger planning against the
/// screen from *before* the movement, and a grid that scrolls back agrees with
/// that base exactly — so only the client's own base check catches it.
#[test]
fn a_band_the_client_applied_and_never_acknowledged_is_refused_as_a_base() {
    let (mut ledger, mut client, mut version, confirmed) = agreed();

    let scrolled = scrolled_under_the_last_row(&confirmed);
    let (band, refused) = replan(&mut ledger, &mut client, &mut version, &scrolled);
    assert_eq!(band, Some(UNDER_THE_LAST_ROW));
    assert!(!refused, "the band applies to the base");
    assert_eq!(
        client.rows,
        holding(&scrolled),
        "the client applied the band it was sent"
    );
    // The acknowledgement is what is lost.
    ledger.release_in_flight();

    // The grid is once again exactly the screen the ledger last had confirmed.
    let (band, refused) = replan(&mut ledger, &mut client, &mut version, &confirmed);
    assert_eq!(band, None, "nothing moved this time");
    assert!(
        refused,
        "a delta on a screen the client is not holding must be refused"
    );
    assert_eq!(
        client.rows,
        holding(&scrolled),
        "a refused delta paints nothing"
    );

    repaint(&mut ledger, &mut client);
    let (band, refused) = replan(&mut ledger, &mut client, &mut version, &confirmed);
    assert_eq!(band, None, "a client holding no base of ours gets a screen");
    assert!(!refused, "a whole screen needs no base");
    assert_eq!(
        client.rows,
        holding(&confirmed),
        "the repaint did not put the two ends back together"
    );
}

/// A band whose one piece never arrived: finding the shift again would be wrong,
/// because every row it moves inherits one the client may not be holding.
#[test]
fn a_band_the_client_never_saw_is_not_planned_a_second_time() {
    let (mut ledger, mut client, mut version, confirmed) = agreed();

    let scrolled = scrolled_under_the_last_row(&confirmed);
    ledger.note_damage(&RowMask::filled(ROWS));
    let (band, lost) = cut_next(&mut ledger, &mut version, &scrolled);
    assert_eq!(band, Some(UNDER_THE_LAST_ROW));
    drop(lost);
    ledger.release_in_flight();

    // The grid has not moved again, so the same shift is still there.
    let (band, refused) = replan(&mut ledger, &mut client, &mut version, &scrolled);
    assert_eq!(
        band, None,
        "a band cannot move rows the client may not be holding"
    );
    assert!(!refused, "the client still holds the base this delta names");
    assert_eq!(
        client.rows,
        holding(&scrolled),
        "the rows the lost band carried were never named again"
    );
}
