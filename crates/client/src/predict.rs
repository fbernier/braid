#![forbid(unsafe_code)]

//! Local echo: draw a keystroke before the session echoes it, suppress the
//! echo when it arrives, and take a wrong guess back off the row.

use braid_proto::{CmdSeq, InputCue};
use std::time::Duration;
use unicode_width::UnicodeWidthChar;

/// One predicted byte, and what is owed for it.
struct Pending {
    byte: u8,
    /// The run it was typed into. `absorb` promotes `confirmed_epoch` no
    /// further than this, so an old run's echo cannot confirm a new one.
    epoch: u64,
    /// The sequence it went out under, or `None` while it is only buffered.
    /// Output can never echo a keystroke that never left this client.
    sent_as: Option<CmdSeq>,
    /// Always a prefix of `outstanding`: held-back predictions are drawn as a
    /// group, so a drawn byte never sits behind an undrawn one.
    drawn: bool,
}

/// What a wrong prediction costs to take off the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repair {
    None,
    /// Still the last thing under the cursor, and [`Predictor::undo`] carries
    /// the bytes that take it back.
    Local,
    /// The terminal is holding characters the session did not send and this
    /// side cannot say where they are. Only a whole screen takes them off.
    Repaint,
}

/// What a chunk of session output means for what the terminal already shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Absorbed {
    /// Leading bytes of the chunk the terminal already shows, being the echo
    /// of a drawn prediction. Writing them again doubles them on the row.
    pub skip: usize,
    pub repair: Repair,
}

/// How much of the round trip a user has asked this client to hide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Prediction {
    /// Draw nothing. The bookkeeping still runs: a run whose end went
    /// unrecorded stays confirmed into whatever is typed next.
    Never,
    /// Draw only while the measured link is slow enough to be worth it.
    #[default]
    Adaptive,
    Always,
}

impl Prediction {
    /// The name a user writes, on the command line or in `BRD_PREDICT`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "never" => Some(Self::Never),
            "adaptive" => Some(Self::Adaptive),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
}

/// Whether every keystroke before these ones reached the predictor.
///
/// Drawing happens under a `try_lock` on the display and may be skipped; the
/// bookkeeping may not. A missed Return leaves the run confirmed into the
/// password prompt it reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typing {
    Continuous,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Open,
    Closed,
}

/// Two figures rather than one, so a link jittering either side of a single
/// value does not turn predictions on and off mid-word.
const PREDICT_ABOVE: Duration = Duration::from_millis(30);
const PREDICT_BELOW: Duration = Duration::from_millis(20);

/// Keystrokes drawn ahead of the session, and what is owed for them.
pub struct Predictor {
    /// Echo the session still owes, oldest first, as it is expected back.
    outstanding: Vec<Pending>,
    /// Reused, so drawing a keystroke allocates nothing.
    drawing: Vec<u8>,
    epoch: u64,
    /// The run is confirmed exactly while this equals `epoch`.
    confirmed_epoch: u64,
    /// A judgement postponed because its prediction was still pending: the
    /// sequence whose acknowledgement settles it.
    deferred: Option<CmdSeq>,
    /// Newest command the server has acknowledged writing to the pty. Fed from
    /// the same ordered stream the output arrives on, which is what makes an
    /// echo evidence rather than a coincidence.
    delivered: Option<CmdSeq>,
    /// Widths of the cells this run put on the session's line, newest last. A
    /// backspace may only be predicted over these: the line editor holds
    /// exactly them, and the rest of the row belongs to the session.
    run_cells: Vec<u8>,
    /// KMP failure function for [`Predictor::restated_tail`], reused so a row
    /// rewrite - one per keystroke under `fish` - allocates nothing.
    failure: Vec<usize>,
    cue: InputCue,
    mode: Prediction,
    /// Starts open: a session that has measured nothing is on an unknown link.
    gate: Gate,
    /// Either the bytes this run has on the terminal or the bytes that take
    /// them back, depending on how far [`Predictor::absorb`] got with it.
    undoing: Vec<u8>,
    /// Where the cursor stands, when this side can say - a `\r`-led rewrite
    /// states it, and every byte drawn after one is a width this module chose.
    /// It answers the question a rewrite cannot answer about itself: whether
    /// the columns it painted hold this run's drawn cells.
    column: Option<isize>,
}

impl Default for Predictor {
    fn default() -> Self {
        Self::new(Prediction::default())
    }
}

impl Predictor {
    #[must_use]
    pub const fn new(mode: Prediction) -> Self {
        Self {
            outstanding: Vec::new(),
            drawing: Vec::new(),
            // The first run starts unconfirmed, so the two must differ.
            epoch: 1,
            confirmed_epoch: 0,
            deferred: None,
            delivered: None,
            run_cells: Vec::new(),
            failure: Vec::new(),
            cue: InputCue::Opaque,
            mode,
            gate: Gate::Open,
            undoing: Vec::new(),
            column: None,
        }
    }

    /// Record typed bytes and return what to draw for them now.
    ///
    /// `sent_as` is `None` when the transport was down and the keystroke is
    /// only buffered. The result may be longer than `typed` - it carries the
    /// predictions a tentative run held back - and is empty while the run is
    /// unconfirmed, the cue refuses it, or nothing is being drawn at all.
    ///
    /// Must be called for every keystroke even when nothing will be drawn:
    /// this is also where a run *ends*, and a run that fails to end is a run
    /// that stays confirmed into the password prompt below it.
    pub fn predict(&mut self, typed: &[u8], sent_as: Option<CmdSeq>, since: Typing) -> &[u8] {
        // Ahead of the keystroke, because what was missed came first.
        if since == Typing::Interrupted {
            self.stall();
        }
        let InputCue::Echoing { room } = self.cue else {
            return self.stall();
        };
        match Keystroke::of(typed) {
            // `room` counts columns and `outstanding` counts bytes, which for
            // UTF-8 is never fewer, so the budget is spent early on an
            // accented or CJK line and the row's last cell stays free.
            Some(Keystroke::Print { text, cols })
                if cols <= PASTE_CELLS
                    && self.outstanding.len() + typed.len() <= usize::from(room) =>
            {
                self.queue(typed, sent_as);
                self.run_cells.extend(text.chars().filter_map(cell_width));
                if !self.confirmed() {
                    return &[];
                }
                self.release()
            }
            // Only over `run_cells`: characters this run put on the line, so
            // the session's line editor holds and will delete exactly them.
            Some(Keystroke::Erase(cells))
                if self.confirmed()
                    && self.outstanding.iter().all(|pending| pending.drawn)
                    && self.run_cells.len() >= cells =>
            {
                for _ in 0..cells {
                    if let Some(width) = self.run_cells.pop() {
                        self.queue(erase_echo(width), sent_as);
                    }
                }
                self.release()
            }
            _ => self.stall(),
        }
    }

    /// The smoothed round trip the transport has measured, or `None` while it
    /// has measured none.
    pub fn observed_rtt(&mut self, srtt: Option<Duration>) {
        let Some(srtt) = srtt else {
            return;
        };
        if srtt > PREDICT_ABOVE {
            self.gate = Gate::Open;
        } else if srtt <= PREDICT_BELOW && !self.anything_drawn() {
            // Closing waits until the terminal is clear, so the change is
            // never visible as a flicker.
            self.gate = Gate::Closed;
        }
    }

    const fn drawing_now(&self) -> bool {
        match self.mode {
            Prediction::Never => false,
            Prediction::Adaptive => matches!(self.gate, Gate::Open),
            Prediction::Always => true,
        }
    }

    fn anything_drawn(&self) -> bool {
        self.outstanding.iter().any(|pending| pending.drawn)
    }

    /// The bytes that take back what [`Repair::Local`] named; meaningless
    /// after anything but an [`Absorbed`] carrying it.
    pub fn undo(&self) -> &[u8] {
        &self.undoing
    }

    const fn confirmed(&self) -> bool {
        self.epoch == self.confirmed_epoch
    }

    fn queue(&mut self, bytes: &[u8], sent_as: Option<CmdSeq>) {
        self.outstanding.extend(bytes.iter().map(|&byte| Pending {
            byte,
            epoch: self.epoch,
            sent_as,
            drawn: false,
        }));
    }

    /// Draw every prediction not yet on the terminal, oldest first.
    fn release(&mut self) -> &[u8] {
        self.drawing.clear();
        if !self.drawing_now() {
            // Still owed, so echoes are still matched against them and a gate
            // that opens later draws them as the next keystroke's group.
            return &self.drawing;
        }
        for pending in &mut self.outstanding {
            if !pending.drawn {
                pending.drawn = true;
                self.drawing.push(pending.byte);
            }
        }
        // A stale column would place the next rewrite against a grown run.
        self.column = column_after(self.column, &self.drawing);
        &self.drawing
    }

    /// End the run without ending what is drawn: a keystroke this side cannot
    /// model leaves the row in a shape nothing here can predict onto. What is
    /// already drawn stays owed so its echo is still suppressed.
    fn stall(&mut self) -> &[u8] {
        self.epoch += 1;
        // Nothing will echo undrawn predictions in the shape they were queued
        // in, and left in place they would block every later match.
        self.outstanding.retain(|pending| pending.drawn);
        // Carrying the cells over would let a backspace predicted after the
        // next confirmation reach past this run's line, into the prompt.
        self.run_cells.clear();
        &[]
    }

    /// Reconcile a chunk of session output with what was predicted.
    ///
    /// `echo_ack` is the newest command the application has had in front of it
    /// long enough to have answered; older output judges nothing.
    pub fn absorb(&mut self, session: &[u8], cue: InputCue, echo_ack: Option<CmdSeq>) -> Absorbed {
        self.cue = cue;
        let echoed = self
            .outstanding
            .iter()
            .zip(session)
            .take_while(|(pending, actual)| pending.byte == **actual)
            .count();
        // Not gated on `confirms`: suppressing an echo of what the terminal
        // already shows is safe whatever the match is evidence of, and a run
        // whose echo arrives in two chunks would otherwise double the first.
        let skip = self.outstanding[..echoed]
            .iter()
            .take_while(|pending| pending.drawn)
            .count();
        if let Some(run) = self.confirms(echoed) {
            self.confirmed_epoch = self.confirmed_epoch.max(run);
        }
        if echoed > 0 {
            // The session sent back whatever the postponed judgement was about.
            self.deferred = None;
            self.outstanding.drain(..echoed);
        }
        let rest = &session[echoed..];
        if rest.is_empty() {
            self.column = column_after(self.column, &session[skip..]);
            return Absorbed {
                skip,
                repair: Repair::None,
            };
        }
        if restates_row(rest) {
            let restated = self.restated_tail(rest);
            let extent = rewrite_extent(rest);
            // A rewrite ending with this run's predictions places itself
            // against the run outright; one ending with none of them is placed
            // by its extent, or the ones it stopped short of are stranded.
            if restated == 0 && !self.rewrite_accounts_for_the_run(extent) {
                return Absorbed {
                    skip,
                    repair: self.end_run(&[]),
                };
            }
            // As far as the rewrite reaches, the row carries what the session
            // says whatever was predicted onto it. One that has caught up with
            // no prediction is an echo still in flight behind the typing, and
            // the run survives it.
            if let Some(run) = self.confirms(restated) {
                self.confirmed_epoch = self.confirmed_epoch.max(run);
            }
            if restated > 0 {
                self.outstanding.drain(..restated);
            } else if !self.confirmed() {
                // Predictions queued behind a keystroke this side could not
                // model are unverifiable: dropping them is what lets the next
                // keystroke confirm a run again.
                self.outstanding.clear();
            }
            // Either the rewrite painted over the drawn cells, or they begin
            // at the cursor it leaves, where the next release writes them
            // again byte for byte over themselves.
            for pending in &mut self.outstanding {
                pending.drawn = false;
            }
            self.deferred = None;
            self.column = extent.cols.filter(|cols| *cols >= 0);
            return Absorbed {
                skip,
                repair: Repair::None,
            };
        }
        // Output the session produced on its own account - unless the
        // application had not been given the prediction yet, in which case
        // this output is not evidence and the judgement waits for the ack.
        if let Some(unanswered) = self.unanswered(echo_ack) {
            self.deferred = Some(unanswered);
            self.column = column_after(self.column, &session[skip..]);
            return Absorbed {
                skip,
                repair: Repair::None,
            };
        }
        let repair = self.end_run(rest);
        Absorbed { skip, repair }
    }

    /// The server has written every command up to `highest` to the pty.
    ///
    /// Read off the inbound stream the session's output comes down and in the
    /// same order, which is what [`Predictor::confirms`] rests on. Monotone,
    /// because a reconnect replays commands the far end has already acked.
    pub fn acknowledged(&mut self, highest: CmdSeq) {
        self.delivered = self.delivered.max(Some(highest));
    }

    /// Settle what a heartbeat's echo ack now answers for, returning whether
    /// the terminal is holding characters the session did not send.
    ///
    /// Always a whole screen when it is: the chunk that diverged was written
    /// frames ago, so the cursor is nowhere near the cells a local undo would
    /// back over.
    pub fn echo_ack(&mut self, echo_ack: Option<CmdSeq>) -> bool {
        let Some(deferred) = self.deferred else {
            return false;
        };
        if Some(deferred) > echo_ack {
            return false;
        }
        self.end_run(&[]) != Repair::None
    }

    /// The sequence of the oldest prediction the application cannot have seen,
    /// which is the one whose echo the match failed on.
    fn unanswered(&self, echo_ack: Option<CmdSeq>) -> Option<CmdSeq> {
        // `None` is "nothing acknowledged yet", and `Option`'s own ordering
        // puts it below every sequence: exactly the comparison this wants.
        self.outstanding
            .first()?
            .sent_as
            .filter(|seq| Some(*seq) > echo_ack)
    }

    /// The run `matched` echoed predictions confirm, counted from the oldest,
    /// or `None` when the match is no evidence the session echoed anything.
    ///
    /// A confirmation draws every prediction the run holds, and at a prompt
    /// that does not echo those are the password - so the match must cover
    /// *everything* still owed rather than a prefix, and the last prediction
    /// it covers must already be acknowledged, which orders the keystroke
    /// ahead of the read that produced this output.
    fn confirms(&self, matched: usize) -> Option<u64> {
        if matched == 0 || matched < self.outstanding.len() {
            return None;
        }
        let last = self.outstanding.last()?;
        last.sent_as
            .is_some_and(|seq| Some(seq) <= self.delivered)
            .then_some(last.epoch)
    }

    /// How many of the predictions still owed a row rewrite accounts for: the
    /// longest prefix of what is owed which is a suffix of the rewrite.
    ///
    /// One pass of the KMP automaton, because `fish` restates the whole row on
    /// every keystroke and a naive search costs a 200-column row times 200
    /// outstanding bytes on the one path the module exists for.
    fn restated_tail(&mut self, rewrite: &[u8]) -> usize {
        let owed = &self.outstanding;
        let width = owed.len();
        if width == 0 || rewrite.is_empty() {
            return 0;
        }
        // `failure[i]` is the longest proper prefix of the first `i + 1`
        // predictions that is also a suffix of them: where a match that stops
        // agreeing falls back to, rather than starting over one byte along.
        let failure = &mut self.failure;
        failure.clear();
        failure.push(0);
        let mut border = 0;
        for index in 1..width {
            let byte = owed[index].byte;
            while border > 0 && byte != owed[border].byte {
                border = failure[border - 1];
            }
            if byte == owed[border].byte {
                border += 1;
            }
            failure.push(border);
        }
        let mut matched = 0;
        for &actual in rewrite {
            // Everything owed agrees already, and that state holds no edge of
            // its own: the automaton leaves it through its longest border.
            if matched == width {
                matched = failure[width - 1];
            }
            while matched > 0 && actual != owed[matched].byte {
                matched = failure[matched - 1];
            }
            if actual == owed[matched].byte {
                matched += 1;
            }
        }
        matched
    }

    /// The terminal is about to be painted from the session's own screen.
    ///
    /// Returns whether that paint has to be a whole screen: a delta carries
    /// only the rows the session changed, and the row a prediction was drawn
    /// on is not one of them unless the session happened to touch it.
    pub fn invalidate(&mut self) -> bool {
        let repair = self.end_run(&[]);
        // Only passthrough output carries a cue, and this screen is not it.
        self.cue = InputCue::Opaque;
        repair != Repair::None
    }

    /// The terminal was resized and the server has not applied it yet, so
    /// `room` still describes a column count that may have shrunk: predicting
    /// against it lands past the new right margin and commits the terminal to
    /// exactly the wrap the last-cell exclusion exists to prevent.
    pub fn resized(&mut self) {
        self.cue = InputCue::Opaque;
        self.column = None;
    }

    /// End the run, reporting what the terminal is left holding. `follows` is
    /// the output about to be written where the cursor now stands, or empty.
    fn end_run(&mut self, follows: &[u8]) -> Repair {
        let repair = self.plan_repair(follows);
        self.outstanding.clear();
        self.run_cells.clear();
        self.deferred = None;
        self.column = None;
        self.epoch += 1;
        repair
    }

    /// Whether the cells this run drew can be taken off the row from here.
    ///
    /// Everything drawn has to be a plain append - undoing an erase echo means
    /// writing the character it deleted, whose width this side kept but never
    /// the character - and `follows` has to begin with a printable byte, since
    /// a control byte or escape there is a cursor gone somewhere this side
    /// cannot follow. A row boundary is not a condition: `room` keeps every
    /// drawn cell on the cursor's own line.
    fn plan_repair(&mut self, follows: &[u8]) -> Repair {
        if self.drawn_bytes().is_empty() {
            return Repair::None;
        }
        let printable = follows
            .first()
            .is_some_and(|byte| *byte >= b' ' && *byte != 0x7f);
        let Some(cols) = appended_columns(&self.undoing).filter(|_| printable) else {
            self.undoing.clear();
            return Repair::Repaint;
        };
        self.undoing.clear();
        self.undoing.resize(cols, 0x08);
        self.undoing.resize(cols * 2, b' ');
        self.undoing.resize(cols * 3, 0x08);
        Repair::Local
    }

    /// The bytes this run has on the terminal, gathered into the scratch the
    /// undo is later built in.
    fn drawn_bytes(&mut self) -> &[u8] {
        self.undoing.clear();
        self.undoing.extend(
            self.outstanding
                .iter()
                .take_while(|pending| pending.drawn)
                .map(|pending| pending.byte),
        );
        &self.undoing
    }

    /// Whether a rewrite that restated none of this run's predictions left
    /// them accounted for.
    ///
    /// A rewrite of extent `E` paints `[0, E)` and leaves the rest standing,
    /// so only two answers can be acted on: it reached the cursor, or it
    /// stopped exactly where the drawn cells begin. In between it covered
    /// some and left the rest, which no state here can record. With no column
    /// in hand the run is placed at the row's first cell, erring toward trust
    /// by the session's prefix - the cheap direction on a slow link.
    fn rewrite_accounts_for_the_run(&mut self, extent: Extent) -> bool {
        // Everything from the rewrite's cursor to the end of the row is gone,
        // whatever its column count says.
        if extent.clears_tail {
            return true;
        }
        let Some(advance) = cursor_advance(self.drawn_bytes()) else {
            return false;
        };
        // Nothing of this run stands to the right of the cursor: a run that
        // drew nothing has no cells, and an erase echo leaves a blank one.
        if advance <= 0 {
            return true;
        }
        let Some(cols) = extent.cols else {
            return false;
        };
        match self.column {
            Some(cursor) => cols >= cursor || cols == cursor - advance,
            None => cols >= advance,
        }
    }
}

/// A keystroke shape this side can model without an emulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keystroke<'a> {
    /// Text whose every scalar has a width this side will vouch for. No
    /// combining mark to fold into the cell before it, and - since these bytes
    /// are drawn on the user's own terminal - nothing carrying an escape.
    Print { text: &'a str, cols: usize },
    /// Backspace or delete, and the cells it takes back.
    Erase(usize),
}

impl<'a> Keystroke<'a> {
    /// A chunk is one shape or it is nothing: a run mixing the two would need
    /// the cursor arithmetic this client deliberately does not have.
    fn of(typed: &'a [u8]) -> Option<Self> {
        if typed.is_empty() {
            return None;
        }
        if typed.iter().all(|byte| *byte == 0x7f || *byte == 0x08) {
            return Some(Self::Erase(typed.len()));
        }
        // A chunk the read split mid-scalar is not text yet; half a scalar
        // drawn is a row to take back, and stalling costs one round trip.
        let text = std::str::from_utf8(typed).ok()?;
        let mut cols = 0;
        for ch in text.chars() {
            cols += usize::from(cell_width(ch)?);
        }
        Some(Self::Print { text, cols })
    }
}

/// The cells a scalar takes, or `None` for one this side will not place.
///
/// A general width table with an exclusion list rather than an allowlist,
/// which would leave Devanagari, Arabic, Hebrew, Thai and the rest paying a
/// round trip per keystroke. What is excluded is anything folding into a
/// neighbouring cell, since that cell may be one the session put there.
fn cell_width(ch: char) -> Option<u8> {
    if FOLDS_INTO_NEIGHBOUR
        .iter()
        .any(|&(first, last)| (first..=last).contains(&ch))
    {
        return None;
    }
    match ch.width() {
        Some(1) => Some(1),
        Some(2) => Some(2),
        // Zero is a combining mark, a joiner or a variation selector; `None`
        // is a control byte; three is `U+17D8`, which no two terminals place
        // alike.
        _ => None,
    }
}

/// Scalars a width table sizes on their own that a terminal sizes as part of
/// a cluster: an emoji modifier tints its neighbour into two cells rather than
/// four, and a regional indicator pairs into a flag. Combining marks, ZWJ and
/// the variation selectors need no entry - the table calls them zero-width.
const FOLDS_INTO_NEIGHBOUR: [(char, char); 2] =
    [('\u{1f1e6}', '\u{1f1ff}'), ('\u{1f3fb}', '\u{1f3ff}')];

/// Cells one chunk may predict, which is mosh's bound for the same reason: a
/// paste arrives faster than any echo can answer it, and nothing here can tell
/// a shell that will echo it verbatim from a program that will reformat it.
const PASTE_CELLS: usize = 100;

/// What a line editor writes to take back a one-cell character, measured
/// against `bash`, `sh` and `zsh`; `fish` rewrites the whole row instead.
///
/// A measurement, not an invariant. The echo ack is what makes that
/// affordable: a mismatch the application cannot have answered yet is pending
/// rather than wrong, so being mistaken here costs a round trip, not a screen.
const ERASE_ECHO: &[u8] = b"\x08 \x08";

/// The same for a two-cell character. One `\x08 \x08` would leave the right
/// half of the glyph on the row with the cursor standing in it.
const ERASE_ECHO_WIDE: &[u8] = b"\x08\x08  \x08\x08";

const fn erase_echo(cells: u8) -> &'static [u8] {
    match cells {
        2 => ERASE_ECHO_WIDE,
        _ => ERASE_ECHO,
    }
}

/// Whether output rewrites the row the cursor is on from its first column: a
/// carriage return with no line feed behind it is the whole idiom.
fn restates_row(session: &[u8]) -> bool {
    session.starts_with(b"\r") && !session.starts_with(b"\r\n")
}

/// What a row rewrite does to the row, as far as the predictions on it care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Extent {
    /// The column it leaves the cursor in, counted from the row's first cell,
    /// or `None` when the chunk left the row or could not be read.
    cols: Option<isize>,
    /// Whether it erases from where it stands to the end of the row, which
    /// takes off everything past it whatever the column count says.
    clears_tail: bool,
}

/// Read a row rewrite for how far along the row it reaches.
///
/// Deliberately not an emulator: escape sequences are skipped rather than
/// interpreted, except `EL` with a zero parameter, and anything that leaves
/// the row or cannot be sized reports no columns - the answer that refuses to
/// place the chunk against the run.
fn rewrite_extent(rewrite: &[u8]) -> Extent {
    let mut clears_tail = false;
    let cols = 'walk: {
        let mut cols: isize = 0;
        let mut index = 0;
        while index < rewrite.len() {
            match rewrite[index] {
                b'\r' => {
                    cols = 0;
                    index += 1;
                }
                0x08 => {
                    cols -= 1;
                    index += 1;
                }
                0x1b => {
                    let Some(len) = escape_len(&rewrite[index..]) else {
                        break 'walk None;
                    };
                    if matches!(&rewrite[index..index + len], b"\x1b[K" | b"\x1b[0K") {
                        clears_tail = true;
                    }
                    index += len;
                }
                byte if byte < 0x20 || byte == 0x7f => break 'walk None,
                _ => {
                    let Some(ch) = leading_char(&rewrite[index..]) else {
                        break 'walk None;
                    };
                    // This extent is the module's only cursor claim: counting
                    // a regional-indicator pair as zero or a ZWJ family as six
                    // places the run against a column the terminal never had.
                    let Some(width) = cell_width(ch) else {
                        break 'walk None;
                    };
                    cols += isize::from(width);
                    index += ch.len_utf8();
                }
            }
        }
        Some(cols)
    };
    Extent { cols, clears_tail }
}

/// The length of the escape sequence at the front of `bytes`, or `None` when
/// this chunk does not hold the whole of one.
fn escape_len(bytes: &[u8]) -> Option<usize> {
    match *bytes.get(1)? {
        // A CSI runs to its final byte.
        b'[' => Some(
            3 + bytes[2..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))?,
        ),
        // The string-terminated introducers, whose text this side never reads.
        b']' | b'P' | b'X' | b'^' | b'_' => {
            (2..bytes.len()).find_map(|index| match (bytes[index], bytes.get(index + 1)) {
                (0x07, _) => Some(index + 1),
                (0x1b, Some(b'\\')) => Some(index + 2),
                _ => None,
            })
        }
        _ => Some(2),
    }
}

fn leading_char(bytes: &[u8]) -> Option<char> {
    let len = match *bytes.first()? {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return None,
    };
    std::str::from_utf8(bytes.get(..len)?).ok()?.chars().next()
}

/// How far drawn bytes moved the cursor. Signed, because an erase echo backs
/// over a cell, blanks it and backs over it again, leaving the cursor a column
/// to the *left* of where the run began.
fn cursor_advance(drawn: &[u8]) -> Option<isize> {
    let text = std::str::from_utf8(drawn).ok()?;
    let mut advance: isize = 0;
    for ch in text.chars() {
        advance += match ch {
            '\u{8}' => -1,
            _ => isize::from(cell_width(ch)?),
        };
    }
    Some(advance)
}

/// The column `written` bytes leave the cursor in, or `None` for any byte
/// sequence whose effect on the cursor this module did not choose.
fn column_after(column: Option<isize>, written: &[u8]) -> Option<isize> {
    let column = column? + cursor_advance(written)?;
    (column >= 0).then_some(column)
}

/// The columns drawn bytes appended at the cursor, or `None` when they are not
/// a plain append. An erase echo fails here on its backspace, on purpose.
fn appended_columns(drawn: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(drawn).ok()?;
    let mut cols = 0;
    for ch in text.chars() {
        cols += usize::from(cell_width(ch)?);
    }
    Some(cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: InputCue = InputCue::Echoing { room: 40 };
    const WIDE: InputCue = InputCue::Echoing { room: 400 };
    const SENT_SEQ: u64 = 1;
    const SENT: Option<CmdSeq> = CmdSeq::from_u64(SENT_SEQ);
    /// Covers [`SENT`], so a prediction the output contradicts is convicted
    /// rather than left pending; tests wanting the other case name their own.
    const ACKED: Option<CmdSeq> = SENT;
    const FLOWING: Typing = Typing::Continuous;

    fn seq(value: u64) -> CmdSeq {
        CmdSeq::from_u64(value).expect("a test sequence is non-zero")
    }

    /// A predictor whose server has acknowledged [`SENT`], which is the order
    /// the reader loop sees for any keystroke that is going to be echoed.
    fn typing() -> Predictor {
        let mut predictor = Predictor::new(Prediction::Adaptive);
        predictor.acknowledged(seq(SENT_SEQ));
        predictor
    }

    /// A run whose first keystroke a line rewrite has already confirmed.
    fn confirmed_run() -> Predictor {
        let mut predictor = typing();
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"\r~ > l", ROOM, ACKED);
        predictor
    }

    /// Seven bytes of password buffered into the run Return opened.
    fn buffered_password() -> Predictor {
        let mut predictor = confirmed_run();
        assert!(
            predictor.predict(b"\r", SENT, FLOWING).is_empty(),
            "Return is how the prompt is reached, and it ends the run"
        );
        for byte in b"hunter2" {
            assert!(
                predictor
                    .predict(std::slice::from_ref(byte), SENT, FLOWING)
                    .is_empty(),
                "a prompt that does not echo never confirms the run typed into it"
            );
        }
        predictor
    }

    /// One drawn prediction under seq 2 with seq 1 acknowledged: the shape
    /// every judgement about a pending prediction is made in.
    fn pending_prediction() -> Predictor {
        let mut predictor = Predictor::new(Prediction::Adaptive);
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        predictor.predict(b"l", Some(seq(1)), FLOWING);
        predictor.acknowledged(seq(1));
        predictor.absorb(b"\r~ > l", ROOM, Some(seq(1)));
        predictor
    }

    /// Confirming a run authorises the next keystroke to draw everything the
    /// run is holding, which at a prompt that never echoes is the password.
    /// A byte in common - leading, or ending a rewrite - is a coincidence.
    #[test]
    fn output_agreeing_with_part_of_the_buffer_releases_no_password() {
        for chunk in [&b"h"[..], b"\rSorry, try again: h"] {
            let mut predictor = buffered_password();
            assert_eq!(
                predictor.absorb(chunk, ROOM, ACKED),
                Absorbed {
                    skip: 0,
                    repair: Repair::None
                },
                "nothing was drawn, so {chunk:?} is written as it stands"
            );
            let drawn = predictor.predict(b"!", SENT, FLOWING);
            assert!(
                drawn.is_empty(),
                "{chunk:?} caught up with one buffered byte of seven; it drew {drawn:?}"
            );
        }
    }

    #[test]
    fn an_untransmitted_prediction_is_never_confirmed() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        assert!(predictor.predict(b"l", None, FLOWING).is_empty());
        assert_eq!(
            predictor.absorb(b"l", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the session printed an `l` of its own accord"
        );
        assert!(
            predictor.predict(b"s", None, FLOWING).is_empty(),
            "which is a coincidence, not the echo of a keystroke never sent"
        );
    }

    /// The echo of the command line's last character arrives in its own frame,
    /// ahead of the prompt asking for a password, and must not confirm the run
    /// that password is being typed into. Either shape of echo.
    #[test]
    fn trust_does_not_launder_across_a_stall() {
        for (echo, skip) in [(&b"o"[..], 1), (&b"\r~ > lo"[..], 0)] {
            let mut predictor = confirmed_run();
            assert_eq!(predictor.predict(b"o", SENT, FLOWING), b"o");
            assert!(
                predictor.predict(b"\r", SENT, FLOWING).is_empty(),
                "Return stalls, and the drawn character stays owed"
            );
            assert!(predictor.predict(b"h", SENT, FLOWING).is_empty());
            assert_eq!(
                predictor.absorb(echo, ROOM, ACKED),
                Absorbed {
                    skip,
                    repair: Repair::None
                },
                "the echo of the command line still suppresses its own drawn byte"
            );
            assert!(
                predictor.predict(b"u", SENT, FLOWING).is_empty(),
                "but it confirms the run it belonged to, not the one typing the password"
            );
        }
    }

    #[test]
    fn an_unanswered_prediction_is_pending_rather_than_wrong() {
        let mut predictor = pending_prediction();
        assert_eq!(predictor.predict(b"s", Some(seq(2)), FLOWING), b"s");
        assert_eq!(
            predictor.absorb(b"...", ROOM, Some(seq(1))),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "output the application produced before it was given seq 2 judges nothing"
        );
        assert_eq!(
            predictor.predict(b"t", Some(seq(3)), FLOWING),
            b"t",
            "and the run survives it"
        );
    }

    /// The same divergence once the server says the application has had the
    /// keystroke. The output that convicts it is ordinary text, so the cells
    /// come off the row from here, at the width they were drawn.
    #[test]
    fn an_answered_prediction_that_diverges_is_undone_at_its_own_width() {
        for (drawn, erase) in [("s", ERASE_ECHO), ("\u{754c}", ERASE_ECHO_WIDE)] {
            let mut predictor = pending_prediction();
            assert_eq!(
                predictor.predict(drawn.as_bytes(), Some(seq(2)), FLOWING),
                drawn.as_bytes()
            );
            assert_eq!(
                predictor.absorb(b"no", ROOM, Some(seq(2))),
                Absorbed {
                    skip: 0,
                    repair: Repair::Local
                }
            );
            assert_eq!(
                predictor.undo(),
                erase,
                "each cell drawn is backed over, blanked and backed over"
            );
        }
    }

    /// An application that falls silent after diverging produces no second
    /// chunk to settle the judgement, so the heartbeat's ack carries it.
    #[test]
    fn a_heartbeat_ack_settles_a_postponed_judgement() {
        let mut predictor = pending_prediction();
        predictor.predict(b"s", Some(seq(2)), FLOWING);
        predictor.absorb(b"...", ROOM, Some(seq(1)));
        assert!(
            !predictor.echo_ack(Some(seq(1))),
            "an ack that still does not cover the keystroke settles nothing"
        );
        assert!(
            predictor.echo_ack(Some(seq(2))),
            "once it does, the drawn character is one the session never sent"
        );
        assert!(
            !predictor.echo_ack(Some(seq(3))),
            "and the run it belonged to is over"
        );
    }

    #[test]
    fn an_echo_cancels_a_postponed_judgement() {
        let mut predictor = pending_prediction();
        predictor.predict(b"s", Some(seq(2)), FLOWING);
        predictor.acknowledged(seq(2));
        predictor.absorb(b"...", ROOM, Some(seq(1)));
        assert_eq!(
            predictor.absorb(b"s", ROOM, Some(seq(2))),
            Absorbed {
                skip: 1,
                repair: Repair::None
            }
        );
        assert!(
            !predictor.echo_ack(Some(seq(9))),
            "there is nothing left to judge"
        );
    }

    /// The cells a run put on the line went with the line when Return
    /// submitted it, so a backspace predicted after the next confirmation must
    /// not reach back into the new prompt.
    #[test]
    fn backspace_cannot_reach_across_a_stall_into_the_prompt() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"a", SENT, FLOWING);
        predictor.absorb(b"a", ROOM, ACKED);
        assert_eq!(predictor.predict(b"b", SENT, FLOWING), b"b");
        predictor.absorb(b"b", ROOM, ACKED);
        assert!(predictor.predict(b"\r", SENT, FLOWING).is_empty());

        predictor.absorb(b"\r\n$ ", ROOM, ACKED);
        predictor.predict(b"x", SENT, FLOWING);
        predictor.absorb(b"x", ROOM, ACKED);
        assert_eq!(predictor.predict(b"\x7f", SENT, FLOWING), ERASE_ECHO);
        assert!(
            predictor.predict(b"\x7f", SENT, FLOWING).is_empty(),
            "only the one cell this run drew may be taken back"
        );
    }

    /// A line editor that rewrites rather than erasing lands on top of the
    /// predicted erase, so the row is correct either way.
    #[test]
    fn a_rewrite_absorbs_a_predicted_erase() {
        let mut predictor = typing();
        predictor.absorb(b"\r$ ab", ROOM, ACKED);
        predictor.predict(b"c", SENT, FLOWING);
        predictor.absorb(b"\r$ abc", ROOM, ACKED);
        assert_eq!(predictor.predict(b"\x7f", SENT, FLOWING), ERASE_ECHO);
        assert_eq!(
            predictor.absorb(b"\r$ ab", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "a rewrite never asks for a repaint"
        );
    }

    /// The rule that keeps a password off the screen without recognising one:
    /// nothing is drawn until the session has confirmed a prediction.
    #[test]
    fn a_confirmed_run_draws_and_suppresses_the_echo() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        assert!(predictor.predict(b"l", SENT, FLOWING).is_empty());
        assert_eq!(
            predictor.absorb(b"l", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "nothing was drawn for the tentative keystroke, so its echo is written"
        );
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        assert_eq!(
            predictor.absorb(b"s", ROOM, ACKED),
            Absorbed {
                skip: 1,
                repair: Repair::None
            },
            "the echo of a drawn prediction is already on the terminal"
        );
    }

    /// Typing faster than the link leaves the echo covering a prefix of what
    /// is owed, which is a coincidence away from covering nothing.
    #[test]
    fn an_echo_the_typing_has_outrun_confirms_nothing() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        assert!(predictor.predict(b"l", SENT, FLOWING).is_empty());
        assert!(predictor.predict(b"s", SENT, FLOWING).is_empty());
        assert_eq!(
            predictor.absorb(b"l", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "one of the two still owed came back"
        );
        assert!(
            predictor.predict(b" ", SENT, FLOWING).is_empty(),
            "which does not confirm the run, so nothing is drawn"
        );
        assert_eq!(
            predictor.absorb(b"s ", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the echo catches up with everything owed, and that does confirm it"
        );
        assert_eq!(predictor.predict(b"x", SENT, FLOWING), b"x");
    }

    /// Suppression is not gated on confirmation: a run whose echo arrives in
    /// two chunks would otherwise have the first written a second time.
    #[test]
    fn a_partial_echo_of_a_drawn_run_is_still_suppressed() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"l", ROOM, ACKED);
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        assert_eq!(predictor.predict(b"t", SENT, FLOWING), b"t");
        assert_eq!(
            predictor.absorb(b"s", ROOM, ACKED),
            Absorbed {
                skip: 1,
                repair: Repair::None
            }
        );
        assert_eq!(
            predictor.absorb(b"t", ROOM, ACKED),
            Absorbed {
                skip: 1,
                repair: Repair::None
            }
        );
    }

    #[test]
    fn unpredicted_output_ends_the_run() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"l", ROOM, ACKED);
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        assert_eq!(
            predictor.absorb(b"[1]+ Done\r\n", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::Local
            },
            "the chunk opens with a printable byte, so the cursor is still on the cell"
        );
        assert_eq!(predictor.undo(), ERASE_ECHO);
        assert!(
            predictor.predict(b"t", SENT, FLOWING).is_empty(),
            "the next run starts tentative again"
        );
    }

    /// The same divergence costs nothing when the run never drew anything.
    #[test]
    fn a_tentative_run_diverges_for_free() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        assert_eq!(
            predictor.absorb(b"\x1b[32ml\x1b[0m", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            }
        );
        assert!(predictor.predict(b"s", SENT, FLOWING).is_empty());
    }

    #[test]
    fn an_opaque_cue_refuses_every_keystroke() {
        let mut predictor = typing();
        predictor.absorb(b"l", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"l", ROOM, ACKED);
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        // The application took the alternate screen.
        predictor.absorb(b"\x1b[?1049h", InputCue::Opaque, ACKED);
        assert!(predictor.predict(b"i", SENT, FLOWING).is_empty());
    }

    #[test]
    fn the_last_cell_of_a_row_is_never_predicted_into() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", InputCue::Echoing { room: 2 }, ACKED);
        predictor.predict(b"a", SENT, FLOWING);
        predictor.absorb(b"a", InputCue::Echoing { room: 1 }, ACKED);
        assert_eq!(predictor.predict(b"b", SENT, FLOWING), b"b");
        predictor.absorb(b"b", InputCue::Echoing { room: 0 }, ACKED);
        assert!(
            predictor.predict(b"c", SENT, FLOWING).is_empty(),
            "no room left before the last cell"
        );
    }

    /// `room` describes the server's column count, which a resize has just
    /// invalidated: predicting against it draws past the new right margin.
    #[test]
    fn a_resize_refuses_the_width_the_cue_still_describes() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"l", ROOM, ACKED);
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        predictor.absorb(b"s", ROOM, ACKED);

        predictor.resized();
        assert!(
            predictor.predict(b"t", SENT, FLOWING).is_empty(),
            "nothing is predicted until a cue measured against the new width"
        );
    }

    #[test]
    fn a_control_byte_is_never_predicted() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"l", ROOM, ACKED);
        assert!(
            predictor.predict(b"\r", SENT, FLOWING).is_empty(),
            "only a scalar of known width has a knowable effect on the cursor"
        );
        assert!(predictor.predict(b"\x1b[A", SENT, FLOWING).is_empty());
    }

    /// A scalar past `0x7f` is predicted like any other - stalling on one
    /// costs a French or CJK user a round trip per character - and the erase
    /// that takes it back is its own width, not one column. Without a
    /// prediction for backspace its echo matches nothing outstanding, and
    /// `repair` asks for a whole screen once per keystroke on a slow link.
    #[test]
    fn a_scalar_is_predicted_and_erased_at_its_own_width() {
        for (first, second, erase) in [
            ("a", "b", ERASE_ECHO),
            ("é", "è", ERASE_ECHO),
            ("世", "界", ERASE_ECHO_WIDE),
        ] {
            let mut predictor = typing();
            predictor.absorb(b"$ ", ROOM, ACKED);
            predictor.predict(first.as_bytes(), SENT, FLOWING);
            predictor.absorb(first.as_bytes(), ROOM, ACKED);
            assert_eq!(
                predictor.predict(second.as_bytes(), SENT, FLOWING),
                second.as_bytes(),
                "the run is confirmed, so {second:?} is drawn"
            );
            assert_eq!(
                predictor.absorb(second.as_bytes(), ROOM, ACKED),
                Absorbed {
                    skip: second.len(),
                    repair: Repair::None
                },
                "its echo is the bytes it was drawn as"
            );
            assert_eq!(predictor.predict(b"\x7f", SENT, FLOWING), erase);
            assert_eq!(
                predictor.absorb(erase, ROOM, ACKED),
                Absorbed {
                    skip: erase.len(),
                    repair: Repair::None
                },
                "the erase is already on the terminal, and no repaint is owed"
            );
            assert_eq!(
                predictor.predict(b"\x7f", SENT, FLOWING),
                erase,
                "and so is taking back the one before it"
            );
            assert!(
                predictor.predict(b"\x7f", SENT, FLOWING).is_empty(),
                "with nothing this run drew left to erase"
            );
        }
    }

    /// The budget is counted in bytes and the cue in columns: every two-cell
    /// scalar is three or more bytes of UTF-8, so the last cell stays free.
    #[test]
    fn a_wide_scalar_is_refused_when_the_row_is_nearly_full() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"a", SENT, FLOWING);
        predictor.absorb(b"a", InputCue::Echoing { room: 2 }, ACKED);
        assert!(
            predictor.predict("世".as_bytes(), SENT, FLOWING).is_empty(),
            "two columns free is not enough for a glyph the budget counts in bytes"
        );
    }

    #[test]
    fn a_scalar_of_no_modellable_width_stalls_the_run() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"a", SENT, FLOWING);
        predictor.absorb(b"a", ROOM, ACKED);
        assert!(
            predictor
                .predict("\u{301}".as_bytes(), SENT, FLOWING)
                .is_empty(),
            "a combining mark belongs to the cell before it, which may not be ours"
        );
        assert!(
            predictor.predict(b"b", SENT, FLOWING).is_empty(),
            "and the run it ended stays tentative until the session confirms one again"
        );
    }

    /// An inverted range, or one overlapping its neighbour, would refuse
    /// scalars nobody meant to refuse - and every refusal is a round trip.
    #[test]
    fn the_folding_table_is_sorted_and_disjoint() {
        for &(first, last) in &FOLDS_INTO_NEIGHBOUR {
            assert!(first <= last, "range {first:?}..={last:?} is inverted");
        }
        for pair in FOLDS_INTO_NEIGHBOUR.windows(2) {
            assert!(
                pair[0].1 < pair[1].0,
                "{pair:?} is out of order or overlaps"
            );
        }
    }

    /// The width table's boundaries decide whether a keystroke is drawn at
    /// all. The scripts an allowlist of Latin, Greek and Cyrillic would have
    /// left out are here on purpose: a refusal costs a round trip.
    #[test]
    fn the_width_table_names_what_it_will_and_will_not_place() {
        for (ch, cells) in [
            ('a', Some(1)),
            (' ', Some(1)),
            ('~', Some(1)),
            ('é', Some(1)),
            ('ẞ', Some(1)),
            ('Ω', Some(1)),
            ('б', Some(1)),
            ('क', Some(1)),
            ('ع', Some(1)),
            ('א', Some(1)),
            ('ก', Some(1)),
            ('ա', Some(1)),
            ('ბ', Some(1)),
            ('ሀ', Some(1)),
            ('ᐃ', Some(1)),
            ('ក', Some(1)),
            ('世', Some(2)),
            ('界', Some(2)),
            ('あ', Some(2)),
            ('ア', Some(2)),
            ('한', Some(2)),
            ('글', Some(2)),
            ('，', Some(2)),
            ('Ａ', Some(2)),
            ('⌚', Some(2)),
            ('🙂', Some(2)),
            ('🚀', Some(2)),
            // The first jamo, the last of the initials, and the medial after
            // them, which composes into the syllable before it.
            ('\u{1100}', Some(2)),
            ('\u{115f}', Some(2)),
            ('\u{1160}', None),
            // The last fullwidth form and the halfwidth one after it.
            ('\u{ff60}', Some(2)),
            ('\u{ff61}', Some(1)),
            // A combining mark, an emoji modifier, a regional indicator, a
            // joiner, a filler, a variation selector and a control byte.
            ('\u{301}', None),
            ('\u{1f3fb}', None),
            ('\u{1f1e6}', None),
            ('\u{200d}', None),
            ('\u{3164}', None),
            ('\u{fe0f}', None),
            ('\u{7}', None),
            // Three cells, which no two terminals place alike.
            ('\u{17d8}', None),
        ] {
            assert_eq!(cell_width(ch), cells, "{ch:?}");
        }
    }

    /// A paste is not typing: it outruns any echo that could answer it, and
    /// two hundred wrong characters cost a whole screen to take back.
    #[test]
    fn a_paste_is_drawn_at_the_cap_and_refused_over_it() {
        let wide = InputCue::Echoing { room: 1000 };
        for (cells, drawn) in [(PASTE_CELLS, true), (PASTE_CELLS + 1, false)] {
            let mut predictor = typing();
            predictor.absorb(b"$ ", wide, ACKED);
            predictor.predict(b"a", SENT, FLOWING);
            predictor.absorb(b"a", wide, ACKED);

            let paste = vec![b'x'; cells];
            assert_eq!(
                predictor.predict(&paste, SENT, FLOWING) == paste.as_slice(),
                drawn,
                "the row had room for {cells} cells, so only the cap can refuse them"
            );
        }
    }

    /// A repaint replaces the whole screen, so it needs no help; a delta
    /// carries only what the session changed, so it does.
    #[test]
    fn invalidating_reports_whether_a_prediction_is_still_on_screen() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        assert!(!predictor.invalidate(), "nothing was drawn");
        predictor.absorb(b"l", ROOM, ACKED);
        predictor.predict(b"s", SENT, FLOWING);
        predictor.absorb(b"s", ROOM, ACKED);
        assert_eq!(predictor.predict(b"t", SENT, FLOWING), b"t");
        assert!(predictor.invalidate());
    }

    /// A line editor never sends a keystroke back: it rewrites the line, and
    /// the rewrite is the echo - the byte stream `fish` produces per keystroke.
    #[test]
    fn a_line_rewrite_confirms_the_predictions_it_ends_with() {
        let mut predictor = typing();
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        assert!(
            predictor.predict(b"g", SENT, FLOWING).is_empty(),
            "the run is tentative"
        );
        assert_eq!(
            predictor.absorb(b"\r~ > g", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the rewrite carries the row, so it is written as it stands"
        );
        assert_eq!(
            predictor.predict(b"i", SENT, FLOWING),
            b"i",
            "the run is confirmed and the next keystroke is drawn"
        );
        assert_eq!(
            predictor.absorb(b"\r~ > gi", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "a rewrite lands on top of the prediction rather than doubling it"
        );
        assert_eq!(predictor.predict(b"t", SENT, FLOWING), b"t");
    }

    #[test]
    fn a_rewrite_confirms_only_as_far_as_it_has_caught_up() {
        let mut predictor = confirmed_run();
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        predictor.predict(b" ", SENT, FLOWING);
        assert_eq!(
            predictor.absorb(b"\r~ > ls", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            }
        );
        assert_eq!(
            predictor.predict(b"x", SENT, FLOWING),
            b" x",
            "the space the rewrite had not reached is still owed to the terminal"
        );
    }

    /// Every password prompt is reached by pressing Return, and Return is a
    /// keystroke this side cannot model: the run ends there.
    #[test]
    fn return_ends_the_run_before_the_prompt_it_reaches() {
        let mut predictor = confirmed_run();
        assert_eq!(predictor.predict(b"o", SENT, FLOWING), b"o");
        predictor.absorb(b"\r~ > lo", ROOM, ACKED);
        assert!(predictor.predict(b"\r", SENT, FLOWING).is_empty());
        predictor.absorb(b"\r\n[sudo] password for u: ", ROOM, ACKED);
        assert!(
            predictor.predict(b"h", SENT, FLOWING).is_empty(),
            "the first keystroke of the password is not drawn"
        );
        assert!(predictor.predict(b"u", SENT, FLOWING).is_empty());
    }

    /// The echo runs a round trip behind the typing, so a rewrite that has
    /// caught up with none of it is not a reason to stop predicting.
    #[test]
    fn a_rewrite_behind_the_typing_keeps_the_run() {
        let mut predictor = confirmed_run();
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        assert_eq!(
            predictor.absorb(b"\r~ > l", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the rewrite covers the row, so the drawn prediction needs no repaint"
        );
        assert_eq!(
            predictor.predict(b" ", SENT, FLOWING),
            b"s ",
            "the keystroke the rewrite had not reached is drawn again with it"
        );
    }

    /// A carriage return that opens a new line is output, not a rewrite, and
    /// an escape has moved the cursor somewhere this side cannot follow:
    /// backing over the cells this run drew would blank someone else's.
    #[test]
    fn output_that_moves_the_cursor_is_repaired_by_a_screen() {
        for chunk in [&b"\r\nfile\r\n$ "[..], b"\x1b[2;5Hgone"] {
            let mut predictor = confirmed_run();
            assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
            assert_eq!(
                predictor.absorb(chunk, ROOM, ACKED),
                Absorbed {
                    skip: 0,
                    repair: Repair::Repaint
                },
                "{chunk:?}"
            );
            assert!(
                predictor.undo().is_empty(),
                "a repaint offers no bytes to write"
            );
        }
    }

    /// This side kept the width of the character an erase echo deleted but
    /// never the character, so the undo would blank a cell that held a letter.
    #[test]
    fn a_drawn_erase_echo_cannot_be_undone_locally() {
        let mut predictor = typing();
        predictor.absorb(b"$ ", ROOM, ACKED);
        predictor.predict(b"a", SENT, FLOWING);
        predictor.absorb(b"a", ROOM, ACKED);
        assert_eq!(predictor.predict(b"b", SENT, FLOWING), b"b");
        assert_eq!(predictor.predict(b"\x7f", SENT, FLOWING), ERASE_ECHO);
        assert_eq!(
            predictor.absorb(b"nope", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::Repaint
            }
        );
    }

    /// A rewrite restating nothing still owed is placed by its extent. A
    /// progress counter narrower than the drawn cells leaves them standing
    /// while `drawn` says they are gone, so their echo would double them; the
    /// erase a real redraw ends with takes them off whatever the columns say;
    /// and a ZWJ family charged its scalars' widths names no column at all.
    #[test]
    fn a_rewrite_is_trusted_only_where_it_accounts_for_the_drawn_run() {
        for (drawn, rewrite, repair) in [
            (40, &b"\r 34%  1.2MB/s"[..], Repair::Repaint),
            (40, &b"\r 34%\x1b[K"[..], Repair::None),
            (
                5,
                "\r\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}> ".as_bytes(),
                Repair::Repaint,
            ),
        ] {
            let mut predictor = typing();
            predictor.absorb(b"\r$ ", WIDE, ACKED);
            predictor.predict(b"x", SENT, FLOWING);
            predictor.absorb(b"\r$ x", WIDE, ACKED);
            let typed = vec![b'y'; drawn];
            assert_eq!(predictor.predict(&typed, SENT, FLOWING), typed.as_slice());
            assert_eq!(
                predictor.absorb(rewrite, WIDE, ACKED),
                Absorbed { skip: 0, repair },
                "{rewrite:?} against {drawn} drawn columns"
            );
        }
    }

    /// The extent is this module's only cursor claim, so a scalar the width
    /// table sizes on its own and the terminal sizes as part of a cluster has
    /// to refuse it rather than be counted at some convenient number.
    #[test]
    fn a_rewrite_holding_a_cluster_this_side_cannot_size_names_no_column() {
        assert_eq!(rewrite_extent(b"\r$ done").cols, Some(6));
        assert_eq!(
            rewrite_extent("\r\u{1f1e8}\u{1f1e6}> ".as_bytes()).cols,
            None,
            "a regional-indicator pair is a two-cell flag, not two cells of nothing"
        );
        assert_eq!(
            rewrite_extent("\r\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}> ".as_bytes()).cols,
            None,
            "a ZWJ family is one two-cell cluster, not six cells"
        );
    }

    /// The cost the extent guard must not charge, measured against a real
    /// `fish` over a 200 ms link: a typist outruns the redraws, and the second
    /// of two identical ones restates nothing still owed because the first
    /// drained it. Judged on width alone every one is a whole screen.
    #[test]
    fn a_line_editor_redrawing_behind_the_typing_costs_no_repaint() {
        let mut predictor = typing();
        // Four columns of prompt and the keystroke whose redraw confirms the
        // run: the cursor stands in column five.
        predictor.absorb(b"\r~ > ", WIDE, ACKED);
        predictor.predict(b"t", SENT, FLOWING);
        predictor.absorb(b"\r~ > t", WIDE, ACKED);
        assert_eq!(predictor.predict(b"ouch", SENT, FLOWING), b"ouch");
        assert_eq!(
            predictor.absorb(b"\r~ > t", WIDE, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "a redraw that stops where the drawn cells begin painted over none"
        );
        assert_eq!(
            predictor.predict(b" /tmp", SENT, FLOWING),
            b"ouch /tmp",
            "the cells it stopped short of are written again where they stand"
        );
        assert_eq!(
            predictor.absorb(b"\r~ > touch", WIDE, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "nine columns, four of which the run still owed"
        );
        assert_eq!(
            predictor.predict(b"/brd_mark_PREDICT", SENT, FLOWING),
            b" /tmp/brd_mark_PREDICT"
        );
        assert_eq!(
            predictor.absorb(b"\r~ > touch", WIDE, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the same nine columns again, with twenty-two drawn past them"
        );
        assert_eq!(
            predictor.absorb(b"\r~ > touch /tmp/brd_mark_PREDICT", WIDE, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "the redraw that has caught up carries the whole line"
        );
        assert_eq!(
            predictor.column,
            Some(31),
            "the cursor stands where the line the session drew ends"
        );
        assert_eq!(
            predictor.predict(b"!", SENT, FLOWING),
            b"!",
            "the run owes the terminal nothing, so nothing is drawn twice"
        );
    }

    /// The input thread draws under `try_lock` and gives up when the reader
    /// holds it - which is exactly while a command line's echo and the
    /// `Password:` below it are being painted. Miss it on Return and the run
    /// stays confirmed into the next line.
    #[test]
    fn a_keystroke_that_missed_the_display_lock_ends_the_run() {
        let mut predictor = confirmed_run();
        assert_eq!(predictor.predict(b"o", SENT, FLOWING), b"o");
        predictor.absorb(b"\r~ > lo", ROOM, ACKED);
        assert!(
            predictor
                .predict(b"h", SENT, Typing::Interrupted)
                .is_empty(),
            "the first byte of the password is not drawn"
        );
        assert!(
            predictor.predict(b"u", SENT, FLOWING).is_empty(),
            "and the run the missed keystroke ended stays over"
        );
    }

    /// `never` is a display choice, not a licence to lose track of a run's end.
    #[test]
    fn refusing_to_draw_still_ends_a_run_and_suppresses_nothing() {
        let mut predictor = Predictor::new(Prediction::Never);
        predictor.acknowledged(seq(SENT_SEQ));
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"\r~ > l", ROOM, ACKED);
        assert!(
            predictor.predict(b"s", SENT, FLOWING).is_empty(),
            "the run is confirmed and the keystroke is still not drawn"
        );
        assert_eq!(
            predictor.absorb(b"s", ROOM, ACKED),
            Absorbed {
                skip: 0,
                repair: Repair::None
            },
            "nothing was drawn, so the echo is written and nothing is repaired"
        );
    }

    #[test]
    fn always_draws_on_a_link_the_gate_would_close() {
        let mut predictor = Predictor::new(Prediction::Always);
        predictor.acknowledged(seq(SENT_SEQ));
        predictor.observed_rtt(Some(Duration::from_millis(1)));
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"\r~ > l", ROOM, ACKED);
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
    }

    /// The gap between the two thresholds is where nothing changes: a link
    /// jittering across one value would turn predictions on and off mid-word.
    #[test]
    fn the_latency_gate_needs_more_to_open_than_it_needs_to_stay_open() {
        let mut predictor = typing();
        predictor.observed_rtt(Some(Duration::from_millis(5)));
        predictor.absorb(b"\r~ > ", ROOM, ACKED);
        predictor.predict(b"l", SENT, FLOWING);
        predictor.absorb(b"\r~ > l", ROOM, ACKED);
        assert!(
            predictor.predict(b"s", SENT, FLOWING).is_empty(),
            "a five millisecond link has no round trip worth hiding"
        );
        predictor.absorb(b"\r~ > ls", ROOM, ACKED);

        predictor.observed_rtt(Some(Duration::from_millis(25)));
        assert!(
            predictor.predict(b" ", SENT, FLOWING).is_empty(),
            "twenty-five is inside the gap, so nothing has changed"
        );
        predictor.absorb(b"\r~ > ls ", ROOM, ACKED);

        predictor.observed_rtt(Some(Duration::from_millis(60)));
        assert_eq!(predictor.predict(b"x", SENT, FLOWING), b"x");
    }

    /// Closing waits for the row to be clear, so a link that speeds up
    /// mid-word never leaves half of it undrawn behind an echo in flight.
    #[test]
    fn the_latency_gate_will_not_close_over_a_drawn_prediction() {
        let mut predictor = confirmed_run();
        assert_eq!(predictor.predict(b"s", SENT, FLOWING), b"s");
        predictor.observed_rtt(Some(Duration::from_millis(2)));
        assert_eq!(
            predictor.predict(b"t", SENT, FLOWING),
            b"t",
            "a cell of this run is still on the terminal"
        );
        predictor.absorb(b"\r~ > lst", ROOM, ACKED);
        predictor.observed_rtt(Some(Duration::from_millis(2)));
        assert!(
            predictor.predict(b"x", SENT, FLOWING).is_empty(),
            "and once it is clear the gate closes"
        );
    }

    /// xorshift64, seeded so a failure reproduces exactly.
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

        /// Three letters: borders and near-misses are the whole of what the
        /// automaton has to get right, and random bytes never share a prefix.
        fn letter(&mut self) -> u8 {
            b'a' + u8::try_from(self.below(3)).expect("a value below three")
        }
    }

    /// What [`Predictor::restated_tail`] means, spelled out: the longest
    /// suffix of the rewrite that is a prefix of what is still owed.
    fn naive_tail(owed: &[u8], rewrite: &[u8]) -> usize {
        (1..=owed.len().min(rewrite.len()))
            .rev()
            .find(|&length| rewrite[rewrite.len() - length..] == owed[..length])
            .unwrap_or(0)
    }

    /// One predictor throughout, so the reused failure buffer is exercised.
    #[test]
    fn the_linear_rewrite_match_agrees_with_the_search_it_replaced() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut predictor = Predictor::new(Prediction::Adaptive);
        for _ in 0..2_000 {
            let owed: Vec<u8> = (0..rng.below(21)).map(|_| rng.letter()).collect();
            let rewrite: Vec<u8> = (0..rng.below(33)).map(|_| rng.letter()).collect();
            predictor.outstanding = owed
                .iter()
                .map(|&byte| Pending {
                    byte,
                    epoch: 1,
                    sent_as: None,
                    drawn: false,
                })
                .collect();
            assert_eq!(
                predictor.restated_tail(&rewrite),
                naive_tail(&owed, &rewrite),
                "owed {owed:?}, rewrite {rewrite:?}"
            );
        }
    }
}
