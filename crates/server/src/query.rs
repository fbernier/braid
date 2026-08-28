#![forbid(unsafe_code)]
// One spelling per item: `pub` where `braid-fuzz` reaches it and nowhere else,
// because without that feature the module itself is private.
#![cfg_attr(not(feature = "fuzzing"), allow(unreachable_pub))]

//! Terminal queries the emulator answered, cut from what a client sees.
//!
//! A query an application makes of its terminal — Device Attributes, a cursor
//! report — may be answered here by [`braid_vt`], and the reply goes to the
//! PTY. Those same query bytes are in the PTY's output, so forwarding the
//! output verbatim asks the *client's* terminal the question a second time and
//! its answer lands on the user's screen: a full-screen application's startup
//! `CSI c` left `?62;22c` on the prompt exactly so.
//!
//! What may not happen is the reverse. A query the emulator does *not* answer
//! has to reach the client, whose terminal will: that leak is the only reason
//! `OSC 11` background-colour detection and XTGETTCAP work at all here, since
//! libghostty-vt exposes no callback to answer either. Cutting one of those
//! turns a working capability into an application waiting for a reply that
//! will never come.
//!
//! So nothing in this module names a query. A sequence is cut on exactly one
//! signal — the emulator wrote a reply while consuming it — which is the same
//! fact the client's terminal would otherwise act on. A list of query shapes
//! kept here by hand would be a second answer to a question [`braid_vt`]
//! already answers, and the two would drift.

/// Whether handing a span of output to the emulator made it answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// The emulator wrote nothing back, so these bytes are the application's
    /// output and belong to the client.
    Silent,
    /// The emulator replied on the PTY, so this span carried a query it owns.
    Replied,
}

/// The emulator, as the filter drives it.
///
/// The filter hands over every byte exactly once and in order, splitting the
/// stream only where it needs to know who a reply belonged to.
pub trait Emulator {
    type Error;

    /// Consume `bytes` and report whether consuming them produced a reply.
    fn consume(&mut self, bytes: &[u8]) -> Result<Answer, Self::Error>;
}

/// How far the scanner has read into an escape sequence.
///
/// A single sequence can arrive in two pieces, split across two chunks of PTY
/// output. The scanner keeps its position here between chunks, so a query cut
/// in half is still recognised as one query rather than let through as text.
enum Scan {
    /// Not inside a sequence.
    Ground,
    /// Just saw `ESC`; the next byte says what kind of sequence this is.
    Escape,
    /// Inside a CSI (`ESC [ ...`), reading up to its final byte.
    Csi,
    /// Inside a control string, reading up to `BEL`, `ESC \` or the C0 that
    /// means it was never terminated.
    String,
    /// Inside a control string and just saw `ESC`: a `\` next ends it, anything
    /// else means it was never terminated.
    StringEscape,
}

/// What the scanner did with one byte.
enum Mark {
    /// Ordinary output, or a byte of the sequence being scanned. Either way
    /// the scanner has placed it and the caller only advances.
    Consumed,
    /// The sequence being scanned ends with this byte.
    Boundary,
    /// The sequence ends before this byte, which is an `ESC` opening the next.
    OpenerHere,
    /// The sequence ends before the `ESC` already held, which opens the next
    /// one; this byte has not been placed and must be stepped again.
    OpenerHeld,
}

/// How many bytes of one sequence the scanner will buffer before giving up.
///
/// A sequence that opens but never ends would otherwise grow the buffer for the
/// life of the session. Once a sequence reaches this length the scanner stops
/// buffering it and lets the rest through as ordinary bytes.
pub const SCAN_LIMIT: usize = 4096;

/// Removes the terminal queries the emulator answers from a forwarded stream.
///
/// Feed it the PTY output a client would be sent, along with the emulator that
/// output is going to; it returns the same bytes with the emulator-answered
/// queries removed. It only keeps state while a sequence is split across a
/// chunk boundary; on ordinary output it keeps none.
pub struct QueryFilter {
    scan: Scan,
    /// The bytes of the sequence read so far. When the sequence ends it is
    /// either dropped (the emulator answered it) or written out unchanged.
    pending: Vec<u8>,
    /// Set once the current sequence reaches [`SCAN_LIMIT`]. From then on its
    /// bytes are written straight to the output instead of buffered, and
    /// `pending` is empty because there is no longer anything to decide.
    overrun: bool,
    /// The emulator answered bytes of the sequence still open. A control string
    /// is dispatched at the `ESC` that ends it, so a chunk boundary between
    /// that `ESC` and its `\` produces the reply a whole chunk before the byte
    /// this scanner settles the sequence on.
    answered: bool,
}

impl Default for QueryFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryFilter {
    const ESC: u8 = 0x1b;
    const ENQ: u8 = 0x05;

    #[must_use]
    pub fn new() -> Self {
        Self {
            scan: Scan::Ground,
            pending: Vec::new(),
            overrun: false,
            answered: false,
        }
    }

    /// Bytes of an unfinished sequence being kept from the client until the
    /// emulator has seen its end.
    ///
    /// This is the filter's whole contribution to latency, which is why it is
    /// bounded: an unterminated sequence stops being held at [`SCAN_LIMIT`],
    /// and every state that cannot reach a terminator ends on the first C0.
    /// Nothing in the daemon reads it - it exists so the test and the fuzz
    /// target can hold that bound to account.
    #[cfg(any(test, feature = "fuzzing"))]
    #[must_use]
    pub fn held(&self) -> usize {
        self.pending.len()
    }

    /// Hand `bytes` to `emulator` and return what the client is sent.
    ///
    /// The result borrows `bytes` when the chunk opened no sequence at all, and
    /// `out` otherwise; `out` is the caller's reused buffer. A sequence still
    /// unfinished when `bytes` ends is not written out: it stays buffered for
    /// the next call, because whether to drop it is not known until the
    /// emulator has seen its final byte.
    pub fn filter<'a, E: Emulator>(
        &mut self,
        bytes: &'a [u8],
        out: &'a mut Vec<u8>,
        emulator: &mut E,
    ) -> Result<&'a [u8], E::Error> {
        // Bulk output opens no sequence: nothing to attribute, nothing to cut,
        // and the client is sent the caller's own slice rather than a copy.
        // The offset is carried into the loop rather than found again, which
        // would rescan the whole run up to it.
        let mut index = match self.scan {
            Scan::Ground => match find_opener(bytes) {
                None => {
                    emulator.consume(bytes)?;
                    return Ok(bytes);
                }
                Some(opener) => opener,
            },
            _ => 0,
        };
        out.clear();
        out.extend_from_slice(&bytes[..index]);
        // Bytes of this chunk the emulator has not been given yet. Every byte
        // is handed over exactly once, in order; the spans only decide how
        // finely a reply can be attributed.
        let mut unfed = 0;
        while index < bytes.len() {
            // Even a screen dense in escape sequences is mostly the text
            // between them, and that text is a copy, not a decision.
            if matches!(self.scan, Scan::Ground) {
                let Some(opener) = find_opener(&bytes[index..]) else {
                    out.extend_from_slice(&bytes[index..]);
                    break;
                };
                out.extend_from_slice(&bytes[index..index + opener]);
                index += opener;
            }
            match self.step(bytes[index], out) {
                Mark::Consumed => index += 1,
                Mark::Boundary => {
                    index += 1;
                    self.settle(&bytes[unfed..index], out, emulator)?;
                    unfed = index;
                }
                Mark::OpenerHere => {
                    self.settle(&bytes[unfed..index], out, emulator)?;
                    unfed = index;
                    self.open();
                    index += 1;
                }
                Mark::OpenerHeld => {
                    // The `ESC` closing the buffer belongs to what comes next,
                    // not to the sequence it broke off.
                    self.unhold(out);
                    self.settle(&bytes[unfed..index], out, emulator)?;
                    unfed = index;
                    self.open();
                }
            }
        }
        // The tail: ordinary output already in `out`, and at most one sequence
        // still open, whose bytes stay held for the chunk that finishes it. Its
        // answer is carried rather than discarded, because the emulator may
        // have replied to what it has seen of the sequence so far.
        if unfed < bytes.len() {
            self.answered |= emulator.consume(&bytes[unfed..])? == Answer::Replied;
        }
        Ok(out.as_slice())
    }

    /// Whether a byte can open something the emulator might answer.
    ///
    /// Only `ESC` and `ENQ`: libghostty-vt parses in UTF-8, where the 8-bit C1
    /// introducers are not control bytes, which the test
    /// `the_fast_path_skips_nothing_the_emulator_answers` holds it to.
    const fn opens(byte: u8) -> bool {
        matches!(byte, Self::ESC | Self::ENQ)
    }

    fn step(&mut self, byte: u8, out: &mut Vec<u8>) -> Mark {
        match self.scan {
            Scan::Ground => match byte {
                // A one-byte query. Held like any other sequence so that the
                // emulator, not this module, decides whether it is one.
                Self::ENQ => {
                    self.begin(byte);
                    Mark::Boundary
                }
                Self::ESC => {
                    self.open();
                    Mark::Consumed
                }
                _ => {
                    out.push(byte);
                    Mark::Consumed
                }
            },
            // The one byte here that is not held: it opens the next sequence
            // rather than belonging to this one.
            Scan::Escape if byte == Self::ESC => Mark::OpenerHere,
            Scan::Escape => {
                self.hold(byte, out);
                match byte {
                    b'[' => {
                        self.scan = Scan::Csi;
                        Mark::Consumed
                    }
                    // Every control string: OSC, DCS, SOS, PM and APC. They
                    // differ in what the emulator does with the body and not at
                    // all in where the body ends, and one it answers - a kitty
                    // graphics query is an APC - has to be cut whole or the
                    // client is left holding an unterminated string that eats
                    // the rest of its screen.
                    b']' | b'P' | b'X' | b'^' | b'_' => {
                        self.scan = Scan::String;
                        Mark::Consumed
                    }
                    // A two-byte escape. `ESC Z` is DECID, which is answered,
                    // so this ends a sequence like any other rather than
                    // passing straight through.
                    _ => Mark::Boundary,
                }
            }
            // A CSI ends on its final byte (0x40..=0x7e). Parameter and
            // intermediate bytes (0x20..=0x3f) keep it open. A C0 in the middle
            // is held with the sequence rather than executed where it stands:
            // moving it ahead of the sequence it sits inside would reorder the
            // client's stream, and no application puts one there.
            Scan::Csi => {
                self.hold(byte, out);
                if (0x40..=0x7e).contains(&byte) {
                    Mark::Boundary
                } else {
                    Mark::Consumed
                }
            }
            Scan::String => {
                self.hold(byte, out);
                match byte {
                    Self::ESC => {
                        self.scan = Scan::StringEscape;
                        Mark::Consumed
                    }
                    // `BEL` ends an OSC, and the emulator abandons a string of
                    // any kind on any other C0, so the scanner has to end one
                    // here too or its spans stop matching the emulator's. It is
                    // also what keeps a stray `ESC P` from holding the client's
                    // output back until SCAN_LIMIT bytes arrive, which on an
                    // interactive screen is a freeze.
                    0x00..=0x1f => Mark::Boundary,
                    _ => Mark::Consumed,
                }
            }
            Scan::StringEscape => {
                if byte == b'\\' {
                    self.hold(byte, out);
                    Mark::Boundary
                } else {
                    // `ESC` not followed by `\` is not an ST. The emulator ends
                    // the string at that `ESC` and reads it as the start of the
                    // next sequence, so the scanner has to as well - reading it
                    // as part of this one loses whatever follows.
                    Mark::OpenerHeld
                }
            }
        }
    }

    /// Start buffering a new sequence, `byte` being its first byte.
    fn begin(&mut self, byte: u8) {
        self.pending.clear();
        self.overrun = false;
        self.answered = false;
        self.pending.push(byte);
    }

    /// Begin a sequence at an `ESC` and read what introduces it next.
    fn open(&mut self) {
        self.begin(Self::ESC);
        self.scan = Scan::Escape;
    }

    /// Buffer one byte of the sequence being scanned, keeping the buffer bounded.
    fn hold(&mut self, byte: u8, out: &mut Vec<u8>) {
        if !self.overrun && self.pending.len() < SCAN_LIMIT {
            self.pending.push(byte);
            return;
        }
        if !self.overrun {
            // Over the limit: stop deciding. Write what was held so far and let
            // the rest through as plain bytes. Nothing an emulator answers is
            // four kilobytes long.
            self.overrun = true;
            out.append(&mut self.pending);
        }
        out.push(byte);
    }

    /// Take back the byte [`hold`](Self::hold) last placed: an `ESC` that turns
    /// out to open the next sequence rather than close this one. It went to
    /// `out` rather than `pending` if the sequence had already overrun, and
    /// popping the wrong one of the two sends the client an `ESC` twice.
    fn unhold(&mut self, out: &mut Vec<u8>) {
        if self.overrun {
            out.pop();
        } else {
            self.pending.pop();
        }
    }

    /// The sequence has ended on `span`'s last byte: drop it if the emulator
    /// answered, otherwise pass it through unchanged.
    fn settle<E: Emulator>(
        &mut self,
        span: &[u8],
        out: &mut Vec<u8>,
        emulator: &mut E,
    ) -> Result<(), E::Error> {
        let answered = emulator.consume(span)? == Answer::Replied || self.answered;
        // An overran sequence is already in `out` byte by byte, so `pending` is
        // empty and there is nothing left to drop even if the emulator answered.
        if !answered {
            out.extend_from_slice(&self.pending);
        }
        self.scan = Scan::Ground;
        self.pending.clear();
        self.overrun = false;
        self.answered = false;
        Ok(())
    }
}

/// Where the next byte that can open a sequence is, if there is one.
///
/// A word at a time, because the state machine above is a byte at a time and
/// almost every byte of a terminal's output is neither of the two that matter.
/// The kernel is the usual zero-byte search: subtracting `0x01` from a lane
/// borrows into its high bit exactly when the lane is zero, and `& !value`
/// discards the lanes that had that bit set already.
fn find_opener(bytes: &[u8]) -> Option<usize> {
    const LANES: usize = size_of::<u64>();
    const LOW: u64 = u64::from_ne_bytes([0x01; LANES]);
    const HIGH: u64 = u64::from_ne_bytes([0x80; LANES]);
    const ESCAPES: u64 = u64::from_ne_bytes([QueryFilter::ESC; LANES]);
    const ENQUIRIES: u64 = u64::from_ne_bytes([QueryFilter::ENQ; LANES]);

    let (words, remainder) = bytes.as_chunks::<LANES>();
    let mut offset = 0;
    for &word in words {
        let value = u64::from_ne_bytes(word);
        let escapes = value ^ ESCAPES;
        let enquiries = value ^ ENQUIRIES;
        let hit =
            (escapes.wrapping_sub(LOW) & !escapes) | (enquiries.wrapping_sub(LOW) & !enquiries);
        if hit & HIGH != 0 {
            let at = word
                .iter()
                .position(|&byte| QueryFilter::opens(byte))
                .expect("a borrow chain starts at a zero lane, so this word holds one");
            return Some(offset + at);
        }
        offset += LANES;
    }
    remainder
        .iter()
        .position(|&byte| QueryFilter::opens(byte))
        .map(|at| offset + at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use braid_proto::GridSize;
    use braid_vt::{ContinuationLimit, EffectSink, ScrollbackLimit, VtEngine};
    use std::cell::RefCell;
    use std::convert::Infallible;
    use std::rc::Rc;

    /// The emulator's replies, kept so a test can see whether a span produced
    /// one and what the client would have been asked.
    #[derive(Default)]
    struct Replies(RefCell<Vec<u8>>);

    impl EffectSink for Replies {
        fn pty_write(&self, bytes: &[u8]) {
            self.0.borrow_mut().extend_from_slice(bytes);
        }
    }

    /// A real emulator behind the filter's view of one.
    struct Live {
        vt: VtEngine<Replies>,
    }

    impl Live {
        fn new() -> Self {
            let vt = VtEngine::new(
                GridSize::new(80, 24).expect("a valid grid"),
                ScrollbackLimit(64),
                ContinuationLimit(4096),
                Rc::new(Replies::default()),
            )
            .expect("terminal should initialize");
            Self { vt }
        }

        fn replies(&self) -> Vec<u8> {
            self.vt.sink().0.borrow().clone()
        }
    }

    impl Emulator for Live {
        type Error = braid_vt::VtError;

        fn consume(&mut self, bytes: &[u8]) -> Result<Answer, Self::Error> {
            let before = self.vt.sink().0.borrow().len();
            self.vt.feed(bytes)?;
            if self.vt.sink().0.borrow().len() == before {
                Ok(Answer::Silent)
            } else {
                Ok(Answer::Replied)
            }
        }
    }

    /// An emulator that answers nothing, for the tests about what the scanner
    /// does with the bytes rather than about which of them are queries.
    struct Mute;

    impl Emulator for Mute {
        type Error = Infallible;

        fn consume(&mut self, _bytes: &[u8]) -> Result<Answer, Self::Error> {
            Ok(Answer::Silent)
        }
    }

    /// What a client is sent for `chunks`, and what the emulator replied.
    fn forwarded(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        let mut filter = QueryFilter::new();
        let mut emulator = Live::new();
        let mut out = Vec::new();
        let mut sent = Vec::new();
        for chunk in chunks {
            let kept = filter
                .filter(chunk, &mut out, &mut emulator)
                .expect("the emulator accepts its own output");
            sent.extend_from_slice(kept);
        }
        (sent, emulator.replies())
    }

    /// Every sequence the emulator answers is cut, and every sequence it does
    /// not answer survives.
    ///
    /// This is the whole contract, and it is checked against the emulator
    /// rather than against a list: a libghostty-vt that starts or stops
    /// answering something moves both sides of the assertion at once. The
    /// sequences here are the ones a terminal is actually asked, kept so a
    /// failure names which one moved.
    #[test]
    fn a_sequence_is_cut_exactly_when_the_emulator_answers_it() {
        for query in [
            &b"\x05"[..],                                  // ENQ
            b"\x1b[c",                                     // DA1
            b"\x1b[>c",                                    // DA2
            b"\x1b[=c",                                    // DA3
            b"\x1b[5n",                                    // DSR, operating status
            b"\x1b[6n",                                    // DSR, cursor position
            b"\x1b[?2026$p",                               // DECRQM, synchronised output
            b"\x1b[?u",                                    // kitty keyboard flags
            b"\x1b[>q",                                    // XTVERSION
            b"\x1b]4;1;?\x07",                             // palette entry
            b"\x1bP$qm\x1b\\",                             // DECRQSS, graphic rendition
            b"\x1bP$qr\x1b\\",                             // DECRQSS, scrolling region
            b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\", // kitty graphics
        ] {
            let (sent, replies) = forwarded(&[query]);
            assert!(
                !replies.is_empty(),
                "{query:?} is in this list because the emulator answers it"
            );
            assert!(sent.is_empty(), "{query:?} reached the client as {sent:?}");
        }

        for passed in [
            &b"\x1b[?6n"[..],     // DECXCPR
            b"\x1b[4$p",          // DECRQM on an ANSI mode
            b"\x1bP+q544e\x1b\\", // XTGETTCAP
            b"\x1b]10;?\x07",     // foreground colour
            b"\x1b]11;?\x07",     // background colour
            b"\x1b]12;?\x07",     // cursor colour
            b"\x1b]52;c;?\x1b\\", // clipboard read
            b"\x1b[18t",          // window size in cells
            b"\x1b^status\x1b\\", // PM
            b"\x1bXstatus\x1b\\", // SOS
        ] {
            let (sent, replies) = forwarded(&[passed]);
            assert!(
                replies.is_empty(),
                "{passed:?} is in this list because the emulator answers nothing"
            );
            assert_eq!(
                sent, passed,
                "{passed:?} was cut, so nothing will ever answer it"
            );
        }
    }

    /// The fast path decides from the opening byte alone that a chunk holds no
    /// query, so a query the emulator answers must not be reachable without
    /// one. libghostty-vt parses UTF-8, where an 8-bit `CSI` is not a control
    /// byte - if that ever changes, this catches it before the fast path
    /// starts forwarding answered queries.
    #[test]
    fn the_fast_path_skips_nothing_the_emulator_answers() {
        for eight_bit in [&b"\x9bc"[..], b"\x9d4;1;?\x07", b"\x90$qm\x9c"] {
            let mut emulator = Live::new();
            emulator.consume(eight_bit).expect("bytes parse");
            assert!(
                emulator.replies().is_empty(),
                "{eight_bit:?} was answered, so `opens` has to admit 8-bit C1"
            );
        }
    }

    /// A query split at every byte boundary is still one query. The steady
    /// state of a real PTY is chunks cut at arbitrary offsets.
    ///
    /// The DCS matters most: the emulator dispatches a control string on the
    /// `ESC` that ends it, so a chunk cut between that `ESC` and its `\` makes
    /// the reply arrive a chunk before the byte this scanner settles on.
    #[test]
    fn a_query_split_across_chunks_is_still_cut() {
        let burst = b"\x1b[?1049h\x1b[?2004h\x1b[?u\x1b[c\x1b]4;1;?\x07\x1bP$qm\x1b\\\x1b[?25h";
        let whole = forwarded(&[burst]).0;
        assert_eq!(whole, b"\x1b[?1049h\x1b[?2004h\x1b[?25h");

        for width in 1..=9 {
            let split: Vec<&[u8]> = burst.chunks(width).collect();
            assert_eq!(forwarded(&split).0, whole, "in chunks of {width}");
        }
    }

    /// Ordinary output is handed back as the caller's own slice, with nothing
    /// copied and nothing held.
    #[test]
    fn ordinary_output_is_forwarded_without_a_copy() {
        let text = b"hello \x1b[31mworld\x1b[0m\r\n";
        assert_eq!(forwarded(&[text]).0, text);

        let bulk = b"no escapes here, just output\r\n";
        let mut filter = QueryFilter::new();
        let mut out = Vec::new();
        let kept = filter
            .filter(bulk, &mut out, &mut Mute)
            .expect("the mute emulator cannot fail");
        assert!(
            std::ptr::eq(kept.as_ptr(), bulk.as_ptr()),
            "a copy was made"
        );
        assert!(out.is_empty(), "the buffer was touched on the fast path");
    }

    /// An unterminated control string must not hold the client's screen back.
    /// A string body has no C0 in it, so one ends the sequence rather than
    /// extending it to the scan limit - this is the difference between a stray
    /// `ESC P` costing nothing and costing four kilobytes of frozen output.
    #[test]
    fn an_unterminated_sequence_does_not_withhold_the_output_behind_it() {
        for opener in [&b"\x1bP"[..], b"\x1b]", b"\x1b_", b"\x1b^", b"\x1bX"] {
            let mut stream = opener.to_vec();
            stream.extend_from_slice(b"status line\r\n");
            let mut filter = QueryFilter::new();
            let mut out = Vec::new();
            let kept = filter
                .filter(&stream, &mut out, &mut Live::new())
                .expect("the emulator accepts its own output");
            assert_eq!(
                kept, stream,
                "{opener:?} withheld the output that followed it"
            );
            assert_eq!(filter.held(), 0, "{opener:?} is still being scanned");
        }
    }

    /// A sequence longer than the scan limit stops being buffered, so a stream
    /// that opens one and never closes it cannot grow the buffer for the life
    /// of the session. Driven by [`Mute`]: this is about what the scanner does
    /// with the bytes, and a real emulator refuses a parameter list this long
    /// before the scanner is the interesting part.
    #[test]
    fn an_overlong_sequence_stops_being_buffered() {
        let mut stream = b"\x1b[".to_vec();
        stream.extend_from_slice(&vec![b'1'; SCAN_LIMIT * 2]);
        let mut filter = QueryFilter::new();
        let mut out = Vec::new();
        let kept = filter
            .filter(&stream, &mut out, &mut Mute)
            .expect("the mute emulator cannot fail");
        assert_eq!(kept.len(), stream.len(), "the overrun held bytes back");
        assert_eq!(kept, stream);
    }

    /// An overran string ended by a bare `ESC` had that `ESC` written out with
    /// the rest of its bytes, so reopening on it must not buffer it a second
    /// time. The filter may only ever drop bytes, never invent one: an `ESC`
    /// the application did not write starts a sequence on the user's terminal.
    #[test]
    fn reopening_an_overran_sequence_does_not_duplicate_its_escape() {
        let mut stream = b"\x1b]".to_vec();
        stream.extend_from_slice(&vec![b'a'; SCAN_LIMIT + 1]);
        stream.extend_from_slice(b"\x1bx");

        let mut filter = QueryFilter::new();
        let mut out = Vec::new();
        let kept = filter
            .filter(&stream, &mut out, &mut Mute)
            .expect("the mute emulator cannot fail");
        assert_eq!(
            kept.len() + filter.held(),
            stream.len(),
            "the client was sent a byte the application never wrote"
        );
        assert_eq!(kept, stream);
    }

    /// An `ESC` inside an unterminated string ends it and opens what follows,
    /// the way the emulator reads it. Reading it as part of the string instead
    /// swallows the next sequence, and a query hidden behind one would reach
    /// the client.
    #[test]
    fn an_escape_inside_an_unterminated_string_opens_the_next_sequence() {
        let (sent, replies) = forwarded(&[b"\x1b]11;?\x1b[c"]);
        assert!(!replies.is_empty(), "the DA1 behind the OSC was not seen");
        assert_eq!(
            sent, b"\x1b]11;?",
            "the OSC belongs to the client and the DA1 does not"
        );

        let (sent, _) = forwarded(&[b"\x1b\x1b[c"]);
        assert_eq!(sent, b"\x1b", "a doubled escape lost the first one");
    }

    /// A mode set that shares a final byte with a query must not be mistaken
    /// for one: `CSI ? 25 h` shows the cursor and has to reach the client.
    #[test]
    fn ordinary_sequences_reach_the_client() {
        for keep in [
            &b"\x1b[?25h"[..],
            b"\x1b[?1049l",
            b"\x1b[?2004h",
            b"\x1b[2J",
            b"\x1b[H",
            b"\x1b]0;a title\x07",
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b]52;c;aGVsbG8=\x1b\\",
            b"\x1b7",
        ] {
            assert_eq!(forwarded(&[keep]).0, keep, "{keep:?} was cut");
        }
    }

    /// Every byte the filter is given reaches the emulator exactly once and in
    /// order, whatever the chunk boundaries: the emulator's screen is the one
    /// the server paints from, so a byte lost here is a client painting from a
    /// terminal that never saw its own output.
    #[test]
    fn every_byte_reaches_the_emulator_once_and_in_order() {
        #[derive(Default)]
        struct Seen(Vec<u8>);

        impl Emulator for Seen {
            type Error = Infallible;

            fn consume(&mut self, bytes: &[u8]) -> Result<Answer, Self::Error> {
                self.0.extend_from_slice(bytes);
                Ok(Answer::Silent)
            }
        }

        let stream = b"text\x1b[c\x1b]11;?\x07more\x1bP$qm\x1b\\\x05\x1b[?25h\x1b]52;c;?\x1b\\tail";
        for width in 1..=9 {
            let mut filter = QueryFilter::new();
            let mut emulator = Seen::default();
            let mut out = Vec::new();
            for chunk in stream.chunks(width) {
                filter
                    .filter(chunk, &mut out, &mut emulator)
                    .expect("the counting emulator cannot fail");
            }
            assert_eq!(emulator.0, stream, "in chunks of {width}");
        }
    }
}
