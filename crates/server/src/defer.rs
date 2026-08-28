#![forbid(unsafe_code)]
// One spelling per item: `pub` where `braid-fuzz` reaches it and nowhere else,
// because without that feature the module itself is private.
#![cfg_attr(not(feature = "fuzzing"), allow(unreachable_pub))]

//! OSC sequences a sync episode would otherwise swallow: title, working
//! directory, hyperlinks, clipboard, prompt marks, notifications. In a sync
//! episode the byte stream is not sent at all, so a `yank` over OSC 52 landing
//! in one would silently do nothing.

use std::collections::VecDeque;

/// Bytes of one OSC sequence the scanner holds before abandoning it: a stream
/// that opens an OSC and never terminates it would otherwise grow for the life
/// of the session.
pub const OSC_SCAN_LIMIT: usize = 4096;

/// Sequences and bytes the log carries, oldest dropped first.
pub const DEFERRED_ENTRIES: usize = 16;
pub const DEFERRED_BYTES: usize = 4096;

/// Per attachment, because sync episodes are: a log drained by whichever screen
/// went out first would lose the other client's clipboard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeferMark(pub(crate) u64);

enum Osc {
    Ground,
    /// `ESC` seen; the next byte decides whether this is an OSC at all.
    Escape,
    /// Inside `ESC ] ...`, collecting the body.
    Body,
    /// Inside a body with `ESC` seen: `\` ends it, anything else aborts it.
    BodyEscape,
}

/// Each entry is the sequence's *body* — what lies strictly between `ESC ]` and
/// the terminator, with `BEL` and `ST` endings producing the same entry. The
/// client re-emits it as `ESC ] <body> ESC \`.
pub struct DeferredOsc {
    scan: Osc,
    pub(crate) partial: Vec<u8>,
    /// Overran [`OSC_SCAN_LIMIT`]: consume the sequence to its end and drop it,
    /// rather than carry a fragment.
    pub(crate) truncated: bool,
    pub(crate) entries: VecDeque<(DeferMark, String)>,
    pub(crate) bytes: usize,
    pub(crate) next: DeferMark,
}

impl DeferredOsc {
    const ESC: u8 = 0x1b;
    const BEL: u8 = 0x07;

    #[must_use]
    pub fn new() -> Self {
        Self {
            scan: Osc::Ground,
            partial: Vec::new(),
            truncated: false,
            entries: VecDeque::new(),
            bytes: 0,
            next: DeferMark(0),
        }
    }

    /// Published for the fuzz target that pins the identity, not the bound.
    #[cfg(feature = "fuzzing")]
    #[must_use]
    pub fn held(&self) -> (usize, usize) {
        (self.entries.len(), self.bytes)
    }

    #[must_use]
    pub const fn mark(&self) -> DeferMark {
        self.next
    }

    #[must_use]
    pub fn since(&self, from: DeferMark) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(mark, _)| *mark >= from)
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// The newest that fit, in order, the same rule the encoder applies at the
    /// wire bound: a stale title must never crowd out a `yank`. Anything that
    /// does not fit is gone.
    #[must_use]
    pub fn carry(&self, from: DeferMark, budget: usize) -> Vec<String> {
        let mut owed = self.since(from);
        let mut total = 0;
        let kept = owed
            .iter()
            .rev()
            .take_while(|entry| {
                total += entry.len() + 2;
                total <= budget
            })
            .count();
        owed.split_off(owed.len() - kept)
    }

    /// The bound would hold this on its own; this keeps a quiet session from
    /// carrying a stale title until sixteen more sequences push it out.
    pub fn forget_before(&mut self, mark: DeferMark) {
        while self.entries.front().is_some_and(|(at, _)| *at < mark) {
            if let Some((_, dropped)) = self.entries.pop_front() {
                self.bytes -= dropped.len();
            }
        }
    }

    /// Skipping the run between escapes rather than stepping it: this runs only
    /// during a sync episode, which is exactly the flood.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            if matches!(self.scan, Osc::Ground) {
                let Some(escape) = rest.iter().position(|&byte| byte == Self::ESC) else {
                    return;
                };
                self.scan = Osc::Escape;
                rest = &rest[escape + 1..];
            } else {
                self.step(rest[0]);
                rest = &rest[1..];
            }
        }
    }

    pub(crate) fn step(&mut self, byte: u8) {
        match self.scan {
            Osc::Ground => {
                if byte == Self::ESC {
                    self.scan = Osc::Escape;
                }
            }
            Osc::Escape => {
                self.scan = match byte {
                    b']' => {
                        self.partial.clear();
                        self.truncated = false;
                        Osc::Body
                    }
                    Self::ESC => Osc::Escape,
                    _ => Osc::Ground,
                };
            }
            Osc::Body => match byte {
                Self::BEL => self.finish(),
                Self::ESC => self.scan = Osc::BodyEscape,
                // No C0 byte belongs in an OSC body, so one here is a sequence
                // that was never terminated: abandoning it keeps a stream of
                // `ESC ]` from parking the scanner in `Body` forever.
                0x00..=0x1f => self.abandon(),
                _ => self.push(byte),
            },
            Osc::BodyEscape => match byte {
                b'\\' => self.finish(),
                Self::ESC => {}
                _ => self.abandon(),
            },
        }
    }

    pub(crate) fn push(&mut self, byte: u8) {
        if self.partial.len() < OSC_SCAN_LIMIT {
            self.partial.push(byte);
        } else {
            self.truncated = true;
        }
    }

    fn abandon(&mut self) {
        self.scan = Osc::Ground;
        self.partial.clear();
        self.truncated = false;
    }

    fn finish(&mut self) {
        let body = std::mem::take(&mut self.partial);
        let truncated = self.truncated;
        self.abandon();
        if truncated {
            return;
        }
        let Ok(body) = String::from_utf8(body) else {
            return;
        };
        // A control byte would be refused by the encoder, costing the whole
        // screen rather than one sequence; `Body` above admits none.
        if body.chars().any(char::is_control) {
            return;
        }
        let Some(command) = deferred_command(&body) else {
            return;
        };
        self.record(command, body);
    }

    pub(crate) fn record(&mut self, command: DeferredKind, body: String) {
        if let DeferredKind::Sticky(number) = command {
            // A shell sets the title on every prompt; superseding stops a
            // spinner in `$PS1` from evicting the OSC 52 a `yank` depends on.
            // Re-marked, not updated in place: a client already past the old
            // mark must still be given the new title.
            let mut freed = 0;
            self.entries.retain(|(_, kept)| {
                let stale = deferred_command(kept) == Some(DeferredKind::Sticky(number));
                if stale {
                    freed += kept.len();
                }
                !stale
            });
            self.bytes -= freed;
        }
        self.bytes += body.len();
        self.entries.push_back((self.next, body));
        self.next = DeferMark(self.next.0 + 1);
        while self.entries.len() > DEFERRED_ENTRIES || self.bytes > DEFERRED_BYTES {
            let Some((_, dropped)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= dropped.len();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeferredKind {
    /// Idempotent state: the newest one is the only one that matters.
    Sticky(u16),
    /// An event or a stateful pair, where every one of them counts.
    Event,
}

fn deferred_command(body: &str) -> Option<DeferredKind> {
    let number: u16 = body
        .split(';')
        .next()
        .filter(|head| !head.is_empty() && head.len() <= 3)
        .and_then(|head| head.parse().ok())?;
    match number {
        // 0/1/2 window and icon title, 7 the working directory a terminal
        // tracks for new tabs.
        0 | 1 | 2 | 7 => Some(DeferredKind::Sticky(number)),
        // 8 hyperlink (an open/close pair), 9 and 777 notifications, 52 the
        // clipboard, 133 shell prompt marks.
        8 | 9 | 52 | 133 | 777 => Some(DeferredKind::Event),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_osc_a_sync_episode_would_swallow_is_carried_on_the_next_screen() {
        let mut log = DeferredOsc::new();
        let start = log.mark();
        log.feed(b"\x1b]52;c;aGVsbG8=\x07");
        log.feed(b"ordinary output\r\n\x1b]8;;https://example\x1b\\link");
        // A screen already says where the cursor is and what every cell holds.
        log.feed(b"\x1b[2J\x1b[H\x1b]4;1;#ff0000\x07");
        assert_eq!(
            log.since(start),
            vec!["52;c;aGVsbG8=".to_owned(), "8;;https://example".to_owned()]
        );
        // A client that entered its episode later is owed only what came after.
        let later = log.mark();
        log.feed(b"\x1b]0;title\x07");
        assert_eq!(log.since(later), vec!["0;title".to_owned()]);
    }

    /// A shell sets the title on every prompt. Appending would let a spinner in
    /// `$PS1` evict the clipboard the user's `yank` depends on.
    #[test]
    fn a_newer_title_supersedes_the_one_it_replaces_rather_than_evicting_a_yank() {
        let mut log = DeferredOsc::new();
        let start = log.mark();
        log.feed(b"\x1b]52;c;d2FudGVk\x07");
        for spin in 0..DEFERRED_ENTRIES * 4 {
            log.feed(format!("\x1b]2;working {spin}\x07").as_bytes());
        }
        let carried = log.since(start);
        assert_eq!(carried.len(), 2, "{carried:?}");
        assert_eq!(carried[0], "52;c;d2FudGVk");
        assert!(carried[1].starts_with("2;working "));
        // The newest title, under a mark no client has passed.
        assert_eq!(
            carried[1],
            format!("2;working {}", DEFERRED_ENTRIES * 4 - 1)
        );
    }

    /// What the skipping scanner records must be byte for byte what stepping
    /// records, most of all where a sequence straddles two chunks.
    #[test]
    fn skipping_the_run_between_escapes_records_what_stepping_recorded() {
        type Case<'a> = (&'a str, &'a [&'a [u8]], &'a [&'a str]);

        let plain = vec![b'a'; 64 * 1024];
        let mut oversized = b"\x1b]0;".to_vec();
        oversized.resize(oversized.len() + OSC_SCAN_LIMIT * 2, b'x');
        oversized.extend_from_slice(b"\x07\x1b]0;after\x07");
        let mut long_run = vec![b'.'; 100_000];
        long_run.extend_from_slice(b"\x1b]52;c;QUJD\x07");

        let cases: [Case<'_>; 4] = [
            ("no escapes at all", &[plain.as_slice()], &[]),
            (
                "a sequence split across two feeds",
                &[b"\x1b]0;ti", b"tle\x07"],
                &["0;title"],
            ),
            (
                "a sequence past the scan limit",
                &[oversized.as_slice()],
                &["0;after"],
            ),
            (
                "a long run of plain bytes before a sequence",
                &[long_run.as_slice()],
                &["52;c;QUJD"],
            ),
        ];

        for (case, chunks, expected) in cases {
            let mut skipping = DeferredOsc::new();
            let mut stepping = DeferredOsc::new();
            for chunk in chunks {
                skipping.feed(chunk);
                for &byte in *chunk {
                    stepping.step(byte);
                }
            }
            let carried: Vec<String> = expected.iter().map(|body| (*body).to_owned()).collect();
            assert_eq!(skipping.since(DeferMark(0)), carried, "{case}");
            assert_eq!(stepping.since(DeferMark(0)), carried, "{case}");
            assert_eq!(skipping.bytes, stepping.bytes, "{case}");
            assert_eq!(skipping.partial, stepping.partial, "{case}");
            assert_eq!(skipping.truncated, stepping.truncated, "{case}");
        }
    }

    /// A sequence dropped for its size must not derail the ones after it.
    #[test]
    fn an_unterminated_sequence_is_abandoned_rather_than_buffered_forever() {
        let mut log = DeferredOsc::new();
        let start = log.mark();
        log.feed(b"\x1b]52;c;");
        for _ in 0..64 {
            log.feed(&[b'A'; 4096]);
        }
        assert!(log.partial.len() <= OSC_SCAN_LIMIT);
        log.feed(b"\x07\x1b]0;after\x07");
        assert_eq!(log.since(start), vec!["0;after".to_owned()]);

        // A C0 byte cannot appear in an OSC body, so one is a sequence that
        // was never terminated at all.
        log.feed(b"\x1b]2;half\nprinted\x1b]7;file:///tmp\x07");
        assert_eq!(
            log.since(start),
            vec!["0;after".to_owned(), "7;file:///tmp".to_owned()]
        );
    }

    #[test]
    fn the_deferred_log_is_bounded_in_entries_and_in_bytes() {
        let mut log = DeferredOsc::new();
        let start = log.mark();
        for n in 0..DEFERRED_ENTRIES * 4 {
            log.feed(format!("\x1b]9;notification {n}\x07").as_bytes());
        }
        assert_eq!(log.since(start).len(), DEFERRED_ENTRIES);
        assert!(log.bytes <= DEFERRED_BYTES);

        let mut wide = DeferredOsc::new();
        for _ in 0..8 {
            wide.feed(b"\x1b]52;c;");
            wide.feed(&[b'A'; DEFERRED_BYTES - 8]);
            wide.feed(b"\x07");
        }
        assert!(wide.bytes <= DEFERRED_BYTES, "{}", wide.bytes);
        assert_eq!(wide.since(DeferMark(0)).len(), 1);
    }

    #[test]
    fn deferred_sequences_every_client_has_carried_are_forgotten() {
        let mut log = DeferredOsc::new();
        log.feed(b"\x1b]0;first\x07");
        let carried = log.mark();
        log.feed(b"\x1b]0;second\x07");
        log.forget_before(carried);
        assert_eq!(log.since(DeferMark(0)), vec!["0;second".to_owned()]);
        assert_eq!(log.bytes, "0;second".len());
    }
}
