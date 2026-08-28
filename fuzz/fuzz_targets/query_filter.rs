#![no_main]

//! The query filter. It sits between the emulator and every client, so a byte
//! it invents, reorders or loses is one the client paints and the server does
//! not: the emulator must be handed the input exactly, the client must be sent
//! a subsequence of it, and how the stream was cut into chunks must not change
//! either answer.

use braid_server::query::{Answer, Emulator, QueryFilter, SCAN_LIMIT};
use libfuzzer_sys::fuzz_target;

/// Records what it was given and answers as told, so the filter's own splitting
/// is the only variable.
struct Recorder {
    seen: Vec<u8>,
    answer: Answer,
}

impl Emulator for Recorder {
    type Error = std::convert::Infallible;

    fn consume(&mut self, bytes: &[u8]) -> Result<Answer, Self::Error> {
        self.seen.extend_from_slice(bytes);
        Ok(self.answer)
    }
}

/// Filter `data` in chunks of `width`, returning what the client is sent, what
/// the emulator was given, and what the filter still holds back.
fn run(data: &[u8], width: usize, answer: Answer) -> (Vec<u8>, Vec<u8>, usize) {
    let mut filter = QueryFilter::new();
    let mut emulator = Recorder {
        seen: Vec::new(),
        answer,
    };
    let mut out = Vec::new();
    let mut sent = Vec::new();
    for chunk in data.chunks(width.max(1)) {
        let kept = filter
            .filter(chunk, &mut out, &mut emulator)
            .expect("the recorder cannot fail");
        sent.extend_from_slice(kept);
    }
    (sent, emulator.seen, filter.held())
}

/// Whether `part` appears in `whole` in order, which is all the filter may ever
/// produce: it drops sequences and copies everything else through.
fn is_subsequence(part: &[u8], whole: &[u8]) -> bool {
    let mut rest = whole.iter();
    part.iter()
        .all(|byte| rest.any(|candidate| candidate == byte))
}

fuzz_target!(|data: &[u8]| {
    for answer in [Answer::Silent, Answer::Replied] {
        let (sent, seen, held) = run(data, data.len(), answer);

        // The emulator's screen is what the server paints from, so a byte lost
        // or duplicated here is a client painting from a terminal that never
        // saw its own output.
        assert_eq!(seen, data, "the emulator was not handed the input: {answer:?}");
        assert!(
            is_subsequence(&sent, data),
            "the client was sent bytes the application never wrote: {answer:?}"
        );
        assert!(
            held <= SCAN_LIMIT,
            "{held} bytes withheld past a bound of {SCAN_LIMIT}: {answer:?}"
        );

        // An emulator that answers nothing may not cost the client a byte:
        // every capability braid does not implement itself reaches the client's
        // own terminal through this path, and cutting one strands the
        // application waiting for a reply nothing will send.
        if answer == Answer::Silent {
            assert_eq!(
                sent.len() + held,
                data.len(),
                "output was dropped for a query the emulator never answered"
            );
            assert_eq!(
                sent,
                data[..data.len() - held],
                "the client's stream diverged from the application's"
            );
        }

        // Chunking is the PTY's business, not the protocol's: a sequence cut in
        // half by a read boundary has to be judged as the one sequence it is.
        for width in [1, 2, 3, 7, 17, 64] {
            let (split_sent, split_seen, split_held) = run(data, width, answer);
            assert_eq!(
                split_seen, seen,
                "chunks of {width} changed what the emulator was given"
            );
            assert_eq!(
                split_sent, sent,
                "chunks of {width} changed what the client was sent"
            );
            assert_eq!(
                split_held, held,
                "chunks of {width} changed what was withheld"
            );
        }
    }
});
