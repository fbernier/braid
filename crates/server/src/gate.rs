#![forbid(unsafe_code)]
use crate::sink::STREAM_LIMIT;
use std::time::{Duration, Instant};

/// Outstanding bytes at which a datagram client is called caught up: half of
/// what puts one into sync mode, because entering and leaving on the same
/// number is a session that flaps across it once per chunk.
const DATAGRAM_WINDOW: u64 = STREAM_LIMIT as u64 / 2;

/// Whether this client has caught up, as far as its own transport can tell. A
/// stream has TCP underneath, so the sink's queue emptying is a fact about the
/// client; a datagram sink's `send_to` returns the moment the kernel takes the
/// packet, so there only the outstanding-byte window says anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchUp {
    Stream { drained: bool },
    Datagram { drained: bool, outstanding: u64 },
}

impl CatchUp {
    const fn caught_up(self) -> bool {
        match self {
            Self::Stream { drained } => drained,
            Self::Datagram {
                drained,
                outstanding,
            } => drained && outstanding <= DATAGRAM_WINDOW,
        }
    }
}

/// Whether a session coalescing output into whole screens may resume forwarding
/// the raw byte stream. Two conditions, because either one is enough and
/// neither alone is.
///
/// [`CatchUp`] is the honest one. Its `drained` half comes from
/// [`AttachmentSink::is_drained`](crate::sink::AttachmentSink::is_drained),
/// which answers false once that sink is closed: a client whose writer has died
/// is gone, not caught up.
///
/// Quiescence is the fallback for a client that has not acknowledged anything
/// yet. On its own it is a trap: `last_output` is refreshed by every PTY read,
/// so any progress bar would pin a session in whole-screen mode.
#[must_use]
pub fn may_return_to_passthrough(
    caught_up: CatchUp,
    now: Instant,
    last_output: Option<Instant>,
    quiescence: Duration,
) -> bool {
    caught_up.caught_up()
        || last_output.is_none_or(|last| now.saturating_duration_since(last) >= quiescence)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram sink is drained the instant the kernel takes the packet, so
    /// there a drained sink alone says nothing about the client: leaving sync
    /// mode on it re-trips the window and the session flaps once per chunk.
    #[test]
    fn passthrough_resumes_on_catch_up_or_quiescence() {
        const QUIESCENCE: Duration = Duration::from_millis(33);
        let behind = CatchUp::Stream { drained: false };
        let now = Instant::now();
        let since = |millis| {
            now.checked_sub(Duration::from_millis(millis))
                .expect("monotonic clock")
        };

        let cases: &[(&str, CatchUp, Option<Instant>, bool)] = &[
            (
                "a silent stream returns to passthrough",
                behind,
                Some(since(80)),
                true,
            ),
            (
                "a stream still producing stays in sync",
                behind,
                Some(since(5)),
                false,
            ),
            (
                "a drained client ends the episode whatever the shell is printing",
                CatchUp::Stream { drained: true },
                Some(since(5)),
                true,
            ),
            (
                "a session that never wrote is quiescent",
                behind,
                None,
                true,
            ),
            (
                "a datagram client outside the window has not caught up",
                CatchUp::Datagram {
                    drained: true,
                    outstanding: DATAGRAM_WINDOW + 1,
                },
                Some(now),
                false,
            ),
            (
                "a datagram client at the window has",
                CatchUp::Datagram {
                    drained: true,
                    outstanding: DATAGRAM_WINDOW,
                },
                Some(now),
                true,
            ),
        ];

        for (case, caught_up, last_output, expected) in cases {
            assert_eq!(
                may_return_to_passthrough(*caught_up, now, *last_output, QUIESCENCE),
                *expected,
                "{case}"
            );
        }
    }

    /// A sink whose writer has died must not supply `drained`: sync mode would
    /// end for a transport that can no longer carry anything.
    #[test]
    fn a_closed_sink_does_not_report_drained() {
        let sink = crate::sink::AttachmentSink::new(
            Box::new(std::io::sink()),
            braid_proto::Version::LOCAL,
        )
        .expect("sink");
        sink.close();
        assert!(sink.is_closed());
        let now = Instant::now();
        assert!(!may_return_to_passthrough(
            CatchUp::Stream {
                drained: sink.is_drained()
            },
            now,
            Some(now),
            Duration::from_millis(33)
        ));
    }
}
