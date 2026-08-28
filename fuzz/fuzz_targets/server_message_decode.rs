#![no_main]

//! Everything the far end of the ssh pipe can say. Accepted payloads may carry newer trailing
//! fields; encoding their parsed value must preserve it and reach a stable canonical form.

use braid_proto::{RowFrame, RowSpan, ScreenPart, ServerMessage, Version};
use libfuzzer_sys::fuzz_target;

/// Bytes `encode` prepends and `decode` never sees.
const PREFIX: usize = 4;

/// Trailing blanks no style paints, the one thing that keeps this format from
/// being canonical byte for byte.
fn elide(row: &RowFrame) -> RowFrame {
    RowFrame {
        text: row.text[..row.painted_bytes()].to_owned(),
        runs: row.runs.clone(),
        cells: row.cells,
    }
}

/// A screen piece is the only message this direction that carries rows.
fn elide_message(message: &ServerMessage) -> ServerMessage {
    match message {
        ServerMessage::Screen { part } => {
            let mut part = part.clone();
            match &mut part {
                ScreenPart::Head { rows, .. } | ScreenPart::Tail { rows, .. } => {
                    *rows = rows
                        .iter()
                        .map(|span| RowSpan {
                            frame: elide(&span.frame),
                            ..span.clone()
                        })
                        .collect();
                }
            }
            ServerMessage::Screen { part }
        }
        other => other.clone(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(message) = ServerMessage::decode(data, Version::LOCAL) else {
        return;
    };
    let frame = message.encode(Version::LOCAL).unwrap_or_else(|error| {
        panic!("a message the decoder accepted must re-encode: {error:?} in {message:?}")
    });
    let again =
        ServerMessage::decode(&frame[PREFIX..], Version::LOCAL).expect("a re-encoded frame");
    let elided = elide_message(&message);
    assert_eq!(again, elided, "re-encoding lost more than trailing blanks");
    assert_eq!(
        again
            .encode(Version::LOCAL)
            .expect("a message the decoder accepted must re-encode"),
        frame,
        "eliding trailing blanks is not a fixed point"
    );
});
