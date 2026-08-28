#![no_main]

//! Everything that reaches the per-user daemon socket. Accepted payloads may carry trailing
//! fields from a newer peer; encoding their parsed value must be a stable canonical form.

use braid_proto::{ClientMessage, Version};
use libfuzzer_sys::fuzz_target;

/// Bytes `encode` prepends and `decode` never sees.
const PREFIX: usize = 4;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = ClientMessage::decode(data, Version::LOCAL) else {
        return;
    };
    let frame = message
        .encode(Version::LOCAL)
        .expect("a message the decoder accepted must re-encode");
    let again =
        ClientMessage::decode(&frame[PREFIX..], Version::LOCAL).expect("a re-encoded frame");
    assert_eq!(again, message);
    assert_eq!(
        again
            .encode(Version::LOCAL)
            .expect("a message the decoder accepted must re-encode"),
        frame,
        "a client encoding is not a fixed point"
    );
});
