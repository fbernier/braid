#![no_main]

//! `read_frame_into` with the buffer a session loop reuses: a short frame
//! after a long one must leave none of the long one behind, and a refused
//! length must not have grown the buffer on the way to being refused.

use braid_proto::{MAX_CLIENT_FRAME, read_frame_into};
use libfuzzer_sys::fuzz_target;

/// Bytes of length prefix before each frame's payload.
const PREFIX: usize = 4;

fuzz_target!(|data: &[u8]| {
    let limit = usize::try_from(MAX_CLIENT_FRAME).expect("a 32-bit limit fits a usize");
    let mut stream = data;
    let mut buffer = Vec::new();
    let mut at = 0_usize;
    // Every accepted frame consumes its own length, so this terminates.
    while read_frame_into(&mut stream, &mut buffer, MAX_CLIENT_FRAME).is_ok() {
        let claimed =
            u32::from_be_bytes(data[at..at + PREFIX].try_into().expect("a length prefix"));
        assert_eq!(
            u32::try_from(buffer.len()).ok(),
            Some(claimed),
            "the reader kept a frame that is not the length it claims"
        );
        assert!(
            !buffer.is_empty() && buffer.len() <= limit,
            "the reader accepted a frame outside the bound"
        );
        at += PREFIX;
        assert_eq!(
            &buffer[..],
            &data[at..at + buffer.len()],
            "the reused buffer holds bytes this frame did not carry"
        );
        at += buffer.len();
    }
});
