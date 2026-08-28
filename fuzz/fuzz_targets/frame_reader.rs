#![no_main]

//! The framing layer, where an attacker-controlled length becomes an
//! allocation. Both limits are exercised because they differ: only a server
//! sends a screen, so only [`MAX_FRAME`] is large enough to hold one.

use braid_proto::{MAX_CLIENT_FRAME, MAX_FRAME, read_frame};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    for limit in [MAX_CLIENT_FRAME, MAX_FRAME] {
        let mut stream = Cursor::new(data);
        let bound = usize::try_from(limit).expect("a 32-bit limit fits a usize");
        while let Ok(payload) = read_frame(&mut stream, limit) {
            // Every accepted frame consumes its own length, so this terminates.
            assert!(!payload.is_empty(), "the reader accepted an empty frame");
            assert!(
                payload.len() <= bound,
                "the reader accepted an oversize frame"
            );
        }
    }
});
