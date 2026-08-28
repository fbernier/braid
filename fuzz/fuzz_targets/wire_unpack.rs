#![no_main]

//! The datagram's outermost decoder, and the only one that allocates from a
//! length it is not told: deflate carries no size on the wire, so the ceiling
//! has to be applied to the buffer instead. Anything at all may be handed to
//! `unpack` without a panic, and whatever `pack` produced comes back exactly.

use braid_proto::wire::{pack, unpack};
use libfuzzer_sys::fuzz_target;

/// What a real caller states: the largest frame this direction accepts.
const LIMIT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    let _ = unpack(data, LIMIT, &mut out);
    assert!(
        out.len() <= LIMIT,
        "unpack reserved {} bytes against a {LIMIT}-byte ceiling",
        out.len()
    );

    // Including the case the tag exists for: deflate would have grown the
    // payload and the stored form is what went out.
    if data.len() <= LIMIT {
        let mut packed = Vec::new();
        pack(data, &mut packed);
        assert!(
            packed.len() <= data.len() + 1,
            "packing {} bytes produced {}",
            data.len(),
            packed.len()
        );
        let mut back = Vec::new();
        unpack(&packed, LIMIT, &mut back).expect("a payload this side packed");
        assert_eq!(back, data, "the codec is not its own inverse");
    }

    // Both buffers are caller-owned and reused per datagram, so a decoder that
    // appends rather than replaces corrupts under load and passes every
    // single-shot test.
    let mut reused = vec![0xAB; 4096];
    let _ = unpack(data, LIMIT, &mut reused);
    let mut fresh = Vec::new();
    let first = unpack(data, LIMIT, &mut fresh);
    if first.is_ok() {
        assert_eq!(reused, fresh, "unpack depends on the buffer it was given");
    }
});
