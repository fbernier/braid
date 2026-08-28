//! Framing for a datagram's payload: a codec tag, then the payload.
//!
//! Whether sync mode converges is decided here. A 200x50 repaint is ~19 KiB, so at 3%
//! loss a whole screen rarely arrives intact and the ledger re-sends it forever;
//! halving the piece count squares the odds.

use crate::DecodeError;
use miniz_oxide::DataFormat;
use miniz_oxide::deflate::CompressionLevel;
use miniz_oxide::deflate::core::{CompressorOxide, TDEFLFlush, TDEFLStatus, compress};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use std::cell::RefCell;

/// Published because every caller that cuts a frame for a path owes the subtraction.
pub const PACK_TAG: usize = 1;

const TAG_STORED: u8 = 0;
/// Raw deflate, no zlib wrapper: the transport already authenticates every byte, and
/// an Adler-32 beside a Poly1305 tag is two bytes of nothing.
const TAG_DEFLATE: u8 = 1;

/// A keystroke echo cannot win back its own block header; above this the only thing
/// sending is a repaint.
const DEFLATE_FLOOR: usize = 256;

/// A payload is about an MTU, so this is usually `unpack`'s only reservation; the
/// growth loop below exists for the hostile case.
const INFLATE_GUESS: usize = 1024;

/// Stack a thread must have spare the first time it packs: `CompressorOxide` is 64 KiB
/// by value with no way to build one onto the heap without `unsafe`, and measured, the
/// initialiser peaks at close to four copies. A 256 KiB sink thread aborted the whole
/// daemon here, and a stack overflow is a `SIGSEGV` no `catch_unwind` contains.
pub const CODEC_STACK: usize = 4 * size_of::<CompressorOxide>() + 4096;

/// Measured warm on a 10550-byte repaint of this path's traffic: level 1 is 24 µs/3009
/// B, level 3 is 73 µs/2225 B, levels 6 and 9 are both 190 µs/2150 B — so 3 keeps 4.74x
/// of the 4.91x available. A `u8` because the level wanted is between the
/// `CompressionLevel` variants, and `set_format_and_level` alone admits one.
const DEFLATE_LEVEL: u8 = 3;

thread_local! {
    /// Reused for the life of the thread: a fresh compressor per call would be the
    /// largest allocation in the send loop.
    static DEFLATE: RefCell<Box<CompressorOxide>> = RefCell::new(Box::new({
        let mut state =
            CompressorOxide::with_format_and_level(DataFormat::Raw, CompressionLevel::DefaultLevel);
        state.set_format_and_level(DataFormat::Raw, DEFLATE_LEVEL);
        state
    }));
    static INFLATE: RefCell<Box<DecompressorOxide>> =
        RefCell::new(Box::new(DecompressorOxide::new()));
}

/// A codec tag then the body. `out` is caller-owned and reused, so once warm this
/// allocates nothing.
pub fn pack(payload: &[u8], out: &mut Vec<u8>) {
    pack_from(payload, out, 0);
}

/// The same, written from `at` and leaving `out[..at]` untouched.
///
/// The datagram framing carries a length prefix in front of the packed payload,
/// and reserving room for it here is what lets a screen be packed straight into
/// the frame that will be sent rather than into a scratch it is copied out of.
pub fn pack_from(payload: &[u8], out: &mut Vec<u8>, at: usize) {
    if payload.len() >= DEFLATE_FLOOR && deflate_into(payload, out, at) {
        return;
    }
    out.truncate(at);
    out.push(TAG_STORED);
    out.extend_from_slice(payload);
}

/// Room for `len` bytes the caller overwrites in full. No `clear` before the `resize`:
/// that would zero every byte about to be written over. [`crate::read_frame_into`]'s rule.
fn room_for(out: &mut Vec<u8>, len: usize) {
    out.resize(len, 0);
}

/// The scratch is one byte shorter than stored would cost, collapsing "did not fit"
/// and "did not win": a datagram that grows may no longer fit the path it was cut for.
fn deflate_into(payload: &[u8], out: &mut Vec<u8>, at: usize) -> bool {
    // `room_for` grows without clearing, so `out[..at]` - the caller's prefix - survives.
    room_for(out, at + payload.len());
    out[at] = TAG_DEFLATE;
    let Some(written) = DEFLATE.with_borrow_mut(|state| {
        state.reset();
        let (status, read, written) =
            compress(state, payload, &mut out[at + 1..], TDEFLFlush::Finish);
        (status == TDEFLStatus::Done && read == payload.len()).then_some(written)
    }) else {
        return false;
    };
    out.truncate(at + 1 + written);
    true
}

/// Recover a datagram's payload. Bounded: `unpack` refuses anything that
/// would inflate past `limit`.
pub fn unpack(datagram_body: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), DecodeError> {
    let (&tag, body) = datagram_body.split_first().ok_or(DecodeError::Truncated)?;
    match tag {
        TAG_STORED => {
            if body.len() > limit {
                return Err(DecodeError::InvalidField);
            }
            // `extend_from_slice` after a `clear` copies and never zeroes, so this
            // path owes nothing to [`room_for`].
            out.clear();
            out.extend_from_slice(body);
            Ok(())
        }
        TAG_DEFLATE => inflate_into(body, limit, out),
        _ => Err(DecodeError::InvalidField),
    }
}

/// The ceiling is applied to the buffer, not to a claimed length, because deflate
/// carries no such claim: a payload that decompresses forever is refused once its room
/// reaches `limit`, having reserved exactly that and not a byte more.
fn inflate_into(body: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), DecodeError> {
    let mut input = body;
    let mut room = body.len().saturating_mul(4).max(INFLATE_GUESS).min(limit);
    room_for(out, room);
    let mut filled = 0_usize;
    INFLATE.with_borrow_mut(|state| {
        state.init();
        loop {
            let (status, read, written) = decompress(
                state,
                input,
                out,
                filled,
                inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
            );
            filled += written;
            match status {
                // A stream ending with input to spare is `TrailingBytes` on the stream
                // path; admitting it here is a second encoding of every payload.
                TINFLStatus::Done if read == input.len() => {
                    out.truncate(filled);
                    return Ok(());
                }
                // `read` is bounded by the library, but a slice index that trusts it
                // is a panic path in a decoder that promises not to have one.
                TINFLStatus::HasMoreOutput if read <= input.len() && room < limit => {
                    input = &input[read..];
                    room = room.saturating_mul(2).min(limit);
                    room_for(out, room);
                }
                _ => {
                    out.clear();
                    return Err(DecodeError::InvalidField);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The edges: nothing at all, one byte, noise, and a screen's worth of redundancy.
    fn corpus() -> Vec<Vec<u8>> {
        let mut noise = Vec::new();
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            noise.extend_from_slice(&state.to_be_bytes());
        }
        vec![
            Vec::new(),
            vec![7],
            b"\x1b[1;32muser@host\x1b[0m:~$ ".to_vec(),
            b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400),
            vec![b' '; 20_000],
            noise,
            (0..=255_u8).cycle().take(300).collect(),
        ]
    }

    fn roundtrip(payload: &[u8]) -> Vec<u8> {
        let mut packed = Vec::new();
        pack(payload, &mut packed);
        let mut out = Vec::new();
        unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        out
    }

    #[test]
    fn every_payload_survives_the_datagram_framing_unchanged() {
        for payload in corpus() {
            assert_eq!(roundtrip(&payload), payload, "len {}", payload.len());
        }
    }

    #[test]
    fn the_codec_tag_follows_what_the_payload_is_worth() {
        // Noise is the case deflate loses on, and an echo under the floor never reaches
        // the compressor at all, whatever it would have won.
        let noise = corpus().into_iter().nth(5).expect("the noise payload");
        let echo = vec![b'a'; DEFLATE_FLOOR - 1];
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400);
        for (label, payload, want) in [
            ("incompressible noise", &noise, TAG_STORED),
            ("a keystroke echo under the floor", &echo, TAG_STORED),
            ("a repaint", &screen, TAG_DEFLATE),
        ] {
            let mut packed = Vec::new();
            pack(payload, &mut packed);
            assert_eq!(packed[0], want, "{label}");
            if want == TAG_STORED {
                assert_eq!(packed.len(), payload.len() + 1, "{label}");
            } else {
                assert!(
                    packed.len() * 8 < payload.len(),
                    "{label}: a repaint that compresses eightfold went out at {} of {}",
                    packed.len(),
                    payload.len()
                );
            }
            assert_eq!(roundtrip(payload), *payload, "{label}");
        }
    }

    #[test]
    fn a_truncated_deflate_stream_is_refused_rather_than_fatal() {
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400);
        let mut packed = Vec::new();
        pack(&screen, &mut packed);
        assert_eq!(packed[0], TAG_DEFLATE);
        let mut out = Vec::new();
        for cut in 1..packed.len() {
            let err = unpack(&packed[..cut], 1 << 20, &mut out);
            assert!(err.is_err(), "a stream cut at {cut} decoded anyway");
        }
    }

    /// The stream path refuses a body with bytes left over, so admitting one here would
    /// give the datagram path a second spelling of every payload.
    #[test]
    fn bytes_appended_after_a_deflate_stream_are_refused() {
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400);
        let mut packed = Vec::new();
        pack(&screen, &mut packed);
        assert_eq!(packed[0], TAG_DEFLATE);
        let mut out = Vec::new();
        unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        for trailer in [&[0_u8][..], &[0xff][..], &b"garbage"[..], &packed[1..]] {
            let mut extended = packed.clone();
            extended.extend_from_slice(trailer);
            assert!(
                matches!(
                    unpack(&extended, 1 << 20, &mut out),
                    Err(DecodeError::InvalidField)
                ),
                "a stream with {} bytes appended decoded anyway",
                trailer.len()
            );
            assert!(out.is_empty(), "a refused body left {} bytes", out.len());
        }
    }

    #[test]
    fn a_corrupted_deflate_stream_is_refused_rather_than_fatal() {
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400);
        let mut packed = Vec::new();
        pack(&screen, &mut packed);
        let mut out = Vec::new();
        for index in 1..packed.len() {
            let mut damaged = packed.clone();
            damaged[index] ^= 0xff;
            // A flipped bit may still decode to something; what it may never do is
            // panic or exceed the ceiling.
            let _ = unpack(&damaged, 1 << 20, &mut out);
            assert!(out.len() <= 1 << 20);
        }
    }

    #[test]
    fn a_payload_that_would_inflate_past_the_limit_is_refused_without_reserving_it() {
        // A megabyte of zeros deflates to about a kilobyte: 34 bytes of wire buying a
        // megabyte of memory is the amplifier the ceiling exists for.
        let bomb = vec![0_u8; 1 << 20];
        let mut packed = Vec::new();
        pack(&bomb, &mut packed);
        assert!(packed.len() < 4096, "the bomb did not compress");
        let mut out = Vec::new();
        assert!(matches!(
            unpack(&packed, 4096, &mut out),
            Err(DecodeError::InvalidField)
        ));
        assert!(
            out.capacity() <= 4096,
            "refusing the payload still reserved {} bytes",
            out.capacity()
        );
    }

    #[test]
    fn a_payload_larger_than_the_ceiling_is_refused_on_either_path() {
        let mut stored = Vec::new();
        pack(&[0xab_u8; 100], &mut stored);
        assert_eq!(stored[0], TAG_STORED);
        let mut deflated = Vec::new();
        pack(&vec![b'x'; 4096], &mut deflated);
        assert_eq!(deflated[0], TAG_DEFLATE);

        let mut out = Vec::new();
        assert!(matches!(
            unpack(&stored, 99, &mut out),
            Err(DecodeError::InvalidField)
        ));
        assert!(unpack(&stored, 100, &mut out).is_ok());

        // A zero ceiling admits nothing, on either path, and refuses it calmly.
        let mut fresh = Vec::new();
        assert!(unpack(&stored, 0, &mut fresh).is_err());
        assert!(unpack(&deflated, 0, &mut fresh).is_err());
        assert!(fresh.is_empty());
    }

    #[test]
    fn an_unknown_codec_tag_is_refused() {
        let mut out = Vec::new();
        for tag in 2..=u8::MAX {
            assert!(matches!(
                unpack(&[tag, 1, 2, 3], 1 << 20, &mut out),
                Err(DecodeError::InvalidField)
            ));
        }
    }

    #[test]
    fn a_datagram_with_no_body_at_all_is_truncated_rather_than_a_panic() {
        let mut out = Vec::new();
        assert!(matches!(
            unpack(&[], 1 << 20, &mut out),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn a_warm_buffer_pair_stops_allocating() {
        let screen = b"\x1b[1;32muser@host\x1b[0m:~$ ".repeat(400);
        let (mut packed, mut out) = (Vec::new(), Vec::new());
        pack(&screen, &mut packed);
        unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        let (packed_room, out_room) = (packed.capacity(), out.capacity());
        for _ in 0..64 {
            pack(&screen, &mut packed);
            unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        }
        assert_eq!((packed.capacity(), out.capacity()), (packed_room, out_room));
    }

    /// The rule [`crate::read_frame_into`] is written against, on the datagram path.
    #[test]
    fn making_room_in_a_warm_buffer_does_not_zero_what_is_about_to_be_overwritten() {
        let mut out = vec![0xAA_u8; 4096];
        room_for(&mut out, 1024);
        assert_eq!(out.len(), 1024);
        assert!(
            out.iter().all(|&byte| byte == 0xAA),
            "the buffer was zeroed before the codec wrote a byte of it"
        );
    }

    /// Neither codec may let a byte of the last frame survive into this one.
    #[test]
    fn a_buffer_the_last_frame_left_full_carries_none_of_it_into_the_next() {
        let mut packed = vec![0xAA_u8; 8192];
        let mut out = vec![0xBB_u8; 8192];

        let stored = b"short".to_vec();
        pack(&stored, &mut packed);
        unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        assert_eq!(out, stored);

        let deflated = b"the same line over and over ".repeat(64);
        pack(&deflated, &mut packed);
        assert_eq!(packed[0], TAG_DEFLATE, "the test payload must compress");
        unpack(&packed, 1 << 20, &mut out).expect("a payload this side just packed");
        assert_eq!(out, deflated);
    }
}
