#![forbid(unsafe_code)]

//! Sealing and opening one datagram with ChaCha20-Poly1305 (RFC 8439): the
//! header is associated data, the packet number is the nonce.

use crate::keys::DirectionKey;
use crate::packet::{HEADER_BYTES, MAX_PAYLOAD, TAG_BYTES};
use chacha20poly1305::{AeadInOut, Nonce};

/// Carries nothing: any detail of why a tag failed is a forgery oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("datagram failed authentication")]
pub struct AuthFailed;

/// The cipher refuses a body past `2^32` blocks, which is the only way either
/// call below can fail. A datagram is six orders of magnitude short of it.
const _: () = assert!(MAX_PAYLOAD / 64 < u32::MAX as usize);

/// The packet number is unique within an epoch and the key is per epoch and
/// per direction, so the leading four bytes are room the construction asks for
/// and this protocol has no counter to put in.
fn nonce(number: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&number.to_be_bytes());
    Nonce::from(bytes)
}

/// Encrypt `body` in place and return the tag over `header` and the ciphertext.
///
/// The header is authenticated but not encrypted: it routes the datagram and
/// names the key. Fixed length because Poly1305 pads associated data to a
/// block and commits its length, so nothing here has to frame it.
#[must_use]
pub fn seal(
    keys: &DirectionKey,
    header: &[u8; HEADER_BYTES],
    number: u64,
    body: &mut [u8],
) -> [u8; TAG_BYTES] {
    keys.cipher()
        .encrypt_inout_detached(&nonce(number), header, body.into())
        .expect("a datagram body is bounded by MAX_PAYLOAD")
        .into()
}

/// Verify then decrypt; the other order hands the caller attacker-chosen
/// plaintext it has to remember not to look at. `decrypt_inout_detached`
/// applies the keystream only after `Poly1305::verify`.
pub fn open(
    keys: &DirectionKey,
    header: &[u8; HEADER_BYTES],
    number: u64,
    body: &mut [u8],
    tag: &[u8; TAG_BYTES],
) -> Result<(), AuthFailed> {
    keys.cipher()
        .decrypt_inout_detached(&nonce(number), header, body.into(), tag.into())
        .map_err(|_| AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Direction, KeySchedule, RootSecret};

    fn keys() -> DirectionKey {
        let schedule = KeySchedule::new(&RootSecret::new([3u8; 32]), Direction::ClientToServer);
        schedule.sending().clone()
    }

    fn header(byte: u8) -> [u8; HEADER_BYTES] {
        [byte; HEADER_BYTES]
    }

    #[test]
    fn a_sealed_datagram_opens_to_what_went_in() {
        let keys = keys();
        let header = header(1);
        let mut body = b"a keystroke".to_vec();
        let plain = body.clone();
        let tag = seal(&keys, &header, 7, &mut body);
        assert_ne!(body, plain);
        open(&keys, &header, 7, &mut body, &tag).unwrap();
        assert_eq!(body, plain);
    }

    /// Covers both halves of `header || ciphertext`; the header is not
    /// encrypted, so the tag is all that stops a rewritten packet number.
    #[test]
    fn tampering_with_either_half_fails_authentication() {
        let keys = keys();
        let mut body = b"a keystroke".to_vec();
        let tag = seal(&keys, &header(1), 7, &mut body);
        let sealed = body.clone();

        body[3] ^= 1;
        assert_eq!(open(&keys, &header(1), 7, &mut body, &tag), Err(AuthFailed));

        body.copy_from_slice(&sealed);
        let mut rewritten = header(1);
        rewritten[HEADER_BYTES - 1] ^= 1;
        assert_eq!(open(&keys, &rewritten, 7, &mut body, &tag), Err(AuthFailed));
    }

    /// A rewritten packet number reaches the nonce as well as the tag, so this
    /// is what proves an unauthenticated body is never handed back.
    #[test]
    fn the_wrong_nonce_fails_and_leaves_the_ciphertext_alone() {
        let keys = keys();
        let mut body = b"a keystroke".to_vec();
        let tag = seal(&keys, &header(1), 7, &mut body);
        let ciphertext = body.clone();
        assert_eq!(open(&keys, &header(1), 8, &mut body, &tag), Err(AuthFailed));
        assert_eq!(body, ciphertext, "a failed open decrypts nothing");
        open(&keys, &header(1), 7, &mut body, &tag).unwrap();
        assert_eq!(body, b"a keystroke");
    }

    #[test]
    fn an_empty_body_still_authenticates_its_header() {
        let keys = keys();
        let tag = seal(&keys, &header(9), 1, &mut []);
        open(&keys, &header(9), 1, &mut [], &tag).unwrap();
        assert_eq!(open(&keys, &header(8), 1, &mut [], &tag), Err(AuthFailed));
    }

    /// RFC 8439 section 2.8.2. A vector nobody here chose is the point of
    /// moving off a construction we designed.
    #[test]
    fn it_matches_the_rfc_8439_test_vector() {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + u8::try_from(i).unwrap());
        let cipher = ChaCha20Poly1305::new(&key.into());
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&[0x07, 0x00, 0x00, 0x00]);
        nonce[4..].copy_from_slice(&[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
        let mut body = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it."
            .to_vec();

        let tag = cipher
            .encrypt_inout_detached(&Nonce::from(nonce), &aad, body.as_mut_slice().into())
            .unwrap();

        assert_eq!(
            &body[..16],
            &[
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2
            ]
        );
        assert_eq!(
            tag.as_slice(),
            &[
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91
            ]
        );
    }
}
