use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};

use crate::MESSAGE_LENGTH;

/// Trait to model a hash function used for message hashing.
///
/// This is a variant of a tweakable hash function that we use for
/// message hashing. Specifically, it contains one more input,
/// and is always executed with respect to epochs, i.e., tweaks
/// are implicitly derived from the epoch.
///
/// Note that BASE must be at most 2^8, as we encode chunks as u8.
pub trait MessageHash {
    type Parameter: Clone + Sized + Serialize + DeserializeOwned;
    type Randomness: Serialize + DeserializeOwned;

    /// number of entries in a hash
    const DIMENSION: usize;

    /// each hash entry is between 0 and BASE - 1
    const BASE: usize;

    /// Generates a random domain element.
    fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;

    /// Applies the message hash to a parameter, an epoch,
    /// a randomness, and a message. It outputs a list of chunks.
    /// The list contains DIMENSION many elements, each between
    /// 0 and BASE - 1 (inclusive).
    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8>;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod poseidon;
pub mod top_level_poseidon;

#[cfg(test)]
/// Splits a list of bytes into smaller fixed-size bit chunks.
///
/// Each byte in the input slice is divided into `chunk_size`-bit chunks,
/// starting from the least significant bits. The `chunk_size` must divide 8 exactly
/// (i.e., valid values are 1, 2, 4, or 8), since each byte contains 8 bits.
#[must_use]
#[inline]
pub fn bytes_to_chunks(bytes: &[u8], chunk_size: usize) -> Vec<u8> {
    // Only the chunk sizes 1, 2, 4, or 8 are valid.
    assert!(
        matches!(chunk_size, 1 | 2 | 4 | 8),
        "chunk_size must be 1, 2, 4, or 8"
    );

    // Calculate how many chunks each byte will produce and preallocate exactly.
    let chunks_per_byte = 8 / chunk_size;
    let mut out = Vec::with_capacity(bytes.len() * chunks_per_byte);

    match chunk_size {
        8 => {
            out.extend_from_slice(bytes);
        }
        4 => {
            for &b in bytes {
                out.push(b & 0x0F);
                out.push(b >> 4);
            }
        }
        2 => {
            for &b in bytes {
                out.push(b & 0b11);
                out.push((b >> 2) & 0b11);
                out.push((b >> 4) & 0b11);
                out.push((b >> 6) & 0b11);
            }
        }
        1 => {
            for &b in bytes {
                out.push(b & 1);
                out.push((b >> 1) & 1);
                out.push((b >> 2) & 1);
                out.push((b >> 3) & 1);
                out.push((b >> 4) & 1);
                out.push((b >> 5) & 1);
                out.push((b >> 6) & 1);
                out.push((b >> 7) & 1);
            }
        }
        _ => unreachable!(),
    }

    out
}

#[cfg(test)]
mod tests {
    use super::bytes_to_chunks;
    use proptest::prelude::*;

    #[test]
    fn test_bytes_to_chunks() {
        let byte_a: u8 = 0b0110_1100;
        let byte_b: u8 = 0b1010_0110;

        let bytes = [byte_a, byte_b];
        let expected_chunks = [0b00, 0b11, 0b10, 0b01, 0b10, 0b01, 0b10, 0b10];

        let chunks = bytes_to_chunks(&bytes, 2);

        assert_eq!(chunks.len(), 8);

        for i in 0..chunks.len() {
            assert_eq!(chunks[i], expected_chunks[i]);
        }

        // now test chunk size 8
        let chunks = bytes_to_chunks(&bytes, 8);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], byte_a);
        assert_eq!(chunks[1], byte_b);
    }

    proptest! {
        #[test]
        fn prop_bytes_to_chunks_matches_manual_bit_extraction(
            bytes in proptest::collection::vec(any::<u8>(), 0..32),
            chunk_size in prop_oneof![Just(1usize), Just(2), Just(4), Just(8)],
        ) {
            let chunks = bytes_to_chunks(&bytes, chunk_size);

            let chunks_per_byte = 8 / chunk_size;
            let mut expected = Vec::with_capacity(bytes.len() * chunks_per_byte);

            for &b in &bytes {
                for i in 0..chunks_per_byte {
                    let shifted = b >> (i * chunk_size);
                    let mask = if chunk_size == 8 { 0xFF } else { (1u8 << chunk_size) - 1 };
                    expected.push(shifted & mask);
                }
            }

            prop_assert_eq!(chunks.as_slice(), expected.as_slice());
        }
    }
}
