use std::fmt::Debug;

use rand::RngExt;

use crate::MESSAGE_LENGTH;
use crate::serialization::Serializable;
use crate::symmetric::prf::Pseudorandom;

/// Trait to model a hash function used for message hashing.
///
/// This is a variant of a tweakable hash function that we use for
/// message hashing. Specifically, it contains one more input,
/// and is always executed with respect to epochs, i.e., tweaks
/// are implicitly derived from the epoch.
///
/// Note that BASE must be at most 2^8, as we encode chunks as u8.
pub trait MessageHash {
    type Parameter: Clone + Serializable;
    type Randomness: Serializable;
    type Error: Debug;

    /// number of entries in a hash
    const DIMENSION: usize;

    /// each hash entry is between 0 and BASE - 1
    const BASE: usize;

    /// Generates a random domain element.
    fn rand<R: RngExt>(rng: &mut R) -> Self::Randomness;

    /// Applies the message hash to a parameter, an epoch,
    /// a randomness, and a message. It outputs a list of chunks.
    /// The list contains DIMENSION many elements, each between
    /// 0 and BASE - 1 (inclusive).
    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Search deterministically for the first randomness whose chunks hit `TARGET_SUM`.
    ///
    /// Implementations may override this with a batched or SIMD-accelerated search.
    fn grind_target_sum<PRF, const TARGET_SUM: usize>(
        parameter: &Self::Parameter,
        prf_key: &PRF::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        max_tries: usize,
    ) -> Option<(Self::Randomness, Vec<u8>)>
    where
        PRF: Pseudorandom,
        PRF::Randomness: Into<Self::Randomness>,
    {
        for attempt in 0..max_tries {
            let randomness = PRF::get_randomness(prf_key, epoch, message, attempt as u64).into();
            let Ok(chunks) = Self::apply(parameter, epoch, &randomness, message) else {
                continue;
            };

            if chunks.iter().map(|&chunk| chunk as usize).sum::<usize>() == TARGET_SUM {
                return Some((randomness, chunks));
            }
        }

        None
    }
}

pub mod aborting;
pub mod poseidon;
pub mod top_level_poseidon;
