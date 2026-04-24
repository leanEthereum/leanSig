use rand::RngExt;
use std::fmt::Debug;

use crate::MESSAGE_LENGTH;
use crate::serialization::Serializable;
use crate::symmetric::prf::Pseudorandom;

/// Trait to model incomparable encoding schemes.
/// These schemes allow to encode a message into a codeword.
///
/// A codeword is a vector of a fixed dimension containing
/// integer elements between 0 and BASE - 1.
/// **WARNING**: We require BASE to be at most 2^8 to ensure that
/// the entries fit into u8.
///
/// The main feature of these encodings is that no two distinct
/// codewords are "comparable", i.e., for no two codewords
/// x = (x_1,..,x_k) and x' = (x'_1,..,x'_k) we have
/// x_i > x'_i for all i = 1,...,k.
pub trait IncomparableEncoding {
    type Parameter: Serializable;
    type Randomness: Serializable;
    type Error: Debug;

    /// number of entries in a codeword
    const DIMENSION: usize;

    /// how often one should try at most
    /// to resample randomness before giving up.
    const MAX_TRIES: usize;

    /// base of the code, i.e., codeword entries
    /// are between 0 and BASE - 1
    const BASE: usize;

    /// Samples a randomness to be used for the encoding.
    fn rand<R: RngExt>(rng: &mut R) -> Self::Randomness;

    /// Apply the incomparable encoding to a message.
    /// It could happen that this fails. Otherwise,
    /// implementations must guarantee that the
    /// result is indeed a valid codeword.
    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Deterministically search for the first randomness that yields a valid codeword.
    ///
    /// Implementations may override this with a batched or SIMD-accelerated search.
    fn grind<PRF>(
        parameter: &Self::Parameter,
        prf_key: &PRF::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Option<(Self::Randomness, Vec<u8>)>
    where
        PRF: Pseudorandom,
        PRF::Randomness: Into<Self::Randomness>,
    {
        for attempt in 0..Self::MAX_TRIES {
            let randomness = PRF::get_randomness(prf_key, epoch, message, attempt as u64).into();
            if let Ok(codeword) = Self::encode(parameter, message, &randomness, epoch) {
                return Some((randomness, codeword));
            }
        }

        None
    }
}

pub mod target_sum;
