use super::IncomparableEncoding;
use crate::{MESSAGE_LENGTH, symmetric::message_hash::MessageHash};
use std::fmt::Debug;
use thiserror::Error;

/// Specific errors that can occur during target sum encoding.
#[derive(Debug, Error)]
pub enum TargetSumError<E> {
    /// Returned when the generated chunks do not sum to the required target.
    #[error("Target sum mismatch: expected {expected}, but got {actual}.")]
    Mismatch { expected: usize, actual: usize },

    /// Returned when the underlying message hash fails.
    #[error("Hash error: {0:?}")]
    HashError(E),
}

/// Incomparable Encoding Scheme based on Target Sums,
/// implemented from a given message hash.
///
/// CHUNK_SIZE has to be 1,2,4, or 8.
/// TARGET_SUM determines how we set the target sum,
/// and has direct impact on the signer's running time,
/// or equivalently the success probability of this encoding scheme.
/// It is recommended to set it close to the expected sum, which is:
///
/// ```ignore
///     const MAX_CHUNK_VALUE: usize = MH::BASE - 1
///     const EXPECTED_SUM: usize = MH::DIMENSION * MAX_CHUNK_VALUE / 2
/// ```
#[derive(Clone)]
pub struct TargetSumEncoding<MH: MessageHash, const TARGET_SUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const TARGET_SUM: usize> IncomparableEncoding
    for TargetSumEncoding<MH, TARGET_SUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    type Error = TargetSumError<MH::Error>;

    const DIMENSION: usize = MH::DIMENSION;

    /// we did one experiment with random message hashes.
    /// In production, this should be estimated via more
    /// extensive experiments with concrete hash functions.
    const MAX_TRIES: usize = 100_000;

    const BASE: usize = MH::BASE;

    fn rand<R: rand::RngExt>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        // Compile-time parameter validation for Target Sum Encoding
        //
        // This encoding implements Construction 6 (IE for Target Sum Winternitz)
        // from DKKW25. It maps a message to a codeword x ∈ C ⊆ Z_w^v, where:
        //
        //   C = { (x_1, ..., x_v) ∈ {0, ..., w-1}^v  |  Σ x_i = T }
        //
        // The code C enforces the *incomparability* property (Definition 13):
        // no two distinct codewords x, x' satisfy x_i ≥ x'_i for all i.
        // This is critical for the security of the XMSS signature scheme.
        //
        // DKKW25: https://eprint.iacr.org/2025/055
        // HHKTW26: https://eprint.iacr.org/2026/016
        const {
            // Representation constraints
            //
            // In the Generalized XMSS construction (DKKW25),
            // each chain position and chain index is encoded as a single byte
            // in the tweak function:
            //
            //   tweak(ep, i, k) = (0x00 || ep || i || k)
            //                      8b     ⌈log L⌉  ⌈log v⌉  w bits
            //
            // - Since chain_index `i` is stored as u8, we need v ≤ 256.
            // - Since pos_in_chain `k` is stored as u8, we need w ≤ 256.
            // - Codeword entries (chunks) are also stored as u8 in signatures.
            assert!(
                MH::BASE <= 1 << 8,
                "Target Sum Encoding: Base must be at most 2^8"
            );
            assert!(
                MH::DIMENSION <= 1 << 8,
                "Target Sum Encoding: Dimension must be at most 2^8"
            );

            // Encoding well-formedness
            //
            // Definition 13 (DKKW25): an incomparable encoding maps messages
            // to codewords in {0, ..., w-1}^v. For the incomparability
            // property to be meaningful, we need w ≥ 2 (otherwise every
            // codeword is the zero vector, and distinct codewords cannot
            // exist).
            assert!(
                MH::BASE >= 2,
                "Target Sum Encoding: Base must be at least 2"
            );

            // Target sum range
            //
            // Construction 6 (DKKW25) defines the code:
            //
            //   C = { x ∈ {0,...,w-1}^v | Σ x_i = T }
            //
            // For C to be non-empty, T must be achievable: each x_i can
            // contribute at most w-1 to the sum, so T ≤ v*(w-1). The lower
            // bound T ≥ 0 is guaranteed by the usize type.
            //
            // Choosing T close to v*(w-1)/2 (the expected sum of a uniform
            // hash) maximizes |C| and minimizes the signing retry rate
            // (Lemma 7, DKKW25).
            assert!(
                TARGET_SUM <= MH::DIMENSION * (MH::BASE - 1),
                "Target Sum Encoding: TARGET_SUM must be at most DIMENSION * (BASE - 1)"
            );
        }

        // apply the message hash first to get chunks
        let chunks =
            MH::apply(parameter, epoch, randomness, message).map_err(TargetSumError::HashError)?;
        let sum: u32 = chunks.iter().map(|&x| x as u32).sum();
        // only output something if the chunks sum to the target sum
        if sum as usize == TARGET_SUM {
            Ok(chunks)
        } else {
            Err(TargetSumError::Mismatch {
                expected: TARGET_SUM,
                actual: sum as usize,
            })
        }
    }
}
