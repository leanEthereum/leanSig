use p3_field::PrimeField64;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use super::MessageHash;
use super::poseidon::poseidon_message_hash_fe;
use crate::F;
use crate::MESSAGE_LENGTH;
use crate::array::FieldArray;

/// A uniform message hash using rejection sampling instead of big integers.
/// See Section 6.1 of [Aborting Random Oracles: How to Build them, How to Use them](https://eprint.iacr.org/2026/016.pdf)
///
/// Given p = Q * w^z + alpha, each Poseidon output field element A_i is:
/// 1) checked to be less than Q * w^z, and if not the hash aborts
/// 2) decomposed as d_i = floor(A_i / Q), then d_i is written in base w with z digits.
pub struct AbortingHypercubeMessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN_FE: usize,
    const HASH_LEN_FE: usize,
    const DIMENSION: usize,
    const BASE: usize,
    const Z: usize,
    const Q_VAL: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
>;

#[derive(Debug, Error)]
#[error("Hash aborted: field element exceeded Q * w^z threshold.")]
pub struct HypercubeAbortError;

impl<
    const PARAMETER_LEN: usize,
    const RAND_LEN_FE: usize,
    const HASH_LEN_FE: usize,
    const DIMENSION: usize,
    const BASE: usize,
    const Z: usize,
    const Q: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
> MessageHash
    for AbortingHypercubeMessageHash<
        PARAMETER_LEN,
        RAND_LEN_FE,
        HASH_LEN_FE,
        DIMENSION,
        BASE,
        Z,
        Q,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >
where
    [F; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [F; RAND_LEN_FE]: Serialize + DeserializeOwned,
{
    type Parameter = FieldArray<PARAMETER_LEN>;
    type Randomness = FieldArray<RAND_LEN_FE>;
    type Error = HypercubeAbortError;
    const DIMENSION: usize = DIMENSION; // v
    const BASE: usize = BASE; // w

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        FieldArray(rng.random())
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, HypercubeAbortError> {
        let hash_fe = poseidon_message_hash_fe::<
            PARAMETER_LEN,
            RAND_LEN_FE,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >(parameter, epoch, randomness, message);

        let q_wz = Q as u64 * (BASE as u64).pow(Z as u32);
        let num_useful_fe = DIMENSION.div_ceil(Z);
        let mut chunks = Vec::with_capacity(DIMENSION);

        for fe in &hash_fe[..num_useful_fe] {
            let a_i = fe.as_canonical_u64();
            if a_i >= q_wz {
                return Err(HypercubeAbortError);
            }
            let mut d_i = a_i / Q as u64;
            for _ in 0..Z {
                if chunks.len() < DIMENSION {
                    chunks.push((d_i % BASE as u64) as u8);
                }
                d_i /= BASE as u64;
            }
        }
        assert_eq!(chunks.len(), DIMENSION);

        Ok(chunks)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // Check that Poseidon of width 24 is enough
        assert!(
            PARAMETER_LEN + RAND_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE <= 24,
            "Poseidon of width 24 is not enough"
        );
        assert!(HASH_LEN_FE <= 24, "Poseidon of width 24 is not enough");

        // Check that we have enough hash output field elements
        assert!(
            HASH_LEN_FE >= DIMENSION.div_ceil(Z),
            "Not enough hash output field elements for the requested dimension"
        );
        assert!(
            PARAMETER_LEN + RAND_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE >= HASH_LEN_FE,
            "Input shorter than requested output"
        );

        // Base check
        assert!(
            Self::BASE <= 1 << 8,
            "Aborting Hypercube Message Hash: Base must be at most 2^8"
        );

        // Check that Q * w^z fits within the field
        assert!(
            Q as u64 * (BASE as u64).pow(Z as u32) <= F::ORDER_U64,
            "Q * w^z exceeds field order"
        );

        // how many bits can be represented by one field element
        let bits_per_fe = f64::floor(f64::log2(F::ORDER_U64 as f64));

        // Check that we have enough bits to encode message
        let message_fe_bits = bits_per_fe * f64::from(MSG_LEN_FE as u32);
        assert!(
            message_fe_bits >= f64::from((8_u32) * (MESSAGE_LENGTH as u32)),
            "Aborting Hypercube Message Hash: not enough field elements to encode the message"
        );

        // Check that we have enough bits to encode tweak
        // Epoch is a u32, and we have one domain separator byte
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN_FE as u32);
        assert!(
            tweak_fe_bits >= f64::from(32 + 8_u32),
            "Aborting Hypercube Message Hash: not enough field elements to encode the epoch tweak"
        );
    }
}

// KoalaBear: p = 2^31 - 2^24 + 1 = 127 * 8^8 + 1
// v=64, w=8, z=8, Q=127, alpha=1, l=8
#[cfg(test)]
pub type HypercubePoseidonMHKoalaBear = AbortingHypercubeMessageHash<5, 5, 8, 64, 8, 8, 127, 2, 9>;

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField32;
    use proptest::prelude::*;

    #[test]
    fn test_internal_consistency() {
        HypercubePoseidonMHKoalaBear::internal_consistency_check();
    }

    #[test]
    fn test_koalabear_parameters() {
        // p = Q * w^z + alpha = 127 * 8^8 + 1
        let p = F::ORDER_U64;
        assert_eq!(p, 127 * 8u64.pow(8) + 1);

        // alpha = 1 means only a single value (p-1) triggers an abort per FE
        let q_wz = 127u64 * 8u64.pow(8);
        assert_eq!(p - 1, q_wz);
    }

    #[test]
    fn test_apply() {
        let mut rng = rand::rng();
        let parameter = FieldArray(rng.random());
        let message = rng.random();
        let randomness = HypercubePoseidonMHKoalaBear::rand(&mut rng);

        let hash =
            HypercubePoseidonMHKoalaBear::apply(&parameter, 42, &randomness, &message).unwrap();
        assert_eq!(hash.len(), 64);
        for &chunk in &hash {
            assert!((chunk as usize) < 8);
        }
    }

    #[test]
    fn test_rand_not_all_same() {
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let randomness = HypercubePoseidonMHKoalaBear::rand(&mut rng);
            let first = randomness[0];
            if randomness.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        assert!(
            all_same_count < K,
            "rand generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_decomposition_manual() {
        // A_i = Q*42 + 3 = 127*42 + 3 = 5337
        // d_i = floor(A_i / Q) = floor(5337 / 127) = 42
        // base-8 digits of 42 (little-endian): [2, 5, 0, 0, 0, 0, 0, 0]
        let a_i = 127u64 * 42 + 3;
        assert_eq!(a_i, 5337);

        let d_i = a_i / 127;
        assert_eq!(d_i, 42);

        // little-endian base-8 decomposition of 42
        assert_eq!(d_i % 8, 2);
        assert_eq!((d_i / 8) % 8, 5);
        assert_eq!((d_i / 64) % 8, 0);
    }

    #[test]
    fn test_abort_boundary() {
        // For KoalaBear: Q*w^z = 127 * 8^8 = p - 1
        // Any A_i >= Q*w^z means A_i = p-1 (the only value), which triggers abort
        let q_wz = 127u64 * 8u64.pow(8);
        let p = F::ORDER_U64;
        assert_eq!(q_wz, p - 1);

        // The maximum valid d_i is w^z - 1 = 8^8 - 1
        let max_valid_a = q_wz - 1; // = Q * w^z - 1
        let max_d = max_valid_a / 127;
        assert_eq!(max_d, 8u64.pow(8) - 1);

        // All base-8 digits of w^z - 1 = 8^8 - 1 should be 7
        let mut d = max_d;
        for _ in 0..8 {
            assert_eq!(d % 8, 7);
            d /= 8;
        }
        assert_eq!(d, 0);
    }

    #[test]
    fn test_decomposition_uniformity_quotient_independent() {
        // For any two values A_i with the same d_i = floor(A_i / Q),
        // the decomposition should produce the same chunks.
        // This verifies that the remainder (A_i mod Q) is discarded.
        let d_i = 42u64;
        let base_chunks: Vec<u8> = {
            let mut d = d_i;
            (0..8).map(|_| { let c = (d % 8) as u8; d /= 8; c }).collect()
        };

        // All values A_i in [Q*42, Q*42 + Q-1] should give the same chunks
        for r in 0..127u64 {
            let a_i = 127 * d_i + r;
            let mut d = a_i / 127;
            assert_eq!(d, d_i);
            let chunks: Vec<u8> = (0..8).map(|_| { let c = (d % 8) as u8; d /= 8; c }).collect();
            assert_eq!(chunks, base_chunks);
        }
    }

    #[test]
    fn test_different_epochs_produce_different_results() {
        let mut rng = rand::rng();
        let parameter = FieldArray(rng.random());
        let message: [u8; 32] = rng.random();
        let randomness = HypercubePoseidonMHKoalaBear::rand(&mut rng);

        let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, 0, &randomness, &message);
        let r2 = HypercubePoseidonMHKoalaBear::apply(&parameter, 1, &randomness, &message);

        // Both should succeed (abort probability ~1/p per FE is negligible)
        let c1 = r1.unwrap();
        let c2 = r2.unwrap();
        assert_ne!(c1, c2, "Different epochs should produce different chunks");
    }

    #[test]
    fn test_different_messages_produce_different_results() {
        let mut rng = rand::rng();
        let parameter = FieldArray(rng.random());
        let randomness = HypercubePoseidonMHKoalaBear::rand(&mut rng);

        let msg1 = [0u8; 32];
        let msg2 = [1u8; 32];

        let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, 0, &randomness, &msg1);
        let r2 = HypercubePoseidonMHKoalaBear::apply(&parameter, 0, &randomness, &msg2);

        let c1 = r1.unwrap();
        let c2 = r2.unwrap();
        assert_ne!(c1, c2, "Different messages should produce different chunks");
    }

    proptest! {
        #[test]
        fn proptest_determinism_and_output_validity(
            message in prop::array::uniform32(any::<u8>()),
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            rand_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            epoch in any::<u32>()
        ) {
            let parameter = FieldArray(std::array::from_fn(|i| F::new(param_values[i])));
            let randomness = FieldArray(std::array::from_fn(|i| F::new(rand_values[i])));

            // determinism: two calls with same inputs must agree
            let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, epoch, &randomness, &message);
            let r2 = HypercubePoseidonMHKoalaBear::apply(&parameter, epoch, &randomness, &message);

            match (&r1, &r2) {
                (Ok(c1), Ok(c2)) => {
                    prop_assert_eq!(c1, c2);

                    // output dimension
                    prop_assert_eq!(c1.len(), HypercubePoseidonMHKoalaBear::DIMENSION);

                    // all chunks in valid range [0, BASE-1]
                    for &chunk in c1 {
                        prop_assert!((chunk as usize) < HypercubePoseidonMHKoalaBear::BASE);
                    }
                }
                (Err(_), Err(_)) => {}
                _ => prop_assert!(false, "determinism violated: one call succeeded, the other failed"),
            }
        }

        #[test]
        fn proptest_different_epochs_produce_different_results(
            message in prop::array::uniform32(any::<u8>()),
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            rand_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            epoch in any::<u32>()
        ) {
            let parameter = FieldArray(std::array::from_fn(|i| F::new(param_values[i])));
            let randomness = FieldArray(std::array::from_fn(|i| F::new(rand_values[i])));

            let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, epoch, &randomness, &message);
            let r2 = HypercubePoseidonMHKoalaBear::apply(
                &parameter, epoch.wrapping_add(1), &randomness, &message,
            );

            // when both succeed, they should differ
            if let (Ok(c1), Ok(c2)) = (&r1, &r2) {
                prop_assert_ne!(c1, c2, "Different epochs should produce different chunks");
            }
        }
    }
}
