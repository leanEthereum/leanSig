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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HypercubeHashError {
    #[error("Hash aborted: field element exceeded Q * w^z threshold.")]
    Abort,
}

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
    type Error = HypercubeHashError;
    const DIMENSION: usize = DIMENSION; // v
    const BASE: usize = BASE; // w

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        FieldArray(rng.random())
    }

    /// Hashes (public_parameter, epoch, randomness, message), and return an error if the resulting outputs does
    /// not pass the rejection sampling check (in order to ensure uniformity of the output distribution), i.e.
    /// if any of the first DIMENSION.div_ceil(Z) output field elements is >= Q * w^z.
    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, HypercubeHashError> {
        const {
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
                BASE <= 1 << 8,
                "Aborting Hypercube Message Hash: Base must be at most 2^8"
            );

            // Check that Q * w^z fits within the field
            assert!(
                Q as u64 * (BASE as u64).pow(Z as u32) <= F::ORDER_U64,
                "Q * w^z exceeds field order"
            );

            // floor(log2(ORDER))
            let bits_per_fe = F::ORDER_U64.ilog2() as usize;

            // Check that we have enough bits to encode message
            assert!(
                bits_per_fe * MSG_LEN_FE >= 8 * MESSAGE_LENGTH,
                "Aborting Hypercube Message Hash: not enough field elements to encode the message"
            );

            // Check that we have enough bits to encode tweak
            // Epoch is a u32, and we have one domain separator byte
            assert!(
                bits_per_fe * TWEAK_LEN_FE >= 40,
                "Aborting Hypercube Message Hash: not enough field elements to encode the epoch tweak"
            );
        }

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
                return Err(HypercubeHashError::Abort);
            }
            let mut d_i = a_i / Q as u64;
            for _ in 0..Z {
                if chunks.len() < DIMENSION {
                    chunks.push((d_i % BASE as u64) as u8);
                }
                d_i /= BASE as u64;
            }
        }
        // Sanity check to ensure we hit our exact dimension
        debug_assert_eq!(chunks.len(), DIMENSION);

        Ok(chunks)
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
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_apply() {
        let mut rng = StdRng::seed_from_u64(1);
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
    fn test_different_epochs_produce_different_results() {
        let mut rng = StdRng::seed_from_u64(2);
        let parameter = FieldArray(rng.random());
        let message: [u8; 32] = rng.random();
        let randomness = HypercubePoseidonMHKoalaBear::rand(&mut rng);

        let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, 0, &randomness, &message);
        let r2 = HypercubePoseidonMHKoalaBear::apply(&parameter, 1, &randomness, &message);

        let c1 = r1.unwrap();
        let c2 = r2.unwrap();
        assert_ne!(c1, c2, "Different epochs should produce different chunks");
    }

    #[test]
    fn test_different_messages_produce_different_results() {
        let mut rng = StdRng::seed_from_u64(3);
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

    #[test]
    fn test_abort_rate() {
        // Parameters chosen so each FE aborts with probability ≈ 1/2:
        // w=8, z=3, Q=2080768, so Q*w^z = 2080768 * 512 = 1065353216 ≈ p/2.
        // With 3 useful FEs (DIMENSION=9, Z=3), success prob ≈ (1/2)^3 = 1/8.
        // Expected attempts per success ≈ 8.
        type HighAbortMH = AbortingHypercubeMessageHash<5, 5, 3, 9, 8, 3, 2_080_768, 2, 9>;
        const NUM_TRIALS: usize = 1000;

        let mut rng = StdRng::seed_from_u64(0);
        let parameter: FieldArray<5> = FieldArray(rng.random());
        let message: [u8; 32] = rng.random();
        let mut total_attempts: usize = 0;

        for _ in 0..NUM_TRIALS {
            let mut attempts = 0;
            loop {
                attempts += 1;
                let randomness = HighAbortMH::rand(&mut rng);
                if let Ok(chunks) = HighAbortMH::apply(&parameter, 0, &randomness, &message) {
                    assert_eq!(chunks.len(), 9);
                    assert!(chunks.iter().all(|&c| c < 8));
                    break;
                }
                assert!(attempts < 1000, "too many attempts, something is wrong");
            }
            total_attempts += attempts;
        }

        let avg = total_attempts as f64 / NUM_TRIALS as f64;

        // Expected ≈ 8
        assert!((7.5..=8.5).contains(&avg));
    }

    #[test]
    #[ignore = "slow: 1M samples"]
    fn test_output_uniformity() {
        // Use a tiny output space: base 4, dimension 2 (= 4^2 = 16 possible messages).
        // Check that each of the 16 possible outputs appears with roughly equal frequency.
        // Q = 66_585_201, so Q * 4^2 = 1_065_363_216 ≈ p/2 (abort prob ≈ 1/2 per FE).
        type SmallMH = AbortingHypercubeMessageHash<5, 5, 1, 2, 4, 2, 66_585_201, 2, 9>;
        const NUM_SAMPLES: usize = 1_000_000;
        const NUM_OUTPUTS: usize = 16; // 4^2

        let mut rng = StdRng::seed_from_u64(42);
        let parameter: FieldArray<5> = FieldArray(rng.random());
        let message: [u8; 32] = rng.random();
        let mut counts = [0usize; NUM_OUTPUTS];
        let mut successes = 0;

        while successes < NUM_SAMPLES {
            let randomness = SmallMH::rand(&mut rng);
            if let Ok(chunks) = SmallMH::apply(&parameter, 0, &randomness, &message) {
                let idx = chunks[0] as usize + 4 * chunks[1] as usize;
                counts[idx] += 1;
                successes += 1;
            }
        }

        for c in counts {
            let left = (NUM_SAMPLES / NUM_OUTPUTS) * 99 / 100; // 99% of expected
            let right = (NUM_SAMPLES / NUM_OUTPUTS) * 101 / 100; // 101% of expected
            assert!((left..=right).contains(&c),);
        }
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
