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
#[derive(Debug, Clone, Copy)]
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

    fn rand<R: rand::RngExt>(rng: &mut R) -> Self::Randomness {
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
        // Compile-time parameter validation for AbortingHypercubeMessageHash
        //
        // This hash implements H^hc_{w,v,z,Q} from §6.1 of HHKTW26. It uses
        // rejection sampling to uniformly map Poseidon field elements into
        // the hypercube Z_w^v, avoiding big-integer arithmetic entirely:
        //
        //   1. Compute (A_1, ..., A_ℓ) := Poseidon(R || P || T || M)
        //   2. For each A_i: reject if A_i ≥ Q·w^z  (ensures uniformity)
        //   3. Decompose d_i = ⌊A_i / Q⌋ into z base-w digits
        //   4. Collect the first v digits as the output
        //
        // The field prime decomposes as  p = Q·w^z + α  (α ≥ 0).
        // Rejection happens with per-element probability α/p, and the
        // overall abort probability is θ = 1 - ((Q·w^z)/p)^ℓ  (Lemma 8).
        //
        // By Theorem 4 of HHKTW26, this construction is indifferentiable
        // from a θ-aborting random oracle when Poseidon is modeled as a
        // standard random oracle.
        //
        // DKKW25: https://eprint.iacr.org/2025/055
        // HHKTW26: https://eprint.iacr.org/2026/016
        const {
            // Poseidon capacity constraints
            //
            // We use Poseidon in compression mode with a width-24 permutation.
            // All inputs must fit in one call, and the output is extracted
            // from the same state.
            assert!(
                PARAMETER_LEN + RAND_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE <= 24,
                "Poseidon of width 24 is not enough for the input"
            );
            assert!(
                HASH_LEN_FE <= 24,
                "Poseidon of width 24 is not enough for the output"
            );

            // Poseidon compression mode can only produce as many output
            // field elements as there are input elements.
            assert!(
                PARAMETER_LEN + RAND_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE >= HASH_LEN_FE,
                "Input shorter than requested output"
            );

            // Hypercube decomposition parameters
            //
            // Each good field element A_i < Q·w^z is decomposed into z
            // base-w digits, so we need ℓ = ⌈v/z⌉ field elements to get
            // at least v digits. HASH_LEN_FE must supply enough elements.
            assert!(
                DIMENSION >= 1,
                "AbortingHypercubeMessageHash: DIMENSION (v) must be at least 1"
            );
            assert!(
                Z >= 1,
                "AbortingHypercubeMessageHash: Z (digits per field element) must be at least 1"
            );
            assert!(
                HASH_LEN_FE >= DIMENSION.div_ceil(Z),
                "Not enough hash output field elements: need ceil(v/z)"
            );

            // Q is the quotient in the decomposition A_i = Q·d_i + c_i,
            // where c_i ∈ {0, ..., Q-1} is discarded and d_i ∈ {0, ..., w^z-1}
            // carries the uniform digits. Q must be positive for a valid range.
            assert!(Q >= 1, "AbortingHypercubeMessageHash: Q must be at least 1");

            // The rejection threshold Q·w^z must not exceed the field order p,
            // since field elements A_i live in {0, ..., p-1}. The remainder
            // α = p - Q·w^z determines the per-element abort probability α/p.
            //
            // Example (KoalaBear): p = 2^31 - 2^24 + 1 = 127·8^8 + 1
            //   ⟹  Q=127, w=8, z=8, α=1, abort prob ≈ 4.7e-10 per element.
            assert!(
                Q as u64 * (BASE as u64).pow(Z as u32) <= F::ORDER_U64,
                "Q * w^z exceeds field order p"
            );

            // Representation constraints
            //
            // Same as the Poseidon message hash: chunks and chain indices
            // are stored as u8 in signatures and tweak encodings.
            assert!(
                BASE >= 2,
                "AbortingHypercubeMessageHash: BASE (w) must be at least 2 (Definition 13, DKKW25)"
            );
            assert!(
                BASE <= 1 << 8,
                "AbortingHypercubeMessageHash: BASE (w) must fit in u8"
            );

            // Injective encoding of inputs
            //
            // Same requirements as the standard Poseidon message hash:
            // message and epoch must be losslessly encodable as field elements.
            let bits_per_fe = F::ORDER_U64.ilog2() as usize;
            assert!(
                bits_per_fe * MSG_LEN_FE >= 8 * MESSAGE_LENGTH,
                "AbortingHypercubeMessageHash: not enough field elements to encode the message"
            );
            assert!(
                bits_per_fe * TWEAK_LEN_FE >= 40,
                "AbortingHypercubeMessageHash: not enough field elements to encode the epoch tweak"
            );
        }

        let hash_fe = poseidon_message_hash_fe::<
            PARAMETER_LEN,
            RAND_LEN_FE,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >(parameter, epoch, randomness, message);

        // Build the output on the stack — no Vec growth overhead.
        let mut chunks = [0u8; DIMENSION];

        for (i, fe) in hash_fe[..const { DIMENSION.div_ceil(Z) }]
            .iter()
            .enumerate()
        {
            let a_i = fe.as_canonical_u64();
            if a_i >= const { Q as u64 * (BASE as u64).pow(Z as u32) } {
                return Err(HypercubeHashError::Abort);
            }
            // Decompose d_i = floor(a_i / Q) into base-BASE digits.
            // Position and count are derived from the FE index — no mutable cursor.
            let mut d_i = a_i / const { Q as u64 };
            let base_idx = i * Z;
            for j in 0..Z.min(DIMENSION - base_idx) {
                chunks[base_idx + j] = (d_i % const { BASE as u64 }) as u8;
                d_i /= const { BASE as u64 };
            }
        }

        Ok(chunks.to_vec())
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
    use rand::{RngExt, SeedableRng, rngs::StdRng};

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
