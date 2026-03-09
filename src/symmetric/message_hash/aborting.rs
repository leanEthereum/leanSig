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
    fn test_decode_manual() {
        // A_i = 127*42 + 3 = 5337 → d_i = 42 → base-8: [2, 5, 0, ...]
        let a_i = 5337u64;
        let d_i = a_i / 127;
        assert_eq!(d_i, 42);
        assert_eq!(d_i % 8, 2);
        assert_eq!((d_i / 8) % 8, 5);

        // Test abort boundary
        let p_minus_1 = F::ORDER_U64 - 1;
        assert_eq!(p_minus_1, 127 * 8u64.pow(8));
    }

    proptest! {
        #[test]
        fn proptest_apply_determinism_and_validity(
            message in prop::array::uniform32(any::<u8>()),
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            rand_values in prop::collection::vec(0u32..F::ORDER_U32, 5),
            epoch in any::<u32>()
        ) {
            let parameter = FieldArray(std::array::from_fn(|i| F::new(param_values[i])));
            let randomness = FieldArray(std::array::from_fn(|i| F::new(rand_values[i])));

            let r1 = HypercubePoseidonMHKoalaBear::apply(&parameter, epoch, &randomness, &message);
            let r2 = HypercubePoseidonMHKoalaBear::apply(&parameter, epoch, &randomness, &message);
            match (&r1, &r2) {
                (Ok(c1), Ok(c2)) => {
                    prop_assert_eq!(c1, c2);
                    prop_assert_eq!(c1.len(), 64);
                    for &chunk in c1 {
                        prop_assert!((chunk as usize) < 8);
                    }
                }
                (Err(_), Err(_)) => {}
                _ => prop_assert!(false, "determinism violated"),
            }
        }
    }
}
