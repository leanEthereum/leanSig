use leansig::array::FieldArray;
use leansig::inc_encoding::IncomparableEncoding;
use leansig::inc_encoding::target_sum::{TargetSumEncoding, TargetSumError};
use leansig::symmetric::message_hash::MessageHash;
use leansig::symmetric::message_hash::poseidon::PoseidonMessageHash;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear as F;
use proptest::prelude::*;
use rand::RngExt;

type PoseidonMessageHash445 = PoseidonMessageHash<4, 4, 5, 128, 4, 2, 9>;

const TEST_TARGET_SUM: usize = 115;
type TestTargetSumEncoding = TargetSumEncoding<PoseidonMessageHash445, TEST_TARGET_SUM>;

#[test]
fn test_successful_encoding_fixed_message() {
    // keep message fixed and only resample randomness
    // this mirrors the actual signature scheme behavior
    let mut rng = rand::rng();
    let parameter: FieldArray<4> = FieldArray(rng.random());
    let message: [u8; 32] = rng.random();
    let epoch = 0u32;

    // retry with different randomness until encoding succeeds
    for _ in 0..1_000 {
        let randomness = TestTargetSumEncoding::rand(&mut rng);

        if let Ok(chunks) = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch)
        {
            // check output has correct dimension
            assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);

            // check all chunks are in valid range [0, BASE-1]
            for &chunk in &chunks {
                assert!((chunk as usize) < TestTargetSumEncoding::BASE);
            }

            // check sum equals target
            let sum: usize = chunks.iter().map(|&x| x as usize).sum();
            assert_eq!(sum, TEST_TARGET_SUM);

            // check determinism: encoding again with same inputs produces same result
            let result2 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
            assert_eq!(chunks, result2.unwrap());

            return;
        }
    }

    panic!("failed to find successful encoding after 1000 attempts");
}

#[test]
fn test_successful_encoding_random_inputs() {
    // retry with all random inputs until encoding succeeds
    let mut rng = rand::rng();
    let epoch = 0u32;

    for _ in 0..1_000 {
        let parameter: FieldArray<4> = FieldArray(rng.random());
        let message: [u8; 32] = rng.random();
        let randomness = TestTargetSumEncoding::rand(&mut rng);

        if let Ok(chunks) = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch)
        {
            // check output has correct dimension
            assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);

            // check all chunks are in valid range [0, BASE-1]
            for &chunk in &chunks {
                assert!((chunk as usize) < TestTargetSumEncoding::BASE);
            }

            // check sum equals target
            let sum: usize = chunks.iter().map(|&x| x as usize).sum();
            assert_eq!(sum, TEST_TARGET_SUM);

            // check determinism: encoding again with same inputs produces same result
            let result2 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
            assert_eq!(chunks, result2.unwrap());

            return;
        }
    }

    panic!("failed to find successful encoding after 1000 attempts");
}

proptest! {
    #[test]
    fn proptest_encoding_determinism_and_error_reporting(
        message in prop::array::uniform32(any::<u8>()),
        randomness_values in prop::collection::vec(0u32..F::ORDER_U32, 4),
        parameter_values in prop::collection::vec(0u32..F::ORDER_U32, 4),
        epoch in any::<u32>()
    ) {
        // build randomness and parameter from proptest values
        let randomness_arr: [F; 4] = std::array::from_fn(|i| F::new(randomness_values[i]));
        let randomness = FieldArray(randomness_arr);
        let parameter_arr: [F; 4] = std::array::from_fn(|i| F::new(parameter_values[i]));
        let parameter = FieldArray(parameter_arr);

        // compute expected sum from underlying message hash
        let hash_chunks = PoseidonMessageHash445::apply(&parameter, epoch, &randomness, &message).unwrap();
        let hash_sum: usize = hash_chunks.iter().map(|&x| x as usize).sum();

        // call encode twice to check determinism
        let result1 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);
        let result2 = TestTargetSumEncoding::encode(&parameter, &message, &randomness, epoch);

        // check determinism: both calls produce same result
        match (&result1, &result2) {
            (Ok(c1), Ok(c2)) => prop_assert_eq!(c1, c2),
            (Err(TargetSumError::Mismatch { expected: e1, actual: a1 }),
             Err(TargetSumError::Mismatch { expected: e2, actual: a2 })) => {
                prop_assert_eq!(e1, e2);
                prop_assert_eq!(a1, a2);
            }
            _ => prop_assert!(false, "determinism violated"),
        }

        // check properties based on success/failure
        match result1 {
            Err(TargetSumError::Mismatch { expected, actual }) => {
                // check error reports correct values
                prop_assert_eq!(expected, TEST_TARGET_SUM);
                prop_assert_eq!(actual, hash_sum);
            }
            Ok(chunks) => {
                // check output dimension
                prop_assert_eq!(chunks.len(), TestTargetSumEncoding::DIMENSION);

                // check all chunks in valid range
                for &chunk in &chunks {
                    prop_assert!((chunk as usize) < TestTargetSumEncoding::BASE);
                }

                // check sum equals target
                let sum: usize = chunks.iter().map(|&x| x as usize).sum();
                prop_assert_eq!(sum, TEST_TARGET_SUM);
            }
        }
    }
}
