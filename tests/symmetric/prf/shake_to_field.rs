use leansig::MESSAGE_LENGTH;
use leansig::symmetric::prf::Pseudorandom;
use leansig::symmetric::prf::shake_to_field::ShakePRFtoF;
use proptest::prelude::*;

const DOMAIN_LEN: usize = 4;
const RAND_LEN: usize = 4;
type PRF = ShakePRFtoF<DOMAIN_LEN, RAND_LEN>;

#[test]
fn test_shake_to_field_prf_key_not_all_same() {
    const K: usize = 10;

    let mut rng = rand::rng();
    let mut all_same_count = 0;

    for _ in 0..K {
        let key = PRF::key_gen(&mut rng);

        let first = key[0];
        if key.iter().all(|&x| x == first) {
            all_same_count += 1;
        }
    }

    assert!(
        all_same_count < K,
        "PRF key had identical elements in all {} trials",
        K
    );
}

proptest! {
    #[test]
    fn proptest_get_domain_element_properties(
        key in prop::array::uniform32(any::<u8>()),
        epoch in any::<u32>(),
        index1 in any::<u64>(),
        index2 in any::<u64>()
    ) {
        // check output has correct length
        let result1 = PRF::get_domain_element(&key, epoch, index1);
        prop_assert_eq!(result1.len(), DOMAIN_LEN);

        // check determinism: same inputs produce same output
        let result2 = PRF::get_domain_element(&key, epoch, index1);
        prop_assert_eq!(result1, result2);

        // check uniqueness: different indices produce different outputs
        let other = PRF::get_domain_element(&key, epoch, index2);
        if index1 == index2 {
            prop_assert_eq!(result1, other);
        } else {
            prop_assert_ne!(result1, other);
        }

        // check different epochs produce different outputs
        let other_epoch = PRF::get_domain_element(&key, epoch.wrapping_add(1), index1);
        prop_assert_ne!(result1, other_epoch);
    }

    #[test]
    fn proptest_get_randomness_properties(
        key in prop::array::uniform32(any::<u8>()),
        epoch in any::<u32>(),
        message in prop::array::uniform32(any::<u8>()),
        counter1 in any::<u64>(),
        counter2 in any::<u64>()
    ) {
        let msg: [u8; MESSAGE_LENGTH] = message;

        // check output has correct length
        let result1 = PRF::get_randomness(&key, epoch, &msg, counter1);
        prop_assert_eq!(result1.len(), RAND_LEN);

        // check determinism: same inputs produce same output
        let result2 = PRF::get_randomness(&key, epoch, &msg, counter1);
        prop_assert_eq!(result1, result2);

        // check uniqueness: different counters produce different outputs
        let other = PRF::get_randomness(&key, epoch, &msg, counter2);
        if counter1 == counter2 {
            prop_assert_eq!(result1, other);
        } else {
            prop_assert_ne!(result1, other);
        }

        // check different epochs produce different outputs
        let other_epoch = PRF::get_randomness(&key, epoch.wrapping_add(1), &msg, counter1);
        prop_assert_ne!(result1, other_epoch);
    }
}
