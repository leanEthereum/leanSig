use crate::F;

use super::Pseudorandom;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::{Serialize, de::DeserializeOwned};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Number of pseudorandom bytes to generate one pseudorandom field element.
///
/// Per RFC 9380 (hash-to-field), L = ceil((ceil(log2(p)) + k) / 8) where k is
/// the security parameter. For KoalaBear (p = 2^31 - 2^24 + 1, ceil(log2(p)) = 31)
/// and k = 128 (matching SHAKE128): L = ceil((31 + 128) / 8) = 20.
///
/// This gives a statistical distance from uniform of at most p / 2^161 < 2^{-129},
/// meeting the 128-bit security target.
const PRF_BYTES_PER_FE: usize = 20;

/// Reduce a 160-bit big-endian value to a field element with negligible bias.
///
/// Splits the 20-byte input into a 128-bit high part and a 32-bit low part,
/// then computes (hi * 2^32 + lo) mod p using native u128 arithmetic.
#[inline]
fn reduce_160_to_field(buf: &[u8; PRF_BYTES_PER_FE]) -> F {
    let hi = u128::from_be_bytes(buf[..16].try_into().unwrap());
    let lo = u32::from_be_bytes(buf[16..20].try_into().unwrap()) as u128;

    let p = F::ORDER_U64 as u128;
    let hi_mod = hi % p;
    let two_32_mod_p = (1u128 << 32) % p;

    let reduced = (hi_mod * two_32_mod_p + lo) % p;
    F::from_u64(reduced as u64)
}

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];
const PRF_DOMAIN_SEP_DOMAIN_ELEMENT: [u8; 1] = [0x00];
const PRF_DOMAIN_SEP_RANDOMNESS: [u8; 1] = [0x01];

/// A pseudorandom function mapping to field elements.
/// It is implemented using Shake128.
/// It outputs DOMAIN_LENGTH_FE or RAND_LENGTH_FE many field elements.
pub struct ShakePRFtoF<const DOMAIN_LENGTH_FE: usize, const RAND_LENGTH_FE: usize>;

impl<const DOMAIN_LENGTH_FE: usize, const RAND_LENGTH_FE: usize> Pseudorandom
    for ShakePRFtoF<DOMAIN_LENGTH_FE, RAND_LENGTH_FE>
where
    [F; DOMAIN_LENGTH_FE]: Serialize + DeserializeOwned,
{
    type Key = [u8; KEY_LENGTH];
    type Domain = [F; DOMAIN_LENGTH_FE];
    type Randomness = [F; RAND_LENGTH_FE];

    fn key_gen<R: rand::RngExt>(rng: &mut R) -> Self::Key {
        rng.random()
    }

    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        hasher.update(&PRF_DOMAIN_SEP_DOMAIN_ELEMENT);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the index
        hasher.update(&index.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Mapping bytes to field elements
        std::array::from_fn(|_| {
            let mut buf = [0u8; PRF_BYTES_PER_FE];
            xof_reader.read(&mut buf);
            reduce_160_to_field(&buf)
        })
    }

    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; crate::MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        hasher.update(&PRF_DOMAIN_SEP_RANDOMNESS);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the message
        hasher.update(message);

        // Hash the counter
        hasher.update(&counter.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Mapping bytes to field elements
        std::array::from_fn(|_| {
            let mut buf = [0u8; PRF_BYTES_PER_FE];
            xof_reader.read(&mut buf);
            reduce_160_to_field(&buf)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MESSAGE_LENGTH;
    use num_bigint::BigUint;
    use p3_field::PrimeField64;
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

        #[test]
        fn proptest_reduce_160_matches_bigint_reference(
            bytes in prop::array::uniform20(any::<u8>())
        ) {
            let fast = reduce_160_to_field(&bytes);

            let value = BigUint::from_bytes_be(&bytes);
            let p = BigUint::from(F::ORDER_U64);
            let expected_u64: u64 = (value % p).try_into().unwrap();
            let reference = F::from_u64(expected_u64);

            prop_assert_eq!(fast, reference);
        }
    }

    #[test]
    fn test_prf_bytes_per_fe_matches_rfc9380() {
        let ceil_log2_p = 64 - (F::ORDER_U64 - 1).leading_zeros() as usize;
        let k = 128;
        let expected_l = (ceil_log2_p + k).div_ceil(8);
        assert_eq!(
            PRF_BYTES_PER_FE, expected_l,
            "PRF_BYTES_PER_FE should be L = ceil((ceil(log2(p)) + k) / 8) per RFC 9380"
        );
    }

    #[test]
    fn test_reduce_160_boundary_values() {
        let all_zeros = [0u8; PRF_BYTES_PER_FE];
        assert_eq!(reduce_160_to_field(&all_zeros), F::from_u64(0));

        let all_ones = [0xff; PRF_BYTES_PER_FE];
        let value = BigUint::from_bytes_be(&all_ones);
        let p = BigUint::from(F::ORDER_U64);
        let expected: u64 = (value % p).try_into().unwrap();
        assert_eq!(reduce_160_to_field(&all_ones), F::from_u64(expected));
    }
}
