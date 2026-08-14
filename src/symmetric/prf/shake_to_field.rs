use crate::F;

use super::Pseudorandom;
use p3_field::PrimeCharacteristicRing;
use serde::{Serialize, de::DeserializeOwned};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Number of pseudorandom bytes to generate one pseudorandom field element
const PRF_BYTES_PER_FE: usize = 16;

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
            // Buffer to store the output
            let mut buf = [0u8; PRF_BYTES_PER_FE];

            // Read the extended output into the buffer
            xof_reader.read(&mut buf);

            // Mapping bytes to a field element
            F::from_u128(u128::from_be_bytes(buf))
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
            // Buffer to store the output
            let mut buf = [0u8; PRF_BYTES_PER_FE];

            // Read the extended output into the buffer
            xof_reader.read(&mut buf);

            // Mapping bytes to a field element
            F::from_u128(u128::from_be_bytes(buf))
        })
    }
}
