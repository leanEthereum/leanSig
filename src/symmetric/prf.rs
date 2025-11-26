use rand::Rng;

use crate::serialization::Serializable;

use crate::MESSAGE_LENGTH;

/// Trait to model a pseudorandom function (PRF)
pub trait Pseudorandom {
    type Key: Send + Sync + Serializable;
    type Domain;
    type Randomness;

    /// Sample a random key for the PRF
    fn key_gen<R: Rng>(rng: &mut R) -> Self::Key;

    /// Apply the PRF to an epoch and an index to get a pseudorandom domain element.
    /// This can be used to create the chain starts pseudorandomly.
    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain;

    /// Apply the PRF to an epoch, a message, and a counter to get a pseudorandom randomness.
    /// This can be used to produce a stream of (pseudo-)randomness for the encoding.
    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod shake_to_field;
