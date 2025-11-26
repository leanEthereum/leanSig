//! A unified serialization implementation

use serde::{Serialize, de::DeserializeOwned};
use ssz::{Decode, DecodeError, Encode};

/// A supertrait combining all serialization capabilities needed for leanSig types.
pub trait Serializable: Serialize + DeserializeOwned + Encode + Decode + Sized {
    /// Converts this object to a canonical byte representation.
    ///
    /// # Canonical Format
    ///
    /// - All field elements are converted to canonical `u32` form (not Montgomery)
    /// - All `u32` values are encoded as 4 bytes in little-endian order
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the canonical byte representation of this object.
    fn to_bytes(&self) -> Vec<u8> {
        // TODO: Update this to not use SSZ internally.
        self.as_ssz_bytes()
    }

    /// Parses an object from its canonical byte representation.
    ///
    /// # Canonical Format
    ///
    /// The input bytes must follow the same canonical format as `to_bytes()`:
    /// - Field elements as canonical `u32` values (4 bytes, little-endian)
    /// - Composite structures following SSZ layout rules
    ///
    /// # Arguments
    ///
    /// * `bytes` - The canonical binary data to parse
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` if the bytes represent a valid object
    /// - `Err(DecodeError)` if the bytes are malformed or invalid
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // TODO: Update this to not use SSZ internally.
        Self::from_ssz_bytes(bytes)
    }
}

macro_rules! impl_serializable_for_array {
    ($($N:expr),*) => {
        $(
            impl Serializable for [u8; $N] {}
        )*
    };
}

impl_serializable_for_array!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32
);
