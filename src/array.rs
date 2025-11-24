use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use ssz::{Decode, DecodeError, Encode};
use std::ops::{Deref, DerefMut};

use crate::F;
use p3_field::{PrimeCharacteristicRing, PrimeField32, RawDataSerializable};

/// A wrapper around an array of field elements that implements SSZ Encode/Decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct FieldArray<const N: usize>(pub [F; N]);

impl<const N: usize> Deref for FieldArray<N> {
    type Target = [F; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for FieldArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[F; N]> for FieldArray<N> {
    fn from(arr: [F; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> From<FieldArray<N>> for [F; N] {
    fn from(field_array: FieldArray<N>) -> Self {
        field_array.0
    }
}

impl<const N: usize> Encode for FieldArray<N> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        N * F::NUM_BYTES
    }

    fn ssz_bytes_len(&self) -> usize {
        N * F::NUM_BYTES
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.reserve(N * F::NUM_BYTES);
        for elem in &self.0 {
            let value = elem.as_canonical_u32();
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
}

impl<const N: usize> Decode for FieldArray<N> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        N * F::NUM_BYTES
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected_len = N * F::NUM_BYTES;
        if bytes.len() != expected_len {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: expected_len,
            });
        }

        let arr = std::array::from_fn(|i| {
            let start = i * F::NUM_BYTES;
            let chunk = bytes[start..start + F::NUM_BYTES].try_into().unwrap();
            F::new(u32::from_le_bytes(chunk))
        });

        Ok(Self(arr))
    }
}

impl<const N: usize> Serialize for FieldArray<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.iter().map(|elem| elem.as_canonical_u32()))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FieldArray<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for FieldArrayVisitor<N> {
            type Value = FieldArray<N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array of {} field elements", N)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [F::ZERO; N];
                for (i, p) in arr.iter_mut().enumerate() {
                    let val: u32 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    *p = F::new(val);
                }
                Ok(FieldArray(arr))
            }
        }

        deserializer.deserialize_seq(FieldArrayVisitor::<N>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Small parameter arrays
    const SMALL_SIZE: usize = 5;
    /// Hash output size
    const MEDIUM_SIZE: usize = 7;
    /// Larger parameter arrays
    const LARGE_SIZE: usize = 44;

    #[test]
    fn test_ssz_roundtrip_zero_values() {
        // Start with an array of zeros
        let original = FieldArray([F::ZERO; SMALL_SIZE]);

        // Encode to bytes using SSZ
        let encoded = original.as_ssz_bytes();

        // Decode back from bytes
        let decoded = FieldArray::<SMALL_SIZE>::from_ssz_bytes(&encoded)
            .expect("Failed to decode valid SSZ bytes");

        // Verify round-trip preserves the value
        assert_eq!(original, decoded, "Round-trip failed for zero values");
    }

    #[test]
    fn test_ssz_roundtrip_max_values() {
        // Create array with maximum valid field values
        let max_val = F::ORDER_U32 - 1;
        let original = FieldArray([F::new(max_val); MEDIUM_SIZE]);

        // Perform round-trip encoding/decoding
        let encoded = original.as_ssz_bytes();
        let decoded = FieldArray::<MEDIUM_SIZE>::from_ssz_bytes(&encoded)
            .expect("Failed to decode max values");

        // Verify the values survived the round-trip
        assert_eq!(original, decoded, "Round-trip failed for max values");
    }

    #[test]
    fn test_ssz_roundtrip_specific_values() {
        // Create an array with sequential values for easy verification
        let original = FieldArray([F::new(1), F::new(2), F::new(3), F::new(4), F::new(5)]);

        // Encode and verify the byte representation
        let encoded = original.as_ssz_bytes();

        // Each u32 should be encoded as F::NUM_BYTES bytes in little-endian
        assert_eq!(
            &encoded[0..F::NUM_BYTES],
            &[1, 0, 0, 0],
            "First element encoding incorrect"
        );
        assert_eq!(
            &encoded[F::NUM_BYTES..2 * F::NUM_BYTES],
            &[2, 0, 0, 0],
            "Second element encoding incorrect"
        );
        assert_eq!(
            &encoded[2 * F::NUM_BYTES..3 * F::NUM_BYTES],
            &[3, 0, 0, 0],
            "Third element encoding incorrect"
        );

        // Decode and verify round-trip
        let decoded = FieldArray::<SMALL_SIZE>::from_ssz_bytes(&encoded)
            .expect("Failed to decode specific values");

        assert_eq!(original, decoded, "Round-trip failed for specific values");
    }

    #[test]
    fn test_ssz_encoding_deterministic() {
        let mut rng = rand::rng();

        // Create a random field array
        let field_array = FieldArray(rng.random::<[F; SMALL_SIZE]>());

        // Encode it multiple times
        let encoding1 = field_array.as_ssz_bytes();
        let encoding2 = field_array.as_ssz_bytes();
        let encoding3 = field_array.as_ssz_bytes();

        // All encodings should be identical
        assert_eq!(encoding1, encoding2, "Encoding not deterministic (1 vs 2)");
        assert_eq!(encoding2, encoding3, "Encoding not deterministic (2 vs 3)");
    }

    #[test]
    fn test_ssz_encoded_size() {
        let field_array = FieldArray([F::ZERO; LARGE_SIZE]);
        let encoded = field_array.as_ssz_bytes();

        // Verify the encoded size matches expectations
        let expected_size = LARGE_SIZE * F::NUM_BYTES;
        assert_eq!(
            encoded.len(),
            expected_size,
            "Encoded size should be {} bytes (array of {} elements, {} bytes each)",
            expected_size,
            LARGE_SIZE,
            F::NUM_BYTES
        );

        // Also verify the trait method reports the same size
        assert_eq!(
            field_array.ssz_bytes_len(),
            expected_size,
            "ssz_bytes_len() should match actual encoded size"
        );
    }

    #[test]
    fn test_ssz_decode_rejects_wrong_length() {
        let expected_len = SMALL_SIZE * F::NUM_BYTES;

        // Test buffer that's too short (missing one byte)
        let too_short = vec![0u8; expected_len - 1];
        let result = FieldArray::<SMALL_SIZE>::from_ssz_bytes(&too_short);
        assert!(result.is_err(), "Should reject buffer that's too short");
        if let Err(DecodeError::InvalidByteLength { len, expected }) = result {
            assert_eq!(len, expected_len - 1);
            assert_eq!(expected, expected_len);
        } else {
            panic!("Expected InvalidByteLength error");
        }

        // Test buffer that's too long (extra byte)
        let too_long = vec![0u8; expected_len + 1];
        let result = FieldArray::<SMALL_SIZE>::from_ssz_bytes(&too_long);
        assert!(result.is_err(), "Should reject buffer that's too long");
        if let Err(DecodeError::InvalidByteLength { len, expected }) = result {
            assert_eq!(len, expected_len + 1);
            assert_eq!(expected, expected_len);
        } else {
            panic!("Expected InvalidByteLength error");
        }
    }

    #[test]
    fn test_ssz_fixed_len_trait_methods() {
        // Arrays are always fixed-length in SSZ
        assert!(
            <FieldArray<SMALL_SIZE> as Encode>::is_ssz_fixed_len(),
            "FieldArray should report as fixed-length (Encode)"
        );
        assert!(
            <FieldArray<SMALL_SIZE> as Decode>::is_ssz_fixed_len(),
            "FieldArray should report as fixed-length (Decode)"
        );

        // The fixed length should be N * F::NUM_BYTES
        let expected_len = SMALL_SIZE * F::NUM_BYTES;
        assert_eq!(
            <FieldArray<SMALL_SIZE> as Encode>::ssz_fixed_len(),
            expected_len,
            "Encode::ssz_fixed_len() incorrect"
        );
        assert_eq!(
            <FieldArray<SMALL_SIZE> as Decode>::ssz_fixed_len(),
            expected_len,
            "Decode::ssz_fixed_len() incorrect"
        );
    }

    proptest! {
        #[test]
        fn proptest_ssz_roundtrip_large(
            values in prop::collection::vec(0u32..F::ORDER_U32, LARGE_SIZE)
        ) {
            // Convert Vec to array for large sizes
            let arr: [F; LARGE_SIZE] = std::array::from_fn(|i| F::new(values[i]));
            let original = FieldArray(arr);

            let encoded = original.as_ssz_bytes();
            let decoded = FieldArray::<LARGE_SIZE>::from_ssz_bytes(&encoded)
                .expect("Valid SSZ bytes should always decode");

            prop_assert_eq!(original, decoded);
        }

        #[test]
        fn proptest_ssz_deterministic(
            values in prop::array::uniform5(0u32..F::ORDER_U32)
        ) {
            let arr = values.map(F::new);
            let field_array = FieldArray(arr);

            // Encode twice and verify both encodings are identical
            let encoding1 = field_array.as_ssz_bytes();
            let encoding2 = field_array.as_ssz_bytes();

            prop_assert_eq!(encoding1, encoding2);
        }

        #[test]
        fn proptest_ssz_size_invariant(
            values in prop::array::uniform5(0u32..F::ORDER_U32)
        ) {
            let arr = values.map(F::new);
            let field_array = FieldArray(arr);

            let encoded = field_array.as_ssz_bytes();
            let expected_size = SMALL_SIZE * F::NUM_BYTES;

            prop_assert_eq!(encoded.len(), expected_size);
            prop_assert_eq!(field_array.ssz_bytes_len(), expected_size);
        }
    }

    #[test]
    fn test_equality() {
        let arr1 = FieldArray([F::new(1), F::new(2), F::new(3)]);
        let arr2 = FieldArray([F::new(1), F::new(2), F::new(3)]);
        let arr3 = FieldArray([F::new(1), F::new(2), F::new(4)]);

        // Equal arrays should be equal
        assert_eq!(arr1, arr2);

        // Different arrays should not be equal
        assert_ne!(arr1, arr3);
        assert_ne!(arr2, arr3);
    }
}
