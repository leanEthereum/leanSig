use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::ops::{Deref, DerefMut};

use crate::F;
use crate::serialization::Serializable;
use p3_field::{PrimeCharacteristicRing, PrimeField32, RawDataSerializable};

/// A wrapper around an array of field elements that implements SSZ Encode/Decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl<const N: usize> FieldArray<N> {
    /// View a mutable slice of `FieldArray<N>` as a mutable slice of raw `[F; N]` arrays.
    ///
    /// This is a zero-cost transmute enabled by the `#[repr(transparent)]` layout.
    #[inline]
    pub fn as_raw_slice_mut(s: &mut [Self]) -> &mut [[F; N]] {
        // SAFETY: `FieldArray<N>` is `#[repr(transparent)]` over `[F; N]`.
        //
        // So `&mut [FieldArray<N>]` and `&mut [[F; N]]` have identical layouts.
        unsafe { &mut *(std::ptr::from_mut::<[Self]>(s) as *mut [[F; N]]) }
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

impl<const N: usize> Serializable for FieldArray<N> {}

impl<const N: usize> Serialize for FieldArray<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(N)?;
        for element in &self.0 {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de, const N: usize> Deserialize<'de> for FieldArray<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for FieldArrayVisitor<N> {
            type Value = FieldArray<N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array of {} field elements", N)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [F::ZERO; N];
                for (i, elem) in arr.iter_mut().enumerate() {
                    *elem = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(FieldArray(arr))
            }
        }

        deserializer.deserialize_tuple(N, FieldArrayVisitor::<N>)
    }
}
