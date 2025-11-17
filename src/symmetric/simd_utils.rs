use core::array;

use p3_field::PackedValue;

use crate::{F, PackedF};

/// Packs scalar arrays into SIMD-friendly vertical layout.
///
/// Transposes from horizontal layout `[[F; N]; WIDTH]` to vertical layout `[PackedF; N]`.
///
/// Input layout (horizontal): each row is one complete array
/// ```text
/// data[0] = [a0, a1, a2, ..., aN]
/// data[1] = [b0, b1, b2, ..., bN]
/// data[2] = [c0, c1, c2, ..., cN]
/// ...
/// ```
///
/// Output layout (vertical): each PackedF holds one element from each array
/// ```text
/// result[0] = PackedF([a0, b0, c0, ...])  // All first elements
/// result[1] = PackedF([a1, b1, c1, ...])  // All second elements
/// result[2] = PackedF([a2, b2, c2, ...])  // All third elements
/// ...
/// ```
///
/// This vertical packing enables efficient SIMD operations where a single instruction
/// processes the same element position across multiple arrays simultaneously.
#[inline]
pub fn pack_array<const N: usize>(data: &[[F; N]]) -> [PackedF; N] {
    array::from_fn(|i| PackedF::from_fn(|j| data[j][i]))
}

/// Unpacks SIMD vertical layout back into scalar arrays.
///
/// Transposes from vertical layout `[PackedF; N]` to horizontal layout `[[F; N]; WIDTH]`.
///
/// This is the inverse operation of `pack_array`. The output buffer must be preallocated
/// with size `[WIDTH][N]` where `WIDTH = PackedF::WIDTH`.
///
/// Input layout (vertical): each PackedF holds one element from each array
/// ```text
/// packed_data[0] = PackedF([a0, b0, c0, ...])
/// packed_data[1] = PackedF([a1, b1, c1, ...])
/// packed_data[2] = PackedF([a2, b2, c2, ...])
/// ...
/// ```
///
/// Output layout (horizontal): each row is one complete array
/// ```text
/// output[0] = [a0, a1, a2, ..., aN]
/// output[1] = [b0, b1, b2, ..., bN]
/// output[2] = [c0, c1, c2, ..., cN]
/// ...
/// ```
#[inline]
pub fn unpack_array<const N: usize>(packed_data: &[PackedF; N], output: &mut [[F; N]]) {
    for (i, data) in packed_data.iter().enumerate().take(N) {
        let unpacked_v = data.as_slice();
        for j in 0..PackedF::WIDTH {
            output[j][i] = unpacked_v[j];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use proptest::prelude::*;
    use rand::Rng;

    #[test]
    fn test_pack_array_simple() {
        // Test with N=2 (2 field elements per array)
        // Create WIDTH arrays of [F; 2]
        let data: [[F; 2]; PackedF::WIDTH] =
            array::from_fn(|i| [F::from_u64(i as u64), F::from_u64((i + 100) as u64)]);

        let packed = pack_array(&data);

        // Check that packed[0] contains all first elements
        for (lane, &expected) in data.iter().enumerate() {
            assert_eq!(packed[0].as_slice()[lane], expected[0]);
        }

        // Check that packed[1] contains all second elements
        for (lane, &expected) in data.iter().enumerate() {
            assert_eq!(packed[1].as_slice()[lane], expected[1]);
        }
    }

    #[test]
    fn test_unpack_array_simple() {
        // Create packed data
        let packed: [PackedF; 2] = [
            PackedF::from_fn(|i| F::from_u64(i as u64)),
            PackedF::from_fn(|i| F::from_u64((i + 100) as u64)),
        ];

        // Unpack
        let mut output = [[F::ZERO; 2]; PackedF::WIDTH];
        unpack_array(&packed, &mut output);

        // Verify
        for (lane, arr) in output.iter().enumerate() {
            assert_eq!(arr[0], F::from_u64(lane as u64));
            assert_eq!(arr[1], F::from_u64((lane + 100) as u64));
        }
    }

    #[test]
    fn test_pack_preserves_element_order() {
        // Create data where each array has sequential values
        let data: [[F; 3]; PackedF::WIDTH] = array::from_fn(|i| {
            [
                F::from_u64((i * 3) as u64),
                F::from_u64((i * 3 + 1) as u64),
                F::from_u64((i * 3 + 2) as u64),
            ]
        });

        let packed = pack_array(&data);

        // Verify the packing structure
        // packed[0] should contain: [0, 3, 6, 9, ...]
        // packed[1] should contain: [1, 4, 7, 10, ...]
        // packed[2] should contain: [2, 5, 8, 11, ...]
        for (element_idx, p) in packed.iter().enumerate() {
            for lane in 0..PackedF::WIDTH {
                let expected = F::from_u64((lane * 3 + element_idx) as u64);
                assert_eq!(p.as_slice()[lane], expected);
            }
        }
    }

    #[test]
    fn test_unpack_preserves_element_order() {
        // Create packed data with known pattern
        let packed: [PackedF; 3] = [
            PackedF::from_fn(|i| F::from_u64((i * 3) as u64)),
            PackedF::from_fn(|i| F::from_u64((i * 3 + 1) as u64)),
            PackedF::from_fn(|i| F::from_u64((i * 3 + 2) as u64)),
        ];

        let mut output = [[F::ZERO; 3]; PackedF::WIDTH];
        unpack_array(&packed, &mut output);

        // Verify each array has sequential values
        for (lane, arr) in output.iter().enumerate() {
            assert_eq!(arr[0], F::from_u64((lane * 3) as u64));
            assert_eq!(arr[1], F::from_u64((lane * 3 + 1) as u64));
            assert_eq!(arr[2], F::from_u64((lane * 3 + 2) as u64));
        }
    }

    proptest! {
        #[test]
        fn proptest_pack_unpack_roundtrip(
            _seed in any::<u64>()
        ) {
            let mut rng = rand::rng();

            // Generate random data with N=10
            let original: [[F; 10]; PackedF::WIDTH] = array::from_fn(|_| {
                array::from_fn(|_| rng.random())
            });

            // Pack and unpack
            let packed = pack_array(&original);
            let mut unpacked = [[F::ZERO; 10]; PackedF::WIDTH];
            unpack_array(&packed, &mut unpacked);

            // Verify roundtrip
            prop_assert_eq!(original, unpacked);
        }
    }
}
