use core::array;

use p3_field::{Algebra, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::CryptographicPermutation;
use rayon::prelude::*;

use crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use crate::TWEAK_SEPARATOR_FOR_TREE_HASH;
use crate::array::FieldArray;
use crate::poseidon2_16;
use crate::poseidon2_24;
use crate::simd_utils::{pack_array, pack_even_into, pack_fn_into, pack_odd_into, unpack_array};
use crate::symmetric::prf::Pseudorandom;
use crate::symmetric::tweak_hash::chain;
use crate::{F, PackedF};

use super::TweakableHash;

use p3_koala_bear::Poseidon2KoalaBear;
use std::cell::RefCell;
use thread_local::ThreadLocal;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;
/// The state width for compressing a single hash in a chain.
const CHAIN_COMPRESSION_WIDTH: usize = 16;
/// The state width for merging two hashes in a tree or for the sponge construction.
const MERGE_COMPRESSION_WIDTH: usize = 24;

/// Enum to implement tweaks.
#[derive(Debug)]
pub enum PoseidonTweak {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u8,
        pos_in_chain: u8,
    },
}

impl PoseidonTweak {
    pub fn to_field_elements<const TWEAK_LEN: usize>(&self) -> [F; TWEAK_LEN] {
        // We first represent the entire tweak as one big integer
        let mut acc = match self {
            Self::TreeTweak {
                level,
                pos_in_level,
            } => {
                ((*level as u128) << 40)
                    | ((*pos_in_level as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_TREE_HASH as u128)
            }
            Self::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                ((*epoch as u128) << 24)
                    | ((*chain_index as u128) << 16)
                    | ((*pos_in_chain as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
            }
        };

        // Now we interpret this integer in base-p to get field elements
        std::array::from_fn(|_| {
            let digit = (acc % F::ORDER_U64 as u128) as u64;
            acc /= F::ORDER_U64 as u128;
            F::from_u64(digit)
        })
    }
}

/// Poseidon Compression Function
///
/// Computes:
///     PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
///
/// This function works generically over `R: PrimeCharacteristicRing`, allowing it to process both:
/// - Scalar fields,
/// - Packed SIMD fields
///
/// This follows the Plonky3 pattern that enables automatic SIMD optimization.
///
/// - `WIDTH`: total state width (input length to permutation).
/// - `OUT_LEN`: number of output elements to return.
/// - `perm`: a cryptographically secure Poseidon permutation over `[R; WIDTH]`.
/// - `input`: slice of input values, must be `≤ WIDTH` and `≥ OUT_LEN`.
///
/// ### Warning: Input Padding
/// The `input` slice is **always silently padded with zeros** to match the permutation's `WIDTH`.
/// This means that inputs that are distinct but become identical after zero-padding
/// (e.g., `[A, B]` and `[A, B, 0]`) will produce the same hash. If your use case
/// requires distinguishing between such inputs, you must handle it externally, for example,
/// by encoding the input's length as part of the message.
///
/// Returns: the first `OUT_LEN` elements of the permuted and compressed state.
///
/// Panics:
/// - If `input.len() < OUT_LEN`
/// - If `OUT_LEN > WIDTH`
pub fn poseidon_compress<R, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    input: &[R],
) -> [R; OUT_LEN]
where
    R: PrimeCharacteristicRing + Copy,
    P: CryptographicPermutation<[R; WIDTH]>,
{
    assert!(
        input.len() >= OUT_LEN,
        "Poseidon Compression: Input length must be at least output length."
    );

    // Copy the input into a fixed-width buffer, zero-padding unused elements if any.
    let mut padded_input = [R::ZERO; WIDTH];
    padded_input[..input.len()].copy_from_slice(input);

    // Start with the input as the initial state.
    let mut state = padded_input;

    // Apply the Poseidon permutation in-place.
    perm.permute_mut(&mut state);

    // Feed-forward: Add the input back into the state element-wise.
    for i in 0..WIDTH {
        state[i] += padded_input[i];
    }

    // Truncate and return the first `OUT_LEN` elements of the state.
    state[..OUT_LEN]
        .try_into()
        .expect("OUT_LEN is larger than permutation width")
}

/// Computes a Poseidon-based domain separator by compressing an array of `u32`
/// values using the Poseidon2 KoalaBear permutation with width 24.
///
/// Returns scalar field elements. For SIMD use, broadcast to `PackedF` at the call site.
fn poseidon_safe_domain_separator<const OUT_LEN: usize>(
    perm: &Poseidon2KoalaBear<MERGE_COMPRESSION_WIDTH>,
    params: &[u32; DOMAIN_PARAMETERS_LENGTH],
) -> [F; OUT_LEN] {
    // Combine params into a single number in base 2^32
    //
    // WARNING: We can use a u128 instead of a BigUint only because `params`
    // has 4 elements in base 2^32.
    let mut acc: u128 = 0;
    for &param in params {
        acc = (acc << 32) | (param as u128);
    }

    // Compute base-p decomposition
    let input: [F; MERGE_COMPRESSION_WIDTH] = std::array::from_fn(|_| {
        let digit = (acc % F::ORDER_U64 as u128) as u64;
        acc /= F::ORDER_U64 as u128;
        F::from_u64(digit)
    });

    poseidon_compress::<F, _, MERGE_COMPRESSION_WIDTH, OUT_LEN>(perm, &input)
}

/// Poseidon Sponge Hash Function
///
/// Absorbs an arbitrary-length input using the Poseidon sponge construction
/// and outputs `OUT_LEN` field elements. Domain separation is achieved by
/// injecting a `capacity_value` into the state.
///
/// This function works generically over `A: Algebra<F>`, allowing it to process both:
/// - Scalar fields,
/// - Packed SIMD fields
///
/// ### Parameters
/// - `WIDTH`: sponge state width.
/// - `OUT_LEN`: number of output elements.
/// - `perm`: Poseidon permutation over `[A; WIDTH]`.
/// - `capacity_value`: values to occupy the capacity part of the state (must be < `WIDTH`).
/// - `input`: message to hash (any length).
///
/// ### Sponge Construction
/// This follows the classic sponge structure:
/// - **Absorption**: inputs are added chunk-by-chunk into the first `rate` elements of the state.
/// - **Squeezing**: outputs are read from the first `rate` elements of the state, permuted as needed.
///
/// ### Panics
/// - If `capacity_value.len() >= WIDTH`
fn poseidon_sponge<A, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    capacity_value: &[A],
    input: &[A],
) -> [A; OUT_LEN]
where
    A: Algebra<F> + Copy,
    P: CryptographicPermutation<[A; WIDTH]>,
{
    // The capacity length must be strictly smaller than the width to have a non-zero rate.
    // This check prevents a panic from subtraction underflow when calculating the rate.
    assert!(
        capacity_value.len() < WIDTH,
        "Capacity length must be smaller than the state width."
    );
    let rate = WIDTH - capacity_value.len();

    // initialize
    let mut state = [A::ZERO; WIDTH];
    state[rate..].copy_from_slice(capacity_value);

    let extra_elements = (rate - (input.len() % rate)) % rate;
    // Instead of converting the input to a vector, resizing and feeding the data into the
    // sponge, we instead fill in the vector from all chunks until we are left with a non
    // full chunk. We only add to the state, so padded data does not mutate `state` at all.

    // 1. fill in all full chunks and permute
    let mut it = input.chunks_exact(rate);
    for chunk in &mut it {
        //input.chunks_exact(rate) {
        // iterate the chunks
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        perm.permute_mut(&mut state);
    }
    // 2. fill the remainder and extend with zeros
    let remainder = rate - extra_elements;
    if remainder > 0 {
        for (i, x) in it.remainder().iter().enumerate() {
            state[i] += *x;
        }
        // was a remainder, so permute. No need to mutate `state` as we *add* only anyway
        perm.permute_mut(&mut state);
    }

    // squeeze
    let mut out = [A::ZERO; OUT_LEN];
    let mut out_idx = 0;
    while out_idx < OUT_LEN {
        let chunk_size = (OUT_LEN - out_idx).min(rate);
        out[out_idx..out_idx + chunk_size].copy_from_slice(&state[..chunk_size]);
        out_idx += chunk_size;
        if out_idx < OUT_LEN {
            perm.permute_mut(&mut state);
        }
    }
    out
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN, TWEAK_LEN, CAPACITY, and PARAMETER_LEN must
/// be given in the unit "number of field elements".
#[derive(Clone)]
pub struct PoseidonTweakHash<
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
>;

impl<
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
> TweakableHash for PoseidonTweakHash<PARAMETER_LEN, HASH_LEN, TWEAK_LEN, CAPACITY, NUM_CHUNKS>
{
    type Parameter = FieldArray<PARAMETER_LEN>;

    type Tweak = PoseidonTweak;

    type Domain = FieldArray<HASH_LEN>;

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        FieldArray(rng.random())
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        FieldArray(rng.random())
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak {
        PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        // we are in one of three cases:
        // (1) hashing within chains. We use compression mode.
        // (2) hashing two siblings in the tree. We use compression mode.
        // (3) hashing a long vector of chain ends. We use sponge mode.

        let tweak_fe = tweak.to_field_elements::<TWEAK_LEN>();

        match message {
            [single] => {
                // we compress parameter, tweak, message
                let perm = poseidon2_16();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(single.iter())
                    .copied()
                    .collect();
                FieldArray(
                    poseidon_compress::<F, _, CHAIN_COMPRESSION_WIDTH, HASH_LEN>(
                        &perm,
                        &combined_input,
                    ),
                )
            }

            [left, right] => {
                // we compress parameter, tweak, message (now containing two parts)
                let perm = poseidon2_24();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(left.iter())
                    .chain(right.iter())
                    .copied()
                    .collect();
                FieldArray(
                    poseidon_compress::<F, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(
                        &perm,
                        &combined_input,
                    ),
                )
            }

            _ if message.len() > 2 => {
                // Hashing many blocks
                let perm = poseidon2_24();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(message.iter().flat_map(|x| x.iter()))
                    .copied()
                    .collect();

                let lengths: [u32; DOMAIN_PARAMETERS_LENGTH] = [
                    PARAMETER_LEN as u32,
                    TWEAK_LEN as u32,
                    NUM_CHUNKS as u32,
                    HASH_LEN as u32,
                ];
                let capacity_value = poseidon_safe_domain_separator::<CAPACITY>(&perm, &lengths);
                FieldArray(poseidon_sponge::<F, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(
                    &perm,
                    &capacity_value,
                    &combined_input,
                ))
            }
            _ => FieldArray([F::ONE; HASH_LEN]), // Unreachable case, added for safety
        }
    }

    /// SIMD-accelerated computation of one Merkle tree layer.
    ///
    /// Processes `PackedF::WIDTH` parent pairs simultaneously using SIMD instructions,
    /// with a scalar fallback for any remainder elements.
    fn compute_tree_layer(
        parameter: &Self::Parameter,
        level: u8,
        parent_start: usize,
        children: &[Self::Domain],
    ) -> Vec<Self::Domain> {
        const WIDTH: usize = PackedF::WIDTH;

        // Pre-allocate output vector
        let output_len = children.len() / 2;
        let mut parents = vec![FieldArray([F::ZERO; HASH_LEN]); output_len];

        // Broadcast the hash parameter to all SIMD lanes (computed once)
        let packed_parameter: [PackedF; PARAMETER_LEN] =
            array::from_fn(|i| PackedF::from(parameter.0[i]));

        // Permutation for merging two inputs (width-24)
        let perm = poseidon2_24();

        // Offsets for assembling packed_input: [parameter | tweak | left | right]
        let tweak_offset = PARAMETER_LEN;
        let left_offset = PARAMETER_LEN + TWEAK_LEN;
        let right_offset = PARAMETER_LEN + TWEAK_LEN + HASH_LEN;

        // Process SIMD batches with in-place mutation
        parents
            .par_chunks_exact_mut(WIDTH)
            .zip(children.par_chunks_exact(2 * WIDTH))
            .enumerate()
            .for_each(|(chunk_idx, (parents_chunk, children_chunk))| {
                let parent_pos = (parent_start + chunk_idx * WIDTH) as u32;

                // Assemble packed input directly: [parameter | tweak | left | right]
                let mut packed_input = [PackedF::ZERO; MERGE_COMPRESSION_WIDTH];

                // Copy pre-packed parameter
                packed_input[..PARAMETER_LEN].copy_from_slice(&packed_parameter);

                // Pack tweaks directly into destination
                pack_fn_into::<TWEAK_LEN>(&mut packed_input, tweak_offset, |t_idx, lane| {
                    Self::tree_tweak(level, parent_pos + lane as u32)
                        .to_field_elements::<TWEAK_LEN>()[t_idx]
                });

                // Pack left children (even indices) directly into destination
                pack_even_into(&mut packed_input, left_offset, children_chunk);

                // Pack right children (odd indices) directly into destination
                pack_odd_into(&mut packed_input, right_offset, children_chunk);

                // Compress all WIDTH parent pairs simultaneously
                let packed_parents =
                    poseidon_compress::<PackedF, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(
                        &perm,
                        &packed_input,
                    );

                // Unpack directly to output slice
                unpack_array(&packed_parents, parents_chunk);
            });

        // Handle remainder (elements that don't fill a complete SIMD batch)
        let remainder_start = (children.len() / (2 * WIDTH)) * WIDTH;
        let children_remainder = &children[remainder_start * 2..];
        let parents_remainder = &mut parents[remainder_start..];

        for (i, pair) in children_remainder.chunks_exact(2).enumerate() {
            let pos = parent_start + remainder_start + i;
            parents_remainder[i] =
                Self::apply(parameter, &Self::tree_tweak(level, pos as u32), pair);
        }

        parents
    }

    #[allow(clippy::too_many_lines)]
    fn compute_tree_leaves<PRF>(
        prf_key: &PRF::Key,
        parameter: &Self::Parameter,
        epochs: &[u32],
        num_chains: usize,
        chain_length: usize,
    ) -> Vec<Self::Domain>
    where
        PRF: Pseudorandom,
        PRF::Domain: Into<Self::Domain>,
    {
        // Verify that num_chains matches the encoding dimension.
        assert_eq!(
            num_chains, NUM_CHUNKS,
            "Poseidon SIMD implementation requires num_chains == NUM_CHUNKS. Got num_chains={}, NUM_CHUNKS={}",
            num_chains, NUM_CHUNKS
        );

        // SIMD-ACCELERATED IMPLEMENTATION
        //
        // This path leverages architecture-specific SIMD instructions.
        // `PackedF` represents multiple field elements processed in parallel.
        //
        // The key point: process multiple epochs simultaneously using SIMD.
        // Each SIMD lane corresponds to one epoch.

        // Determine SIMD width based on architecture.
        let width = PackedF::WIDTH;

        // Allocate output buffer for all leaves.
        let mut leaves = vec![FieldArray([F::ZERO; HASH_LEN]); epochs.len()];

        // PREPARE PACKED CONSTANTS

        // Broadcast the hash parameter to all SIMD lanes.
        // Each lane will use the same parameter for its epoch.
        let packed_parameter: [PackedF; PARAMETER_LEN] =
            array::from_fn(|i| PackedF::from(parameter[i]));

        // Create Poseidon permutation instances.
        // - Width-16 for chain compression,
        // - Width-24 for sponge hashing.
        let chain_perm = poseidon2_16();
        let sponge_perm = poseidon2_24();

        // Compute domain separator for the sponge construction.
        // This ensures different use cases produce different outputs.
        let lengths = [
            PARAMETER_LEN as u32,
            TWEAK_LEN as u32,
            NUM_CHUNKS as u32,
            HASH_LEN as u32,
        ];
        let capacity_val: [PackedF; CAPACITY] =
            poseidon_safe_domain_separator::<CAPACITY>(&sponge_perm, &lengths).map(PackedF::from);

        // Compute sponge input length. Required to init packed input vector for each rayon worker
        let sponge_tweak_offset = PARAMETER_LEN;
        let sponge_chains_offset = PARAMETER_LEN + TWEAK_LEN;
        let sponge_input_len = PARAMETER_LEN + TWEAK_LEN + NUM_CHUNKS * HASH_LEN;

        let tls: ThreadLocal<RefCell<Vec<PackedF>>> = ThreadLocal::new();

        // PARALLEL SIMD PROCESSING
        //
        // Process epochs in batches of size `width`.
        // Each batch is handled by one thread.
        // Within each batch, SIMD processes `width` epochs simultaneously.
        epochs
            .par_chunks_exact(width)
            .zip(leaves.par_chunks_exact_mut(width))
            .for_each(|(epoch_chunk, leaves_chunk)| {
                // STEP 1: GENERATE AND PACK CHAIN STARTING POINTS
                //
                // For each chain, generate starting points for all epochs in the chunk.
                // Use vertical packing: transpose from [lane][element] to [element][lane].
                //
                // This layout enables efficient SIMD operations across epochs.

                let cell = tls.get_or(|| {
                    RefCell::new(vec![PackedF::ZERO; sponge_input_len])
                });
                let mut packed_leaf_input = cell.borrow_mut();
                // reset not needed

                let mut packed_chains: [[PackedF; HASH_LEN]; NUM_CHUNKS] =
                    array::from_fn(|c_idx| {
                        // Generate starting points for this chain across all epochs.
                        let starts: [_; PackedF::WIDTH] = array::from_fn(|lane| {
                            PRF::get_domain_element(prf_key, epoch_chunk[lane], c_idx as u64)
                                .into()
                        });

                        // Transpose to vertical packing for SIMD efficiency.
                        pack_array(&starts)
                    });

                // STEP 2: WALK CHAINS IN PARALLEL USING SIMD
                //
                // For each chain, walk all epochs simultaneously using SIMD.
                // The chains start at their initial values and are walked step-by-step
                // until they reach their endpoints.
                //
                // Cache strategy: process one chain at a time to maximize locality.
                // All epochs for that chain stay in registers across iterations.

                // Offsets for chain compression: [parameter | tweak | current_value]
                let chain_tweak_offset = PARAMETER_LEN;
                let chain_value_offset = PARAMETER_LEN + TWEAK_LEN;

                for (chain_index, packed_chain) in
                        packed_chains.iter_mut().enumerate().take(num_chains)
                    {
                        // Walk this chain for `chain_length - 1` steps.
                        // The starting point is step 0, so we need `chain_length - 1` iterations.
                        for step in 0..chain_length - 1 {
                            // Current position in the chain.
                            let pos = (step + 1) as u8;

                            // Assemble the packed input for the hash function.
                            // Layout: [parameter | tweak | current_value]
                            let mut packed_input = [PackedF::ZERO; CHAIN_COMPRESSION_WIDTH];

                            // Copy pre-packed parameter
                            packed_input[..PARAMETER_LEN].copy_from_slice(&packed_parameter);

                            // Pack tweaks directly into destination
                            pack_fn_into::<TWEAK_LEN>(
                                &mut packed_input,
                                chain_tweak_offset,
                                |t_idx, lane| {
                                    Self::chain_tweak(epoch_chunk[lane], chain_index as u8, pos)
                                        .to_field_elements::<TWEAK_LEN>()[t_idx]
                                },
                            );

                            // Copy current chain value (already packed)
                            packed_input[chain_value_offset..chain_value_offset + HASH_LEN]
                                .copy_from_slice(packed_chain);

                            // Apply the hash function to advance the chain.
                            // This single call processes all epochs in parallel.
                            *packed_chain =
                                poseidon_compress::<PackedF, _, CHAIN_COMPRESSION_WIDTH, HASH_LEN>(
                                    &chain_perm,
                                    &packed_input,
                                );
                        }
                    }

                // STEP 3: HASH CHAIN ENDS TO PRODUCE TREE LEAVES
                //
                // All chains have been walked to their endpoints.
                // Now hash all chain ends together to form the tree leaf.
                //
                // This uses the sponge construction for variable-length input.

                // Assemble the sponge input.
                // Layout: [parameter | tree_tweak | all_chain_ends]
                // NOTE: `packed_leaf_input` is preallocated per worker. We overwrite the entire
                // vector in each iteration, so no need to `fill(0)`!
                //let mut packed_leaf_input = vec![PackedF::ZERO; sponge_input_len];

                // Copy pre-packed parameter
                packed_leaf_input[..PARAMETER_LEN].copy_from_slice(&packed_parameter);

                // Pack tree tweaks directly (level 0 for bottom-layer leaves)
                pack_fn_into::<TWEAK_LEN>(
                    &mut packed_leaf_input,
                    sponge_tweak_offset,
                    |t_idx, lane| {
                        Self::tree_tweak(0, epoch_chunk[lane]).to_field_elements::<TWEAK_LEN>()
                                [t_idx]
                    },
                );

                // Copy all chain ends (already packed)
                let dst = &mut packed_leaf_input[sponge_chains_offset
                        ..sponge_chains_offset + packed_chains.len() * HASH_LEN];
                for (dst_chunk, src_chain) in
                        dst.chunks_exact_mut(HASH_LEN).zip(packed_chains.iter())
                    {
                        dst_chunk.copy_from_slice(src_chain);
                    }

                // Apply the sponge hash to produce the leaf.
                // This absorbs all chain ends and squeezes out the final hash.
                let packed_leaves =
                    poseidon_sponge::<PackedF, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(
                        &sponge_perm,
                        &capacity_val,
                        &packed_leaf_input,
                    );

                // STEP 4: UNPACK RESULTS TO SCALAR REPRESENTATION
                //
                // Convert from vertical packing back to scalar layout.
                // Each lane becomes one leaf in the output slice.
                unpack_array(&packed_leaves, leaves_chunk);
            },
            );

        // HANDLE REMAINDER EPOCHS
        //
        // If the total number of epochs is not divisible by the SIMD width,
        // process the remaining epochs using scalar code.
        //
        // This ensures correctness for all input sizes.

        let remainder_start = (epochs.len() / width) * width;
        for (i, epoch) in epochs[remainder_start..].iter().enumerate() {
            let global_index = remainder_start + i;

            // Walk all chains for this epoch.
            let chain_ends: Vec<_> = (0..NUM_CHUNKS)
                .map(|chain_index| {
                    let start = PRF::get_domain_element(prf_key, *epoch, chain_index as u64).into();
                    chain::<Self>(
                        parameter,
                        *epoch,
                        chain_index as u8,
                        0,
                        chain_length - 1,
                        &start,
                    )
                })
                .collect();

            // Hash the chain ends to produce the leaf.
            leaves[global_index] =
                Self::apply(parameter, &Self::tree_tweak(0, *epoch), &chain_ends);
        }

        leaves
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            CAPACITY < 24,
            "Poseidon Tweak Chain Hash: Capacity must be less than 24"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + HASH_LEN <= 16,
            "Poseidon Tweak Chain Hash: Input lengths too large for Poseidon instance"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + 2 * HASH_LEN <= 24,
            "Poseidon Tweak Tree Hash: Input lengths too large for Poseidon instance"
        );

        let bits_per_fe = f64::floor(f64::log2(F::ORDER_U64 as f64));
        let state_bits = bits_per_fe * f64::from(24_u32);
        assert!(
            state_bits >= f64::from((DOMAIN_PARAMETERS_LENGTH * 32) as u32),
            "Poseidon Tweak Leaf Hash: not enough field elements to hash the domain separator"
        );

        let bits_for_tree_tweak = f64::from(32 + 8_u32);
        let bits_for_chain_tweak = f64::from(32 + 8 + 8 + 8_u32);
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN as u32);
        assert!(
            tweak_fe_bits >= bits_for_tree_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the tree tweak"
        );
        assert!(
            tweak_fe_bits >= bits_for_chain_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the chain tweak"
        );
    }
}

// Example instantiations
#[cfg(test)]
pub type PoseidonTweak44 = PoseidonTweakHash<4, 4, 3, 9, 128>;
#[cfg(test)]
pub type PoseidonTweak37 = PoseidonTweakHash<3, 7, 3, 9, 128>;
#[cfg(test)]
pub type PoseidonTweakW1L5 = PoseidonTweakHash<5, 7, 2, 9, 163>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use num_bigint::BigUint;
    use rand::Rng;

    use super::*;
    use crate::symmetric::prf::shake_to_field::ShakePRFtoF;
    use p3_field::PrimeField32;
    use proptest::prelude::*;

    #[test]
    fn test_apply_44() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak44::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let message_two = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak44::chain_tweak(2, 3, 4);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_chain, &[message_one]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let chains = [PoseidonTweak44::rand_domain(&mut rng); 128];
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_tree, &chains);
    }

    #[test]
    fn test_apply_37() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak37::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let message_two = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak37::tree_tweak(0, 3);
        let _ = PoseidonTweak37::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak37::chain_tweak(2, 3, 4);
        let _ = PoseidonTweak37::apply(&parameter, &tweak_chain, &[message_one]);
    }

    #[test]
    fn test_rand_parameter_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let parameter = PoseidonTweak44::rand_parameter(&mut rng);

            // Check if all elements in `parameter` are identical
            let first = parameter[0];
            if parameter.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_parameter generated identical elements in all {K} trials"
        );
    }

    #[test]
    fn test_rand_domain_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let domain = PoseidonTweak44::rand_domain(&mut rng);

            // Check if all elements in `domain` are identical
            let first = domain[0];
            if domain.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_domain generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_tree_tweak_field_elements() {
        // Tweak
        let level = 1u8;
        let pos_in_level = 2u32;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        // Compute tweak_bigint
        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements() {
        // Tweak
        let epoch = 1u32;
        let chain_index = 2u8;
        let pos_in_chain = 3u8;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        // Compute tweak_bigint = (epoch << 24) + (chain_index << 16) + (pos_in_chain << 8) + sep
        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_field_elements_max_values() {
        let level = u8::MAX;
        let pos_in_level = u32::MAX;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements_max_values() {
        let epoch = u32::MAX;
        let chain_index = u8::MAX;
        let pos_in_chain = u8::MAX;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that tree tweak maps from
        // parameters to field elements array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let level = rng.random();
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some((prev_level, prev_pos_in_level)) =
                map.insert(tweak_encoding, (level, pos_in_level))
            {
                assert_eq!(
                    (prev_level, prev_pos_in_level),
                    (level, pos_in_level),
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level,
                    prev_pos_in_level,
                    level,
                    pos_in_level,
                    tweak_encoding
                );
            }
        }

        // inputs with common level
        let mut map = HashMap::new();
        let level = rng.random();
        for _ in 0..10_000 {
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_pos_in_level) = map.insert(tweak_encoding, pos_in_level) {
                assert_eq!(
                    prev_pos_in_level, pos_in_level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    level, prev_pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }

        // inputs with common pos_in_level
        let mut map = HashMap::new();
        let pos_in_level = rng.random();
        for _ in 0..10_000 {
            let level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_level) = map.insert(tweak_encoding, level) {
                assert_eq!(
                    prev_level, level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level, pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }
    }

    #[test]
    fn test_chain_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that chain tweak maps from
        // parameters to field element array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let epoch = rng.random();
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed epoch
        let mut map = HashMap::new();
        let epoch = rng.random();
        for _ in 0..10_000 {
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed chain_index
        let mut map = HashMap::new();
        let chain_index = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed pos_in_chain
        let mut map = HashMap::new();
        let pos_in_chain = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let chain_index = rng.random();

            let input = (epoch, chain_index);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }
    }

    /// Naive/scalar implementation of compute_tree_leaves for testing purposes.
    fn compute_tree_leaves_naive<
        TH: TweakableHash,
        PRF: Pseudorandom,
        const PARAMETER_LEN: usize,
        const HASH_LEN: usize,
        const TWEAK_LEN: usize,
        const CAPACITY: usize,
        const NUM_CHUNKS: usize,
    >(
        prf_key: &PRF::Key,
        parameter: &TH::Parameter,
        epochs: &[u32],
        num_chains: usize,
        chain_length: usize,
    ) -> Vec<TH::Domain>
    where
        PRF::Domain: Into<TH::Domain>,
    {
        // Process each epoch in parallel
        epochs
            .iter()
            .map(|&epoch| {
                // For each epoch, walk all chains in parallel
                let chain_ends = (0..num_chains)
                    .map(|chain_index| {
                        // Each chain start is just a PRF evaluation
                        let start =
                            PRF::get_domain_element(prf_key, epoch, chain_index as u64).into();
                        // Walk the chain to get the public chain end
                        chain::<TH>(
                            parameter,
                            epoch,
                            chain_index as u8,
                            0,
                            chain_length - 1,
                            &start,
                        )
                    })
                    .collect::<Vec<_>>();
                // Build hash of chain ends / public keys
                TH::apply(parameter, &TH::tree_tweak(0, epoch), &chain_ends)
            })
            .collect()
    }

    #[test]
    fn test_compute_tree_leaves_matches_naive() {
        type TestPRF = ShakePRFtoF<4, 4>;
        type TestTH = PoseidonTweak44;

        let mut rng = rand::rng();

        // Generate test parameters
        let prf_key = TestPRF::key_gen(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);

        // Test with different numbers of epochs to cover both SIMD and remainder paths
        let test_cases = vec![
            // Small cases that fit in one SIMD batch
            vec![0, 1, 2, 3],
            // Exact multiple of SIMD width (assuming width is typically 4, 8, or 16)
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            // Non-multiple of SIMD width to test remainder handling
            vec![0, 1, 2, 3, 4, 5],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        ];

        let num_chains = 128;
        let chain_length = 10;

        for epochs in test_cases {
            // Compute using SIMD implementation
            let simd_result = TestTH::compute_tree_leaves::<TestPRF>(
                &prf_key,
                &parameter,
                &epochs,
                num_chains,
                chain_length,
            );

            // Compute using naive/scalar implementation
            let naive_result = compute_tree_leaves_naive::<TestTH, TestPRF, 4, 4, 3, 9, 128>(
                &prf_key,
                &parameter,
                &epochs,
                num_chains,
                chain_length,
            );

            // Results should match exactly
            assert_eq!(
                simd_result.len(),
                naive_result.len(),
                "SIMD and naive implementations produced different number of leaves for epochs {:?}",
                epochs
            );

            for (i, (simd_leaf, naive_leaf)) in
                simd_result.iter().zip(naive_result.iter()).enumerate()
            {
                assert_eq!(
                    simd_leaf, naive_leaf,
                    "Mismatch at epoch index {} (epoch {}): SIMD and naive implementations produced different results",
                    i, epochs[i]
                );
            }
        }
    }

    #[test]
    fn test_compute_tree_leaves_matches_naive_random_epochs() {
        type TestPRF = ShakePRFtoF<4, 4>;
        type TestTH = PoseidonTweak44;

        let mut rng = rand::rng();

        // Generate test parameters
        let prf_key = TestPRF::key_gen(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);

        let num_chains = 128;
        let chain_length = 10;

        // Test with random epochs (not necessarily sequential)
        let random_epochs: Vec<u32> = (0..17).map(|_| rng.random::<u32>() % 1000).collect();

        // Compute using SIMD implementation
        let simd_result = TestTH::compute_tree_leaves::<TestPRF>(
            &prf_key,
            &parameter,
            &random_epochs,
            num_chains,
            chain_length,
        );

        // Compute using naive/scalar implementation
        let naive_result = compute_tree_leaves_naive::<TestTH, TestPRF, 4, 4, 3, 9, 128>(
            &prf_key,
            &parameter,
            &random_epochs,
            num_chains,
            chain_length,
        );

        // Results should match exactly
        assert_eq!(
            simd_result.len(),
            naive_result.len(),
            "SIMD and naive implementations produced different number of leaves"
        );

        for (i, (simd_leaf, naive_leaf)) in simd_result.iter().zip(naive_result.iter()).enumerate()
        {
            assert_eq!(
                simd_leaf, naive_leaf,
                "Mismatch at epoch index {} (epoch {}): SIMD and naive implementations produced different results",
                i, random_epochs[i]
            );
        }
    }

    proptest! {
        #[test]
        fn proptest_apply_properties(
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 4),
            msg_values in prop::collection::vec(0u32..F::ORDER_U32, 4),
            epoch in any::<u32>(),
            chain_index in any::<u8>(),
            pos_in_chain in any::<u8>()
        ) {
            // build parameter and message from proptest values
            let parameter = FieldArray(std::array::from_fn::<_, 4, _>(|i| F::new(param_values[i])));
            let message = FieldArray(std::array::from_fn::<_, 4, _>(|i| F::new(msg_values[i])));

            // create chain tweak
            let tweak = PoseidonTweak44::chain_tweak(epoch, chain_index, pos_in_chain);

            // call apply twice to check determinism
            let result1 = PoseidonTweak44::apply(&parameter, &tweak, &[message]);
            let result2 = PoseidonTweak44::apply(&parameter, &tweak, &[message]);

            // check determinism
            prop_assert_eq!(result1, result2);

            // check output has correct length
            prop_assert_eq!(result1.0.len(), 4);

            // check different tweaks produce different results
            let other_tweak = PoseidonTweak44::chain_tweak(
                epoch.wrapping_add(1),
                chain_index,
                pos_in_chain,
            );
            let other_result = PoseidonTweak44::apply(&parameter, &other_tweak, &[message]);
            prop_assert_ne!(result1, other_result);
        }

        #[test]
        fn proptest_chain_tweak_encoding_properties(
            epoch1 in any::<u32>(),
            epoch2 in any::<u32>(),
            chain_index in any::<u8>(),
            pos_in_chain in any::<u8>()
        ) {
            // check encoding is deterministic
            let tweak1 = PoseidonTweak::ChainTweak { epoch: epoch1, chain_index, pos_in_chain };
            let result1 = tweak1.to_field_elements::<2>();
            let result2 = tweak1.to_field_elements::<2>();
            prop_assert_eq!(result1, result2);

            // check output has correct length
            prop_assert_eq!(result1.len(), 2);

            // check different epochs produce different encodings
            let tweak2 = PoseidonTweak::ChainTweak { epoch: epoch2, chain_index, pos_in_chain };
            let other = tweak2.to_field_elements::<2>();
            if epoch1 == epoch2 {
                prop_assert_eq!(result1, other);
            } else {
                prop_assert_ne!(result1, other);
            }

            // check chain tweaks differ from tree tweaks (domain separation)
            let tree_tweak = PoseidonTweak::TreeTweak { level: 0, pos_in_level: epoch1 };
            let tree_result = tree_tweak.to_field_elements::<2>();
            prop_assert_ne!(result1, tree_result);
        }

        #[test]
        fn proptest_tree_tweak_encoding_properties(
            level1 in any::<u8>(),
            level2 in any::<u8>(),
            pos_in_level in any::<u32>()
        ) {
            // check encoding is deterministic
            let tweak1 = PoseidonTweak::TreeTweak { level: level1, pos_in_level };
            let result1 = tweak1.to_field_elements::<2>();
            let result2 = tweak1.to_field_elements::<2>();
            prop_assert_eq!(result1, result2);

            // check output has correct length
            prop_assert_eq!(result1.len(), 2);

            // check different levels produce different encodings
            let tweak2 = PoseidonTweak::TreeTweak { level: level2, pos_in_level };
            let other = tweak2.to_field_elements::<2>();
            if level1 == level2 {
                prop_assert_eq!(result1, other);
            } else {
                prop_assert_ne!(result1, other);
            }
        }
    }

    /// Scalar reference implementation for compute_tree_layer.
    /// Used to verify the SIMD implementation produces correct results.
    fn compute_tree_layer_scalar<TH: TweakableHash>(
        parameter: &TH::Parameter,
        level: u8,
        parent_start: usize,
        children: &[TH::Domain],
    ) -> Vec<TH::Domain> {
        children
            .chunks_exact(2)
            .enumerate()
            .map(|(i, pair)| {
                TH::apply(
                    parameter,
                    &TH::tree_tweak(level, (parent_start + i) as u32),
                    pair,
                )
            })
            .collect()
    }

    #[test]
    fn test_compute_tree_layer_matches_scalar() {
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        // Test with 16 children (8 pairs)
        let children: Vec<_> = (0..16)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let level = 1u8;
        let parent_start = 0usize;

        let simd_result =
            PoseidonTweak44::compute_tree_layer(&parameter, level, parent_start, &children);
        let scalar_result = compute_tree_layer_scalar::<PoseidonTweak44>(
            &parameter,
            level,
            parent_start,
            &children,
        );

        assert_eq!(simd_result.len(), scalar_result.len());
        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_compute_tree_layer_output_length() {
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        // Test various input sizes
        for num_pairs in [1, 2, 4, 7, 8, 15, 16, 17, 32, 33] {
            let children: Vec<_> = (0..num_pairs * 2)
                .map(|_| PoseidonTweak44::rand_domain(&mut rng))
                .collect();

            let result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);

            assert_eq!(
                result.len(),
                num_pairs,
                "Expected {} parents for {} children, got {}",
                num_pairs,
                num_pairs * 2,
                result.len()
            );
        }
    }

    #[test]
    fn test_compute_tree_layer_determinism() {
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let children: Vec<_> = (0..20)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let result1 = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let result2 = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);

        assert_eq!(
            result1, result2,
            "compute_tree_layer should be deterministic"
        );
    }

    #[test]
    fn test_compute_tree_layer_level_affects_output() {
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let children: Vec<_> = (0..16)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let result_level_1 = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let result_level_2 = PoseidonTweak44::compute_tree_layer(&parameter, 2, 0, &children);

        assert_ne!(
            result_level_1, result_level_2,
            "Different levels should produce different outputs"
        );
    }

    #[test]
    fn test_compute_tree_layer_parent_start_affects_output() {
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let children: Vec<_> = (0..16)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let result_start_0 = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let result_start_10 = PoseidonTweak44::compute_tree_layer(&parameter, 1, 10, &children);

        assert_ne!(
            result_start_0, result_start_10,
            "Different parent_start should produce different outputs"
        );
    }

    #[test]
    fn test_compute_tree_layer_simd_boundary_exact_width() {
        // Test with exactly 2 * WIDTH children (one full SIMD batch, no remainder)
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;
        let children: Vec<_> = (0..2 * width)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let scalar_result =
            compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_compute_tree_layer_simd_boundary_with_remainder() {
        // Test with 2 * WIDTH + 2 children (one SIMD batch + one remainder pair)
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;
        let children: Vec<_> = (0..2 * width + 2)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let scalar_result =
            compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

        assert_eq!(
            simd_result.len(),
            width + 1,
            "Should have WIDTH + 1 parents"
        );
        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_compute_tree_layer_only_remainder() {
        // Test with fewer than 2 * WIDTH children (entire computation is remainder)
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;

        // Test sizes smaller than one SIMD batch
        for num_pairs in 1..width {
            let children: Vec<_> = (0..num_pairs * 2)
                .map(|_| PoseidonTweak44::rand_domain(&mut rng))
                .collect();

            let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
            let scalar_result =
                compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

            assert_eq!(
                simd_result, scalar_result,
                "Failed for num_pairs = {}",
                num_pairs
            );
        }
    }

    #[test]
    fn test_compute_tree_layer_two_simd_batches() {
        // Test with 4 * WIDTH children (two full SIMD batches)
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;
        let children: Vec<_> = (0..4 * width)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let scalar_result =
            compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

        assert_eq!(simd_result.len(), 2 * width);
        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_compute_tree_layer_two_batches_with_remainder() {
        // Test with 4 * WIDTH + 2 children (two SIMD batches + one remainder pair)
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;
        let children: Vec<_> = (0..4 * width + 2)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

        let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
        let scalar_result =
            compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

        assert_eq!(simd_result.len(), 2 * width + 1);
        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_compute_tree_layer_boundary_sweep() {
        // Test all sizes from 2 to 4 * WIDTH + 2 to catch off-by-one errors
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;
        let max_pairs = 4 * width + 1;

        for num_pairs in 1..=max_pairs {
            let children: Vec<_> = (0..num_pairs * 2)
                .map(|_| PoseidonTweak44::rand_domain(&mut rng))
                .collect();

            let simd_result = PoseidonTweak44::compute_tree_layer(&parameter, 1, 0, &children);
            let scalar_result =
                compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, 1, 0, &children);

            assert_eq!(
                simd_result, scalar_result,
                "Mismatch for num_pairs = {} (WIDTH = {})",
                num_pairs, width
            );
        }
    }

    #[test]
    fn test_compute_tree_layer_nonzero_parent_start() {
        // Test with various parent_start values to ensure tweaks are correct
        let mut rng = rand::rng();
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);

        let width = PackedF::WIDTH;

        for parent_start in [0, 1, 10, 100, 1000] {
            let children: Vec<_> = (0..2 * width + 4)
                .map(|_| PoseidonTweak44::rand_domain(&mut rng))
                .collect();

            let simd_result =
                PoseidonTweak44::compute_tree_layer(&parameter, 1, parent_start, &children);
            let scalar_result = compute_tree_layer_scalar::<PoseidonTweak44>(
                &parameter,
                1,
                parent_start,
                &children,
            );

            assert_eq!(
                simd_result, scalar_result,
                "Mismatch for parent_start = {}",
                parent_start
            );
        }
    }

    proptest! {
        #[test]
        fn proptest_compute_tree_layer_matches_scalar(
            num_pairs in 1usize..64,
            level in 0u8..32,
            parent_start in 0usize..1000,
            seed in any::<u64>(),
        ) {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

            let parameter = PoseidonTweak44::rand_parameter(&mut rng);
            let children: Vec<_> = (0..num_pairs * 2)
            .map(|_| PoseidonTweak44::rand_domain(&mut rng))
            .collect();

            let simd_result =
            PoseidonTweak44::compute_tree_layer(&parameter, level, parent_start, &children);
            let scalar_result =
            compute_tree_layer_scalar::<PoseidonTweak44>(&parameter, level, parent_start, &children);

            prop_assert_eq!(simd_result.len(), num_pairs);
            prop_assert_eq!(simd_result, scalar_result);
        }
    }
}
