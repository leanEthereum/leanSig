use rand::RngExt;

use rayon::prelude::*;

use crate::serialization::Serializable;
use crate::symmetric::prf::Pseudorandom;

/// Trait to model a tweakable hash function.
/// Such a function takes a public parameter, a tweak, and a
/// message to be hashed. The tweak should be understood as an
/// address for domain separation.
///
/// In our setting, we require the support of hashing lists of
/// hashes. Therefore, we just define a type `Domain` and the
/// hash function maps from [Domain] to Domain.
///
/// We also require that the tweak hash already specifies how
/// to obtain distinct tweaks for applications in chains and
/// applications in Merkle trees.
pub trait TweakableHash {
    /// Public parameter type for the hash function
    type Parameter: Copy + Send + Sync + Serializable;

    /// Tweak type for domain separation
    type Tweak;

    /// Domain element type (defines output and input types to the hash)
    type Domain: Copy + PartialEq + Send + Sync + Serializable;

    /// Generates a random public parameter.
    fn rand_parameter<R: RngExt>(rng: &mut R) -> Self::Parameter;

    /// Generates a random domain element.
    fn rand_domain<R: RngExt>(rng: &mut R) -> Self::Domain;

    /// Returns a tweak to be used in the Merkle tree.
    /// Note: this is assumed to be distinct from the outputs of chain_tweak
    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak;

    /// Returns a tweak to be used in chains.
    /// Note: this is assumed to be distinct from the outputs of tree_tweak
    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak;

    /// Applies the tweakable hash to parameter, tweak, and message.
    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain;

    /// Computes one layer of a Merkle tree by hashing pairs of children into parents.
    ///
    /// Consecutive pairs of child nodes produce their parent node by hashing
    /// `(children[2*i], children[2*i+1])`. Each hash application uses a unique
    /// tweak derived from the tree level and position.
    ///
    /// # Arguments
    /// * `parameter` - Public parameter for the hash function
    /// * `level` - Tree level of the *parent* nodes being computed. NOTE: callers
    ///   need to pass `level + 1` where `level` is the children's level, since
    ///   tree levels are numbered from leaves (level 0) upward.
    /// * `parent_start` - Starting index of the first parent in this layer, used
    ///   for computing position-dependent tweaks
    /// * `children` - Slice of child nodes to hash pairwise (length must be even)
    ///
    /// # Returns
    /// A vector of parent nodes with length `children.len() / 2`.
    ///
    /// This default implementation processes pairs in parallel using Rayon.
    /// The Poseidon implementation overrides this with a SIMD-accelerated variant.
    fn compute_tree_layer(
        parameter: &Self::Parameter,
        level: u8,
        parent_start: usize,
        children: &[Self::Domain],
    ) -> Vec<Self::Domain> {
        // default implementation is scalar. tweak_tree/poseidon.rs provides a SIMD variant
        children
            .par_chunks_exact(2)
            .enumerate()
            .map(|(i, children)| {
                // Parent index in this layer
                let parent_pos = (parent_start + i) as u32;
                // Hash children into their parent using the tweak
                Self::apply(parameter, &Self::tree_tweak(level, parent_pos), children)
            })
            .collect()
    }

    /// Computes bottom tree leaves by walking hash chains for multiple epochs.
    ///
    /// This method has a default scalar implementation that processes epochs in parallel.
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
        Self: Sized;
}

/// Function implementing hash chains, implemented over a tweakable hash function
/// The chain is specific to an epoch `epoch`, and an index `chain_index`. All
/// evaluations of the tweakable hash function use the given parameter `parameter`
/// and tweaks determined by `epoch`, `chain_index`, and their position in the chain.
/// We start walking the chain at position `start_pos_in_chain` with `start`,
/// and then walk the chain for `steps` many steps. For example, walking two steps
/// with `start = A` would mean we walk A -> B -> C, and then return C.
#[allow(clippy::too_long_first_doc_paragraph)]
pub fn chain<TH: TweakableHash>(
    parameter: &TH::Parameter,
    epoch: u32,
    chain_index: u8,
    start_pos_in_chain: u8,
    steps: usize,
    start: &TH::Domain,
) -> TH::Domain {
    // keep track of what we have
    let mut current = *start;

    // otherwise, walk the right amount of steps
    for j in 0..steps {
        let tweak = TH::chain_tweak(epoch, chain_index, start_pos_in_chain + (j as u8) + 1u8);
        current = TH::apply(parameter, &tweak, &[current]);
    }

    // return where we are now
    current
}

pub mod poseidon;
