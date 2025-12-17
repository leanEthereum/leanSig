use crate::serialization::Serializable;
use crate::symmetric::tweak_hash::TweakableHash;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

/// A single layer of a sparse Hash-Tree
/// based on tweakable hash function
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
struct HashTreeLayer<TH: TweakableHash> {
    start_index: u64,
    nodes: Vec<TH::Domain>,
}

impl<TH: TweakableHash> Encode for HashTreeLayer<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // - Fixed part: start_index (8 bytes) + offset (4 bytes)
        // - Variable part: nodes
        8 + 4 + self.nodes.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // SSZ Container encoding order:
        // 1. Fixed field: start_index
        self.start_index.ssz_append(buf);

        // 2. Offset for variable field: nodes
        // Offset points to where variable data starts = end of fixed part
        // 8 bytes (start_index) + 4 bytes (offset itself)
        let offset: u32 = 12;
        buf.extend_from_slice(&offset.to_le_bytes());

        // 3. Variable data: nodes
        self.nodes.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashTreeLayer<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Minimum size: start_index (8) + offset (4) = 12 bytes
        const FIXED_SIZE: usize = 12;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        // 1. Decode fixed field: start_index
        let start_index = u64::from_ssz_bytes(&bytes[0..8])?;

        // 2. Read offset for variable field
        let offset = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 12,
            }
        })?) as usize;

        // 3. Validate offset points to end of fixed part
        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        // 4. Decode variable field: nodes
        let nodes = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self { start_index, nodes })
    }
}

impl<TH: TweakableHash> Serializable for HashTreeLayer<TH> {}

impl<TH: TweakableHash> HashTreeLayer<TH> {
    /// Construct a layer from a contiguous run of nodes and pad it so that:
    /// - the layer starts at an even index (a left child), and
    /// - the layer ends at an odd index (a right child).
    ///
    /// Input interpretation:
    /// - `nodes` conceptually occupy tree indices
    ///   `[start_index, start_index + nodes.len() - 1]` (inclusive).
    ///
    /// Padding rules:
    /// - If `start_index` is odd, we insert one random node in front and shift
    ///   the effective start to the previous even index.
    /// - If the end index is even, we append one random node at the back so the
    ///   final index is odd.
    ///
    /// Why this matters:
    /// - With this alignment every parent is formed from exactly two children,
    ///   so upper layers can be built with exact size-2 chunks, with no edge cases.
    #[inline]
    fn padded<R: Rng>(rng: &mut R, nodes: Vec<TH::Domain>, start_index: usize) -> Self {
        // End index of the provided contiguous run (inclusive).
        let end_index = start_index + nodes.len() - 1;

        // Do we need a front pad? Start must be even.
        let needs_front = (start_index & 1) == 1;

        // Do we need a back pad? End must be odd.
        let needs_back = (end_index & 1) == 0;

        // The effective start index after optional front padding (always even).
        let actual_start_index = start_index - (needs_front as usize);

        // Reserve exactly the space we may need: original nodes plus up to two pads.
        let mut out =
            Vec::with_capacity(nodes.len() + (needs_front as usize) + (needs_back as usize));

        // Optional front padding to align to an even start index.
        if needs_front {
            out.push(TH::rand_domain(rng));
        }

        // Insert the actual content in order.
        out.extend(nodes);

        // Optional back padding to ensure we end on an odd index.
        if needs_back {
            out.push(TH::rand_domain(rng));
        }

        // Return the padded layer with the corrected start index.
        Self {
            start_index: actual_start_index as u64,
            nodes: out,
        }
    }
}

/// Sub-tree of a sparse Hash-Tree based on a tweakable hashes.
/// We consider hash trees in which each leaf is first
/// hashed individually.
///
/// The tree can be sparse in the following sense:
/// There is a contiguous range of leafs that exist,
/// and the tree is built on top of that.
/// For instance, we may consider a tree of depth 32,
/// but only 2^{26} leafs really exist.
///
/// This struct may represent only a subtree of the full tree,
/// which may only contain the top layers of the tree.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HashSubTree<TH: TweakableHash> {
    /// Depth of the full tree. The tree can have at most
    /// 1 << depth many leafs. The full tree has depth + 1
    /// many layers, whereas the sub-tree can have less.
    depth: u64,

    /// The lowest layer of the sub-tree. If this represents the
    /// full tree, then lowest_layer = 0.
    lowest_layer: u64,

    /// Layers of the hash tree, starting with the
    /// lowest_level. That is, layers[i] contains the nodes
    /// in level i + lowest_level of the tree. For the full tree
    /// (lowest_layer = 0), the leafs are not included: the
    /// bottom layer is the list of hashes of all leafs
    layers: Vec<HashTreeLayer<TH>>,
}

impl<TH: TweakableHash> Encode for HashSubTree<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // - Fixed part: depth (8) + lowest_layer (8) + offset (4)
        // - Variable part: layers
        8 + 8 + 4 + self.layers.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // SSZ Container encoding order:
        // 1. Fixed field: depth
        self.depth.ssz_append(buf);

        // 2. Fixed field: lowest_layer
        self.lowest_layer.ssz_append(buf);

        // 3. Offset for variable field: layers
        let offset: u32 = 20; // 8 (depth) + 8 (lowest_layer) + 4 (offset itself)
        buf.extend_from_slice(&offset.to_le_bytes());

        // 4. Variable data: layers
        self.layers.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashSubTree<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Minimum size: depth (8) + lowest_layer (8) + offset (4) = 20 bytes
        const FIXED_SIZE: usize = 20;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        // 1. Decode fixed field: depth
        let depth = u64::from_ssz_bytes(&bytes[0..8])?;

        // 2. Decode fixed field: lowest_layer
        let lowest_layer = u64::from_ssz_bytes(&bytes[8..16])?;

        // 3. Read offset for variable field
        let offset = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 20,
            }
        })?) as usize;

        // 4. Validate offset points to end of fixed part
        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        // 5. Decode variable field: layers
        let layers = Vec::<HashTreeLayer<TH>>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self {
            depth,
            lowest_layer,
            layers,
        })
    }
}

/// Opening in a hash-tree: a co-path, without the leaf
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct HashTreeOpening<TH: TweakableHash> {
    /// The co-path needed to verify
    /// If the tree has depth h, i.e, 2^h leafs
    /// the co-path should have size D
    co_path: Vec<TH::Domain>,
}

impl<TH: TweakableHash> Encode for HashTreeOpening<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // - Fixed part: offset (4 bytes)
        // - Variable part: co_path
        4 + self.co_path.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // SSZ Container encoding order:
        // 1. Offset for variable field: co_path
        // Only the offset itself in fixed part
        let offset: u32 = 4;
        buf.extend_from_slice(&offset.to_le_bytes());

        // 2. Variable data: co_path
        self.co_path.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for HashTreeOpening<TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Minimum size: offset (4 bytes)
        const FIXED_SIZE: usize = 4;
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: FIXED_SIZE,
            });
        }

        // 1. Read offset for variable field
        let offset = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 4,
            }
        })?) as usize;

        // 2. Validate offset points to end of fixed part
        if offset != FIXED_SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: offset,
                expected: FIXED_SIZE,
            });
        }

        // 3. Decode variable field: co_path
        let co_path = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset..])?;

        Ok(Self { co_path })
    }
}

impl<TH: TweakableHash> Serializable for HashTreeOpening<TH> {}

impl<TH: TweakableHash> Serializable for HashSubTree<TH> {}

impl<TH> HashSubTree<TH>
where
    TH: TweakableHash,
{
    /// Function to compute a (sub-tree of a) hash-tree, which contains the top layers
    /// of a hash tree. The function takes the nodes in layer `lowest_layer` as input.
    /// They correspond to the (hashes of) the leafs if `lowest_layer = 0`.
    /// The full tree is assumed to have depth `depth`. Consequently, the full tree
    /// can have at most `1 << depth` many leafs and it has `depth + 1` layers.
    ///
    /// For the sub-tree that is generated, the number of `lowest_layer_nodes` cannot
    /// be more than `1 << (depth - lowest_layer)`.
    ///
    /// The lowest_layer nodes start at the given start index, namely, the nodes that
    /// exist in this layer are `start, start + 1, ... start + leafs.len() - 1`
    ///
    /// Caller must ensure that there is enough space for the leafs, i.e.,
    /// `start_index + leafs.len() <= 1 << (depth - lowest_layer)`
    ///
    /// Important: if this is used for the full tree (lowest_layer = 0), the leafs are
    /// expected to already be hashes. This is in to contrast to hash_tree_verify.
    ///
    /// Note: The RNG is used for generating nodes used for padding in the case of
    /// sparse trees. They could as well be fixed, and hence the RNG does not need
    /// to be cryptographically secure for this function.
    pub fn new_subtree<R: Rng>(
        rng: &mut R,
        lowest_layer: usize,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        lowest_layer_nodes: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            lowest_layer < depth,
            "Hash-Tree new: lowest_layer exceeds depth. Ensure that it is between 0 and depth - 1."
        );

        assert!(
            start_index + lowest_layer_nodes.len() <= 1 << (depth - lowest_layer),
            "Hash-Tree new: Not enough space for lowest layer nodes. Consider changing start_index or number of lowest layer nodes."
        );

        // we build the tree from the lowest layer to the root,
        // while building the tree, we ensure that the following two invariants hold via appropriate padding:
        // 1. the layer starts at an even index, i.e., a left child
        // 2. the layer ends at an odd index, i.e., a right child (does not hold for the root layer)
        // In this way, we can ensure that we can always hash two siblings to get their parent
        // The padding is ensured using the helper function `get_padded_layer`.

        let mut layers = Vec::with_capacity(depth + 1 - lowest_layer);

        // start with the lowest layer, padded accordingly
        layers.push(HashTreeLayer::padded(rng, lowest_layer_nodes, start_index));

        // now, build the tree layer by layer
        for level in lowest_layer..depth {
            // Previous layer (already padded so len is even and start_index is even)
            let prev = &layers[level - lowest_layer];

            // Parent layer starts at half the previous start index
            let parent_start = (prev.start_index >> 1) as usize;

            // Compute all parents in parallel, pairing children two-by-two
            //
            // We do exact chunks of two children, no remainder.
            let parents =
                TH::compute_tree_layer(parameter, level as u8 + 1, parent_start, &prev.nodes);

            // Add the new layer with padding so next iteration also has even start and length
            layers.push(HashTreeLayer::padded(rng, parents, parent_start));
        }

        Self {
            depth: depth as u64,
            lowest_layer: lowest_layer as u64,
            layers,
        }
    }

    /// Function to compute a top sub-tree of a tree of even depth.
    /// The top tree contains only the top layers, starting with layer
    /// depth / 2, and ending with the root of the full tree, which is layer depth + 1.
    ///
    /// It takes as input the roots of all 2^{depth/2} bottom trees. Note that these are
    /// exactly the nodes in layer depth / 2. The `start_index` indicates which bottom tree
    /// is the first that is given. It be in [0, 2^{depth/2}).
    pub fn new_top_tree<R: Rng>(
        rng: &mut R,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        roots_of_bottom_trees: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth.is_multiple_of(2),
            "Hash-Tree new top tree: Depth must be even."
        );

        // the top tree is just the sub-tree that starts at layer depth / 2, and contains
        // the roots of the bottom trees in the lowest layer.
        let lowest_layer = depth / 2;
        let lowest_layer_nodes = roots_of_bottom_trees;
        Self::new_subtree(
            rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        )
    }

    /// Function to compute a bottom sub-tree of a tree of even depth.
    /// This is a tree containing 2^{depth/2} leafs, which are at positions
    /// bottom_tree_index * 2^{depth/2}, ... (bottom_tree_index + 1) * 2^{depth/2} - 1
    pub fn new_bottom_tree(
        depth: usize,
        bottom_tree_index: usize,
        parameter: &TH::Parameter,
        leafs: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth > 2 && depth.is_multiple_of(2),
            "Hash-Tree new bottom tree: Depth must be even and more than 2."
        );

        assert!(
            leafs.len() == 1 << (depth / 2),
            "Hash-Tree new bottom tree: Bottom trees must be full, not sparse."
        );

        // note that this bottom tree will have no padding due to the previous
        // assert this means we can instantiate the RNG used in new_subtree with some
        // dummy RNG, because it will never be used. More precisely, all padding nodes
        // that will be generated in new_subtree will be removed below.
        //
        // Also, even if there were dummy nodes, it is not critical for security
        // that they are generated by a good PRG, they could be fixed as well.
        let mut dummy_rng = StdRng::seed_from_u64(0);

        // we first compute the bottom tree as if it was a sparse tree, i.e.,
        // as if we were to compute the full tree but only this bottom tree part was filled.
        let leafs_per_bottom_tree = 1 << (depth / 2);
        let lowest_layer = 0;
        let lowest_layer_nodes = leafs;
        let start_index = bottom_tree_index * leafs_per_bottom_tree;
        let mut bottom_tree = Self::new_subtree(
            &mut dummy_rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        );

        // Now, note that the bottom_tree contains dummy nodes for the top depth/2 + 1 layers,
        // These notes are incompatible with the other bottom trees, so we need to make sure that we remove
        // them. We also make sure the root is alone in its layer so that the root() function works.
        let bottom_tree_root = bottom_tree.layers[depth / 2].nodes[bottom_tree_index % 2];
        bottom_tree.layers.truncate(depth / 2);
        bottom_tree.layers.push(HashTreeLayer {
            start_index: bottom_tree_index as u64,
            nodes: vec![bottom_tree_root],
        });

        bottom_tree
    }

    /// Function to get a sub-tree root from a sub-tree.
    /// The tree must have at least one layer.
    #[must_use]
    pub fn root(&self) -> TH::Domain {
        self.layers
            .last()
            .expect("Hash-Tree must have at least one layer")
            .nodes[0]
    }

    /// Function to compute the Merkle authentication path
    /// from a sub-tree and the position of the node in the lowest layer.
    /// It is assumed that the tree is well-formed, i.e., each layer is half
    /// the size of the previous layer, and the final layer has
    /// size 1.
    #[must_use]
    pub fn path(&self, position: u32) -> HashTreeOpening<TH> {
        assert!(
            !self.layers.is_empty(),
            "Hash-Tree path: Need at least one layer"
        );
        assert!(
            (position as u64) >= self.layers[0].start_index,
            "Hash-Tree path: Invalid position, position before start index"
        );
        assert!(
            (position as u64) < self.layers[0].start_index + self.layers[0].nodes.len() as u64,
            "Hash-Tree path: Invalid position, position too large"
        );

        // in our co-path, we will have one node per layer
        // except the final layer (which is just the root)
        let mut co_path = Vec::with_capacity(self.depth as usize);
        let mut current_position = position;
        for l in 0..((self.depth - self.lowest_layer) as usize) {
            // if we are already at the root, we can stop (this is a special case for bottom trees)
            if self.layers[l].nodes.len() <= 1 {
                break;
            }
            // position of the sibling that we want to include
            let sibling_position = current_position ^ 0x01;
            let sibling_position_in_vec =
                (sibling_position as u64 - self.layers[l].start_index) as usize;
            let sibling = self.layers[l].nodes[sibling_position_in_vec];
            co_path.push(sibling);
            // new position in next layer
            current_position >>= 1;
        }

        HashTreeOpening { co_path }
    }
}

/// Function to compute a Merkle authentication path from a tree that is
/// splitted into top tree and bottom trees.
#[must_use]
pub fn combined_path<TH: TweakableHash>(
    top_tree: &HashSubTree<TH>,
    bottom_tree: &HashSubTree<TH>,
    position: u32,
) -> HashTreeOpening<TH> {
    assert!(
        bottom_tree.depth == top_tree.depth,
        "Hash-Tree combined path: Bottom tree and top tree must have the same depth."
    );

    assert!(
        bottom_tree.depth.is_multiple_of(2),
        "Hash-Tree combined path: Tree depth must be even."
    );
    let depth = bottom_tree.depth;
    assert!(
        bottom_tree.layers[0]
            .start_index
            .is_multiple_of(1 << (depth / 2)),
        "Hash-Tree combined path: Bottom tree start index must be multiple of 1 << depth/2."
    );
    let bottom_tree_index = bottom_tree.layers[0].start_index / (1 << (depth / 2));

    // Note: other asserts are in path.

    // First, we compute the path for the bottom tree. Note that this contains
    // dummy elements in the top layers. We will remove them below.
    let bottom_opening = bottom_tree.path(position);

    // Now, we compute the path for the top tree. Intuitively, this authenticates
    // the root of the bottom tree.
    let top_opening = top_tree.path(bottom_tree_index as u32);

    // Finally, we combine them.
    let co_path = [bottom_opening.co_path, top_opening.co_path].concat();

    HashTreeOpening { co_path }
}

/// Function to verify an Merkle authentication path
/// with respect to a root, a position, and a leaf.
///
/// Note: this function expects the leaf to be a list of hashes,
/// whereas `new` expects each leaf to be a single hash,
/// which should be the hash of this list of hashes.
pub fn hash_tree_verify<TH: TweakableHash>(
    parameter: &TH::Parameter,
    root: &TH::Domain,
    position: u32,
    leaf: &[TH::Domain],
    opening: &HashTreeOpening<TH>,
) -> bool {
    // given the length of the path, we know how
    // large the tree was. So we can check if the
    // position makes sense.
    let depth = opening.co_path.len();
    let num_leafs: u64 = 1 << depth;

    assert!(
        depth <= 32,
        "Hash-Tree verify: Tree depth must be at most 32"
    );

    assert!(
        (position as u64) < num_leafs,
        "Hash-Tree verify: Position and Path Length not compatible"
    );

    // first hash the leaf to get the node in the bottom layer
    let tweak = TH::tree_tweak(0, position);
    let mut current_node = TH::apply(parameter, &tweak, leaf);

    // now reconstruct the root using the co-path
    let mut current_position = position;
    for l in 0..depth {
        // Need to distinguish two cases, depending on
        // if current is a left child or a right child
        let children = if current_position.is_multiple_of(2) {
            // left child, so co-path contains the right sibling
            [current_node, opening.co_path[l]]
        } else {
            // right child, so co-path contains the left sibling
            [opening.co_path[l], current_node]
        };

        // determine new position, which is position of the parent
        current_position >>= 1;

        // now hash to get the parent
        let tweak = TH::tree_tweak((l + 1) as u8, current_position);
        current_node = TH::apply(parameter, &tweak, &children);
    }

    // Finally, check that recomputed root matches given root
    current_node == *root
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use crate::symmetric::tweak_hash::poseidon::PoseidonTweak44;

    use super::*;

    type TestTH = PoseidonTweak44;

    /// We test that the following honest procedure succeeds:
    /// (1) build the Merkle tree to get the root,
    /// (2) build an authentication path for the leaf,
    /// (3) verify the authentication path with respect to leaf and root
    fn test_commit_open_helper(
        num_leafs: usize,
        depth: usize,
        start_index: usize,
        leaf_len: usize,
    ) {
        let mut rng = rand::rng();
        // sample a random parameter and leafs
        let parameter = TestTH::rand_parameter(&mut rng);

        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let mut leaf = Vec::new();
            for _ in 0..leaf_len {
                leaf.push(TestTH::rand_domain(&mut rng));
            }
            leafs.push(leaf);
        }

        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (i + start_index) as u32),
                    v.as_slice(),
                )
            })
            .collect();

        // Build the hash tree using the random parameter and leaves
        let tree = HashSubTree::<TestTH>::new_subtree(
            &mut rng,
            0,
            depth,
            start_index,
            &parameter,
            leafs_hashes,
        );

        // now compute a commitment, i.e., Merkle root
        let root = tree.root();

        // now check that opening and verification works as expected
        for (offset, leaf) in leafs.iter().enumerate().take(num_leafs) {
            // calculate the position
            let position = start_index as u32 + offset as u32;
            // first get the opening
            let path = tree.path(position);
            // now assert that it verifies
            assert!(hash_tree_verify(&parameter, &root, position, leaf, &path));
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree() {
        let num_leafs = 1024;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_left() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 5;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_large() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 512;
        let leaf_len = 10;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_small() {
        let num_leafs = 2;
        let depth = 2;
        let start_index: usize = 2;
        let leaf_len = 6;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_sparse_non_aligned() {
        let num_leafs = 213;
        let depth = 10;
        let start_index: usize = 217;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    proptest! {
        #[test]
        fn proptest_commit_open_verify(
            // Test with up to 32 leaf nodes (fast but nontrivial)
            num_leafs in 1usize..32,

            // Tree depth capped at 6 → supports up to 64 leaves
            depth in 3usize..7,

            // Start index limited to 0–64 (sparse trees, padded trees)
            start_index in 0usize..64,

            // Leaves with up to 5 elements (non-scalar values)
            leaf_len in 1usize..5,
        ) {
            // Make sure the leaves actually fit in the tree
            prop_assume!(start_index + num_leafs <= 1 << depth);

            test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
        }
    }

    /// We test that the following honest procedure succeeds:
    /// (1) build the Merkle tree to get the root,
    /// (2) build an authentication path for the leaf,
    /// (3) verify the authentication path with respect to leaf and root
    ///
    /// This is tested for the approach that first builds all bottom trees,
    /// and then the top tree on top of that. And it computes the Merkle
    /// authentication paths using the combined path function.
    fn test_commit_open_helper_top_bottom(
        num_bottom_trees: usize,
        depth: usize,
        start_bottom_tree_index: usize,
        leaf_len: usize,
    ) {
        // sample a random parameter and leafs
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        let leafs_per_bottom_tree = 1 << (depth / 2);
        let num_leafs = num_bottom_trees * leafs_per_bottom_tree;
        let start_index = start_bottom_tree_index * leafs_per_bottom_tree;
        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let mut leaf = Vec::new();
            for _ in 0..leaf_len {
                leaf.push(TestTH::rand_domain(&mut rng));
            }
            leafs.push(leaf);
        }

        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (i + start_index) as u32),
                    v.as_slice(),
                )
            })
            .collect();

        // Now, we build the hash tree. To this end, we first build all bottom trees.
        let mut bottom_trees = Vec::with_capacity(num_bottom_trees);
        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            // compute a bottom tree, which is for 1 << depth/2 many leafs
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let leafs_end = leafs_start + leafs_per_bottom_tree;
            let bottom_tree = HashSubTree::<TestTH>::new_bottom_tree(
                depth,
                bottom_tree_index,
                &parameter,
                leafs_hashes[leafs_start..leafs_end].to_vec(),
            );
            roots_of_bottom_trees.push(bottom_tree.root());
            bottom_trees.push(bottom_tree);
        }
        // We now build the top tree using the roots of the bottom trees
        let top_tree = HashSubTree::<TestTH>::new_top_tree(
            &mut rng,
            depth,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );

        // now compute a commitment, i.e., Merkle root of the top tree
        let root = top_tree.root();

        // now check that opening and verification works as expected. We iterate over each bottom tree, and
        // over each leaf in that bottom tree. Then, we compute an authentication path and verify it.
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let bottom_tree = &bottom_trees[bottom_tree_index - start_bottom_tree_index];

            for l in 0..leafs_per_bottom_tree {
                // calculate the position and get the leaf
                let offset = leafs_start + l;
                let leaf = leafs[offset].clone();
                let position = start_index as u32 + offset as u32;
                // compute the path using the combined_path function
                let path = combined_path(&top_tree, bottom_tree, position);
                // assert that the path verifies
                assert!(hash_tree_verify(&parameter, &root, position, &leaf, &path));
            }
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree_top_bottom() {
        let num_bottom_trees = 4;
        let depth = 4;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_left_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 8;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_middle_tree_right_top_bottom() {
        let num_bottom_trees = 7;
        let depth = 8;
        let start_bottom_tree_index: usize = 4;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_ssz_encoding_structure() {
        let mut rng = rand::rng();

        // HashTreeLayer: Generate sample nodes
        let nodes: Vec<_> = (0..3).map(|_| TestTH::rand_domain(&mut rng)).collect();
        // Create layer with specific index
        let layer = HashTreeLayer::<TestTH> {
            start_index: 256,
            nodes,
        };
        // Serialize to bytes
        let encoded = layer.as_ssz_bytes();
        // Verify minimum size: 8 bytes for index + 4 bytes for offset
        assert!(encoded.len() >= 12);
        // Verify index value in bytes 0-8
        assert_eq!(u64::from_le_bytes(encoded[0..8].try_into().unwrap()), 256);
        // Verify offset value in bytes 8-12 points to byte 12
        assert_eq!(u32::from_le_bytes(encoded[8..12].try_into().unwrap()), 12);

        // HashSubTree: Create minimal tree with no layers
        let tree = HashSubTree::<TestTH> {
            depth: 16,
            lowest_layer: 8,
            layers: vec![],
        };
        // Serialize to bytes
        let encoded = tree.as_ssz_bytes();
        // Verify minimum size: 8 + 8 + 4 = 20 bytes
        assert!(encoded.len() >= 20);
        // Verify depth value in bytes 0-8
        assert_eq!(u64::from_le_bytes(encoded[0..8].try_into().unwrap()), 16);
        // Verify lowest layer value in bytes 8-16
        assert_eq!(u64::from_le_bytes(encoded[8..16].try_into().unwrap()), 8);
        // Verify offset value in bytes 16-20 points to byte 20
        assert_eq!(u32::from_le_bytes(encoded[16..20].try_into().unwrap()), 20);

        // HashTreeOpening: Generate authentication path
        let co_path: Vec<_> = (0..5).map(|_| TestTH::rand_domain(&mut rng)).collect();
        // Create opening structure
        let opening = HashTreeOpening::<TestTH> { co_path };
        // Serialize to bytes
        let encoded = opening.as_ssz_bytes();
        // Verify minimum size: 4 bytes for offset
        assert!(encoded.len() >= 4);
        // Verify offset value in bytes 0-4 points to byte 4
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), 4);
    }

    #[test]
    fn test_ssz_decoding_errors() {
        // HashTreeLayer: Buffer too small (8 bytes instead of minimum 12)
        let encoded = vec![0u8; 8];
        // Attempt decode, expect error
        let result = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        // HashTreeLayer: Invalid offset value (99 instead of 12)
        let mut encoded = vec![0u8; 12];
        // Write zero for index field
        encoded[0..8].copy_from_slice(&0u64.to_le_bytes());
        // Write incorrect offset
        encoded[8..12].copy_from_slice(&99u32.to_le_bytes());
        // Attempt decode, expect error with expected value 12
        let result = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 12, .. })
        ));

        // HashSubTree: Buffer too small (16 bytes instead of minimum 20)
        let encoded = vec![0u8; 16];
        let result = HashSubTree::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        // HashSubTree: Invalid offset value (100 instead of 20)
        let mut encoded = vec![0u8; 20];
        // Write depth field
        encoded[0..8].copy_from_slice(&10u64.to_le_bytes());
        // Write lowest layer field
        encoded[8..16].copy_from_slice(&5u64.to_le_bytes());
        // Write incorrect offset
        encoded[16..20].copy_from_slice(&100u32.to_le_bytes());
        let result = HashSubTree::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 20, .. })
        ));

        // HashTreeOpening: Buffer too small (2 bytes instead of minimum 4)
        let encoded = vec![0u8; 2];
        let result = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(result, Err(DecodeError::InvalidByteLength { .. })));

        // HashTreeOpening: Invalid offset value (10 instead of 4)
        let mut encoded = vec![0u8; 4];
        // Write incorrect offset
        encoded[0..4].copy_from_slice(&10u32.to_le_bytes());
        let result = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength { expected: 4, .. })
        ));
    }

    #[test]
    fn test_ssz_determinism() {
        let mut rng = rand::rng();

        // HashTreeLayer: Generate random nodes
        let nodes: Vec<_> = (0..7).map(|_| TestTH::rand_domain(&mut rng)).collect();
        // Create structure
        let layer = HashTreeLayer::<TestTH> {
            start_index: 999,
            nodes,
        };
        // Encode twice, verify identical bytes
        let encoded1 = layer.as_ssz_bytes();
        let encoded2 = layer.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);

        // HashSubTree: Create tree with one layer
        let layer = HashTreeLayer::<TestTH> {
            start_index: 4,
            nodes: (0..6).map(|_| TestTH::rand_domain(&mut rng)).collect(),
        };
        let tree = HashSubTree::<TestTH> {
            depth: 20,
            lowest_layer: 10,
            layers: vec![layer],
        };
        // Encode twice, verify identical bytes
        let encoded1 = tree.as_ssz_bytes();
        let encoded2 = tree.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);

        // HashTreeOpening: Generate random authentication path
        let co_path: Vec<_> = (0..15).map(|_| TestTH::rand_domain(&mut rng)).collect();
        let opening = HashTreeOpening::<TestTH> { co_path };
        // Encode twice, verify identical bytes
        let encoded1 = opening.as_ssz_bytes();
        let encoded2 = opening.as_ssz_bytes();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_ssz_merkle_integration() {
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        // Build tree: 8 leaves at depth 3
        let num_leafs = 8;
        let depth = 3;
        let start_index = 0;
        let leaf_len = 2;
        // Generate leaf data
        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let leaf: Vec<_> = (0..leaf_len)
                .map(|_| TestTH::rand_domain(&mut rng))
                .collect();
            leafs.push(leaf);
        }
        // Hash leaves for tree construction
        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| TestTH::apply(&parameter, &TestTH::tree_tweak(0, i as u32), v.as_slice()))
            .collect();
        // Build complete merkle tree
        let tree = HashSubTree::<TestTH>::new_subtree(
            &mut rng,
            0,
            depth,
            start_index,
            &parameter,
            leafs_hashes,
        );
        let root = tree.root();

        // Test tree serialization roundtrip
        let tree_encoded = tree.as_ssz_bytes();
        let tree_decoded = HashSubTree::<TestTH>::from_ssz_bytes(&tree_encoded).unwrap();
        // Verify decoded tree has same root
        assert_eq!(root, tree_decoded.root());

        // Test authentication path at position 3
        let position = 3u32;
        let path = tree.path(position);
        let leaf = &leafs[position as usize];

        // Test path serialization roundtrip
        let path_encoded = path.as_ssz_bytes();
        let path_decoded = HashTreeOpening::<TestTH>::from_ssz_bytes(&path_encoded).unwrap();

        // Verify decoded path authenticates correctly
        assert!(hash_tree_verify(
            &parameter,
            &root,
            position,
            leaf,
            &path_decoded
        ));

        // Verify path from decoded tree also works
        let path_from_decoded = tree_decoded.path(position);
        assert!(hash_tree_verify(
            &parameter,
            &root,
            position,
            leaf,
            &path_from_decoded
        ));
    }

    proptest! {
        #[test]
        fn proptest_hash_tree_layer_ssz_roundtrip(
            start_index in 0u64..1000,
            num_nodes in 0usize..20,
        ) {
            // Generate random nodes
            let mut rng = rand::rng();
            let nodes: Vec<_> = (0..num_nodes).map(|_| TestTH::rand_domain(&mut rng)).collect();
            // Create layer structure
            let layer = HashTreeLayer::<TestTH> {
                start_index,
                nodes,
            };

            // Perform serialization roundtrip
            let encoded = layer.as_ssz_bytes();
            let decoded = HashTreeLayer::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            // Verify index field preserved
            prop_assert_eq!(layer.start_index, decoded.start_index);
            // Verify node count preserved
            prop_assert_eq!(layer.nodes.len(), decoded.nodes.len());
            // Verify each node value preserved
            for i in 0..layer.nodes.len() {
                prop_assert_eq!(layer.nodes[i], decoded.nodes[i]);
            }
            // Verify determinism by re-encoding
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }

        #[test]
        fn proptest_hash_sub_tree_ssz_roundtrip(
            depth in 1u64..32,
            lowest_layer in 0u64..16,
            num_layers in 0usize..5,
        ) {
            // Ensure valid tree configuration
            prop_assume!(lowest_layer < depth);

            // Generate random layers
            let mut rng = rand::rng();
            let mut layers = Vec::new();
            for _ in 0..num_layers {
                let num_nodes = rng.random_range(0..10);
                let layer = HashTreeLayer::<TestTH> {
                    start_index: rng.random_range(0..100),
                    nodes: (0..num_nodes).map(|_| TestTH::rand_domain(&mut rng)).collect(),
                };
                layers.push(layer);
            }
            // Create tree structure
            let tree = HashSubTree::<TestTH> {
                depth,
                lowest_layer,
                layers,
            };

            // Perform serialization roundtrip
            let encoded = tree.as_ssz_bytes();
            let decoded = HashSubTree::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            // Verify tree metadata preserved
            prop_assert_eq!(tree.depth, decoded.depth);
            prop_assert_eq!(tree.lowest_layer, decoded.lowest_layer);
            // Verify layer count preserved
            prop_assert_eq!(tree.layers.len(), decoded.layers.len());
            // Verify each layer structure preserved
            for i in 0..tree.layers.len() {
                prop_assert_eq!(tree.layers[i].start_index, decoded.layers[i].start_index);
                prop_assert_eq!(tree.layers[i].nodes.len(), decoded.layers[i].nodes.len());
            }
            // Verify determinism by re-encoding
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }

        #[test]
        fn proptest_hash_tree_opening_ssz_roundtrip(
            co_path_len in 0usize..64,
        ) {
            // Generate random authentication path
            let mut rng = rand::rng();
            let co_path: Vec<_> = (0..co_path_len).map(|_| TestTH::rand_domain(&mut rng)).collect();
            // Create opening structure
            let opening = HashTreeOpening::<TestTH> { co_path };

            // Perform serialization roundtrip
            let encoded = opening.as_ssz_bytes();
            let decoded = HashTreeOpening::<TestTH>::from_ssz_bytes(&encoded).unwrap();

            // Verify path length preserved
            prop_assert_eq!(opening.co_path.len(), decoded.co_path.len());
            // Verify each path element preserved
            for i in 0..opening.co_path.len() {
                prop_assert_eq!(opening.co_path[i], decoded.co_path[i]);
            }
            // Verify determinism by re-encoding
            let reencoded = decoded.as_ssz_bytes();
            prop_assert_eq!(encoded, reencoded);
        }
    }
}
