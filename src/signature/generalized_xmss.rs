use std::marker::PhantomData;

use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    MESSAGE_LENGTH,
    inc_encoding::IncomparableEncoding,
    serialization::Serializable,
    signature::SignatureSchemeSecretKey,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{TweakableHash, chain},
        tweak_hash_tree::{HashSubTree, HashTreeOpening, combined_path, hash_tree_verify},
    },
};

use super::{SignatureScheme, SigningError};

use ssz::{Decode, DecodeError, Encode};

/// Implementation of the generalized XMSS signature scheme
/// from any incomparable encoding scheme and any tweakable hash
///
/// It also uses a PRF for key generation, and one has to specify
/// the (base 2 log of the) key lifetime.
///
/// Note: lifetimes beyond 2^32 are not supported.
pub struct GeneralizedXMSSSignatureScheme<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    _prf: std::marker::PhantomData<PRF>,
    _ie: std::marker::PhantomData<IE>,
    _th: std::marker::PhantomData<TH>,
}

/// Signature for GeneralizedXMSSSignatureScheme
/// It contains a Merkle authentication path, encoding randomness, and a list of hashes
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Encode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // SSZ Container: offset (4) + rho (fixed) + offset (4) + variable data
        let offset_size = 4;
        let rho_size = self.rho.ssz_bytes_len();
        let path_size = self.path.ssz_bytes_len();
        let hashes_size = self.hashes.ssz_bytes_len();

        offset_size + rho_size + offset_size + path_size + hashes_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Appends the SSZ encoding to the buffer.
        //
        // SSZ Container encoding with fields interleaved in declaration order:
        // - Field 1 (path): variable → write offset
        // - Field 2 (rho): fixed → write data
        // - Field 3 (hashes): variable → write offset
        //
        // Then write variable data in order: path, hashes

        // Calculate offsets (start of variable data)
        let rho_size = self.rho.ssz_bytes_len();
        // offset + rho + offset
        let fixed_size = 4 + rho_size + 4;

        let offset_path = fixed_size;
        let offset_hashes = offset_path + self.path.ssz_bytes_len();

        // 1. Encode offset for first variable field: path
        buf.extend_from_slice(&(offset_path as u32).to_le_bytes());

        // 2. Encode fixed field: rho
        self.rho.ssz_append(buf);

        // 3. Encode offset for second variable field: hashes
        buf.extend_from_slice(&(offset_hashes as u32).to_le_bytes());

        // 4. Encode variable data in order
        self.path.ssz_append(buf);
        self.hashes.ssz_append(buf);
    }
}

impl<IE: IncomparableEncoding, TH: TweakableHash> Decode for GeneralizedXMSSSignature<IE, TH> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Decodes a generalized XMSS signature from SSZ bytes.
        //
        // Fields are interleaved: offset_path → rho → offset_hashes → variable data

        // Get fixed size of rho field
        let rho_size = if <IE::Randomness as Encode>::is_ssz_fixed_len() {
            <IE::Randomness as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "IE::Randomness must be fixed length".into(),
            ));
        };

        // Minimum size: offset (4) + rho (fixed) + offset (4)
        let min_size = 4 + rho_size + 4;
        if bytes.len() < min_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_size,
            });
        }

        // 1. Read offset for first variable field: path
        let offset_path = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 4,
            }
        })?) as usize;

        // 2. Decode fixed field: rho
        let rho = IE::Randomness::from_ssz_bytes(&bytes[4..4 + rho_size])?;

        // 3. Read offset for second variable field: hashes
        let offset_hashes =
            u32::from_le_bytes(bytes[4 + rho_size..8 + rho_size].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: 8 + rho_size,
                }
            })?) as usize;

        // Validate offset_path points to end of fixed part
        let expected_offset_path = 4 + rho_size + 4;
        if offset_path != expected_offset_path {
            return Err(DecodeError::InvalidByteLength {
                len: offset_path,
                expected: expected_offset_path,
            });
        }

        // Panic safety: Ensure offsets are monotonic and within bounds
        // This prevents panic when creating slices below
        if offset_path > offset_hashes || offset_hashes > bytes.len() {
            return Err(DecodeError::BytesInvalid(format!(
                "Invalid variable offsets: path={} hashes={} len={}",
                offset_path,
                offset_hashes,
                bytes.len()
            )));
        }

        // 4. Decode variable fields (now safe after bounds check)
        let path = HashTreeOpening::<TH>::from_ssz_bytes(&bytes[offset_path..offset_hashes])?;
        let hashes = Vec::<TH::Domain>::from_ssz_bytes(&bytes[offset_hashes..])?;

        Ok(Self { path, rho, hashes })
    }
}

/// Public key for GeneralizedXMSSSignatureScheme
/// It contains a Merkle root and a parameter for the tweakable hash
#[derive(Serialize, Deserialize)]
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

/// Secret key for GeneralizedXMSSSignatureScheme
/// It contains a PRF key and a Merkle tree.
///
/// Note: one may choose to regenerate the tree on the fly, but this
/// would be costly for signatures.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSecretKey<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    prf_key: PRF::Key,
    parameter: TH::Parameter,
    activation_epoch: u64,
    num_active_epochs: u64,
    top_tree: HashSubTree<TH>,
    left_bottom_tree_index: u64,
    left_bottom_tree: HashSubTree<TH>,
    right_bottom_tree: HashSubTree<TH>,
    _encoding_type: PhantomData<IE>,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Encode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        // It has variable length due to HashSubTree field
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // Computes the SSZ encoded length.
        // Format: Fields interleaved in declaration order with offsets for variable fields

        // Fixed-length fields (using u64 for platform independence)
        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();
        let activation_epoch_size = 8; // u64
        let num_active_epochs_size = 8; // u64

        // Variable fields need 4-byte offsets each
        let offset_size = 4;
        let top_tree_size = self.top_tree.ssz_bytes_len();

        let left_bottom_tree_index_size = 8; // u64
        let left_bottom_tree_size = self.left_bottom_tree.ssz_bytes_len();
        let right_bottom_tree_size = self.right_bottom_tree.ssz_bytes_len();

        prf_key_size
            + parameter_size
            + activation_epoch_size
            + num_active_epochs_size
            + offset_size // top_tree offset
            + left_bottom_tree_index_size
            + offset_size // left_bottom_tree offset
            + offset_size // right_bottom_tree offset
            + top_tree_size
            + left_bottom_tree_size
            + right_bottom_tree_size
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Appends the SSZ encoding to the buffer.
        //
        // SSZ Container encoding with fields interleaved in declaration order:
        // - Field 1 (prf_key): fixed → write data
        // - Field 2 (parameter): fixed → write data
        // - Field 3 (activation_epoch): fixed → write data
        // - Field 4 (num_active_epochs): fixed → write data
        // - Field 5 (top_tree): variable → write offset
        // - Field 6 (left_bottom_tree_index): fixed → write data
        // - Field 7 (left_bottom_tree): variable → write offset
        // - Field 8 (right_bottom_tree): variable → write offset
        //
        // Then write variable data in order: top_tree, left_bottom_tree, right_bottom_tree

        // Calculate sizes of fixed fields
        let prf_key_size = self.prf_key.ssz_bytes_len();
        let parameter_size = self.parameter.ssz_bytes_len();

        // Calculate start of variable data
        let fixed_size = prf_key_size + parameter_size + 8 + 8 + 4 + 8 + 4 + 4;

        let offset_top_tree = fixed_size;
        let offset_left_bottom = offset_top_tree + self.top_tree.ssz_bytes_len();
        let offset_right_bottom = offset_left_bottom + self.left_bottom_tree.ssz_bytes_len();

        // 1. Encode fixed field: prf_key
        self.prf_key.ssz_append(buf);

        // 2. Encode fixed field: parameter
        self.parameter.ssz_append(buf);

        // 3. Encode fixed field: activation_epoch (u64)
        buf.extend_from_slice(&self.activation_epoch.to_le_bytes());

        // 4. Encode fixed field: num_active_epochs (u64)
        buf.extend_from_slice(&self.num_active_epochs.to_le_bytes());

        // 5. Encode offset for first variable field: top_tree
        buf.extend_from_slice(&(offset_top_tree as u32).to_le_bytes());

        // 6. Encode fixed field: left_bottom_tree_index (u64)
        buf.extend_from_slice(&self.left_bottom_tree_index.to_le_bytes());

        // 7. Encode offset for second variable field: left_bottom_tree
        buf.extend_from_slice(&(offset_left_bottom as u32).to_le_bytes());

        // 8. Encode offset for third variable field: right_bottom_tree
        buf.extend_from_slice(&(offset_right_bottom as u32).to_le_bytes());

        // 9. Encode variable data in order
        self.top_tree.ssz_append(buf);
        self.left_bottom_tree.ssz_append(buf);
        self.right_bottom_tree.ssz_append(buf);
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Decode for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    #[allow(clippy::too_many_lines)]
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Decodes a generalized XMSS secret key from SSZ bytes.
        //
        // Fields are interleaved:
        // - prf_key
        // - parameter
        // - activation_epoch
        // - num_active_epochs
        // - offset_top_tree
        // - left_bottom_tree_index
        // - offset_left_bottom
        // - offset_right_bottom
        // - variable data

        // Get fixed sizes for prf_key and parameter
        let prf_key_size = if <PRF::Key as Encode>::is_ssz_fixed_len() {
            <PRF::Key as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "PRF::Key must be fixed length".into(),
            ));
        };

        let parameter_size = if <TH::Parameter as Encode>::is_ssz_fixed_len() {
            <TH::Parameter as Encode>::ssz_fixed_len()
        } else {
            return Err(DecodeError::BytesInvalid(
                "TH::Parameter must be fixed length".into(),
            ));
        };

        // Minimum size: prf_key + parameter + 3×u64 (24) + 3×offset (12)
        let min_fixed_size = prf_key_size + parameter_size + 24 + 12;
        if bytes.len() < min_fixed_size {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: min_fixed_size,
            });
        }

        // Track current position
        let mut pos = 0;

        // 1. Decode fixed field: prf_key
        let prf_key = PRF::Key::from_ssz_bytes(&bytes[pos..pos + prf_key_size])?;
        pos += prf_key_size;

        // 2. Decode fixed field: parameter
        let parameter = TH::Parameter::from_ssz_bytes(&bytes[pos..pos + parameter_size])?;
        pos += parameter_size;

        // 3. Decode fixed field: activation_epoch (u64)
        let activation_epoch =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        // 4. Decode fixed field: num_active_epochs (u64)
        let num_active_epochs =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        // 5. Read offset for first variable field: top_tree
        let offset_top_tree = u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: pos + 4,
            }
        })?) as usize;
        pos += 4;

        // 6. Decode fixed field: left_bottom_tree_index (u64)
        let left_bottom_tree_index =
            u64::from_le_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 8,
                }
            })?);
        pos += 8;

        // 7. Read offset for second variable field: left_bottom_tree
        let offset_left_bottom =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 4,
                }
            })?) as usize;
        pos += 4;

        // 8. Read offset for third variable field: right_bottom_tree
        let offset_right_bottom =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().map_err(|_| {
                DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: pos + 4,
                }
            })?) as usize;
        pos += 4;

        // Validate that fixed part ends at first offset
        if pos != offset_top_tree {
            return Err(DecodeError::InvalidByteLength {
                len: pos,
                expected: offset_top_tree,
            });
        }

        // Panic safety: Ensure offsets are monotonic and within bounds
        //
        // This prevents panic when creating slices below
        // Verify: offset_top <= offset_left <= offset_right <= bytes.len()
        if offset_top_tree > offset_left_bottom
            || offset_left_bottom > offset_right_bottom
            || offset_right_bottom > bytes.len()
        {
            return Err(DecodeError::BytesInvalid(format!(
                "Invalid variable offsets: top={} left={} right={} len={}",
                offset_top_tree,
                offset_left_bottom,
                offset_right_bottom,
                bytes.len()
            )));
        }

        // 9. Decode variable fields (now safe after bounds check)
        let top_tree =
            HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_top_tree..offset_left_bottom])?;
        let left_bottom_tree =
            HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_left_bottom..offset_right_bottom])?;
        let right_bottom_tree = HashSubTree::<TH>::from_ssz_bytes(&bytes[offset_right_bottom..])?;

        Ok(Self {
            prf_key,
            parameter,
            activation_epoch,
            num_active_epochs,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
            _encoding_type: PhantomData,
        })
    }
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureSchemeSecretKey for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    fn get_activation_interval(&self) -> std::ops::Range<u64> {
        let start = self.activation_epoch;
        let end = start + self.num_active_epochs;
        start..end
    }

    fn get_prepared_interval(&self) -> std::ops::Range<u64> {
        // the key is prepared for all epochs covered by the left and right bottom tree
        // and each bottom tree covers exactly 2^{LOG_LIFETIME / 2} leafs
        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let start = self.left_bottom_tree_index * leafs_per_bottom_tree;
        let end = start + (2 * leafs_per_bottom_tree);
        start..end
    }

    fn advance_preparation(&mut self) {
        // First, check if advancing is possible by comparing to activation interval.
        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let next_prepared_end_epoch =
            self.left_bottom_tree_index * leafs_per_bottom_tree + 3 * leafs_per_bottom_tree;
        if next_prepared_end_epoch > self.get_activation_interval().end {
            return;
        }

        // We compute the new right bottom subtree (using the helper function bottom_tree_from_prf_key)
        let new_right_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &self.prf_key,
            self.left_bottom_tree_index + 2,
            &self.parameter,
        );

        // The bottom tree that was previously right should now be left.
        // So, we move the right bottom subtree to the left one and update our index.
        // We also write the new right bottom tree into the right bottom tree field.
        // Note that once the function terminates, the old left bottom tree is dropped
        // from memory. So, at any point in time, we have at most 4 trees in memory,
        // namely, the three bottom trees (two current, one new) and the top tree.
        self.left_bottom_tree =
            std::mem::replace(&mut self.right_bottom_tree, new_right_bottom_tree);
        self.left_bottom_tree_index += 1;
    }
}

/// Helper function to take a desired activation time (given by start and duration)
/// and potentially increase it, so that, for C = 1 << (LOG_LIFETIME/2).
///     1. the new duration is a multiple of C
///     2. the new duration is at least 2 * C
///     3. the new activation time starts at a multiple of C
///     4. the new activation interval is contained in [0...C^2) = [0,..LIFETIME).
///     5. the new interval contains the desired interval.
///
/// The returned result is a pair (start, excl_end) of integers, such that the new
/// activation interval is given by [start * C , excl_end * C).
fn expand_activation_time<const LOG_LIFETIME: usize>(
    desired_activation_epoch: usize,
    desired_num_active_epochs: usize,
) -> (usize, usize) {
    let lifetime = 1usize << LOG_LIFETIME;
    let c = 1usize << (LOG_LIFETIME / 2);
    // c_mask has the form 1...10...0, with LOG_LIFETIME / 2 many 0's.
    let c_mask = !(c - 1);

    let desired_start = desired_activation_epoch;
    let desired_end = desired_activation_epoch + desired_num_active_epochs;

    // 1. Start by aligning the *start* downward to a multiple of C.
    // we can do that by bitwise and with c_mask.
    let mut start = desired_start & c_mask;

    // 2. Round the *end* upward to a multiple of C.
    // This guarantees the original interval is fully contained.
    let mut end = (desired_end + c - 1) & c_mask;

    // 3. Enforce minimum duration of 2*C.
    if end - start < 2 * c {
        end = start + 2 * c;
    }

    // 4. If the new interval exceeds lifetime, shift it left to fit inside [0, lifetime)
    if end > lifetime {
        let duration = end - start;
        if duration > lifetime {
            // Pathological: expanded interval exceeds lifetime
            start = 0;
            end = lifetime;
        } else {
            end = lifetime;
            start = (lifetime - duration) & c_mask;
        }
    }

    // now divide by c to get what we want
    start >>= LOG_LIFETIME / 2;
    end >>= LOG_LIFETIME / 2;

    (start, end)
}

/// Helper function to compute a bottom tree from the PRF key. The PRF key is used to re-generate
/// the secret keys, then the public keys are generated and hashed to obtain the leafs of the
/// bottom tree. Then the bottom tree is computed.
fn bottom_tree_from_prf_key<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
>(
    prf_key: &PRF::Key,
    bottom_tree_index: u64,
    parameter: &TH::Parameter,
) -> HashSubTree<TH>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
    let num_chains = IE::DIMENSION;
    let chain_length = IE::BASE;

    // the range of epochs covered by that bottom tree
    let epoch_start = bottom_tree_index * leafs_per_bottom_tree;
    let epochs: Vec<u32> = (epoch_start..epoch_start + leafs_per_bottom_tree)
        .map(|e| e as u32)
        .collect();

    // Compute chain ends for all epochs.
    let chain_ends_hashes =
        TH::compute_tree_leaves::<PRF>(prf_key, parameter, &epochs, num_chains, chain_length);

    // now that we have the hashes of all chain ends (= leafs of our tree), we can compute the bottom tree
    HashSubTree::new_bottom_tree(
        LOG_LIFETIME,
        bottom_tree_index as usize,
        parameter,
        chain_ends_hashes,
    )
}

impl<
    PRF: Pseudorandom,
    IE: IncomparableEncoding + Sync + Send,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // checks for `activation_epoch` and `num_active_epochs`
        assert!(
            activation_epoch + num_active_epochs <= Self::LIFETIME as usize,
            "Key gen: `activation_epoch` and `num_active_epochs` are invalid for this lifetime"
        );

        // Note: this implementation uses the top-bottom tree approach, which is as follows:
        //
        // We envision that the full Merkle tree into one top tree and `sqrt(LIFETIME)` bottom trees.
        // The top tree contains the root and the `LOG_LIFETIME/2` layers below it. This top tree has
        // `sqrt(LIFETIME)` many leafs (but can be sparse and have less). For each leaf that exists,
        // this leaf is the roof of a bottom tree. Thus, there are at most `sqrt(LIFETIME)` bottom trees,
        // each having `sqrt(LIFETIME)` leafs. We now restrict increase the activation time to be a
        // multiple of `sqrt(LIFETIME)` that aligns with these bottom trees, and is at least of length
        // `2*sqrt(LIFETIME)` so that we have at least two bottom trees.
        //
        // Our invariant is that the secret key always stores the full top tree and two consecutive
        // bottom trees. The secret key can then sign epochs contained in the leafs of these two
        // consecutive bottom trees, and we provide an update function that re-computes the next bottom
        // tree and drops the older of the two current ones (function advance_preparation).
        //
        // During key generation, we first generate all bottom trees and store their roots, then we
        // generate the top tree just from their roots.

        // before we do anything, we expand our activation range so that the
        // top-bottom tree approach can be applied cleanly.
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let (start_bottom_tree_index, end_bottom_tree_index) =
            expand_activation_time::<LOG_LIFETIME>(activation_epoch, num_active_epochs);
        let num_bottom_trees = end_bottom_tree_index - start_bottom_tree_index;
        assert!(num_bottom_trees >= 2);
        let activation_epoch = start_bottom_tree_index * leafs_per_bottom_tree;
        let num_active_epochs = num_bottom_trees * leafs_per_bottom_tree;

        // we need a random parameter to be used for the tweakable hash
        let parameter = TH::rand_parameter(rng);

        // we need a PRF key to generate our list of actual secret keys
        let prf_key = PRF::key_gen(rng);

        // first, we build all bottom trees and keep track of their root. We treat the first two
        // bottom trees differently, as we want to keep them in our key. While building the bottom
        // trees, we generate all hash chains using our PRF key, and hash their ends to get the
        // leafs of our bottom trees. This is done in `bottom_tree_from_prf_key`.
        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);

        let left_bottom_tree_index = start_bottom_tree_index as u64;
        let left_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &prf_key,
            left_bottom_tree_index,
            &parameter,
        );
        roots_of_bottom_trees.push(left_bottom_tree.root());

        let right_bottom_tree_index = (start_bottom_tree_index + 1) as u64;
        let right_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &prf_key,
            right_bottom_tree_index,
            &parameter,
        );
        roots_of_bottom_trees.push(right_bottom_tree.root());

        // the rest of the bottom trees in parallel
        roots_of_bottom_trees.extend(
            (start_bottom_tree_index + 2..end_bottom_tree_index)
                .into_par_iter()
                .map(|bottom_tree_index| {
                    let bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
                        &prf_key,
                        bottom_tree_index as u64,
                        &parameter,
                    );
                    bottom_tree.root()
                })
                .collect::<Vec<_>>(), // note: roots are in the correct order.
        );

        // second, we build the top tree, which has the roots of our bottom trees
        // as leafs. the root of it will be our public key.
        let top_tree = HashSubTree::new_top_tree(
            rng,
            LOG_LIFETIME,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );
        let root = top_tree.root();

        // assemble public key and secret key
        let pk = GeneralizedXMSSPublicKey { root, parameter };
        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            parameter,
            activation_epoch: activation_epoch as u64,
            num_active_epochs: num_active_epochs as u64,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
            _encoding_type: PhantomData,
        };

        (pk, sk)
    }

    fn sign(
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        // check that epoch is indeed a valid epoch in the activation range

        assert!(
            sk.get_activation_interval().contains(&(epoch as u64)),
            "Signing: key not active during this epoch."
        );

        // check that we are already prepared for this epoch
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Signing: key not yet prepared for this epoch, try calling sk.advance_preparation."
        );

        // first component of the signature is the Merkle path that
        // opens the one-time pk for that epoch, where the one-time pk
        // will be recomputed by the verifier from the signature.
        let leafs_per_bottom_tree = 1u64 << (LOG_LIFETIME / 2);
        let boundary_between_bottom_trees =
            (sk.left_bottom_tree_index * leafs_per_bottom_tree + leafs_per_bottom_tree) as u32;
        let bottom_tree = if epoch < boundary_between_bottom_trees {
            &sk.left_bottom_tree
        } else {
            &sk.right_bottom_tree
        };
        let path = combined_path(&sk.top_tree, bottom_tree, epoch);

        // now, we need to encode our message using the incomparable encoding.
        // we retry until we get a valid codeword, or until we give up.
        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            // get a randomness and try to encode the message. Note: we get the randomness from the PRF
            // which ensures that signing is deterministic. The PRF is applied to the message and the epoch.
            // While the intention is that users of the scheme never call sign twice with the same (epoch, sk) pair,
            // this deterministic approach ensures that calling sign twice is fine, as long as the message stays the same.
            let curr_rho = PRF::get_randomness(&sk.prf_key, epoch, message, attempts as u64).into();
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            // check if we have found a valid codeword, and if so, stop searching
            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok();
                break;
            }

            attempts += 1;
        }

        // if we have not found a valid codeword, return an error
        if x.is_none() {
            return Err(SigningError::EncodingAttemptsExceeded {
                attempts: max_tries,
            });
        }

        // otherwise, unwrap x and rho
        let x = x.unwrap();
        let rho = rho.unwrap();

        // we will include rho in the signature, and
        // we use x to determine how far the signer walks in the chains
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );

        // In parallel, compute the hash values for each chain based on the codeword `x`.
        let hashes = (0..num_chains)
            .into_par_iter()
            .map(|chain_index| {
                // get back to the start of the chain from the PRF
                let start = PRF::get_domain_element(&sk.prf_key, epoch, chain_index as u64).into();
                // now walk the chain for a number of steps determined by the current chunk of x
                let steps = x[chain_index] as usize;
                chain::<TH>(&sk.parameter, epoch, chain_index as u8, 0, steps, &start)
            })
            .collect();

        // assemble the signature: Merkle path, randomness, chain elements
        Ok(GeneralizedXMSSSignature { path, rho, hashes })
    }

    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool {
        assert!(
            (epoch as u64) < Self::LIFETIME,
            "Generalized XMSS - Verify: Epoch too large."
        );

        // first get back the codeword and make sure
        // encoding succeeded with the given randomness.
        let Ok(x) = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch) else {
            return false;
        };

        // now, we recompute the epoch's one-time public key
        // from the hashes by walking hash chains.
        let chain_length = IE::BASE;
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for (chain_index, xi) in x.iter().enumerate() {
            // If the signer has already walked x[i] steps, then we need
            // to walk chain_length - 1 - x[i] steps to reach the end of the chain
            // Note: by our consistency checks, we have chain_length <= 2^8, so chain_length - 1 fits into u8
            let steps = (chain_length - 1) as u8 - xi;
            let start_pos_in_chain = *xi;
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u8,
                start_pos_in_chain,
                steps as usize,
                start,
            );
            chain_ends.push(end);
        }

        // this set of chain ends should be a leaf in the Merkle tree
        // we verify that by checking the Merkle authentication path
        hash_tree_verify(
            &pk.parameter,
            &pk.root,
            epoch,
            chain_ends.as_slice(),
            &sig.path,
        )
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // we check consistency of all internally used components
        // namely, PRF, incomparable encoding, and tweak hash
        PRF::internal_consistency_check();
        IE::internal_consistency_check();
        TH::internal_consistency_check();

        // assert BASE and DIMENSION are small enough to make sure that we can fit
        // pos_in_chain and chain_index in u8.

        assert!(
            IE::BASE <= 1 << 8,
            "Generalized XMSS: Encoding base too large, must be at most 2^8"
        );
        assert!(
            IE::DIMENSION <= 1 << 8,
            "Generalized XMSS: Encoding dimension too large, must be at most 2^8"
        );

        // LOG_LIFETIME needs to be even, so that we can use the top-bottom tree approach
        assert!(
            LOG_LIFETIME.is_multiple_of(2),
            "Generalized XMSS: LOG_LIFETIME must be multiple of two"
        );
    }
}

impl<TH: TweakableHash> Encode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Encode>::is_ssz_fixed_len() && <TH::Parameter as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Encode>::ssz_fixed_len() + <TH::Parameter as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.root.ssz_bytes_len() + self.parameter.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.root.ssz_append(buf);
        self.parameter.ssz_append(buf);
    }
}

impl<TH: TweakableHash> Decode for GeneralizedXMSSPublicKey<TH> {
    fn is_ssz_fixed_len() -> bool {
        <TH::Domain as Decode>::is_ssz_fixed_len() && <TH::Parameter as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <TH::Domain as Decode>::ssz_fixed_len() + <TH::Parameter as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected_len = <Self as Decode>::ssz_fixed_len();
        if bytes.len() != expected_len {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: expected_len,
            });
        }

        let root_len = <TH::Domain as Decode>::ssz_fixed_len();
        let (root_bytes, param_bytes) = bytes.split_at(root_len);

        let root = TH::Domain::from_ssz_bytes(root_bytes)?;
        let parameter = TH::Parameter::from_ssz_bytes(param_bytes)?;

        Ok(Self { root, parameter })
    }
}

impl<TH: TweakableHash> Serializable for GeneralizedXMSSPublicKey<TH> {}

impl<IE: IncomparableEncoding, TH: TweakableHash> Serializable
    for GeneralizedXMSSSignature<IE, TH>
{
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    Serializable for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
{
}

/// Instantiations of the generalized XMSS signature scheme based on Poseidon2
pub mod instantiations_poseidon;
/// Instantiations of the generalized XMSS signature scheme based on the
/// top level target sum encoding using Poseidon2
pub mod instantiations_poseidon_top_level;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::test_templates::test_signature_scheme_correctness,
        symmetric::{
            message_hash::{
                MessageHash,
                poseidon::{PoseidonMessageHash, PoseidonMessageHashW1},
            },
            prf::shake_to_field::ShakePRFtoF,
            tweak_hash::poseidon::PoseidonTweakW1L5,
        },
    };

    use super::*;

    use crate::array::FieldArray;
    use p3_field::PrimeField32;
    use proptest::prelude::*;

    use crate::{F, symmetric::tweak_hash::poseidon::PoseidonTweakHash};
    use p3_field::RawDataSerializable;
    use rand::rng;
    use ssz::{Decode, Encode};

    type TestTH = PoseidonTweakHash<5, 7, 2, 9, 155>;

    #[test]
    pub fn test_target_sum_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_deterministic() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        // we sign the same (epoch, message) pair twice (which users of this code should not do)
        // and ensure that it produces the same randomness for the signature.
        let mut rng = rand::rng();
        let (_pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 29;

        // prepare key for epoch
        let mut iterations = 0;
        while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
            sk.advance_preparation();
            iterations += 1;
        }
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Did not even try signing, failed to advance key preparation to desired epoch {:?}.",
            epoch
        );

        let sig1 = Sig::sign(&sk, epoch, &message).unwrap();
        let sig2 = Sig::sign(&sk, epoch, &message).unwrap();
        let rho1 = sig1.rho;
        let rho2 = sig2.rho;
        assert_eq!(rho1, rho2);
    }

    #[test]
    pub fn test_large_base_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<4, 8>;
        type TH = PoseidonTweakHash<4, 4, 2, 8, 32>;
        type MH = PoseidonMessageHash<4, 8, 8, 32, 256, 2, 9>;
        const TARGET_SUM: usize = 1 << 12;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_dimension_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<8, 8>;
        type TH = PoseidonTweakHash<4, 8, 2, 8, 256>;
        type MH = PoseidonMessageHash<4, 8, 8, 256, 2, 2, 9>;
        const TARGET_SUM: usize = 128;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_expand_activation_time() {
        const LOG_LIFETIME: usize = 4;

        // no padding needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 8);
        assert!((start == 0) && (end_excl == 2));

        // no padding needed in principle, but is extended to minimum duration of two bottom trees
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 4);
        assert!((start == 0) && (end_excl == 2));

        // simple padding needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 7);
        assert!((start == 0) && (end_excl == 2));

        // simple padding needed, and extended to minimum duration of two bottom trees
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 3);
        assert!((start == 0) && (end_excl == 2));

        // padding on both sides needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(1, 8);
        assert!((start == 0) && (end_excl == 3));

        // padding only in the end needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(8, 5);
        assert!((start == 2) && (end_excl == 4));

        // large padding to the left needed because of two bottom trees constraint
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(12, 2);
        assert!((start == 2) && (end_excl == 4));
    }

    #[test]
    fn test_ssz_encoding_structure() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // Test PublicKey encoding structure
        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        // Serialize to bytes
        let encoded = public_key.as_ssz_bytes();
        // Verify expected size based on field element counts
        assert_eq!(encoded.len(), (7 + 5) * F::NUM_BYTES);
        // Verify first field element is encoded correctly
        let first_fe_bytes = root.as_ssz_bytes();
        assert_eq!(&encoded[0..F::NUM_BYTES], &first_fe_bytes[0..F::NUM_BYTES]);
        // Decode and verify roundtrip
        let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(public_key.root, decoded.root);
        assert_eq!(public_key.parameter, decoded.parameter);

        // Test Signature encoding structure
        let (pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        // Generate valid signature
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Serialize to bytes
        let sig_encoded = signature.as_ssz_bytes();
        // Calculate randomness size
        let rho_size = signature.rho.ssz_bytes_len();
        // Verify minimum size includes two offsets plus fixed field
        assert!(sig_encoded.len() >= 4 + rho_size + 4);
        // Read first offset value from bytes 0-4
        let offset_path = u32::from_le_bytes(sig_encoded[0..4].try_into().unwrap()) as usize;
        // Verify first offset points to end of fixed part
        assert_eq!(offset_path, 4 + rho_size + 4);
        // Decode and verify signature still validates
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));

        // Test SecretKey encoding structure
        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        // Serialize secret key to bytes
        let sk_encoded = sk2.as_ssz_bytes();
        // Calculate fixed field sizes
        let prf_key_size = sk2.prf_key.ssz_bytes_len();
        let param_size = sk2.parameter.ssz_bytes_len();
        let fixed_part_size = prf_key_size + param_size + 8 + 8 + 4 + 8 + 4 + 4;
        // Verify minimum size includes all fixed fields
        assert!(sk_encoded.len() >= fixed_part_size);
        // Read activation epoch value from fixed position
        let activation_start = prf_key_size + param_size;
        let activation_epoch = u64::from_le_bytes(
            sk_encoded[activation_start..activation_start + 8]
                .try_into()
                .unwrap(),
        );
        // Verify stored value matches original
        assert_eq!(activation_epoch, sk2.activation_epoch);
        // Decode and verify roundtrip by re-encoding
        let sk_decoded = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        let sk_reencoded = sk_decoded.as_ssz_bytes();
        assert_eq!(sk_encoded, sk_reencoded);
    }

    #[test]
    fn test_ssz_decoding_errors() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        // PublicKey: buffer too small
        // TestTH = PoseidonTweakW1L5 has FieldArray<7> hash and FieldArray<5> domain
        // Total size: (7 + 5) * F::NUM_BYTES = 12 * 4 = 48 bytes
        // Create buffer with only 47 bytes (one byte short)
        let encoded = vec![0u8; 47];
        // Attempt decode with insufficient bytes
        let result = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded);
        // Decoder reports actual buffer size (47) vs expected (48)
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 47,
                expected: 48
            })
        ));

        // Signature: buffer too small - only 8 bytes when we need more
        // IE::Randomness = MH::Randomness = FieldArray<5> (from PoseidonMessageHashW1)
        // FieldArray<5> has ssz_fixed_len() = 5 * F::NUM_BYTES = 5 * 4 = 20 bytes
        // Minimum size: offset (4) + rho (20) + offset (4) = 28 bytes
        let encoded = vec![0u8; 8];
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        // Decoder checks min_size at line 119: reports actual (8) vs expected (28)
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 8,
                expected: 28
            })
        ));

        // Signature: invalid offset value pointing to wrong location
        // Create buffer with sufficient space (28 + 100 bytes)
        let mut encoded = vec![0u8; 128];
        // Write incorrect offset (99) that doesn't match expected first offset (28)
        encoded[0..4].copy_from_slice(&99u32.to_le_bytes());
        // Write valid rho data at bytes 4..24 (20 bytes of zeros is valid FieldArray<5>)
        for i in 0..20 {
            encoded[4 + i] = 0;
        }
        // Write second offset at position 24..28 (actual value doesn't matter)
        encoded[24..28].copy_from_slice(&78u32.to_le_bytes());
        // Attempt decode with invalid first offset
        let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
        // Decoder at line 149 checks: offset_path (99) != expected_offset_path (28)
        // Expected offset points to byte immediately after fixed part: 4 + 20 + 4 = 28
        assert!(matches!(
            result,
            Err(DecodeError::InvalidByteLength {
                len: 99,
                expected: 28
            })
        ));
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn test_ssz_panic_safety_malicious_offsets() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        // Helper: Dynamic Size Calculation
        //
        // We calculate sizes dynamically to avoid hardcoded mismatch errors.
        let mut rng = rand::rng();

        // Generate dummy objects to measure their SSZ encoded length
        let dummy_prf_key = PRF::key_gen(&mut rng);
        let dummy_param = TH::rand_parameter(&mut rng);

        let prf_key_size = dummy_prf_key.ssz_bytes_len();
        let param_size = dummy_param.ssz_bytes_len();
        let u64_size = 8;
        let offset_size = 4;

        // Calculate the exact size of the "Fixed Part" of the SecretKey container.
        //
        // Layout: [PRF] [Param] [ActEpoch] [NumActive] [OffTop] [LeftIdx] [OffLeft] [OffRight]
        let fixed_part_len = prf_key_size
            + param_size
            + u64_size // activation_epoch
            + u64_size // num_active_epochs
            + offset_size // offset_top_tree
            + u64_size // left_bottom_tree_index
            + offset_size // offset_left_bottom
            + offset_size; // offset_right_bottom

        // Helper: Error Verifier
        fn assert_bytes_invalid<T>(result: Result<T, DecodeError>, expected_msg_part: &str) {
            match result {
                Err(DecodeError::BytesInvalid(msg)) => {
                    assert!(
                        msg.contains(expected_msg_part),
                        "Error message '{}' did not contain expected part '{}'",
                        msg,
                        expected_msg_part
                    );
                }
                Err(e) => panic!("Wrong error type. Expected BytesInvalid, got {:?}", e),
                Ok(_) => panic!("Should have failed with BytesInvalid, but succeeded"),
            }
        }

        // SCENARIO 1: Signature with Reversed Offsets (Non-Monotonic)
        //
        // - Structure: GeneralizedXMSSSignature { path, rho, hashes }
        // - SSZ Layout: [Offset Path (4)] | [Rho (Var)] | [Offset Hashes (4)] | ...
        // - Malicious Input: offset_hashes < offset_path
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();

            // Fixed part = Offset(4) + Rho + Offset(4)
            let sig_fixed_part_size = 4 + rho_size + 4;
            let mut encoded = vec![0u8; 200]; // Sufficient buffer

            // 1. Write [Offset Path] -> Correctly points to end of fixed part
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());

            // 2. Write [Rho] -> Write valid dummy data
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            // 3. Write [Offset Hashes] -> MALICIOUS!
            // We set it to 10, which is less than `offset_path` (sig_fixed_part_size).
            // This implies the `path` field has negative length, which causes panic if unchecked.
            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4].copy_from_slice(&10u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "Invalid variable offsets");
        }

        // SCENARIO 2: Signature with Offset Out of Bounds
        //
        // Malicious Input: offset_hashes points outside the buffer
        {
            let dummy_rho = IE::rand(&mut rng);
            let rho_size = dummy_rho.ssz_bytes_len();
            let sig_fixed_part_size = 4 + rho_size + 4;

            let mut encoded = vec![0u8; 100]; // Buffer length is 100

            // 1. Write [Offset Path] -> Correct
            encoded[0..4].copy_from_slice(&(sig_fixed_part_size as u32).to_le_bytes());

            // 2. Write [Rho] -> Correct
            let mut rho_buf = Vec::new();
            dummy_rho.ssz_append(&mut rho_buf);
            encoded[4..4 + rho_size].copy_from_slice(&rho_buf);

            // 3. Write [Offset Hashes] -> MALICIOUS!
            // Set to 200, which is > encoded.len() (100).
            let offset_hashes_pos = 4 + rho_size;
            encoded[offset_hashes_pos..offset_hashes_pos + 4]
                .copy_from_slice(&200u32.to_le_bytes());

            let result = <Sig as SignatureScheme>::Signature::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "len=100");
        }

        // SCENARIO 3: Secret Key with Interleaved Offset Violation
        //
        // Structure: Fixed Fields interleaved with 3 Variable Offsets (top, left, right)
        // Malicious Input: offset_left < offset_top (Reversed variable sections)
        {
            let mut encoded = vec![0u8; fixed_part_len + 100];
            let mut pos = 0;

            // 1. Write Fixed Fields: PRF Key
            // We write actual valid PRF key bytes
            let mut prf_buf = Vec::new();
            dummy_prf_key.ssz_append(&mut prf_buf);
            encoded[pos..pos + prf_key_size].copy_from_slice(&prf_buf);
            pos += prf_key_size;

            // 2. Write Fixed Fields: Parameter
            let mut param_buf = Vec::new();
            dummy_param.ssz_append(&mut param_buf);
            encoded[pos..pos + param_size].copy_from_slice(&param_buf);
            pos += param_size;

            // 3. Write Fixed Fields: Activation Epoch (u64)
            pos += 8;

            // 4. Write Fixed Fields: Num Active Epochs (u64)
            pos += 8;

            // 5. Write [Offset Top Tree]
            // Should point to the end of the fixed part.
            encoded[pos..pos + 4].copy_from_slice(&(fixed_part_len as u32).to_le_bytes());
            pos += 4;

            // 6. Write Fixed Fields: Left Bottom Tree Index (u64)
            pos += 8;

            // 7. Write [Offset Left Bottom Tree] -> MALICIOUS!
            // We set it to 10.
            // Since 10 < fixed_part_len, this offset comes *before* the Top Tree offset.
            // This would cause `bytes[offset_top..offset_left]` to panic.
            encoded[pos..pos + 4].copy_from_slice(&10u32.to_le_bytes());
            pos += 4;

            // 8. Write [Offset Right Bottom Tree]
            // Set to valid relative location to ensure we don't fail on the third offset check first.
            encoded[pos..pos + 4].copy_from_slice(&((fixed_part_len + 50) as u32).to_le_bytes());

            let result = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&encoded);
            assert_bytes_invalid(result, "Invalid variable offsets");
        }
    }

    #[test]
    fn test_ssz_determinism() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // PublicKey: encode same structure twice
        let root = TestTH::rand_domain(&mut rng);
        let parameter = TestTH::rand_parameter(&mut rng);
        let public_key = GeneralizedXMSSPublicKey::<TestTH> { root, parameter };
        // Serialize twice to verify deterministic output
        let encoded1 = public_key.as_ssz_bytes();
        let encoded2 = public_key.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(encoded1, encoded2);

        // Signature: encode same structure twice
        let (_pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 5;
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Serialize twice to verify deterministic output
        let sig_encoded1 = signature.as_ssz_bytes();
        let sig_encoded2 = signature.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(sig_encoded1, sig_encoded2);

        // SecretKey: encode same structure twice
        let (_pk2, sk2) = Sig::key_gen(&mut rng, 0, 8);
        // Serialize twice to verify deterministic output
        let sk_encoded1 = sk2.as_ssz_bytes();
        let sk_encoded2 = sk2.as_ssz_bytes();
        // Verify byte-for-byte identical encoding
        assert_eq!(sk_encoded1, sk_encoded2);
    }

    #[test]
    fn test_ssz_signature_integration() {
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        let mut rng = rng();

        // Generate keypair and sign message
        let (pk, sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 7;
        // Create valid signature
        let signature = Sig::sign(&sk, epoch, &message).unwrap();
        // Verify signature is valid before serialization
        assert!(Sig::verify(&pk, epoch, &message, &signature));

        // Test PublicKey serialization
        let pk_encoded = pk.as_ssz_bytes();
        let pk_decoded = GeneralizedXMSSPublicKey::<TH>::from_ssz_bytes(&pk_encoded).unwrap();
        // Verify decoded key can still verify signature
        assert!(Sig::verify(&pk_decoded, epoch, &message, &signature));

        // Test Signature serialization
        let sig_encoded = signature.as_ssz_bytes();
        let sig_decoded =
            <Sig as SignatureScheme>::Signature::from_ssz_bytes(&sig_encoded).unwrap();
        // Verify decoded signature still validates with original key
        assert!(Sig::verify(&pk, epoch, &message, &sig_decoded));
        // Verify decoded signature validates with decoded key
        assert!(Sig::verify(&pk_decoded, epoch, &message, &sig_decoded));

        // Test SecretKey serialization
        let sk_encoded = sk.as_ssz_bytes();
        let sk_decoded = <Sig as SignatureScheme>::SecretKey::from_ssz_bytes(&sk_encoded).unwrap();
        // Sign with decoded key
        let sig2 = Sig::sign(&sk_decoded, epoch + 1, &message).unwrap();
        // Verify signature from decoded key validates
        assert!(Sig::verify(&pk, epoch + 1, &message, &sig2));
    }

    proptest! {
        #[test]
        fn proptest_expand_activation_time_invariants(
            desired_start in 0usize..256,
            desired_duration in 1usize..256
        ) {
            const LOG_LIFETIME: usize = 8;
            const C: usize = 1 << (LOG_LIFETIME / 2);
            const LIFETIME: usize = 1 << LOG_LIFETIME;

            let desired_end = (desired_start + desired_duration).min(LIFETIME);

            let (start, end) = expand_activation_time::<LOG_LIFETIME>(desired_start, desired_duration);

            let actual_start = start * C;
            let actual_end = end * C;

            // check minimum duration of 2 bottom trees
            prop_assert!(end - start >= 2);

            // check result fits within lifetime
            prop_assert!(actual_end <= LIFETIME);

            // check result contains the desired interval
            prop_assert!(actual_start <= desired_start);
            prop_assert!(actual_end >= desired_end);

            // check determinism by calling twice
            let (start2, end2) = expand_activation_time::<LOG_LIFETIME>(desired_start, desired_duration);
            prop_assert_eq!((start, end), (start2, end2));
        }

        #[test]
        fn proptest_ssz_public_key_roundtrip_and_determinism(
            root_values in prop::collection::vec(0u32..F::ORDER_U32, 7),
            param_values in prop::collection::vec(0u32..F::ORDER_U32, 5)
        ) {
            // build public key from random field element values
            let root_arr: [F; 7] = std::array::from_fn(|i| F::new(root_values[i]));
            let param_arr: [F; 5] = std::array::from_fn(|i| F::new(param_values[i]));

            let original = GeneralizedXMSSPublicKey::<TestTH> {
                root: FieldArray(root_arr),
                parameter: FieldArray(param_arr),
            };

            // encode to SSZ bytes
            let encoded1 = original.as_ssz_bytes();
            let encoded2 = original.as_ssz_bytes();

            // check encoding is deterministic
            prop_assert_eq!(&encoded1, &encoded2);

            // check size matches expected (7 + 5 field elements * 4 bytes)
            let expected_size = 12 * F::NUM_BYTES;
            prop_assert_eq!(encoded1.len(), expected_size);
            prop_assert_eq!(original.ssz_bytes_len(), expected_size);

            // decode and check roundtrip preserves data
            let decoded = GeneralizedXMSSPublicKey::<TestTH>::from_ssz_bytes(&encoded1)
                .expect("valid SSZ bytes should decode");

            prop_assert_eq!(original.root, decoded.root);
            prop_assert_eq!(original.parameter, decoded.parameter);
        }
    }
}
