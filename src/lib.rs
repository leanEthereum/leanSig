use p3_field::Field;
use p3_koala_bear::{
    KoalaBear, Poseidon1KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon1_24,
};
use std::sync::OnceLock;

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = KoalaBear;
pub(crate) type PackedF = <F as Field>::Packing;

pub mod array;
pub mod inc_encoding;
pub mod serialization;
pub mod signature;
pub(crate) mod simd_utils;
pub mod symmetric;

// Cached Poseidon1 permutations.
//
// Share immutable round constants instead of cloning their heap-backed vectors.

/// A lazily-initialized, thread-safe cache for the Poseidon1 permutation with a width of 24.
static POSEIDON1_24: OnceLock<Poseidon1KoalaBear<24>> = OnceLock::new();

/// A lazily-initialized, thread-safe cache for the Poseidon1 permutation with a width of 16.
static POSEIDON1_16: OnceLock<Poseidon1KoalaBear<16>> = OnceLock::new();

/// Poseidon1 permutation (width 24)
pub(crate) fn poseidon1_24() -> &'static Poseidon1KoalaBear<24> {
    POSEIDON1_24.get_or_init(default_koalabear_poseidon1_24)
}

/// Poseidon1 permutation (width 16)
pub(crate) fn poseidon1_16() -> &'static Poseidon1KoalaBear<16> {
    POSEIDON1_16.get_or_init(default_koalabear_poseidon1_16)
}
