use p3_field::Field;
use p3_koala_bear::{
    KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24,
};
use std::sync::OnceLock;

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = KoalaBear;
pub(crate) type PackedF = <F as Field>::Packing;

pub(crate) mod array;
pub(crate) mod hypercube;
pub mod inc_encoding;
pub mod serialization;
pub mod signature;
pub(crate) mod simd_utils;
pub mod symmetric;

// Cached Poseidon2 permutations.
//
// We cache the default Plonky3 Poseidon2 instances once and return a clone.
// Returning by value preserves existing call sites that take `&perm`.

/// A lazily-initialized, thread-safe cache for the Poseidon2 permutation with a width of 24.
static POSEIDON2_24: OnceLock<Poseidon2KoalaBear<24>> = OnceLock::new();

/// A lazily-initialized, thread-safe cache for the Poseidon2 permutation with a width of 16.
static POSEIDON2_16: OnceLock<Poseidon2KoalaBear<16>> = OnceLock::new();

/// Errors returned when initializing a custom Poseidon2 permutation.
#[derive(Debug, thiserror::Error)]
pub enum Poseidon2InitError {
    #[error("Poseidon2 permutation for width {width} was already initialized")]
    AlreadyInitialized { width: usize },
}

/// Initialize the width-24 Poseidon2 permutation used by this crate.
///
/// This must be called before the first use of the permutation (i.e. before any code paths that
/// compute message/tweak hashes). If not called, the default Plonky3 permutation is used.
pub fn init_poseidon2_24(perm: Poseidon2KoalaBear<24>) -> Result<(), Poseidon2InitError> {
    POSEIDON2_24
        .set(perm)
        .map_err(|_| Poseidon2InitError::AlreadyInitialized { width: 24 })
}

/// Initialize the width-24 Poseidon2 permutation using a constructor.
///
/// The constructor will only be called if the permutation has not been initialized yet.
pub fn init_poseidon2_24_with<B>(builder: B) -> Result<(), Poseidon2InitError>
where
    B: FnOnce() -> Poseidon2KoalaBear<24>,
{
    if POSEIDON2_24.get().is_some() {
        return Err(Poseidon2InitError::AlreadyInitialized { width: 24 });
    }
    init_poseidon2_24(builder())
}

/// Initialize the width-16 Poseidon2 permutation used by this crate.
///
/// This must be called before the first use of the permutation. If not called, the default
/// Plonky3 permutation is used.
pub fn init_poseidon2_16(perm: Poseidon2KoalaBear<16>) -> Result<(), Poseidon2InitError> {
    POSEIDON2_16
        .set(perm)
        .map_err(|_| Poseidon2InitError::AlreadyInitialized { width: 16 })
}

/// Initialize the width-16 Poseidon2 permutation using a constructor.
///
/// The constructor will only be called if the permutation has not been initialized yet.
pub fn init_poseidon2_16_with<B>(builder: B) -> Result<(), Poseidon2InitError>
where
    B: FnOnce() -> Poseidon2KoalaBear<16>,
{
    if POSEIDON2_16.get().is_some() {
        return Err(Poseidon2InitError::AlreadyInitialized { width: 16 });
    }

    init_poseidon2_16(builder())
}

/// Poseidon2 permutation (width 24)
pub(crate) fn poseidon2_24() -> Poseidon2KoalaBear<24> {
    POSEIDON2_24
        .get_or_init(default_koalabear_poseidon2_24)
        .clone()
}

/// Poseidon2 permutation (width 16)
pub(crate) fn poseidon2_16() -> Poseidon2KoalaBear<16> {
    POSEIDON2_16
        .get_or_init(default_koalabear_poseidon2_16)
        .clone()
}

#[cfg(test)]
mod poseidon2_init_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p3_koala_bear::{default_koalabear_poseidon2_16, default_koalabear_poseidon2_24};

    use crate::{
        Poseidon2InitError, init_poseidon2_16, init_poseidon2_16_with, init_poseidon2_24,
        init_poseidon2_24_with, poseidon2_16, poseidon2_24,
    };

    #[test]
    fn init_poseidon2_24_returns_already_initialized_and_does_not_call_builder() {
        // Ensure the OnceLock is initialized (possibly by other tests too).
        let _ = poseidon2_24();

        let calls = AtomicUsize::new(0);
        let res = init_poseidon2_24_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            default_koalabear_poseidon2_24()
        });

        assert!(matches!(
            res,
            Err(Poseidon2InitError::AlreadyInitialized { width: 24 })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let res = init_poseidon2_24(default_koalabear_poseidon2_24());
        assert!(matches!(
            res,
            Err(Poseidon2InitError::AlreadyInitialized { width: 24 })
        ));
    }

    #[test]
    fn init_poseidon2_16_returns_already_initialized_and_does_not_call_builder() {
        // Ensure the OnceLock is initialized (possibly by other tests too).
        let _ = poseidon2_16();

        let calls = AtomicUsize::new(0);
        let res = init_poseidon2_16_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            default_koalabear_poseidon2_16()
        });

        assert!(matches!(
            res,
            Err(Poseidon2InitError::AlreadyInitialized { width: 16 })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let res = init_poseidon2_16(default_koalabear_poseidon2_16());
        assert!(matches!(
            res,
            Err(Poseidon2InitError::AlreadyInitialized { width: 16 })
        ));
    }
}
