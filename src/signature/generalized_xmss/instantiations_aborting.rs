/// Instantiations with Lifetime 2^32
pub mod lifetime_2_to_the_32 {

    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::{
            GeneralizedXMSSPublicKey, GeneralizedXMSSSecretKey, GeneralizedXMSSSignature, GeneralizedXMSSSignatureScheme
        },
        symmetric::{
            message_hash::aborting::AbortingHypercubeMessageHash, prf::shake_to_field::ShakePRFtoF,
            tweak_hash::poseidon::PoseidonTweakHash,
        },
    };

    const LOG_LIFETIME: usize = 32;

    const DIMENSION: usize = 46;
    const BASE: usize = 8;
    const TARGET_SUM: usize = 200;
    const Z: usize = 8;
    const Q: usize = 127;

    const PARAMETER_LEN: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const RAND_LEN_FE: usize = 7;
    const HASH_LEN_FE: usize = 8;

    const CAPACITY: usize = 9;

    type MH = AbortingHypercubeMessageHash<
        PARAMETER_LEN,
        RAND_LEN_FE,
        HASH_LEN_FE,
        DIMENSION,
        BASE,
        Z,
        Q,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >;
    type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
    type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SchemeAbortingTargetSumLifetime32Dim64Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;
    pub type PubKeyAbortingTargetSumLifetime32Dim64Base8 = GeneralizedXMSSPublicKey<TH>;
    pub type SecretKeyAbortingTargetSumLifetime32Dim64Base8 = GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>;
    pub type SigAbortingTargetSumLifetime32Dim64Base8 = GeneralizedXMSSSignature<IE, TH>;

    #[cfg(test)]
    mod test {

        #[cfg(feature = "slow-tests")]
        use super::*;
        #[cfg(feature = "slow-tests")]
        use crate::signature::SignatureScheme;

        #[cfg(feature = "slow-tests")]
        use crate::signature::test_templates::test_signature_scheme_correctness;

        #[test]
        #[cfg(feature = "slow-tests")]
        pub fn test_correctness() {
            test_signature_scheme_correctness::<SIGAbortingTargetSumLifetime32Dim64Base8>(
                213,
                0,
                SIGAbortingTargetSumLifetime32Dim64Base8::LIFETIME as usize,
            );
            test_signature_scheme_correctness::<SIGAbortingTargetSumLifetime32Dim64Base8>(
                4,
                0,
                SIGAbortingTargetSumLifetime32Dim64Base8::LIFETIME as usize,
            );
        }
    }
}

/// Instantiations with Lifetime 2^6. This is for testing purposes only.
///
/// Warning: Should not be used in production environments.
pub mod lifetime_2_to_the_6 {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
        symmetric::{
            message_hash::aborting::AbortingHypercubeMessageHash, prf::shake_to_field::ShakePRFtoF,
            tweak_hash::poseidon::PoseidonTweakHash,
        },
    };

    const LOG_LIFETIME: usize = 6;

    const DIMENSION: usize = 46;
    const BASE: usize = 8;
    const TARGET_SUM: usize = 200;
    const Z: usize = 8;
    const Q: usize = 127;

    const PARAMETER_LEN: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const RAND_LEN_FE: usize = 7;
    const HASH_LEN_FE: usize = 8;

    const CAPACITY: usize = 9;

    type MH = AbortingHypercubeMessageHash<
        PARAMETER_LEN,
        RAND_LEN_FE,
        HASH_LEN_FE,
        DIMENSION,
        BASE,
        Z,
        Q,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >;

    type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
    type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SchemeAbortingTargetSumLifetime6Dim46Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {
        use crate::signature::{
            SignatureScheme, test_templates::test_signature_scheme_correctness,
        };

        use super::SchemeAbortingTargetSumLifetime6Dim46Base8;

        #[test]
        pub fn test_correctness() {
            test_signature_scheme_correctness::<SchemeAbortingTargetSumLifetime6Dim46Base8>(
                2,
                0,
                SchemeAbortingTargetSumLifetime6Dim46Base8::LIFETIME as usize,
            );
            test_signature_scheme_correctness::<SchemeAbortingTargetSumLifetime6Dim46Base8>(
                11,
                0,
                SchemeAbortingTargetSumLifetime6Dim46Base8::LIFETIME as usize,
            );
        }
    }
}
