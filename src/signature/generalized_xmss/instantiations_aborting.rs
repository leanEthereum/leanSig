/// Instantiations with Lifetime 2^6. This is for testing purposes only.
///
/// Warning: Should not be used in production environments.
///
/// !!! TODO: compute properly each parameter. !!!
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

    // KoalaBear: p = 2^31 - 2^24 + 1 = 127 * 8^8 + 1
    // w=8, z=8, Q=127, alpha=1
    const DIMENSION: usize = 64;
    const BASE: usize = 8;
    const Z: usize = 8;
    const Q: usize = 127;

    // TODO
    const PARAMETER_LEN: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const RAND_LEN_FE: usize = 7;
    const MH_HASH_LEN_FE: usize = 8;

    const TH_HASH_LEN_FE: usize = 8;
    const CAPACITY: usize = 9;

    type MH = AbortingHypercubeMessageHash<
        PARAMETER_LEN,
        RAND_LEN_FE,
        MH_HASH_LEN_FE,
        DIMENSION,
        BASE,
        Z,
        Q,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >;

    const TARGET_SUM: usize = 230; // TODO

    type TH = PoseidonTweakHash<PARAMETER_LEN, TH_HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
    type PRF = ShakePRFtoF<TH_HASH_LEN_FE, RAND_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SIGAbortingLifetime6Dim64Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {
        use crate::signature::{
            SignatureScheme, test_templates::test_signature_scheme_correctness,
        };

        use super::SIGAbortingLifetime6Dim64Base8;

        #[test]
        pub fn test_correctness() {
            test_signature_scheme_correctness::<SIGAbortingLifetime6Dim64Base8>(
                2,
                0,
                SIGAbortingLifetime6Dim64Base8::LIFETIME as usize,
            );
            test_signature_scheme_correctness::<SIGAbortingLifetime6Dim64Base8>(
                11,
                0,
                SIGAbortingLifetime6Dim64Base8::LIFETIME as usize,
            );
        }
    }
}
