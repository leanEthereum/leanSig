use std::hint::black_box;

use leansig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::size_optimized::SIGTopLevelTargetSumLifetime32Dim32Base26,
};

/// Cap activation duration to 2^18 to keep runtime reasonable (same as benchmark)
const MAX_LOG_ACTIVATION_DURATION: usize = 18;

fn main() {
    let mut rng = rand::rng();

    // 2^32 lifetime, activation capped at 2^18
    let activation_duration = std::cmp::min(
        1 << MAX_LOG_ACTIVATION_DURATION,
        SIGTopLevelTargetSumLifetime32Dim32Base26::LIFETIME as usize,
    );

    eprintln!(
        "Running single key_gen for 2^32 lifetime (activation 2^{})...",
        MAX_LOG_ACTIVATION_DURATION
    );
    let (pk, sk) = black_box(SIGTopLevelTargetSumLifetime32Dim32Base26::key_gen(
        &mut rng,
        0,
        activation_duration,
    ));
    eprintln!("Done. pk size: {} bytes", std::mem::size_of_val(&pk));

    // Prevent optimization from removing the key_gen call
    black_box((pk, sk));
}
