use std::hint::black_box;

use leansig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
};

fn main() {
    let mut rng = rand::rng();

    // 2^8 lifetime, full activation
    let activation_duration = SIGTopLevelTargetSumLifetime8Dim64Base8::LIFETIME as usize;

    eprintln!("Running single key_gen for 2^8 lifetime...");
    let (pk, sk) = black_box(SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(
        &mut rng,
        0,
        activation_duration,
    ));
    eprintln!("Done. pk size: {} bytes", std::mem::size_of_val(&pk));

    // Prevent optimization from removing the key_gen call
    black_box((pk, sk));
}
