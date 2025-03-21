use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_26::target_sum::SIGTargetSumLifetime26W2Off10;
use hashsig::signature::SignatureScheme;
use rand::rngs::ThreadRng;
use rand::Rng;
use rand::thread_rng;
use std::time::Instant;

// Function to measure execution time
fn measure_time<T: SignatureScheme, R: Rng>(description: &str, rng: &mut R) {
    // key gen

    let start = Instant::now();
    let (_pk, _sk) = T::gen(rng);
    let duration = start.elapsed();
    println!("{} - Gen: {:?}", description, duration);
}

// Main function to run the program
fn main() {
    let mut rng = thread_rng();

    measure_time::<SIGTargetSumLifetime26W2Off10, ThreadRng>(
        "Poseidon - L 26 - Target Sum - w 2 - 10% Off",
        &mut rng,
    );
}
