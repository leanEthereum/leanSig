use leansig::symmetric::tweak_hash::TweakableHash;
use leansig::symmetric::tweak_hash::chain;
use leansig::symmetric::tweak_hash::poseidon::PoseidonTweakHash;
use proptest::prelude::*;

type PoseidonTweak44 = PoseidonTweakHash<4, 4, 3, 9, 128>;

type TestTH = PoseidonTweak44;

#[test]
fn test_chain_associative() {
    let mut rng = rand::rng();

    // we test that first walking k steps, and then walking the remaining steps
    // is the same as directly walking all steps.

    let epoch = 9;
    let chain_index = 20;
    let parameter = TestTH::rand_parameter(&mut rng);
    let start = TestTH::rand_domain(&mut rng);
    let total_steps = 16;

    // walking directly
    let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

    for split in 0..=total_steps {
        let steps_a = split;
        let steps_b = total_steps - split;

        // walking indirectly
        let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
        let end_indirect = chain::<TestTH>(
            &parameter,
            epoch,
            chain_index,
            steps_a as u8,
            steps_b,
            &intermediate,
        );

        // should be the same
        assert_eq!(end_direct, end_indirect);
    }
}

#[test]
fn test_chain_associative_max_value() {
    let mut rng = rand::rng();

    // we test that first walking k steps, and then walking the remaining steps
    // is the same as directly walking all steps.

    let epoch = 12;
    let chain_index = 210;
    let parameter = TestTH::rand_parameter(&mut rng);
    let start = TestTH::rand_domain(&mut rng);
    let total_steps = u8::MAX as usize; // max if we say that pos_in_chain is u8

    // walking directly
    let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

    for split in 0..=total_steps {
        let steps_a = split;
        let steps_b = total_steps - split;

        // walking indirectly
        let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
        let end_indirect = chain::<TestTH>(
            &parameter,
            epoch,
            chain_index,
            steps_a as u8,
            steps_b,
            &intermediate,
        );

        // should be the same
        assert_eq!(end_direct, end_indirect);
    }
}

proptest! {
    #[test]
    fn proptest_chain_associative(
        // Random epoch for domain separation (small range to keep tests fast)
        epoch in 0u32..100,

        // Random chain index to simulate different chains (small range to keep tests fast)
        chain_index in 0u8..10,

        // Total number of steps to walk along the chain (bounded to keep tests fast)
        total_steps in 0usize..16,
    ) {
        // Random number generator for generating parameters and start point
        let mut rng = rand::rng();

        // Generate a random public parameter for the tweakable hash function
        let parameter = TestTH::rand_parameter(&mut rng);

        // Generate a random starting domain element (initial hash state)
        let start = TestTH::rand_domain(&mut rng);

        // Compute the result of walking the entire chain in one go
        let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

        // For every way of splitting the walk into two segments...
        for split in 0..=total_steps {
            let steps_a = split;                  // First segment length
            let steps_b = total_steps - split;    // Second segment length

            // First walk: from start, walk `steps_a` steps
            let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);

            // Second walk: continue from intermediate point for `steps_b` steps
            let end_indirect = chain::<TestTH>(
                &parameter,
                epoch,
                chain_index,
                steps_a as u8,   // Start position for second segment
                steps_b,
                &intermediate,
            );

            // Check that walking in one go or in two segments gives the same result
            prop_assert_eq!(end_direct, end_indirect);
        }
    }
}
