use std::hint::black_box;

use criterion::{Criterion, SamplingMode};
use rand::Rng;

use leansig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_aborting::lifetime_2_to_the_6::SIGAbortingLifetime6Dim64Base8,
    },
};

pub fn bench_function_aborting(c: &mut Criterion) {
    type Sig = SIGAbortingLifetime6Dim64Base8;

    let mut group = c.benchmark_group("Aborting: Lifetime 2^6, Dim64, Base8");
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = rand::rng();

    // keygen (small sample — it's slow)
    group.sample_size(10);
    group.bench_function("- gen", |b| {
        b.iter(|| {
            let _ = Sig::key_gen(black_box(&mut rng), 0, Sig::LIFETIME as usize);
        });
    });

    // sign
    group.sample_size(100);
    let (pk, sk) = Sig::key_gen(&mut rng, 0, Sig::LIFETIME as usize);
    let prepared_interval = sk.get_prepared_interval();

    group.bench_function("- sign", |b| {
        b.iter(|| {
            let message = rng.random();
            let epoch =
                rng.random_range(prepared_interval.start as u32..prepared_interval.end as u32);
            let _ = Sig::sign(black_box(&sk), black_box(epoch), black_box(&message));
        });
    });

    // verify
    let precomputed: Vec<(u32, [u8; MESSAGE_LENGTH], <Sig as SignatureScheme>::Signature)> =
        (0..500)
            .map(|_| {
                let message = rng.random();
                let epoch = rng
                    .random_range(prepared_interval.start as u32..prepared_interval.end as u32);
                let signature = Sig::sign(&sk, epoch, &message).expect("Signing should succeed");
                (epoch, message, signature)
            })
            .collect();

    group.bench_function("- verify", |b| {
        b.iter(|| {
            let (epoch, message, signature) =
                black_box(&precomputed[rng.random_range(0..precomputed.len())]);
            let _ = Sig::verify(
                black_box(&pk),
                *epoch,
                black_box(message),
                black_box(signature),
            );
        });
    });

    group.finish();
}
