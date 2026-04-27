use std::hint::black_box;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use rand::RngExt;

use leansig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_10::target_sum::SIGTargetSumLifetime10W2NoOff,
    },
};

type DemoScheme = SIGTargetSumLifetime10W2NoOff;

fn bench_demo_scheme(c: &mut Criterion) {
    let mut group = c.benchmark_group("demo/perf");
    group.sampling_mode(SamplingMode::Flat);

    let mut rng = rand::rng();

    group.sample_size(10);
    group.bench_function(BenchmarkId::new("keygen", "lifetime_2^10_w2"), |b| {
        b.iter(|| {
            let _ = DemoScheme::key_gen(black_box(&mut rng), 0, DemoScheme::LIFETIME as usize);
        });
    });

    let (public_key, secret_key) = DemoScheme::key_gen(&mut rng, 0, DemoScheme::LIFETIME as usize);
    let prepared_interval = secret_key.get_prepared_interval();
    let message: [u8; MESSAGE_LENGTH] = rng.random();

    group.sample_size(60);
    group.bench_function(BenchmarkId::new("sign", "lifetime_2^10_w2"), |b| {
        let mut next_epoch = prepared_interval.start as u32;
        b.iter(|| {
            let epoch = next_epoch;
            next_epoch += 1;
            if next_epoch >= prepared_interval.end as u32 {
                next_epoch = prepared_interval.start as u32;
            }

            let _ = DemoScheme::sign(
                black_box(&secret_key),
                black_box(epoch),
                black_box(&message),
            )
            .expect("signing should succeed for prepared demo epochs");
        });
    });

    let signatures: Vec<(
        u32,
        [u8; MESSAGE_LENGTH],
        <DemoScheme as SignatureScheme>::Signature,
    )> = (0..64)
        .map(|offset| {
            let epoch = prepared_interval.start as u32 + offset;
            let signature =
                DemoScheme::sign(&secret_key, epoch, &message).expect("precomputing signature");
            (epoch, message, signature)
        })
        .collect();

    group.bench_function(BenchmarkId::new("verify", "lifetime_2^10_w2"), |b| {
        let mut index = 0usize;
        b.iter(|| {
            let (epoch, benchmark_message, signature) = &signatures[index];
            index = (index + 1) % signatures.len();

            let _ = DemoScheme::verify(
                black_box(&public_key),
                *epoch,
                black_box(benchmark_message),
                black_box(signature),
            );
        });
    });

    group.sample_size(30);
    let log_lifetime = DemoScheme::LIFETIME.ilog2() as usize;
    let max_advances_per_key = (1usize << (log_lifetime / 2)).saturating_sub(2);

    group.bench_function(
        BenchmarkId::new("advance_preparation", "lifetime_2^10_w2"),
        |b| {
            b.iter_custom(|iters| {
                let keys_needed = (iters as usize).div_ceil(max_advances_per_key);
                let mut benchmark_rng = rand::rng();
                let mut secret_keys: Vec<_> = (0..keys_needed)
                    .map(|_| {
                        DemoScheme::key_gen(&mut benchmark_rng, 0, DemoScheme::LIFETIME as usize).1
                    })
                    .collect();

                let start = Instant::now();
                let mut remaining = iters as usize;

                for secret_key in &mut secret_keys {
                    if remaining == 0 {
                        break;
                    }

                    let advances_for_key = remaining.min(max_advances_per_key);
                    for _ in 0..advances_for_key {
                        secret_key.advance_preparation();
                    }

                    black_box(secret_key.get_prepared_interval());
                    remaining -= advances_for_key;
                }

                start.elapsed()
            });
        },
    );

    group.finish();
}

criterion_group!(demo_perf, bench_demo_scheme);
criterion_main!(demo_perf);
