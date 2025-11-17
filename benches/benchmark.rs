use criterion::{criterion_group, criterion_main};

mod benchmark_poseidon;
mod benchmark_poseidon_top_level;

use benchmark_poseidon::bench_function_poseidon;
use benchmark_poseidon_top_level::bench_function_poseidon_top_level;

criterion_group!(
    benches,
    bench_function_poseidon_top_level,
    // bench_function_poseidon
);
criterion_main!(benches);
