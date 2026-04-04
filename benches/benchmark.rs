use criterion::{criterion_group, criterion_main};

mod benchmark_poseidon;

use benchmark_poseidon::bench_function_poseidon;

criterion_group!(benches, bench_function_poseidon);
criterion_main!(benches);
