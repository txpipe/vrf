use criterion::{criterion_group, criterion_main, Criterion};
#[allow(unused_must_use)]
use pallas_vrf::vrf03::{PublicKey03, SecretKey03, VrfProof03};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

fn vrf03(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF03 aka Praos");
    let alpha_string = [0u8; 23];
    let secret_key = SecretKey03::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let public_key = PublicKey03::from(&secret_key);

    let vrf_proof = VrfProof03::generate(&public_key, &secret_key, &alpha_string);
    group.bench_function("Generation", |b| {
        b.iter(|| {
            VrfProof03::generate(&public_key, &secret_key, &alpha_string);
        })
    });
    group.bench_function("Verification", |b| {
        b.iter(|| {
            vrf_proof
                .verify(&public_key, &alpha_string)
                .expect("Should pass.");
        })
    });
}

criterion_group!(name = benches;
                 config = Criterion::default().measurement_time(Duration::new(60, 0));
                 targets = vrf03);
criterion_main!(benches);
