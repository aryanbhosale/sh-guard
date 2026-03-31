use criterion::{criterion_group, criterion_main, Criterion};

fn bench_classify(c: &mut Criterion) {
    c.bench_function("classify_noop", |b| {
        b.iter(|| {
            // TODO: benchmark classify once implemented
        });
    });
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
