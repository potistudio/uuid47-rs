use criterion::{black_box, criterion_group, criterion_main, Criterion};
use uuid47::*;

fn benchmark_encoding(criterion: &mut Criterion) {
	let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);
	let uuid = Uuid128::empty(); // 00000000-0000-7000-8000-000000000000

	criterion.bench_function("encode_as_v4facade", |bencher| {
		bencher.iter(|| black_box(&uuid).encode_as_v4facade(black_box(&key)))
	});
}

fn benchmark_decoding(criterion: &mut Criterion) {
	let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);
	let uuid: Uuid128 = Uuid128::empty(); // 00000000-0000-7000-8000-000000000000
	let facade = uuid.encode_as_v4facade(&key);

	criterion.bench_function("decode_from_v4facade", |bencher| {
		bencher.iter(|| black_box(&facade).decode_from_v4facade(black_box(&key)))
	});
}

fn benchmark_parsing(criterion: &mut Criterion) {
	let string = "00000000-0000-7000-8000-000000000000";

	criterion.bench_function("parse_uuid", |bencher| {
		bencher.iter(|| black_box(string).parse::<Uuid128>().unwrap())
	});
}

fn benchmark_formatting(criterion: &mut Criterion) {
	let uuid = Uuid128::empty(); // 00000000-0000-7000-8000-000000000000

	criterion.bench_function("format_uuid", |bencher| {
		bencher.iter(|| black_box(&uuid).to_string())
	});
}

criterion_group!(
	benches,
	benchmark_encoding,
	benchmark_decoding,
	benchmark_parsing,
	benchmark_formatting,
);
criterion_main!(benches);
