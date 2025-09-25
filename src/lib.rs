mod err;
mod uuid;
mod utils;

use utils::*;
pub use err::*;
pub use uuid::*;

pub struct UuidV47Key {
	pub k0: u64,
	pub k1: u64,
}

// SipHash-2-4 (reference) in Rust
#[inline(always)]
fn siphash24(input: &[u8], k0: u64, k1: u64) -> u64 {
	let mut v0 = 0x736f6d6570736575u64 ^ k0;
	let mut v1 = 0x646f72616e646f6du64 ^ k1;
	let mut v2 = 0x6c7967656e657261u64 ^ k0;
	let mut v3 = 0x7465646279746573u64 ^ k1;

	let mut b = (input.len() as u64) << 56;

	let mut chunks = input.chunks_exact(8);
	for chunk in chunks.by_ref() {
		let m = u64::from_le_bytes(chunk.try_into().unwrap());
		v3 ^= m;
		// 2 compression rounds
		for _ in 0..2 {
			v0 = v0.wrapping_add(v1);
			v2 = v2.wrapping_add(v3);
			v1 = v1.rotate_left(13);
			v3 = v3.rotate_left(16);
			v1 ^= v0;
			v3 ^= v2;
			v0 = v0.rotate_left(32);
			v2 = v2.wrapping_add(v1);
			v0 = v0.wrapping_add(v3);
			v1 = v1.rotate_left(17);
			v3 = v3.rotate_left(21);
			v1 ^= v2;
			v3 ^= v0;
			v2 = v2.rotate_left(32);
		}
		v0 ^= m;
	}

	// last 0..7 bytes
	let rem = chunks.remainder();
	let mut t = 0u64;
	for (i, &byte) in rem.iter().enumerate() {
		t |= (byte as u64) << (8 * i as u32);
	}
	b |= t;

	v3 ^= b;
	for _ in 0..2 {
		v0 = v0.wrapping_add(v1);
		v2 = v2.wrapping_add(v3);
		v1 = v1.rotate_left(13);
		v3 = v3.rotate_left(16);
		v1 ^= v0;
		v3 ^= v2;
		v0 = v0.rotate_left(32);
		v2 = v2.wrapping_add(v1);
		v0 = v0.wrapping_add(v3);
		v1 = v1.rotate_left(17);
		v3 = v3.rotate_left(21);
		v1 ^= v2;
		v3 ^= v0;
		v2 = v2.rotate_left(32);
	}
	v0 ^= b;

	v2 ^= 0xff;
	for _ in 0..4 {
		v0 = v0.wrapping_add(v1);
		v2 = v2.wrapping_add(v3);
		v1 = v1.rotate_left(13);
		v3 = v3.rotate_left(16);
		v1 ^= v0;
		v3 ^= v2;
		v0 = v0.rotate_left(32);
		v2 = v2.wrapping_add(v1);
		v0 = v0.wrapping_add(v3);
		v1 = v1.rotate_left(17);
		v3 = v3.rotate_left(21);
		v1 ^= v2;
		v3 ^= v0;
		v2 = v2.rotate_left(32);
	}

	v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn build_sip_input_from_v7(u: &Uuid128, msg: &mut [u8; 10]) {
	// [low-nibble of b6][b7][b8&0x3F][b9..b15]
	msg[0] = u.b[6] & 0x0F;
	msg[1] = u.b[7];
	msg[2] = u.b[8] & 0x3F;
	msg[3..10].copy_from_slice(&u.b[9..16]);
}

#[inline(always)]
pub fn uuidv47_encode_v4facade(v7: &Uuid128, key: &UuidV47Key) -> Uuid128 {
	//* 1. SipHash24(key, v7.random74bits) -> take low 48 bits */
	let mut sipmsg = [0u8; 10];

	build_sip_input_from_v7(&v7, &mut sipmsg);
	let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

	//* 2. Encode timestamp */
	let encoded_timestamp = read_48_big_endian((&v7.b[0..6]).try_into().unwrap()) ^ mask48;

	//* 3. Build v4 facade */
	// Use dereference copy instead of "from_bytes" to ensure performance optimization
	// let mut out = Uuid128::from_bytes(v7.b); <- STUPID
	let mut out = *v7;

	// Force slice to fixed-size (should not panic)
	write_48_big_endian((&mut out.b[0..6]).try_into().unwrap(), encoded_timestamp);

	out.set_version(4);  // facade
	out.set_variant_rfc4122();  // ensure RFC variant bits

	out
}

#[inline(always)]
pub fn uuidv47_decode_v4facade(v4facade: &Uuid128, key: &UuidV47Key) -> Uuid128 {
	// 1. rebuild same Sip input from façade (identical bytes)
	let mut sipmsg = [0u8; 10];
	build_sip_input_from_v7(v4facade, &mut sipmsg);
	let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

	// 2. ts = encTS ^ mask
	// Force slice to fixed-size (should not panic)
	let ts48 = read_48_big_endian((v4facade.b[0..6]).try_into().unwrap()) ^ mask48;

	// 3. restore v7: write ts, set ver=7, set variant
	// Use dereference copy instead of "from_bytes" to ensure performance optimization
	// let mut result = Uuid128::from_bytes(v7.b); <- STUPID
	let mut out = *v4facade;

	// Force slice to fixed-size (should not panic)
	write_48_big_endian((&mut out.b[0..6]).try_into().unwrap(), ts48);

	out.set_version(7);
	out.set_variant_rfc4122();
	out
}

#[inline(always)]
pub fn uuid_parse(s: &[u8]) -> Result<Uuid128, UuidParseError> {
	// expects xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	const IDXS: [usize; 32] = [
		0, 1, 2, 3, 4, 5, 6, 7,
		9, 10, 11, 12, 14, 15, 16, 17,
		19, 20, 21, 22,
		24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	];

	if s.len() < 36 {
		return Err(UuidParseError::TooShort);
	}

	let mut b = [0u8; 16];
	for i in 0..16 {
		let h = hexval(s[IDXS[i * 2]]);
		let l = hexval(s[IDXS[i * 2 + 1]]);

		if h < 0 || l < 0 {
			return Err(UuidParseError::InvalidHex);
		}

		b[i] = ((h << 4) | l) as u8;
	}

	Ok(Uuid128{ b })
}

/// Format UUID into standard 8-4-4-4-12 hex string with dashes.
/// Assumes input is valid UUID (16 bytes).
/// Output buffer must be at least 37 bytes (36 chars + null terminator).
#[inline(always)]
pub fn uuid_format(u: &Uuid128, out: &mut [u8]) {
	const HEXD: &[u8; 16] = b"0123456789abcdef";
	let mut j = 0usize;

	for i in 0..16 {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = b'-';
			j += 1;
		}
		let byte = u.b[i];
		out[j] = HEXD[((byte >> 4) & 0x0F) as usize];
		j += 1;
		out[j] = HEXD[(byte & 0x0F) as usize];
		j += 1;
	}

	out[36] = 0;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_uuid_parse_format_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
		// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
		let s = "00000000-0000-7000-8000-000000000000";

		let u = uuid_parse(s.as_bytes())?;
		assert_eq!(u.uuid_version(), 7);

		let mut out = [0u8; 37];
		uuid_format(&u, &mut out);
		assert_eq!(s.as_bytes(), &out[..36]);

		let u2 = uuid_parse(&out)?;
		assert_eq!(u, u2);

		Ok(())
	}

	#[test]
	fn test_bad_uuid_parse() {
		let bad1 = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";  // invalid hex
		assert!(matches!(uuid_parse(bad1.as_bytes()), Err(UuidParseError::InvalidHex)));

		let bad2 = "00000000-0000-7000-8000-00000000000";  // too short
		assert!(matches!(uuid_parse(bad2.as_bytes()), Err(UuidParseError::TooShort)));
	}

	#[test]
	fn test_version_variant() {
		let mut u = Uuid128::new();

		u.set_version(7);
		assert!(u.uuid_version() == 7);

		u.set_version(4);
		assert!(u.uuid_version() == 4);

		u.set_variant_rfc4122();
		assert!((u.b[8] & 0xC0) == 0x80);
	}

	fn craft_v7(u: &mut Uuid128, ts_ms_48: u64, rand_a_12: u16, rand_b_62: u64) {
		u.b.fill(0);
		write_48_big_endian(&mut u.b[0..6].try_into().unwrap(), ts_ms_48 & 0x0000FFFFFFFFFFFF);
		u.set_version(7);
		u.b[6] = (u.b[6] & 0xF0) | ((rand_a_12 >> 8) as u8 & 0x0F);
		u.b[7] = (rand_a_12 & 0xFF) as u8;
		u.set_variant_rfc4122();
		u.b[8] = (u.b[8] & 0xC0) | ((rand_b_62 >> 56) as u8 & 0x3F);
		for i in 0..7 {
			u.b[9 + i] = ((rand_b_62 >> (8 * (6 - i))) & 0xFF) as u8;
		}
	}

	#[test]
	fn test_encode_decode_roundtrip() {
		let key = UuidV47Key { k0: 0x0123456789abcdef, k1: 0xfedcba9876543210 };

		for i in 0..16 {
			let mut u7 = Uuid128::new();
			let timestamp = ((0x100000 * i as u64) + 123) as u64;
			let random = ((0x0AAA ^ (i * 7) as u32) & 0x0FFF) as u16;
			let rb = (0x0123456789ABCDEF ^ (0x1111111111111111 * i as u64)) & ((1 << 62) - 1);

			craft_v7(&mut u7, timestamp, random, rb);
			assert!(u7.uuid_version() == 7);  // ensure manual creation worked

			let facade = uuidv47_encode_v4facade(&u7, &key);
			assert!(facade.uuid_version() == 4);  // ensure version
			assert!((facade.b[8] & 0xC0) == 0x80);  // ensure RFC variant

			let back = uuidv47_decode_v4facade(&facade, &key);
			assert_eq!(u7.b, back.b);

			let wrong = UuidV47Key { k0: key.k0 ^ 0xdeadbeef, k1: key.k1 ^ 0x1337 };
			let bad = uuidv47_decode_v4facade(&facade, &wrong);
			assert_ne!(u7, bad);
		}
	}
}

