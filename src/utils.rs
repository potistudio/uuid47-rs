#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn write_48_big_endian(dst: &mut [u8; 6], v48: u64) {
	dst[0] = (v48 >> 40) as u8;
	dst[1] = (v48 >> 32) as u8;
	dst[2] = (v48 >> 24) as u8;
	dst[3] = (v48 >> 16) as u8;
	dst[4] = (v48 >> 8) as u8;
	dst[5] = v48 as u8;
}

#[inline]
pub(crate) fn read_48_big_endian(src: [u8; 6]) -> u64 {
	u64::from_be_bytes([0, 0, src[0], src[1], src[2], src[3], src[4], src[5]])
}

#[inline]
pub(crate) fn hexval(c: u8) -> Option<u8> {
	match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		b'A'..=b'F' => Some(c - b'A' + 10),
		_ => None,
	}
}

/// SipHash-2-4 (reference) in Rust
#[inline]
pub(crate) fn siphash24(input: &[u8], k0: u64, k1: u64) -> u64 {
	let mut v0 = 0x736f_6d65_7073_6575_u64 ^ k0;
	let mut v1 = 0x646f_7261_6e64_6f6d_u64 ^ k1;
	let mut v2 = 0x6c79_6765_6e65_7261_u64 ^ k0;
	let mut v3 = 0x7465_6462_7974_6573_u64 ^ k1;

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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_rd_wr_48() {
		let mut buf = [0u8; 6];
		let v = 0x01_23_45_67_89_ABu64 & 0x0000_FFFF_FFFF_FFFFu64;

		write_48_big_endian(&mut buf, v);

		let r = read_48_big_endian(buf);

		assert_eq!(r, v);
	}
}
