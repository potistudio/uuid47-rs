//! SIMD optimizations are in simd.rs, so these are only used in scalar path.

/// 256-entry lookup table for hex decoding (0x00-0xFF).\
/// Returns -1 for invalid chars.
#[cfg(not(feature = "simd"))]
const HEX_DECODE_TABLE: [i8; 256] = {
	const fn make_table() -> [i8; 256] {
		let mut t = [-1i8; 256];
		let mut i = 0u8;
		// '0'-'9' -> 0-9
		while i < 10 {
			t[(b'0' + i) as usize] = i as i8;
			i += 1;
		}
		// 'a'-'f' -> 10-15
		i = 0;
		while i < 6 {
			t[(b'a' + i) as usize] = (10 + i) as i8;
			i += 1;
		}
		// 'A'-'F' -> 10-15
		i = 0;
		while i < 6 {
			t[(b'A' + i) as usize] = (10 + i) as i8;
			i += 1;
		}
		t
	}

	make_table()
};

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn write_48_big_endian(dst: &mut [u8; 6], v48: u64) {
	dst[0] = (v48 >> 40) as u8;
	dst[1] = (v48 >> 32) as u8;
	dst[2] = (v48 >> 24) as u8;
	dst[3] = (v48 >> 16) as u8;
	dst[4] = (v48 >> 8) as u8;
	dst[5] = v48 as u8;
}

/// Read 48-bit big-endian value using direct bit shifts (avoids array construction).
#[inline(always)]
pub(crate) fn read_48_big_endian(src: [u8; 6]) -> u64 {
	((src[0] as u64) << 40)
		| ((src[1] as u64) << 32)
		| ((src[2] as u64) << 24)
		| ((src[3] as u64) << 16)
		| ((src[4] as u64) << 8)
		| (src[5] as u64)
}

/// O(1) hex character to value lookup using precomputed table.
#[cfg(not(any(
	all(feature = "simd", target_arch = "aarch64"),
	all(feature = "simd", target_arch = "x86_64")
)))]
#[inline(always)]
pub(crate) fn hexval(c: u8) -> Option<u8> {
	let v = HEX_DECODE_TABLE[c as usize];
	if v < 0 {
		None
	} else {
		Some(v as u8)
	}
}

/// SipHash round macro for complete unrolling (removes loop overhead).
macro_rules! sip_round {
	($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
		$v0 = $v0.wrapping_add($v1);
		$v2 = $v2.wrapping_add($v3);
		$v1 = $v1.rotate_left(13);
		$v3 = $v3.rotate_left(16);
		$v1 ^= $v0;
		$v3 ^= $v2;
		$v0 = $v0.rotate_left(32);
		$v2 = $v2.wrapping_add($v1);
		$v0 = $v0.wrapping_add($v3);
		$v1 = $v1.rotate_left(17);
		$v3 = $v3.rotate_left(21);
		$v1 ^= $v2;
		$v3 ^= $v0;
		$v2 = $v2.rotate_left(32);
	}};
}

/// SipHash-2-4 optimized implementation with unrolled rounds.
#[inline(always)]
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
		// 2 compression rounds (unrolled)
		sip_round!(v0, v1, v2, v3);
		sip_round!(v0, v1, v2, v3);
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
	// 2 compression rounds (unrolled)
	sip_round!(v0, v1, v2, v3);
	sip_round!(v0, v1, v2, v3);
	v0 ^= b;

	v2 ^= 0xff;
	// 4 finalization rounds (unrolled)
	sip_round!(v0, v1, v2, v3);
	sip_round!(v0, v1, v2, v3);
	sip_round!(v0, v1, v2, v3);
	sip_round!(v0, v1, v2, v3);

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

	#[test]
	#[cfg(not(any(
		all(feature = "simd", target_arch = "aarch64"),
		all(feature = "simd", target_arch = "x86_64")
	)))]
	fn test_hexval_table() {
		// Test digits
		for i in 0..10 {
			assert_eq!(hexval(b'0' + i), Some(i));
		}
		// Test lowercase
		for i in 0..6 {
			assert_eq!(hexval(b'a' + i), Some(10 + i));
		}
		// Test uppercase
		for i in 0..6 {
			assert_eq!(hexval(b'A' + i), Some(10 + i));
		}
		// Test invalid
		assert_eq!(hexval(b'g'), None);
		assert_eq!(hexval(b'G'), None);
		assert_eq!(hexval(b' '), None);
	}
}
