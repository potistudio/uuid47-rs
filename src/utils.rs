#[inline(always)]
pub(crate) fn read_64_little_endian(p: &[u8]) -> u64 {
	u64::from_le_bytes(p[0..8].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn write_48_big_endian(dst: &mut [u8; 6], v48: u64) {
	dst[0] = (v48 >> 40) as u8;
	dst[1] = (v48 >> 32) as u8;
	dst[2] = (v48 >> 24) as u8;
	dst[3] = (v48 >> 16) as u8;
	dst[4] = (v48 >> 8) as u8;
	dst[5] = (v48 >> 0) as u8;
}

#[inline(always)]
pub(super) fn read_48_big_endian(src: &[u8; 6]) -> u64 {
	((src[0] as u64) << 40)
		| ((src[1] as u64) << 32)
		| ((src[2] as u64) << 24)
		| ((src[3] as u64) << 16)
		| ((src[4] as u64) << 8)
		| ((src[5] as u64) << 0)
}

#[inline(always)]
pub(super) fn hexval(c: u8) -> i32 {
	match c {
		b'0'..=b'9' => (c - b'0') as i32,
		b'a'..=b'f' => (c - b'a' + 10) as i32,
		b'A'..=b'F' => (c - b'A' + 10) as i32,
		_ => -1,
	}
}

#[test]
	fn test_rd_wr_48() {
		let mut buf = [0u8; 6];
		let v = 0x01_23_45_67_89_ABu64 & 0x0000_FFFF_FFFF_FFFFu64;

		write_48_big_endian(&mut buf, v);

		let r = read_48_big_endian(&buf);

		assert_eq!(r, v);
	}
