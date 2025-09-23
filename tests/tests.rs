#[cfg(test)]
mod tests {
	use uuidv47::*;

	#[inline(always)]
	fn write_48_big_endian(dst: &mut [u8; 6], v48: u64) {
		dst[0] = (v48 >> 40) as u8;
		dst[1] = (v48 >> 32) as u8;
		dst[2] = (v48 >> 24) as u8;
		dst[3] = (v48 >> 16) as u8;
		dst[4] = (v48 >> 8) as u8;
		dst[5] = (v48 >> 0) as u8;
	}

	#[inline(always)]
	pub fn read_48_big_endian(src: &[u8; 6]) -> u64 {
		((src[0] as u64) << 40)
			| ((src[1] as u64) << 32)
			| ((src[2] as u64) << 24)
			| ((src[3] as u64) << 16)
			| ((src[4] as u64) << 8)
			| ((src[5] as u64) << 0)
	}

	#[test]
	fn test_rd_wr_48() {
		let mut buf = [0u8; 6];
		let v: u64 = 0x01_23_45_67_89_ABu64 & 0x0000_FFFF_FFFF_FFFFu64;
		write_48_big_endian(&mut buf, v);
		let r: u64 = read_48_big_endian(&buf);
		assert_eq!(r, v);
	}

	#[test]
	fn test_uuid_parse_format_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
		// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
		let s = "00000000-0000-7000-8000-000000000000";

		let u = uuid_parse(s.as_bytes())?;
		assert_eq!(u.uuid_version(), 7);

		let mut out = [0u8; 37];
		uuid_format(&u, &mut out);

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
