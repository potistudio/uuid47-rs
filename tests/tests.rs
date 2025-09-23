#[cfg(test)]
mod tests {
	use uuidv47::*;

	#[test]
	fn test_rd_wr_48() {
		let mut buf = [0u8; 6];
		let v: u64 = 0x01_23_45_67_89_ABu64 & 0x0000_FFFF_FFFF_FFFFu64;
		wr48be(&mut buf, v);
		let r: u64 = rd48be(&buf);
		assert_eq!(r, v);
	}

	#[test]
	fn test_uuid_parse_format_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
		// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
		let s = "00000000-0000-7000-8000-000000000000";

		let u = uuid_parse(s.as_bytes())?;
		assert_eq!(uuid_version(&u), 7);

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

		set_version(&mut u, 7);
		assert!(uuid_version(&u) == 7);

		set_variant_rfc4122(&mut u);
		assert!((u.b[8] & 0xC0) == 0x80);
	}
}
