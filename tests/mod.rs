#[cfg(test)]
mod tests {
	use uuidv47_rs::*;

	#[test]
	fn test_rd_wr_48() {
		let mut buf = [0u8; 6];
		let v: u64 = 0x01_23_45_67_89_ABu64 & 0x0000_FFFF_FFFF_FFFFu64;
		wr48be(&mut buf, v);
		let r: u64 = rd48be(&buf);
		assert_eq!(r, v);
	}

	#[test]
	fn test_uuid_parse_format_roundtrip() {
		// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
		let s = "00000000-0000-7000-8000-000000000000";
		let mut u = Uuid128 { b: [0u8; 16] };

		assert!(uuid_parse(s.as_bytes(), &mut u));
		assert_eq!(uuid_version(&u), 7);

		let mut out = [0u8; 37];
		uuid_format(&u, &mut out);

		let mut u2 = Uuid128 { b: [0u8; 16] };
		assert!(uuid_parse(&out, &mut u2));
		//TODO: Equal Trait
		// assert_eq!(u, u2);

		let bad = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
		let mut t = Uuid128 { b: [0u8; 16] };
		assert!(!uuid_parse(bad.as_bytes(), &mut t));
	}
}
