use uuidv47::*;

#[test]
fn test_uuid_parse_format_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
	// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
	let s = "00000000-0000-7000-8000-000000000000";

	let u: Uuid128 = s.parse()?;
	assert_eq!(u.uuid_version(), 7);

	let out = u.to_string();
	assert_eq!(s, out);

	let u2: Uuid128 = out.parse()?;
	assert_eq!(u, u2);

	Ok(())
}

#[test]
fn test_bad_uuid_parse() {
	let invalid_hex = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";  // invalid hex
	assert!(matches!(invalid_hex.parse::<Uuid128>(), Err(UuidParseError::InvalidHex)));

	let invalid_layout = "000000000-000-7000-8000-000000000000";  // invalid layout
	assert!(matches!(invalid_layout.parse::<Uuid128>(), Err(UuidParseError::InvalidHex)));

	let too_short = "00000000-0000-7000-8000-00000000000";  // too short
	assert!(matches!(too_short.parse::<Uuid128>(), Err(UuidParseError::InvalidLength)));

	let too_long = "00000000-0000-7000-8000-0000000000000";  // too long
	assert!(matches!(too_long.parse::<Uuid128>(), Err(UuidParseError::InvalidLength)));
}
