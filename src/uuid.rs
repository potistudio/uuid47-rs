use crate::err::*;
use crate::utils::*;
use crate::UuidV47Key;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Uuid128 {
	pub b: [u8; 16],
}

impl Uuid128 {
	pub fn empty() -> Self {
		Self { b: [0u8; 16] }
	}

	pub fn uuid_version(&self) -> u8 {
		(&self.b[6] >> 4) & 0x0F
	}

	fn set_version(&mut self, ver: u8) {
		self.b[6] = (self.b[6] & 0x0F) | ((ver & 0x0F) << 4);
	}

	fn set_variant_rfc4122(&mut self) {
		// 10xxxxxx
		self.b[8] = (self.b[8] & 0x3F) | 0x80;
	}

	#[inline(always)]
	pub fn uuidv47_encode_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		//* 1. SipHash24(key, v7.random74bits) -> take low 48 bits */
		let mut sipmsg = [0u8; 10];

		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

		//* 2. Encode timestamp */
		let encoded_timestamp = read_48_big_endian((self.b[0..6]).try_into().unwrap()) ^ mask48;

		//* 3. Build v4 facade */
		// Use dereference copy instead of "from_bytes" to ensure performance optimization
		// let mut out = Uuid128::from_bytes(v7.b); <- STUPID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian((&mut out.b[0..6]).try_into().unwrap(), encoded_timestamp);

		out.set_version(4);  // facade
		out.set_variant_rfc4122();  // ensure RFC variant bits

		out
	}

	#[inline(always)]
	pub fn uuidv47_decode_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		// 1. rebuild same Sip input from façade (identical bytes)
		let mut sipmsg = [0u8; 10];
		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

		// 2. ts = encTS ^ mask
		// Force slice to fixed-size (should not panic)
		let ts48 = read_48_big_endian((self.b[0..6]).try_into().unwrap()) ^ mask48;

		// 3. restore v7: write ts, set ver=7, set variant
		// Use dereference copy instead of "from_bytes" to ensure performance optimization
		// let mut result = Uuid128::from_bytes(v7.b); <- STUPID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian((&mut out.b[0..6]).try_into().unwrap(), ts48);

		out.set_version(7);
		out.set_variant_rfc4122();
		out
	}
}

/// Parse UUID from standard 8-4-4-4-12 hex string with dashes.
/// Returns error if string is not valid UUID format.
impl std::str::FromStr for Uuid128 {
	type Err = UuidParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		crate::internal::uuid_parse(s.as_bytes())
	}
}

/// Format UUID into standard 8-4-4-4-12 hex string with dashes.
/// Assumes input is valid UUID (16 bytes).
/// Output buffer must be at least 37 bytes (36 chars + null terminator).
impl std::fmt::Display for Uuid128 {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let out = crate::internal::uuid_format(self);

		write!(f, "{}", unsafe{ std::str::from_utf8_unchecked(&out[..36]) })
	}
}

#[inline(always)]
fn build_sip_input_from_v7(u: &Uuid128, msg: &mut [u8; 10]) {
	// [low-nibble of b6][b7][b8&0x3F][b9..b15]
	msg[0] = u.b[6] & 0x0F;
	msg[1] = u.b[7];
	msg[2] = u.b[8] & 0x3F;
	msg[3..10].copy_from_slice(&u.b[9..16]);
}

#[cfg(test)]
mod tests {
	use super::*;

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
			let mut u7 = Uuid128::empty();
			let timestamp = ((0x100000 * i as u64) + 123) as u64;
			let random = ((0x0AAA ^ (i * 7) as u32) & 0x0FFF) as u16;
			let rb = (0x0123456789ABCDEF ^ (0x1111111111111111 * i as u64)) & ((1 << 62) - 1);

			craft_v7(&mut u7, timestamp, random, rb);
			assert!(u7.uuid_version() == 7);  // ensure manual creation worked

			let facade = u7.uuidv47_encode_v4facade(&key);
			assert!(facade.uuid_version() == 4);  // ensure version
			assert!((facade.b[8] & 0xC0) == 0x80);  // ensure RFC variant

			let back = facade.uuidv47_decode_v4facade(&key);
			assert_eq!(u7.b, back.b);

			let wrong = UuidV47Key { k0: key.k0 ^ 0xdeadbeef, k1: key.k1 ^ 0x1337 };
			let bad = facade.uuidv47_decode_v4facade(&wrong);
			assert_ne!(u7, bad);
		}
	}

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
		let bad1 = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";  // invalid hex
		assert!(matches!(bad1.parse::<Uuid128>(), Err(UuidParseError::InvalidHex)));

		let bad2 = "00000000-0000-7000-8000-00000000000";  // too short
		assert!(matches!(bad2.parse::<Uuid128>(), Err(UuidParseError::TooShort)));
	}

	#[test]
	fn test_version_variant() {
		let mut u = Uuid128::empty();

		u.set_version(7);
		assert!(u.uuid_version() == 7);

		u.set_version(4);
		assert!(u.uuid_version() == 4);

		u.set_variant_rfc4122();
		assert!((u.b[8] & 0xC0) == 0x80);
	}
}
