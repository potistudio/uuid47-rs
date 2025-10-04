use crate::error::*;
use crate::utils::*;
use crate::key::UuidV47Key;

/// A 128-bit UUID (UUIDv4 or UUIDv7).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Uuid128 {
	bytes: [u8; 16],
}

impl Uuid128 {
	/// Create an empty UUIDv7
	///
	/// all bytes excluding version and variant bits are initialized with zero.
	///
	/// # Examples
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// assert_eq!(uuid.to_string(), "00000000-0000-7000-8000-000000000000");
	/// ```
	pub fn empty() -> Self {
		let mut out = Self{ bytes: [0u8; 16] };
		out.set_version(7);
		out.set_variant_rfc4122();

		out
	}

	/// Create a UUID from raw 16 bytes
	///
	/// Always validate version and variant bits.<br>
	/// Returns an error if the bytes do not represent a valid UUIDv4 or UUIDv7 (RFC 4122).
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, UuidValidationError> {
		// Accept only version 4 or 7
		let version = (bytes[6] >> 4) & 0x0F;
		if version != 4 && version != 7 {
			return Err(UuidValidationError::InvalidVersion);
		}

		// Variant: bits 6-7 of byte 8 must be 10xxxxxx (RFC 4122)
		let variant = (bytes[8] & 0xC0) >> 6;
		if variant != 0b10 {
			return Err(UuidValidationError::InvalidVariant);
		}

		Ok(Self { bytes })
	}

	/// Create a UUID from raw 16 bytes **without validating**.
	///
	/// # Safety
	///
	/// The caller must ensure the bytes represent a valid UUID (version and variant bits).<br>
	/// Prefer using [`Uuid128::from_bytes`] for safe construction.
	pub unsafe fn new(bytes: [u8; 16]) -> Self {
		Self{ bytes }
	}

	/// Get this UUID version.
	///
	/// Returns 4 for UUIDv4, 7 for UUIDv7, or other values for invalid versions.
	pub fn uuid_version(&self) -> u8 {
		(&self.bytes[6] >> 4) & 0x0F
	}

	/// Set the UUID version (4 or 7).
	///
	/// set the version bits (4 bits) in byte 6.
	fn set_version(&mut self, ver: u8) {
		self.bytes[6] = (self.bytes[6] & 0x0F) | ((ver & 0x0F) << 4);
	}

	/// Set the UUID variant to RFC 4122 (10xxxxxx in byte 8).
	///
	/// set the variant bits (2 bits) in byte 8.
	fn set_variant_rfc4122(&mut self) {
		self.bytes[8] = (self.bytes[8] & 0x3F) | 0x80;
	}

	/// Encode this UUIDv7 into UUIDv4 facade using UuidV47Key.
	#[inline(always)]
	pub fn uuidv47_encode_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		//* 1. SipHash24(key, v7.random74bits) -> take low 48 bits */
		let mut sipmsg = [0u8; 10];

		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

		//* 2. Encode timestamp */
		let encoded_timestamp = read_48_big_endian((self.bytes[0..6]).try_into().unwrap()) ^ mask48;

		//* 3. Build v4 facade */
		// Use dereference copy instead of "from_bytes" to ensure performance optimization
		// let mut out = Uuid128::from_bytes(v7.b); <- STUPID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian((&mut out.bytes[0..6]).try_into().unwrap(), encoded_timestamp);

		out.set_version(4);  // facade
		out.set_variant_rfc4122();  // ensure RFC variant bits

		out
	}

	/// Decode this UUIDv4 facade back into UUIDv7 using UuidV47Key.
	#[inline(always)]
	pub fn uuidv47_decode_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		// 1. rebuild same Sip input from facade (identical bytes)
		let mut sipmsg = [0u8; 10];
		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0, key.k1) & 0x0000_FFFF_FFFF_FFFFu64;

		// 2. ts = encTS ^ mask
		// Force slice to fixed-size (should not panic)
		let ts48 = read_48_big_endian((self.bytes[0..6]).try_into().unwrap()) ^ mask48;

		// 3. restore v7: write ts, set ver=7, set variant
		// Use dereference copy instead of "from_bytes" to ensure performance optimization
		// let mut result = Uuid128::from_bytes(v7.b); <- STUPID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian((&mut out.bytes[0..6]).try_into().unwrap(), ts48);

		out.set_version(7);
		out.set_variant_rfc4122();
		out
	}
}

impl std::str::FromStr for Uuid128 {
	type Err = UuidParseError;

	/// Parse the string slice into a `Uuid128`.
	///
	/// The valid UUID format is 8-4-4-4-12 hex string with dashes.
	/// E.g. "550e8400-e29b-41d4-a716-446655440000"
	#[inline(always)]
	fn from_str(uuid_string: &str) -> Result<Self, Self::Err> {
		// expects xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		const IDXS: [usize; 32] = [
			0, 1, 2, 3, 4, 5, 6, 7,
			9, 10, 11, 12, 14, 15, 16, 17,
			19, 20, 21, 22,
			24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
		];

		if uuid_string.len() != 36 {
			return Err(UuidParseError::InvalidLength);
		}

		let mut b = [0u8; 16];
		for i in 0..16 {
			let h = hexval(&uuid_string.as_bytes()[IDXS[i * 2]]);
			let l = hexval(&uuid_string.as_bytes()[IDXS[i * 2 + 1]]);

			if h < 0 || l < 0 {
				return Err(UuidParseError::InvalidHex);
			}

			b[i] = ((h << 4) | l) as u8;
		}

		Ok(Uuid128{ bytes: b })
	}
}

impl std::fmt::Display for Uuid128 {
	/// Format the UUID into standard 8-4-4-4-12 hex string with dashes.
	///
	/// A `std::fmt::Result` indicating success or failure of the formatting operation.
	///
	/// # Examples
	///
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// assert_eq!(uuid.to_string(), "00000000-0000-7000-8000-000000000000");
	/// ```
	#[inline(always)]
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		const HEXD: &[u8; 16] = b"0123456789abcdef";
		let mut j = 0usize;

		let mut out = [0u8; 37];
		out[36] = 0;
		for i in 0..16 {
			if i == 4 || i == 6 || i == 8 || i == 10 {
				out[j] = b'-';
				j += 1;
			}
			let byte = self.bytes[i];
			out[j] = HEXD[((byte >> 4) & 0x0F) as usize];
			j += 1;
			out[j] = HEXD[(byte & 0x0F) as usize];
			j += 1;
		}

		write!(f, "{}", unsafe{ std::str::from_utf8_unchecked(&out[..36]) })
	}
}

#[inline(always)]
fn build_sip_input_from_v7(u: &Uuid128, msg: &mut [u8; 10]) {
	// [low-nibble of b6][b7][b8&0x3F][b9..b15]
	msg[0] = u.bytes[6] & 0x0F;
	msg[1] = u.bytes[7];
	msg[2] = u.bytes[8] & 0x3F;
	msg[3..10].copy_from_slice(&u.bytes[9..16]);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_version_variant() {
		let mut u = Uuid128::empty();

		u.set_version(7);
		assert_eq!(u.uuid_version(), 7);

		u.set_version(4);
		assert_eq!(u.uuid_version(), 4);

		u.set_variant_rfc4122();
		assert_eq!((u.bytes[8] & 0xC0), 0x80);
	}

	fn craft_v7(uuid: &mut Uuid128, ts_ms_48: u64, rand_a_12: u16, rand_b_62: u64) {
		uuid.bytes.fill(0);
		write_48_big_endian(&mut uuid.bytes[0..6].try_into().unwrap(), ts_ms_48 & 0x0000FFFFFFFFFFFF);
		uuid.set_version(7);
		uuid.bytes[6] = (uuid.bytes[6] & 0xF0) | ((rand_a_12 >> 8) as u8 & 0x0F);
		uuid.bytes[7] = (rand_a_12 & 0xFF) as u8;
		uuid.set_variant_rfc4122();
		uuid.bytes[8] = (uuid.bytes[8] & 0xC0) | ((rand_b_62 >> 56) as u8 & 0x3F);
		for i in 0..7 {
			uuid.bytes[9 + i] = ((rand_b_62 >> (8 * (6 - i))) & 0xFF) as u8;
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
			assert_eq!(u7.uuid_version(), 7);  // ensure manual creation worked

			let facade = u7.uuidv47_encode_v4facade(&key);
			assert_eq!(facade.uuid_version(), 4);  // ensure version
			assert_eq!((facade.bytes[8] & 0xC0), 0x80);  // ensure RFC variant

			let back = facade.uuidv47_decode_v4facade(&key);
			assert_eq!(u7, back);

			let wrong = UuidV47Key { k0: key.k0 ^ 0xdeadbeef, k1: key.k1 ^ 0x1337 };
			let bad = facade.uuidv47_decode_v4facade(&wrong);
			assert_ne!(u7, bad);
		}
	}
}
