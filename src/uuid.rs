use crate::error::UuidParseError;
use crate::key::UuidV47Key;
use crate::utils::{read_48_big_endian, siphash24, write_48_big_endian};

/// A 128-bit UUID (`UUIDv4` or `UUIDv7`).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Uuid128 {
	bytes: [u8; 16],
}

impl Uuid128 {
	/// Create an empty `UUIDv7`
	///
	/// all bytes excluding version and variant bits are initialized with zero.
	///
	/// # Examples
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// assert_eq!(uuid.to_string(), "00000000-0000-7000-8000-000000000000");
	/// ```
	#[must_use]
	pub fn empty() -> Self {
		let mut out = Self { bytes: [0u8; 16] };
		out.set_version(7);
		out.set_variant_rfc4122();

		out
	}

	/// Create a UUID from raw 16 bytes
	///
	/// Always validate version and variant bits.<br>
	/// Returns an error if the bytes do not represent a valid `UUIDv4` or `UUIDv7` (RFC 4122).
	///
	/// # Errors
	///
	/// * [`UuidParseError::InvalidVersion`] - if the version is not 4 or 7.
	/// * [`UuidParseError::InvalidVariant`] - if the variant is not RFC 4122.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, UuidParseError> {
		// Accept only version 4 or 7
		let version = (bytes[6] >> 4) & 0x0F;
		if version != 4 && version != 7 {
			return Err(UuidParseError::InvalidVersion);
		}

		// Variant: bits 6-7 of byte 8 must be 10xxxxxx (RFC 4122)
		let variant = (bytes[8] & 0xC0) >> 6;
		if variant != 0b10 {
			return Err(UuidParseError::InvalidVariant);
		}

		Ok(Self { bytes })
	}

	/// Create a UUID from raw 16 bytes **without validating**.
	///
	/// This is a `const fn` that performs no validation. The caller is responsible
	/// for ensuring the bytes represent a valid UUID (version and variant bits).
	///
	/// Prefer using [`Uuid128::from_bytes`] for safe construction with validation.
	///
	/// # Examples
	///
	/// ```
	/// // Known-valid UUID bytes
	/// let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
	///              0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
	/// let uuid = uuid47::Uuid128::from_bytes_unchecked(bytes);
	/// assert_eq!(uuid.uuid_version(), 7);
	/// ```
	#[must_use]
	#[inline]
	pub const fn from_bytes_unchecked(bytes: [u8; 16]) -> Self {
		Self { bytes }
	}

	/// Get this UUID version.
	///
	/// Returns 4 for `UUIDv4`, 7 for `UUIDv7`, or other values for invalid versions.
	#[must_use]
	pub fn uuid_version(&self) -> u8 {
		(self.bytes[6] >> 4) & 0x0F
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

	/// Encode this `UUIDv7` into `UUIDv4` facade using `UuidV47Key`.
	///
	/// # Panics
	///
	/// This function does not validate the input `UUIDv7`.
	/// So, invalid input may occur panic.
	#[must_use]
	#[inline]
	pub fn encode_as_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		// 1. SipHash24(key, v7.random74bits) -> take low 48 bits */
		let mut sipmsg = [0u8; 10];

		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0(), key.k1()) & 0x0000_FFFF_FFFF_FFFFu64;

		// 2. Encode timestamp
		let encoded_timestamp = read_48_big_endian((self.bytes[0..6]).try_into().unwrap()) ^ mask48;

		// 3. Build v4 facade
		// Use dereference copy - validation not needed since we're transforming a known-valid UUID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian(
			(&mut out.bytes[0..6]).try_into().unwrap(),
			encoded_timestamp,
		);

		out.set_version(4); // facade
		out.set_variant_rfc4122(); // ensure RFC variant bits

		out
	}

	/// Decode this `UUIDv4` facade back into `UUIDv7` using `UuidV47Key`.
	///
	/// # Panics
	///
	/// This function does not validate the input `UUIDv4` facade.
	/// So, invalid input may occur panic.
	#[must_use]
	#[inline]
	pub fn decode_from_v4facade(&self, key: &UuidV47Key) -> Uuid128 {
		// 1. rebuild same Sip input from facade (identical bytes)
		let mut sipmsg = [0u8; 10];
		build_sip_input_from_v7(self, &mut sipmsg);
		let mask48 = siphash24(&sipmsg, key.k0(), key.k1()) & 0x0000_FFFF_FFFF_FFFFu64;

		// 2. ts = encTS ^ mask
		// Force slice to fixed-size (should not panic)
		let ts48 = read_48_big_endian((self.bytes[0..6]).try_into().unwrap()) ^ mask48;

		// 3. restore v7: write ts, set ver=7, set variant
		// Use dereference copy - validation not needed since we're transforming a known-valid UUID
		let mut out = *self;

		// Force slice to fixed-size (should not panic)
		write_48_big_endian((&mut out.bytes[0..6]).try_into().unwrap(), ts48);

		out.set_version(7);
		out.set_variant_rfc4122();
		out
	}

	/// Format the UUID into a 36-byte buffer directly (no heap allocation).
	///
	/// # Performance
	///
	/// This method is significantly faster than [`to_string()`](std::string::ToString::to_string)
	/// because it avoids heap allocation. Use this when performance is critical.
	///
	/// # Examples
	///
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// let mut buf = [0u8; 36];
	/// uuid.format_to_buf(&mut buf);
	/// assert_eq!(&buf, b"00000000-0000-7000-8000-000000000000");
	/// ```
	#[inline]
	pub fn format_to_buf(&self, buf: &mut [u8; 36]) {
		crate::simd::format_uuid_buf(&self.bytes, buf);
	}

	/// Format the UUID and return it as a UTF-8 string slice.
	///
	/// This writes to the provided buffer and returns a `&str` view into it.
	///
	/// # Performance
	///
	/// This method is significantly faster than [`to_string()`](std::string::ToString::to_string)
	/// because it avoids heap allocation. Use this when performance is critical.
	///
	/// # Examples
	///
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// let mut buf = [0u8; 36];
	/// let s = uuid.format_to_str(&mut buf);
	/// assert_eq!(s, "00000000-0000-7000-8000-000000000000");
	/// ```
	#[inline]
	pub fn format_to_str<'a>(&self, buf: &'a mut [u8; 36]) -> &'a str {
		self.format_to_buf(buf);
		// SAFETY: format_to_buf only writes ASCII hex and '-'
		unsafe { std::str::from_utf8_unchecked(buf) }
	}

	/// Get the raw 16-byte representation of this UUID.
	///
	/// # Examples
	///
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// let bytes = uuid.as_bytes();
	/// assert_eq!(bytes[6] >> 4, 7); // version 7
	/// ```
	#[must_use]
	#[inline]
	pub fn as_bytes(&self) -> &[u8; 16] {
		&self.bytes
	}

	/// Consume this UUID and return the raw 16-byte array.
	///
	/// # Examples
	///
	/// ```
	/// let uuid = uuid47::Uuid128::empty();
	/// let bytes: [u8; 16] = uuid.into_bytes();
	/// assert_eq!(bytes[6] >> 4, 7); // version 7
	/// ```
	#[must_use]
	#[inline]
	pub fn into_bytes(self) -> [u8; 16] {
		self.bytes
	}
}

impl std::str::FromStr for Uuid128 {
	type Err = UuidParseError;

	/// Parse the string slice into a `Uuid128`.
	///
	/// The valid UUID format is 8-4-4-4-12 hex string with dashes.
	/// E.g. "550e8400-e29b-41d4-a716-446655440000"
	#[inline]
	fn from_str(uuid_string: &str) -> Result<Self, Self::Err> {
		let bytes = crate::simd::parse_uuid_str(uuid_string)?;
		Self::from_bytes(bytes)
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
	#[inline]
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut buf = [0u8; 36];
		// Use the optimized format_to_buf (handles SIMD/Scalar)
		self.format_to_buf(&mut buf);
		// SAFETY: format_to_buf produces valid ASCII
		let s = unsafe { std::str::from_utf8_unchecked(&buf) };
		f.write_str(s)
	}
}

#[inline]
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
		write_48_big_endian(
			&mut uuid.bytes[0..6].try_into().unwrap(),
			ts_ms_48 & 0x0000FFFFFFFFFFFF,
		);
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
		let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);

		for i in 0..16 {
			let mut u7 = Uuid128::empty();
			let timestamp = (0x100000 * i as u64) + 123;
			let random = ((0x0AAA ^ (i * 7) as u32) & 0x0FFF) as u16;
			let rb = (0x0123456789ABCDEF ^ (0x1111111111111111 * i as u64)) & ((1 << 62) - 1);

			craft_v7(&mut u7, timestamp, random, rb);
			assert_eq!(u7.uuid_version(), 7); // ensure manual creation worked

			let facade = u7.encode_as_v4facade(&key);
			assert_eq!(facade.uuid_version(), 4); // ensure version
			assert_eq!((facade.bytes[8] & 0xC0), 0x80); // ensure RFC variant

			let back = facade.decode_from_v4facade(&key);
			assert_eq!(u7, back);

			let wrong = UuidV47Key::new(key.k0() ^ 0xdeadbeef, key.k1() ^ 0x1337);
			let bad = facade.decode_from_v4facade(&wrong);
			assert_ne!(u7, bad);
		}
	}
}
