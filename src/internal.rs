use crate::uuid::*;
use crate::err::*;
use crate::utils::*;

/// Format UUID into standard 8-4-4-4-12 hex string with dashes.
/// Assumes input is valid UUID (16 bytes).
/// Output buffer must be at least 37 bytes (36 chars + null terminator).
#[inline(always)]
pub(super) fn uuid_format(u: &Uuid128) -> [u8; 37] {
	const HEXD: &[u8; 16] = b"0123456789abcdef";
	let mut j = 0usize;

	let mut out = [0u8; 37];
	out[36] = 0;
	for i in 0..16 {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = b'-';
			j += 1;
		}
		let byte = u.b[i];
		out[j] = HEXD[((byte >> 4) & 0x0F) as usize];
		j += 1;
		out[j] = HEXD[(byte & 0x0F) as usize];
		j += 1;
	}

	out
}

#[inline(always)]
pub(super) fn uuid_parse(string_bytes: &[u8]) -> Result<Uuid128, UuidParseError> {
	// expects xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	const IDXS: [usize; 32] = [
		0, 1, 2, 3, 4, 5, 6, 7,
		9, 10, 11, 12, 14, 15, 16, 17,
		19, 20, 21, 22,
		24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	];

	if string_bytes.len() < 36 {
		return Err(UuidParseError::TooShort);
	}

	let mut b = [0u8; 16];
	for i in 0..16 {
		let h = hexval(&string_bytes[IDXS[i * 2]]);
		let l = hexval(&string_bytes[IDXS[i * 2 + 1]]);

		if h < 0 || l < 0 {
			return Err(UuidParseError::InvalidHex);
		}

		b[i] = ((h << 4) | l) as u8;
	}

	Ok(Uuid128{ b })
}
