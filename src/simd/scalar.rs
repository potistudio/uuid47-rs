use crate::error::UuidParseError;

/// 256-entry lookup table for hex decoding. Returns -1 for invalid chars.
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

/// O(1) hex character to value lookup using precomputed table.
#[inline(always)]
pub(crate) fn hexval(c: u8) -> Option<u8> {
	let v = HEX_DECODE_TABLE[c as usize];
	if v < 0 {
		None
	} else {
		Some(v as u8)
	}
}

// 256 entries, each entry is 2 bytes (byte value -> two ascii hex chars)
const HEX_PAIR_TABLE: [[u8; 2]; 256] = {
	const fn make_table() -> [[u8; 2]; 256] {
		let mut t = [[0u8; 2]; 256];
		let mut i = 0usize;
		while i < 256 {
			let hi = (i >> 4) & 0xF;
			let lo = i & 0xF;
			// ascii for hex nibble
			let hi_ch = if hi < 10 {
				b'0' + hi as u8
			} else {
				b'a' + (hi as u8 - 10)
			};
			let lo_ch = if lo < 10 {
				b'0' + lo as u8
			} else {
				b'a' + (lo as u8 - 10)
			};
			t[i] = [hi_ch, lo_ch];
			i += 1;
		}
		t
	}
	make_table()
};

/// Scalar implementation of hex string parsing.
///
/// Expects a 36-byte string with dashes: 8-4-4-4-12.
#[inline(always)]
pub(crate) fn parse_hex_scalar(s: &[u8]) -> Result<[u8; 16], UuidParseError> {
	let mut b = [0u8; 16];
	let mut byte_idx = 0;

	// Unrolled parsing for better performance
	// Parse segments: 8-4-4-4-12
	for &(start, end) in &[(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)] {
		let mut i = start;
		while i < end {
			let h = hexval(s[i]).ok_or(UuidParseError::InvalidHex)?;
			let l = hexval(s[i + 1]).ok_or(UuidParseError::InvalidHex)?;
			b[byte_idx] = (h << 4) | l;
			byte_idx += 1;
			i += 2;
		}
	}

	Ok(b)
}

/// Scalar implementation of bytes to hex string formatting.
#[inline(always)]
pub(crate) fn format_hex_scalar(bytes: &[u8; 16], buf: &mut [u8; 36]) {
	let b = bytes;
	// Use unsafe ptr::copy_nonoverlapping for optimal codegen
	// SAFETY: buf is 36 bytes, HEX_PAIR_TABLE matches bounds.
	unsafe {
		let dst = buf.as_mut_ptr();

		// Segment 1: bytes 0-3 (8 hex chars) -> out[0..8]
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[0] as usize].as_ptr(), dst, 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[1] as usize].as_ptr(), dst.add(2), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[2] as usize].as_ptr(), dst.add(4), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[3] as usize].as_ptr(), dst.add(6), 2);
		*dst.add(8) = b'-';

		// Segment 2: bytes 4-5 (4 hex chars) -> out[9..13]
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[4] as usize].as_ptr(), dst.add(9), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[5] as usize].as_ptr(), dst.add(11), 2);
		*dst.add(13) = b'-';

		// Segment 3: bytes 6-7 (4 hex chars) -> out[14..18]
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[6] as usize].as_ptr(), dst.add(14), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[7] as usize].as_ptr(), dst.add(16), 2);
		*dst.add(18) = b'-';

		// Segment 4: bytes 8-9 (4 hex chars) -> out[19..23]
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[8] as usize].as_ptr(), dst.add(19), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[9] as usize].as_ptr(), dst.add(21), 2);
		*dst.add(23) = b'-';

		// Segment 5: bytes 10-15 (12 hex chars) -> out[24..36]
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[10] as usize].as_ptr(), dst.add(24), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[11] as usize].as_ptr(), dst.add(26), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[12] as usize].as_ptr(), dst.add(28), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[13] as usize].as_ptr(), dst.add(30), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[14] as usize].as_ptr(), dst.add(32), 2);
		std::ptr::copy_nonoverlapping(HEX_PAIR_TABLE[b[15] as usize].as_ptr(), dst.add(34), 2);
	}
}
