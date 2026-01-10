//! SIMD-accelerated implementations for UUID parsing and formatting.
//!
//! This module provides the unified interface for parsing and formatting UUIDs.
//! It automatically selects the best implementation:
//! - x86_64: AVX2 (runtime detected) > SSE/SSSE3 > Scalar
//! - aarch64: ARM NEON > Scalar
//! - Other: Scalar fallback

use crate::error::UuidParseError;

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
mod aarch64;

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod x86_64;

#[cfg_attr(any(
	all(feature = "simd", target_arch = "aarch64"),
	all(feature = "simd", target_arch = "x86_64")
), allow(unused))]
mod scalar;

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
use aarch64::{format_hex_simd, parse_hex_simd};

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
use x86_64::{format_hex_runtime, parse_hex_runtime};

/// Parse a UUID string (36 chars, with dashes) into 16 bytes.
///
/// Handles validation and selects the optimal parsing strategy.
#[inline(always)]
pub fn parse_uuid_str(uuid_string: &str) -> Result<[u8; 16], UuidParseError> {
	// expects xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if uuid_string.len() != 36 {
		return Err(UuidParseError::InvalidLength);
	}

	let s = uuid_string.as_bytes();

	// Validate dashes at fixed positions
	if s[8] != b'-' || s[13] != b'-' || s[18] != b'-' || s[23] != b'-' {
		return Err(UuidParseError::InvalidHex);
	}

	// x86_64 SIMD path with runtime AVX2/SSE detection
	#[cfg(all(feature = "simd", target_arch = "x86_64"))]
	{
		// Strip dashes and create 32-byte hex input
		let mut hex_input = [0u8; 32];

		// Unroll copy for performance
		hex_input[0..8].copy_from_slice(&s[0..8]);
		hex_input[8..12].copy_from_slice(&s[9..13]);
		hex_input[12..16].copy_from_slice(&s[14..18]);
		hex_input[16..20].copy_from_slice(&s[19..23]);
		hex_input[20..32].copy_from_slice(&s[24..36]);

		// Use runtime dispatch (AVX2 if available, else SSE)
		match parse_hex_runtime(&hex_input) {
			Some(bytes) => return Ok(bytes),
			None => return Err(UuidParseError::InvalidHex),
		}
	}

	// aarch64 SIMD path
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	{
		// Strip dashes and create 32-byte hex input
		let mut hex_input = [0u8; 32];

		hex_input[0..8].copy_from_slice(&s[0..8]);
		hex_input[8..12].copy_from_slice(&s[9..13]);
		hex_input[12..16].copy_from_slice(&s[14..18]);
		hex_input[16..20].copy_from_slice(&s[19..23]);
		hex_input[20..32].copy_from_slice(&s[24..36]);

		// SAFETY: hex_input is exactly 32 bytes.
		match unsafe { parse_hex_simd(&hex_input) } {
			Some(bytes) => return Ok(bytes),
			None => return Err(UuidParseError::InvalidHex),
		}
	}

	// Scalar fallback path
	#[cfg(not(any(
		all(feature = "simd", target_arch = "aarch64"),
		all(feature = "simd", target_arch = "x86_64")
	)))]
	{
		scalar::parse_hex_scalar(s)
	}
}

/// Format 16 bytes into a UUID buffer (36 chars, with dashes).
///
/// Selects the optimal formatting strategy.
#[inline(always)]
pub fn format_uuid_buf(bytes: &[u8; 16], buf: &mut [u8; 36]) {
	// x86_64 SIMD path with runtime AVX2/SSE detection
	#[cfg(all(feature = "simd", target_arch = "x86_64"))]
	{
		let mut hex_buf = [0u8; 32];
		// Use runtime dispatch (AVX2 if available, else SSE)
		format_hex_runtime(bytes, &mut hex_buf);

		// Insert hex chars with dashes
		buf[0..8].copy_from_slice(&hex_buf[0..8]);
		buf[8] = b'-';
		buf[9..13].copy_from_slice(&hex_buf[8..12]);
		buf[13] = b'-';
		buf[14..18].copy_from_slice(&hex_buf[12..16]);
		buf[18] = b'-';
		buf[19..23].copy_from_slice(&hex_buf[16..20]);
		buf[23] = b'-';
		buf[24..36].copy_from_slice(&hex_buf[20..32]);
	}

	// aarch64 SIMD path
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	{
		let mut hex_buf = [0u8; 32];
		// SAFETY: bytes is exactly 16 bytes, hex_buf is 32 bytes
		unsafe { format_hex_simd(bytes, &mut hex_buf) };

		buf[0..8].copy_from_slice(&hex_buf[0..8]);
		buf[8] = b'-';
		buf[9..13].copy_from_slice(&hex_buf[8..12]);
		buf[13] = b'-';
		buf[14..18].copy_from_slice(&hex_buf[12..16]);
		buf[18] = b'-';
		buf[19..23].copy_from_slice(&hex_buf[16..20]);
		buf[23] = b'-';
		buf[24..36].copy_from_slice(&hex_buf[20..32]);
	}

	// Scalar fallback path
	#[cfg(not(any(
		all(feature = "simd", target_arch = "aarch64"),
		all(feature = "simd", target_arch = "x86_64")
	)))]
	{
		scalar::format_hex_scalar(bytes, buf)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Basic litmus test to ensure the facade works
	#[test]
	fn test_facade_parse_format() {
		let uuid_str = "01234567-89ab-cdef-0123-456789abcdef";
		let bytes = parse_uuid_str(uuid_str).unwrap();

		let mut buf = [0u8; 36];
		format_uuid_buf(&bytes, &mut buf);
		let out_str = std::str::from_utf8(&buf).unwrap();

		assert_eq!(uuid_str, out_str);
	}
}
