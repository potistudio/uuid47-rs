//! SIMD-accelerated implementations for UUID parsing and formatting.
//!
//! This module provides ARM NEON (aarch64) optimized implementations.
//! Enabled via the `simd` feature flag.

#![allow(unsafe_code)]

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
use std::arch::aarch64::*;

/// SIMD-accelerated hex string to bytes conversion (ARM NEON).
///
/// Parses 32 hex characters into 16 bytes using NEON vector operations.
///
/// # Safety
///
/// - `input` must contain exactly 32 valid hex characters (0-9, a-f, A-F).
/// - Caller must ensure the input is valid before calling this function.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn parse_hex_simd(input: &[u8]) -> Option<[u8; 16]> {
	debug_assert!(input.len() == 32);

	// Load 32 hex chars as two 16-byte vectors
	let v0 = vld1q_u8(input.as_ptr());
	let v1 = vld1q_u8(input.as_ptr().add(16));

	// Character class detection constants
	let zero = vdupq_n_u8(b'0');
	let nine = vdupq_n_u8(b'9');
	let a_lower = vdupq_n_u8(b'a');
	let f_lower = vdupq_n_u8(b'f');
	let a_upper = vdupq_n_u8(b'A');
	let f_upper = vdupq_n_u8(b'F');

	// Process first 16 chars (v0)
	let nibbles0 = convert_hex_to_nibbles_neon(v0, zero, nine, a_lower, f_lower, a_upper, f_upper)?;

	// Process second 16 chars (v1)
	let nibbles1 = convert_hex_to_nibbles_neon(v1, zero, nine, a_lower, f_lower, a_upper, f_upper)?;

	// Combine nibble pairs into bytes
	// nibbles0 contains [h0, l0, h1, l1, h2, l2, h3, l3, h4, l4, h5, l5, h6, l6, h7, l7]
	// We want bytes [h0<<4|l0, h1<<4|l1, ...]
	let bytes0 = combine_nibbles_neon(nibbles0);
	let bytes1 = combine_nibbles_neon(nibbles1);

	// Store results
	let mut result = [0u8; 16];
	vst1_u8(result.as_mut_ptr(), bytes0);
	vst1_u8(result.as_mut_ptr().add(8), bytes1);

	Some(result)
}

/// Convert hex ASCII to nibble values using NEON.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
unsafe fn convert_hex_to_nibbles_neon(
	v: uint8x16_t,
	zero: uint8x16_t,
	nine: uint8x16_t,
	a_lower: uint8x16_t,
	f_lower: uint8x16_t,
	a_upper: uint8x16_t,
	f_upper: uint8x16_t,
) -> Option<uint8x16_t> {
	// Check if digit (0-9)
	let is_digit = vandq_u8(vcgeq_u8(v, zero), vcleq_u8(v, nine));

	// Check if lowercase (a-f)
	let is_lower = vandq_u8(vcgeq_u8(v, a_lower), vcleq_u8(v, f_lower));

	// Check if uppercase (A-F)
	let is_upper = vandq_u8(vcgeq_u8(v, a_upper), vcleq_u8(v, f_upper));

	// Validate: all chars must be in one of these categories
	let valid = vorrq_u8(vorrq_u8(is_digit, is_lower), is_upper);

	// Check if all bytes are valid (all bits set to 0xFF)
	let valid_arr: [u8; 16] = std::mem::transmute(valid);
	if !valid_arr.iter().all(|&b| b == 0xFF) {
		return None;
	}

	// Convert to nibble values
	// digit: v - '0'
	// lower: v - 'a' + 10
	// upper: v - 'A' + 10
	let digit_val = vsubq_u8(v, zero);
	let lower_val = vaddq_u8(vsubq_u8(v, a_lower), vdupq_n_u8(10));
	let upper_val = vaddq_u8(vsubq_u8(v, a_upper), vdupq_n_u8(10));

	// Select based on character class
	let result = vbslq_u8(
		is_digit,
		digit_val,
		vbslq_u8(is_lower, lower_val, upper_val),
	);

	Some(result)
}

/// Combine nibble pairs into bytes using NEON.
/// Input: [h0, l0, h1, l1, h2, l2, h3, l3, h4, l4, h5, l5, h6, l6, h7, l7]
/// Output: [h0<<4|l0, h1<<4|l1, h2<<4|l2, h3<<4|l3, h4<<4|l4, h5<<4|l5, h6<<4|l6, h7<<4|l7]
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
unsafe fn combine_nibbles_neon(nibbles: uint8x16_t) -> uint8x8_t {
	// Deinterleave: get high nibbles (even indices) and low nibbles (odd indices)
	let deinterleaved = vuzpq_u8(nibbles, nibbles);
	let high_nibbles = vget_low_u8(deinterleaved.0); // h0, h1, h2, h3, h4, h5, h6, h7
	let low_nibbles = vget_low_u8(deinterleaved.1); // l0, l1, l2, l3, l4, l5, l6, l7

	// Shift high nibbles left by 4 and OR with low nibbles
	let shifted = vshl_n_u8::<4>(high_nibbles);
	vorr_u8(shifted, low_nibbles)
}

/// SIMD-accelerated bytes to hex string conversion (ARM NEON).
///
/// Converts 16 bytes into 32 hex characters using NEON vector operations.
///
/// # Safety
///
/// - `output` must have at least 32 bytes of space.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn format_hex_simd(input: &[u8; 16], output: &mut [u8]) {
	debug_assert!(output.len() >= 32);

	// Load input bytes
	let bytes = vld1q_u8(input.as_ptr());

	// Split into high and low nibbles
	let high_nibbles = vshrq_n_u8::<4>(bytes);
	let low_nibbles = vandq_u8(bytes, vdupq_n_u8(0x0F));

	// Interleave: [h0, l0, h1, l1, ...]
	let interleaved = vzipq_u8(high_nibbles, low_nibbles);

	// Convert nibbles to ASCII hex
	let hex0 = nibbles_to_ascii_neon(interleaved.0);
	let hex1 = nibbles_to_ascii_neon(interleaved.1);

	// Store results
	vst1q_u8(output.as_mut_ptr(), hex0);
	vst1q_u8(output.as_mut_ptr().add(16), hex1);
}

/// Convert nibble values to ASCII hex characters using NEON.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[inline]
unsafe fn nibbles_to_ascii_neon(nibbles: uint8x16_t) -> uint8x16_t {
	let nine = vdupq_n_u8(9);
	let is_digit = vcleq_u8(nibbles, nine);

	// digit: nibble + '0'
	// alpha: nibble - 10 + 'a'
	let as_digit = vaddq_u8(nibbles, vdupq_n_u8(b'0'));
	let as_alpha = vaddq_u8(vsubq_u8(nibbles, vdupq_n_u8(10)), vdupq_n_u8(b'a'));

	vbslq_u8(is_digit, as_digit, as_alpha)
}

// Fallback for non-SIMD or non-aarch64 builds
#[cfg(not(all(feature = "simd", target_arch = "aarch64")))]
#[inline]
pub(crate) fn parse_hex_simd(_input: &[u8]) -> Option<[u8; 16]> {
	// This function should never be called in non-SIMD builds
	// The caller should use the scalar implementation instead
	None
}

#[cfg(not(all(feature = "simd", target_arch = "aarch64")))]
#[inline]
pub(crate) fn format_hex_simd(_input: &[u8; 16], _output: &mut [u8]) {
	// This function should never be called in non-SIMD builds
	// The caller should use the scalar implementation instead
}

#[cfg(test)]
mod tests {
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	use super::*;

	#[test]
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	fn test_parse_hex_simd() {
		unsafe {
			// Test lowercase
			let input = b"0123456789abcdef0123456789abcdef";
			let result = parse_hex_simd(input).unwrap();
			assert_eq!(
				result,
				[
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef
				]
			);

			// Test uppercase
			let input = b"0123456789ABCDEF0123456789ABCDEF";
			let result = parse_hex_simd(input).unwrap();
			assert_eq!(
				result,
				[
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef
				]
			);
		}
	}

	#[test]
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	fn test_format_hex_simd() {
		unsafe {
			let input = [
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef,
			];
			let mut output = [0u8; 32];
			format_hex_simd(&input, &mut output);
			assert_eq!(&output, b"0123456789abcdef0123456789abcdef");
		}
	}
}
