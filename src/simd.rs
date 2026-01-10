//! SIMD-accelerated implementations for UUID parsing and formatting.
//!
//! This module provides ARM NEON (aarch64) optimized implementations.
//! Enabled via the `simd` feature flag.

#![allow(unsafe_code)]

#[cfg(all(feature = "simd", target_arch = "aarch64"))]
use std::arch::aarch64::*;

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
use std::arch::x86_64::*;

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

// ============================================================================
// x86_64 SSE2/SSSE3 Implementation
// ============================================================================

/// SIMD-accelerated hex string to bytes conversion (x86_64 SSE2/SSSE3).
///
/// Parses 32 hex characters into 16 bytes using SSE vector operations.
///
/// # Safety
///
/// - `input` must contain exactly 32 valid hex characters (0-9, a-f, A-F).
/// - Caller must ensure the input is valid before calling this function.
/// - Requires SSE2 and SSSE3 support.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
pub(crate) unsafe fn parse_hex_simd(input: &[u8]) -> Option<[u8; 16]> {
	debug_assert!(input.len() == 32);

	// Load 32 hex chars as two 16-byte vectors
	let v0 = _mm_loadu_si128(input.as_ptr() as *const __m128i);
	let v1 = _mm_loadu_si128(input.as_ptr().add(16) as *const __m128i);

	// Process first 16 chars
	let nibbles0 = convert_hex_to_nibbles_sse(v0)?;

	// Process second 16 chars
	let nibbles1 = convert_hex_to_nibbles_sse(v1)?;

	// Combine nibble pairs into bytes using SSSE3 shuffle
	let bytes0 = combine_nibbles_sse(nibbles0);
	let bytes1 = combine_nibbles_sse(nibbles1);

	// Store results
	let mut result = [0u8; 16];
	_mm_storel_epi64(result.as_mut_ptr() as *mut __m128i, bytes0);
	_mm_storel_epi64(result.as_mut_ptr().add(8) as *mut __m128i, bytes1);

	Some(result)
}

/// Convert hex ASCII to nibble values using SSE2.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
unsafe fn convert_hex_to_nibbles_sse(v: __m128i) -> Option<__m128i> {
	// Character class detection constants
	let zero = _mm_set1_epi8(b'0' as i8);
	let nine = _mm_set1_epi8(b'9' as i8);
	let a_lower = _mm_set1_epi8(b'a' as i8);
	let f_lower = _mm_set1_epi8(b'f' as i8);
	let a_upper = _mm_set1_epi8(b'A' as i8);
	let f_upper = _mm_set1_epi8(b'F' as i8);

	// Check if digit (0-9): v >= '0' && v <= '9'
	let ge_zero = _mm_cmpgt_epi8(v, _mm_sub_epi8(zero, _mm_set1_epi8(1)));
	let le_nine = _mm_cmpgt_epi8(_mm_add_epi8(nine, _mm_set1_epi8(1)), v);
	let is_digit = _mm_and_si128(ge_zero, le_nine);

	// Check if lowercase (a-f): v >= 'a' && v <= 'f'
	let ge_a_lower = _mm_cmpgt_epi8(v, _mm_sub_epi8(a_lower, _mm_set1_epi8(1)));
	let le_f_lower = _mm_cmpgt_epi8(_mm_add_epi8(f_lower, _mm_set1_epi8(1)), v);
	let is_lower = _mm_and_si128(ge_a_lower, le_f_lower);

	// Check if uppercase (A-F): v >= 'A' && v <= 'F'
	let ge_a_upper = _mm_cmpgt_epi8(v, _mm_sub_epi8(a_upper, _mm_set1_epi8(1)));
	let le_f_upper = _mm_cmpgt_epi8(_mm_add_epi8(f_upper, _mm_set1_epi8(1)), v);
	let is_upper = _mm_and_si128(ge_a_upper, le_f_upper);

	// Validate: all chars must be in one of these categories
	let valid = _mm_or_si128(_mm_or_si128(is_digit, is_lower), is_upper);

	// Check if all bytes are valid (all bits set to 0xFF)
	if _mm_movemask_epi8(valid) != 0xFFFF {
		return None;
	}

	// Convert to nibble values
	// digit: v - '0'
	// lower: v - 'a' + 10
	// upper: v - 'A' + 10
	let digit_val = _mm_sub_epi8(v, zero);
	let lower_val = _mm_add_epi8(_mm_sub_epi8(v, a_lower), _mm_set1_epi8(10));
	let upper_val = _mm_add_epi8(_mm_sub_epi8(v, a_upper), _mm_set1_epi8(10));

	// Select based on character class using blendv emulation
	// result = is_digit ? digit_val : (is_lower ? lower_val : upper_val)
	let lower_or_upper = _mm_or_si128(
		_mm_and_si128(is_lower, lower_val),
		_mm_andnot_si128(is_lower, upper_val),
	);
	let result = _mm_or_si128(
		_mm_and_si128(is_digit, digit_val),
		_mm_andnot_si128(is_digit, lower_or_upper),
	);

	Some(result)
}

/// Combine nibble pairs into bytes using SSSE3 shuffle.
/// Input: [h0, l0, h1, l1, h2, l2, h3, l3, h4, l4, h5, l5, h6, l6, h7, l7]
/// Output (low 8 bytes): [h0<<4|l0, h1<<4|l1, h2<<4|l2, h3<<4|l3, h4<<4|l4, h5<<4|l5, h6<<4|l6, h7<<4|l7]
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
unsafe fn combine_nibbles_sse(nibbles: __m128i) -> __m128i {
	// Shuffle to separate even (high nibbles) and odd (low nibbles) indices
	// Even indices: 0, 2, 4, 6, 8, 10, 12, 14 -> positions 0-7
	// Odd indices:  1, 3, 5, 7, 9, 11, 13, 15 -> positions 8-15
	let shuffle_mask = _mm_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15);

	let shuffled = _mm_shuffle_epi8(nibbles, shuffle_mask);

	// High nibbles are now in low 8 bytes, low nibbles in high 8 bytes
	// Shift high nibbles left by 4
	let high_shifted = _mm_slli_epi16(shuffled, 4);

	// Move high 8 bytes (low nibbles) to low position
	let low_nibbles = _mm_srli_si128(shuffled, 8);

	// Mask to keep only lower nibble of each byte after shift
	let mask_low = _mm_set1_epi8(0x0F);
	let mask_high = _mm_set1_epi8(0xF0_u8 as i8);

	// Combine: (high_shifted & 0xF0) | (low_nibbles & 0x0F)
	let high_masked = _mm_and_si128(high_shifted, mask_high);
	let low_masked = _mm_and_si128(low_nibbles, mask_low);

	_mm_or_si128(high_masked, low_masked)
}

/// SIMD-accelerated bytes to hex string conversion (x86_64 SSE2/SSSE3).
///
/// Converts 16 bytes into 32 hex characters using SSE vector operations.
///
/// # Safety
///
/// - `output` must have at least 32 bytes of space.
/// - Requires SSE2 and SSSE3 support.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
pub(crate) unsafe fn format_hex_simd(input: &[u8; 16], output: &mut [u8]) {
	debug_assert!(output.len() >= 32);

	// Load input bytes
	let bytes = _mm_loadu_si128(input.as_ptr() as *const __m128i);

	// Split into high and low nibbles
	let mask_0f = _mm_set1_epi8(0x0F);
	let high_nibbles = _mm_and_si128(_mm_srli_epi16(bytes, 4), mask_0f);
	let low_nibbles = _mm_and_si128(bytes, mask_0f);

	// Interleave high and low nibbles: [h0, l0, h1, l1, ...]
	let interleaved_lo = _mm_unpacklo_epi8(high_nibbles, low_nibbles);
	let interleaved_hi = _mm_unpackhi_epi8(high_nibbles, low_nibbles);

	// Convert nibbles to ASCII hex using lookup table
	// LUT: "0123456789abcdef"
	let hex_lut = _mm_setr_epi8(
		b'0' as i8,
		b'1' as i8,
		b'2' as i8,
		b'3' as i8,
		b'4' as i8,
		b'5' as i8,
		b'6' as i8,
		b'7' as i8,
		b'8' as i8,
		b'9' as i8,
		b'a' as i8,
		b'b' as i8,
		b'c' as i8,
		b'd' as i8,
		b'e' as i8,
		b'f' as i8,
	);

	let hex0 = _mm_shuffle_epi8(hex_lut, interleaved_lo);
	let hex1 = _mm_shuffle_epi8(hex_lut, interleaved_hi);

	// Store results
	_mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, hex0);
	_mm_storeu_si128(output.as_mut_ptr().add(16) as *mut __m128i, hex1);
}

// ============================================================================
// Fallback implementations for non-SIMD or unsupported architectures
// ============================================================================

// Fallback for non-SIMD builds
#[cfg(not(any(
	all(feature = "simd", target_arch = "aarch64"),
	all(feature = "simd", target_arch = "x86_64")
)))]
#[inline]
pub(crate) fn parse_hex_simd(_input: &[u8]) -> Option<[u8; 16]> {
	// This function should never be called in non-SIMD builds
	// The caller should use the scalar implementation instead
	None
}

#[cfg(not(any(
	all(feature = "simd", target_arch = "aarch64"),
	all(feature = "simd", target_arch = "x86_64")
)))]
#[inline]
pub(crate) fn format_hex_simd(_input: &[u8; 16], _output: &mut [u8]) {
	// This function should never be called in non-SIMD builds
	// The caller should use the scalar implementation instead
}

#[cfg(test)]
mod tests {
	#[cfg(all(feature = "simd", target_arch = "aarch64"))]
	use super::*;

	#[cfg(all(feature = "simd", target_arch = "x86_64"))]
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

	// x86_64 SSE2/SSSE3 tests
	#[test]
	#[cfg(all(feature = "simd", target_arch = "x86_64"))]
	fn test_parse_hex_simd_x86() {
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

			// Test mixed case
			let input = b"0123456789AbCdEf0123456789aBcDeF";
			let result = parse_hex_simd(input).unwrap();
			assert_eq!(
				result,
				[
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef
				]
			);

			// Test invalid input
			let input = b"0123456789abcdefghijklmnopqrstuv";
			let result = parse_hex_simd(input);
			assert!(result.is_none());
		}
	}

	#[test]
	#[cfg(all(feature = "simd", target_arch = "x86_64"))]
	fn test_format_hex_simd_x86() {
		unsafe {
			let input = [
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef,
			];
			let mut output = [0u8; 32];
			format_hex_simd(&input, &mut output);
			assert_eq!(&output, b"0123456789abcdef0123456789abcdef");

			// Test all zeros
			let input = [0u8; 16];
			let mut output = [0u8; 32];
			format_hex_simd(&input, &mut output);
			assert_eq!(&output, b"00000000000000000000000000000000");

			// Test all 0xFF
			let input = [0xffu8; 16];
			let mut output = [0u8; 32];
			format_hex_simd(&input, &mut output);
			assert_eq!(&output, b"ffffffffffffffffffffffffffffffff");
		}
	}
}

