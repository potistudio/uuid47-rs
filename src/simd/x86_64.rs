//! SIMD-accelerated implementations for UUID parsing and formatting.
//!
//! This module provides x86_64 SSE2/SSSE3 and AVX2 optimized implementations.
//! AVX2 is preferred when available (runtime detection), with SSE as fallback.
//! Enabled via the `simd` feature flag.

use std::arch::x86_64::*;

// ============================================================================
// Runtime dispatch functions
// ============================================================================

/// Parse hex with runtime CPU feature detection.
/// Selects AVX2 or SSE/SSSE3 based on available CPU features.
#[inline]
pub(crate) fn parse_hex_runtime(input: &[u8]) -> Option<[u8; 16]> {
	if is_x86_feature_detected!("avx2") {
		// SAFETY: AVX2 support verified by is_x86_feature_detected
		unsafe { parse_hex_avx2(input) }
	} else {
		// SAFETY: SSE2/SSSE3 assumed available on all x86_64
		unsafe { parse_hex_sse(input) }
	}
}

/// Format a buffer into hex with runtime CPU feature detection. \
/// This function checks for AVX2 support at runtime using `is_x86_feature_detected!`. \
/// If AVX2 is available, it dispatches to the AVX2-optimized formatter. \
/// Otherwise, it falls back to the SSE2/SSSE3 implementation, which is assumed to be supported on all x86_64 targets. \
///
/// # Safety
/// SIMD implementation requires `unsafe` because they rely on architecture-specific intrinsics. \
/// Their usage here is considered safe because:
/// - AVX2 is only invoked after verifying CPU support.
/// - SSE2/SSSE3 are guaranteed features on all x86_64 CPUs.
#[inline]
pub(crate) fn format_hex_runtime(input: &[u8; 16], output: &mut [u8]) {
	if is_x86_feature_detected!("avx2") {
		// SAFETY: AVX2 support verified by is_x86_feature_detected
		unsafe { format_hex_avx2(input, output) }
	} else {
		// SAFETY: SSE2/SSSE3 assumed available on all x86_64
		unsafe { format_hex_sse(input, output) }
	}
}

// ============================================================================
// AVX2 Implementation (256-bit registers)
// ============================================================================

/// SIMD-accelerated hex string to bytes conversion using AVX2.
///
/// Processes all 32 hex characters in a single 256-bit register.
///
/// # Safety
///
/// - `input` must contain exactly 32 valid hex characters.
/// - Requires AVX2 support.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn parse_hex_avx2(input: &[u8]) -> Option<[u8; 16]> {
	debug_assert!(input.len() == 32);

	// Load all 32 hex chars into a single 256-bit register
	let v = _mm256_loadu_si256(input.as_ptr() as *const __m256i);

	// Character class detection constants
	let zero = _mm256_set1_epi8(b'0' as i8);
	let nine = _mm256_set1_epi8(b'9' as i8);
	let a_lower = _mm256_set1_epi8(b'a' as i8);
	let f_lower = _mm256_set1_epi8(b'f' as i8);
	let a_upper = _mm256_set1_epi8(b'A' as i8);
	let f_upper = _mm256_set1_epi8(b'F' as i8);

	// Check if digit (0-9)
	let ge_zero = _mm256_cmpgt_epi8(v, _mm256_sub_epi8(zero, _mm256_set1_epi8(1)));
	let le_nine = _mm256_cmpgt_epi8(_mm256_add_epi8(nine, _mm256_set1_epi8(1)), v);
	let is_digit = _mm256_and_si256(ge_zero, le_nine);

	// Check if lowercase (a-f)
	let ge_a_lower = _mm256_cmpgt_epi8(v, _mm256_sub_epi8(a_lower, _mm256_set1_epi8(1)));
	let le_f_lower = _mm256_cmpgt_epi8(_mm256_add_epi8(f_lower, _mm256_set1_epi8(1)), v);
	let is_lower = _mm256_and_si256(ge_a_lower, le_f_lower);

	// Check if uppercase (A-F)
	let ge_a_upper = _mm256_cmpgt_epi8(v, _mm256_sub_epi8(a_upper, _mm256_set1_epi8(1)));
	let le_f_upper = _mm256_cmpgt_epi8(_mm256_add_epi8(f_upper, _mm256_set1_epi8(1)), v);
	let is_upper = _mm256_and_si256(ge_a_upper, le_f_upper);

	// Validate all chars
	let valid = _mm256_or_si256(_mm256_or_si256(is_digit, is_lower), is_upper);
	if _mm256_movemask_epi8(valid) != -1i32 {
		return None;
	}

	// Convert to nibble values
	let digit_val = _mm256_sub_epi8(v, zero);
	let lower_val = _mm256_add_epi8(_mm256_sub_epi8(v, a_lower), _mm256_set1_epi8(10));
	let upper_val = _mm256_add_epi8(_mm256_sub_epi8(v, a_upper), _mm256_set1_epi8(10));

	// Select using blendv (AVX2 has _mm256_blendv_epi8)
	let lower_or_upper = _mm256_blendv_epi8(upper_val, lower_val, is_lower);
	let nibbles = _mm256_blendv_epi8(lower_or_upper, digit_val, is_digit);

	// Combine nibble pairs into bytes
	// Shuffle to separate high/low nibbles, then combine
	let shuffle_mask = _mm256_setr_epi8(
		0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15, 0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5,
		7, 9, 11, 13, 15,
	);
	let shuffled = _mm256_shuffle_epi8(nibbles, shuffle_mask);

	// Extract 128-bit lanes
	let lo_lane = _mm256_castsi256_si128(shuffled);
	let hi_lane = _mm256_extracti128_si256(shuffled, 1);

	// Combine nibbles within each lane
	let bytes0 = combine_nibbles_from_shuffled_sse(lo_lane);
	let bytes1 = combine_nibbles_from_shuffled_sse(hi_lane);

	// Store results
	let mut result = [0u8; 16];
	_mm_storel_epi64(result.as_mut_ptr() as *mut __m128i, bytes0);
	_mm_storel_epi64(result.as_mut_ptr().add(8) as *mut __m128i, bytes1);

	Some(result)
}

/// SIMD-accelerated bytes to hex string conversion using AVX2.
///
/// # Safety
///
/// - `output` must have at least 32 bytes of space.
/// - Requires AVX2 support.
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn format_hex_avx2(input: &[u8; 16], output: &mut [u8]) {
	debug_assert!(output.len() >= 32);

	// Load input bytes into 128-bit register, then broadcast to 256-bit
	let bytes_128 = _mm_loadu_si128(input.as_ptr() as *const __m128i);

	// Split into high and low nibbles
	let mask_0f = _mm_set1_epi8(0x0F);
	let high_nibbles = _mm_and_si128(_mm_srli_epi16(bytes_128, 4), mask_0f);
	let low_nibbles = _mm_and_si128(bytes_128, mask_0f);

	// Interleave nibbles
	let interleaved_lo = _mm_unpacklo_epi8(high_nibbles, low_nibbles);
	let interleaved_hi = _mm_unpackhi_epi8(high_nibbles, low_nibbles);

	// Combine into 256-bit register
	let nibbles_256 = _mm256_set_m128i(interleaved_hi, interleaved_lo);

	// Use AVX2 shuffle with LUT for conversion
	// LUT duplicated in both 128-bit lanes
	let hex_lut = _mm256_setr_epi8(
		b'0' as i8, b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8,
		b'7' as i8, b'8' as i8, b'9' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8,
		b'e' as i8, b'f' as i8, b'0' as i8, b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8,
		b'5' as i8, b'6' as i8, b'7' as i8, b'8' as i8, b'9' as i8, b'a' as i8, b'b' as i8,
		b'c' as i8, b'd' as i8, b'e' as i8, b'f' as i8,
	);

	let hex_chars = _mm256_shuffle_epi8(hex_lut, nibbles_256);

	// Store all 32 chars at once
	_mm256_storeu_si256(output.as_mut_ptr() as *mut __m256i, hex_chars);
}

/// Helper to combine pre-shuffled nibbles (after high/low separation).
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
unsafe fn combine_nibbles_from_shuffled_sse(shuffled: __m128i) -> __m128i {
	let high_shifted = _mm_slli_epi16(shuffled, 4);
	let low_nibbles = _mm_srli_si128(shuffled, 8);

	let mask_low = _mm_set1_epi8(0x0F);
	let mask_high = _mm_set1_epi8(0xF0_u8 as i8);

	let high_masked = _mm_and_si128(high_shifted, mask_high);
	let low_masked = _mm_and_si128(low_nibbles, mask_low);

	_mm_or_si128(high_masked, low_masked)
}

// ============================================================================
// SSE2/SSSE3 Implementation (128-bit registers) - Fallback
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
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
pub(crate) unsafe fn parse_hex_sse(input: &[u8]) -> Option<[u8; 16]> {
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
#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
pub(crate) unsafe fn format_hex_sse(input: &[u8; 16], output: &mut [u8]) {
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
		b'0' as i8, b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8,
		b'7' as i8, b'8' as i8, b'9' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8,
		b'e' as i8, b'f' as i8,
	);

	let hex0 = _mm_shuffle_epi8(hex_lut, interleaved_lo);
	let hex1 = _mm_shuffle_epi8(hex_lut, interleaved_hi);

	// Store results
	_mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, hex0);
	_mm_storeu_si128(output.as_mut_ptr().add(16) as *mut __m128i, hex1);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_hex_runtime() {
		// Test lowercase
		let input = b"0123456789abcdef0123456789abcdef";
		let result = parse_hex_runtime(input).unwrap();
		assert_eq!(
			result,
			[
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef
			]
		);

		// Test uppercase
		let input = b"0123456789ABCDEF0123456789ABCDEF";
		let result = parse_hex_runtime(input).unwrap();
		assert_eq!(
			result,
			[
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef
			]
		);

		// Test mixed case
		let input = b"0123456789AbCdEf0123456789aBcDeF";
		let result = parse_hex_runtime(input).unwrap();
		assert_eq!(
			result,
			[
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef
			]
		);

		// Test invalid input
		let input = b"0123456789abcdefghijklmnopqrstuv";
		let result = parse_hex_runtime(input);
		assert!(result.is_none());
	}

	#[test]
	fn test_format_hex_runtime() {
		let input = [
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
			0xcd, 0xef,
		];
		let mut output = [0u8; 32];
		format_hex_runtime(&input, &mut output);
		assert_eq!(&output, b"0123456789abcdef0123456789abcdef");

		// Test all zeros
		let input = [0u8; 16];
		let mut output = [0u8; 32];
		format_hex_runtime(&input, &mut output);
		assert_eq!(&output, b"00000000000000000000000000000000");

		// Test all 0xFF
		let input = [0xffu8; 16];
		let mut output = [0u8; 32];
		format_hex_runtime(&input, &mut output);
		assert_eq!(&output, b"ffffffffffffffffffffffffffffffff");
	}

	#[test]
	fn test_parse_hex_sse() {
		unsafe {
			// Test lowercase
			let input = b"0123456789abcdef0123456789abcdef";
			let result = parse_hex_sse(input).unwrap();
			assert_eq!(
				result,
				[
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
					0xab, 0xcd, 0xef
				]
			);

			// Test invalid input
			let input = b"0123456789abcdefghijklmnopqrstuv";
			let result = parse_hex_sse(input);
			assert!(result.is_none());
		}
	}

	#[test]
	fn test_format_hex_sse() {
		unsafe {
			let input = [
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef,
			];
			let mut output = [0u8; 32];
			format_hex_sse(&input, &mut output);
			assert_eq!(&output, b"0123456789abcdef0123456789abcdef");
		}
	}

	#[test]
	fn test_parse_hex_avx2() {
		if !is_x86_feature_detected!("avx2") {
			return;
		}

		let input = b"0123456789abcdef0123456789abcdef";
		let result = unsafe { parse_hex_avx2(input).unwrap() };
		assert_eq!(
			result,
			[
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
				0xcd, 0xef
			]
		);

		// Test invalid
		let input = b"0123456789abcdefghijklmnopqrstuv";
		let result = unsafe { parse_hex_avx2(input) };
		assert!(result.is_none());
	}

	/// Test AVX2 formatting
	#[test]
	fn test_format_hex_avx2() {
		if !is_x86_feature_detected!("avx2") {
			return;
		}

		let input = [
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
			0xcd, 0xef,
		];
		let mut output = [0u8; 32];
		unsafe { format_hex_avx2(&input, &mut output) };
		assert_eq!(&output, b"0123456789abcdef0123456789abcdef");
	}
}
