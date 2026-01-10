use zeroize::Zeroize;

/// Key structure for `UUIDv47` encoding/decoding.
///
/// This type implements `Zeroize` to securely erase key material on drop.
/// It deliberately does NOT implement `Copy` because bitwise copying would
/// defeat the purpose of secure erasure.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct UuidV47Key {
	/// First 64 bits of the key.
	k0: u64,

	/// Second 64 bits of the key.
	k1: u64,
}

impl UuidV47Key {
	/// Creates a new key.
	#[must_use]
	pub fn new(k0: u64, k1: u64) -> Self {
		Self { k0, k1 }
	}

	/// Returns the first 64 bits of the key.
	#[must_use]
	pub(crate) fn k0(&self) -> u64 {
		self.k0
	}

	/// Returns the second 64 bits of the key.
	#[must_use]
	pub(crate) fn k1(&self) -> u64 {
		self.k1
	}
}

impl std::fmt::Debug for UuidV47Key {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("UuidV47Key").finish_non_exhaustive()
	}
}

impl PartialEq for UuidV47Key {
	/// Constant-time comparison to prevent timing side-channel attacks.
	///
	/// Uses XOR to accumulate differences - if any bit differs, the result
	/// is non-zero. This takes the same amount of time regardless of where
	/// the first difference occurs.
	fn eq(&self, other: &Self) -> bool {
		let diff = (self.k0 ^ other.k0) | (self.k1 ^ other.k1);
		// Use volatile read to prevent compiler optimizations that could
		// introduce timing variations (e.g., branch on first non-zero bit).
		// SAFETY: Reading from a valid stack variable.
		let diff = unsafe { std::ptr::read_volatile(&diff) };
		diff == 0
	}
}

impl Eq for UuidV47Key {}
