/// Key structure for `UUIDv47` encoding/decoding.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct UuidV47Key {
	/// First 64 bits of the key.
	pub k0: u64,

	/// Second 64 bits of the key.
	pub k1: u64,
}

impl UuidV47Key {
	/// Creates a new key.
	#[must_use]
	pub fn new(k0: u64, k1: u64) -> Self {
		Self { k0, k1 }
	}
}
