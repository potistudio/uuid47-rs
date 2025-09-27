/// This is a library-specific error for UUID parsing failures.
#[derive(Debug)]
pub enum UuidParseError {
	/// The input string is too short to be a valid UUID
	InvalidLength,

	/// The input string contains invalid hexadecimal characters
	InvalidHex,
}

impl std::fmt::Display for UuidParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			UuidParseError::InvalidLength => write!(f, "Invalid length for UUID string (should be 36)"),
			UuidParseError::InvalidHex => write!(f, "Invalid hex character in UUID string"),
		}
	}
}

impl std::error::Error for UuidParseError { }

/// This is a library-specific error for UUID validation failures.
#[derive(Debug)]
pub enum UuidValidationError {
	/// The input bytes do not represent a valid UUID version
	InvalidVersion,

	/// The input bytes do not represent a valid UUID variant
	InvalidVariant,
}

impl std::fmt::Display for UuidValidationError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			UuidValidationError::InvalidVersion => write!(f, "Invalid version in UUID bytes. Must be 4 or 7"),
			UuidValidationError::InvalidVariant => write!(f, "Invalid variant in UUID bytes. Must be RFC 4122 variant"),
		}
	}
}

impl std::error::Error for UuidValidationError { }
