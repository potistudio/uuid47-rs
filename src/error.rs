/// An error which could be returned when parsing `Uuid128`.
///
/// This occurs when the `FromStr` implementation of `Uuid128` fails.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum UuidParseError {
	/// The input string length is invalid.<br>
	/// A valid UUID string should be 36 characters long.
	InvalidLength,

	/// The input string contains invalid hexadecimal characters.<br>
	/// A valid UUID string should only contain hexadecimal characters (0-9, a-f, A-F) and hyphens.
	InvalidHex,
}

impl std::fmt::Display for UuidParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			UuidParseError::InvalidLength => write!(f, "Invalid length for UUID string (should be 36)"),
			UuidParseError::InvalidHex => write!(f, "Invalid hex character in UUID string"),
		}
	}
}

impl std::error::Error for UuidParseError { }

/// Error type representing a failure to validate bytes as a UUID."
#[derive(Debug)]
pub enum UuidValidationError {
	/// The input bytes do not represent a valid UUID version<br>
	/// Valid versions are 4 (random) and 7 (time-ordered).
	InvalidVersion,

	/// The input bytes do not represent a valid UUID variant<br>
	/// Valid variant is RFC 4122 (the variant used by UUIDv4 and UUIDv7).
	InvalidVariant,
}

impl std::fmt::Display for UuidValidationError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			UuidValidationError::InvalidVersion => write!(f, "Invalid version in UUID bytes. Must be 4 or 7"),
			UuidValidationError::InvalidVariant => write!(f, "Invalid variant in UUID bytes. Must be RFC 4122 variant"),
		}
	}
}

impl std::error::Error for UuidValidationError { }
