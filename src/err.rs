/// This is a library-specific error for UUID parsing failures.
#[derive(Debug)]
pub enum UuidParseError {
	/// The input string is too short to be a valid UUID
	TooShort,

	/// The input string contains invalid hexadecimal characters
	InvalidHex,
}

impl std::fmt::Display for UuidParseError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			UuidParseError::TooShort => write!(f, "UUID string is too short"),
			UuidParseError::InvalidHex => write!(f, "Invalid hex character in UUID string"),
		}
	}
}

impl std::error::Error for UuidParseError { }
