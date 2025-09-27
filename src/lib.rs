//! A Rust implementation of UUIDv47 that converts between UUIDv7 and UUIDv4.

#![deny(missing_docs)]
#![warn(clippy::all)]

mod uuid;
mod key;
mod error;
mod utils;

pub use uuid::Uuid128;
pub use key::UuidV47Key;
pub use error::{ UuidParseError, UuidValidationError };
