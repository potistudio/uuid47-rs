//! A simple and lightweight library for converting between UUIDv7 and UUIDv4 facade.
//! This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47).
//!
//! # Features
//!
//! - **Safe**: Implemented all APIs in safe Rust.
//! - **Easy**: Provides simple object-oriented API.
//! - **Fast**: Designed to eliminate overhead and run at high performance.
//! - **Lightweight** Zero dependencies.
//!
//! # Example
//!
//! ```
//! use uuid47::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let s = "00000000-0000-7000-8000-000000000000";  // your UUIDv7 string
//!     let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);  // your 128-bit key
//!
//!     // Parse str to UUIDv7
//!     // error if provided string is invalid
//!     let v7: Uuid128 = s.parse()?;
//!     println!("v7(DB)  : {}", v7);
//!
//!     // Encode UUIDv7 to UUIDv4 facade
//!     let facade = v7.encode_as_v4facade(&key);
//!     println!("v4(API) : {}", facade);
//!
//!     // Decode UUIDv4 facade to UUIDv7
//!     let back = facade.decode_from_v4facade(&key);
//!     println!("back    : {}", back);
//!
//!     Ok(())
//! }
//! ```
//!
//! ```
//! // Output:
//! // v7(DB)  : 00000000-0000-7000-8000-000000000000
//! // v4(API) : 22d97126-9609-4000-8000-000000000000
//! // back    : 00000000-0000-7000-8000-000000000000
//! ```

#![doc(html_root_url = "https://docs.rs/uuid47/1.0.0")]

#![deny(missing_docs)]
#![deny(nonstandard_style)]
#![deny(rust_2018_idioms)]
#![deny(unused)]
#![warn(clippy::all)]

mod uuid;
mod key;
mod error;
mod utils;

pub use uuid::Uuid128;
pub use key::UuidV47Key;
pub use error::{ UuidParseError, UuidValidationError };
