use std::str;
use uuidv47::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let s = "00000000-0000-7000-8000-000000000000";

	// Parse str to UUIDv7
	// error if provided string is invalid
	let v7: Uuid128 = s.parse()?;

	// Provide your keys
	let key = UuidV47Key { k0: 0x0123456789abcdef, k1: 0xfedcba9876543210 };

	// Encode UUIDv7 to UUIDv4 facade
	let facade = uuidv47_encode_v4facade(&v7, &key);

	// Decode UUIDv4 facade to UUIDv7
	let back = uuidv47_decode_v4facade(&facade, &key);

	// UUIDv7 in your DB
	let mut a: [u8; 37] = [0u8; 37];
	uuid_format(&v7, &mut a);
	println!("v7(DB)  : {}", str::from_utf8(&a[..36])?);

	// Facade into UUIDv4
	let mut b: [u8; 37] = [0u8; 37];
	uuid_format(&facade, &mut b);
	println!("v4(API) : {}", str::from_utf8(&b[..36])?);

	// Back into UUIDv7 from UUIDv4
	let mut c: [u8; 37] = [0u8; 37];
	uuid_format(&back, &mut c);
	println!("back    : {}", str::from_utf8(&c[..36])?);

	Ok(())
}
