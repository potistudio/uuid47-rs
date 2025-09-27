use uuidv47::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let s = "00000000-0000-7000-8000-000000000000";

	// Parse str to UUIDv7
	// error if provided string is invalid
	let v7: Uuid128 = s.parse()?;

	// Provide your keys
	let key = UuidV47Key { k0: 0x0123456789abcdef, k1: 0xfedcba9876543210 };

	// Encode UUIDv7 to UUIDv4 facade
	let facade = v7.uuidv47_encode_v4facade(&key);

	// Decode UUIDv4 facade to UUIDv7
	let back = facade.uuidv47_decode_v4facade(&key);

	// UUIDv7 in your DB
	let a = v7.to_string();
	println!("v7(DB)  : {}", a);

	// Facade into UUIDv4
	let b = facade.to_string();
	println!("v4(API) : {}", b);

	// Back into UUIDv7 from UUIDv4
	let c = back.to_string();
	println!("back    : {}", c);

	Ok(())
}
