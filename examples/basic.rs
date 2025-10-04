use uuid47::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let s = "00000000-0000-7000-8000-000000000000";  // your UUIDv7 string
	let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);  // your 128-bit key

	// Parse str to UUIDv7
	// error if provided string is invalid
	let v7: Uuid128 = s.parse()?;
	println!("v7(DB)  : {}", v7);

	// Encode UUIDv7 to UUIDv4 facade
	let facade = v7.encode_to_v7(&key);
	println!("v4(API) : {}", facade);

	// Decode UUIDv4 facade to UUIDv7
	let back = facade.decode_from_v4facade(&key);
	println!("back    : {}", back);

	Ok(())
}
