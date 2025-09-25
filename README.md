# UUIDv47-rs — A Rust implementation of UUIDv47

This library provides useful features that convert between UUIDv7 and UUIDv4

- Wraps all API in safe Rust.
- Provides comfortable object-oriented API.

This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47)
> uuidv47 lets you store sortable UUIDv7 in your database while emitting a UUIDv4‑looking façade at your API boundary. It XOR‑masks only the UUIDv7 timestamp field with a keyed SipHash‑2‑4 stream derived from the UUID’s own random bits. The mapping is deterministic and exactly invertible.

## Installation

```shell
cargo add uuidv47
```

## Usage

```rust
use uuidv47::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let s = "00000000-0000-7000-8000-000000000000";

  // Parse str to UUIDv7
  // error if provided string is invalid
  let v7 = uuid_parse(s.as_bytes())?;

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
```

```text
7(DB)   : 00000000-0000-7000-8000-000000000000
v4(API) : 22d97126-9609-4000-8000-000000000000
back    : 00000000-0000-7000-8000-000000000000
```

## Development

```shell
git clone https://github.com/potistudio/uuidv47-rs.git
cd uuidv47-rs

cargo test
cargo run
```

## License

This library is released under the [MIT License](LICENSE).

## Credit

This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47) developed by [@Stateless](https://github.com/stateless-me).
