# UUID47-rs — A Rust implementation of UUIDv47

![GitHub License](https://img.shields.io/github/license/potistudio/uuid47-rs)
![GitHub Release](https://img.shields.io/github/v/release/potistudio/uuid47-rs)

A simple and lightweight library for converting between UUIDv7 and UUIDv4 facade.  
This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47)

> uuidv47 lets you store sortable UUIDv7 in your database while emitting a UUIDv4‑looking façade at your API boundary. It XOR‑masks only the UUIDv7 timestamp field with a keyed SipHash‑2‑4 stream derived from the UUID’s own random bits. The mapping is deterministic and exactly invertible.[^1]

## Features

- **🛡 Safe**: Implemented all APIs in safe Rust.
- **🔰 Easy**: Provides simple object-oriented API.
- **🚀 Fast**: Designed to eliminate overhead and run at high performance.
- **📦 Lightweight** Zero dependencies.

## Benchmarks

All benchmarks were measured on

- CPU: AMD Ryzen 5 5600X
- RAM: DDR4 2133MHz
- rustc: v1.90.0
- OS: Windows 10 22H2

```text
encode_as_v4facade      time: 12.435 ns
decode_from_v4facade    time: 11.906 ns
parse_uuid              time: 13.681 ns
format_uuid             time: 45.141 ns
```

## Installation

```shell
cargo add uuid47
```

## Usage

```rust
use uuid47::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let s = "00000000-0000-7000-8000-000000000000";  // your UUIDv7 string
  let key = UuidV47Key::new(0x0123456789abcdef, 0xfedcba9876543210);  // your 128-bit key

  // Parse str to UUIDv7
  // error if provided string is invalid
  let v7: Uuid128 = s.parse()?;
  println!("v7(DB)  : {}", v7);

  // Encode UUIDv7 to UUIDv4 facade
  let facade = v7.encode_as_v4facade(&key);
  println!("v4(API) : {}", facade);

  // Decode UUIDv4 facade to UUIDv7
  let back = facade.decode_from_v4facade(&key);
  println!("back    : {}", back);

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
git clone https://github.com/potistudio/uuid47-rs.git
cd uuid47-rs

cargo test  # Run test
cargo run --example basic  # Run example
```

## Contributing

Bug reports and pull requests are welcome on GitHub.

## License

This library is released under the [MIT License](LICENSE).

## Credits

This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47) developed by [@Stateless](https://github.com/stateless-me).

[^1]: <https://github.com/stateless-me/uuidv47>
