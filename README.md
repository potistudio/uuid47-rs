# UUIDv47-rs — A Rust implementation of UUIDv47

This is a Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47)  
> uuidv47 lets you store sortable UUIDv7 in your database while emitting a UUIDv4‑looking façade at your API boundary. It XOR‑masks only the UUIDv7 timestamp field with a keyed SipHash‑2‑4 stream derived from the UUID’s own random bits. The mapping is deterministic and exactly invertible.

## Installation

```shell
cargo add uuidv47
```

## Build

```shell
git clone https://github.com/potistudio/uuidv47-rs.git
cd uuidv47-rs
cargo build
```

## License

MIT License

## Credit

- [@Stateless](https://github.com/stateless-me) - Original UUIDv47 Implementation.
