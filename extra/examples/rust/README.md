# Rust example

Hand-declared `extern "C"` FFI over the ABI in [`nfdump.h`](../../../src/libnfdump/nfdump.h) —
see `src/main.rs`'s module doc for why it's hand-declared (no `bindgen`)
and why `nfdump_status_t`/`nfdump_field_id_t` are modeled as plain `i32`
constants rather than Rust `enum`s. Zero crate dependencies, so `cargo
build` never needs network access.

## Usage sketch

```rust
let mut reader = Reader::open(path)?;
while let Ok(Some(_record)) = reader.next_record() {
    let proto = reader.get_u8(field::PROTO).unwrap_or_default();
    let src = reader.get_addr(field::SRC_ADDR).map(|a| a.to_string()).unwrap_or_default();
    let dst = reader.get_addr(field::DST_ADDR).map(|a| a.to_string()).unwrap_or_default();
    let src_port = reader.get_u16(field::SRC_PORT).unwrap_or_default();
    let dst_port = reader.get_u16(field::DST_PORT).unwrap_or_default();
    let packets = reader.get_u64(field::IN_PACKETS).unwrap_or_default();
    let bytes = reader.get_u64(field::IN_BYTES).unwrap_or_default();
    println!("proto={proto} {src}:{src_port} -> {dst}:{dst_port}  packets={packets} bytes={bytes}");
}
// reader is closed automatically when it goes out of scope (see below)
```

(`Reader` and `field` are the small wrapper and constants module defined
in `src/main.rs` — see that file for the real thing, and `nfdump(3)` for
the full contract.)

## Build & run

```
cargo build
./target/debug/read_flows <nfcapd-file> [max]
```

`build.rs` prefers an installed nfdump, found via `pkg-config` (invoked
directly with `std::process::Command`, no `pkg-config` crate needed). If
`pkg-config` can't find it, it falls back to the default install prefix
(`/usr/local`); if nfdump isn't there either, the build fails with a
normal linker error. This crate never reaches into the nfdump source
tree, so it builds identically whether or not you happen to be inside a
checkout of it. Override the fallback prefix with `PREFIX=/opt/nfdump
cargo build` if yours lives elsewhere.

The installed library resolves its own dependencies at run time, so no
loader-path environment variable is needed either way.

The `Reader` type in `src/main.rs` owns the `nfdump_reader_t*` and closes
it in `Drop`, so a normal Rust scope/`drop()` is enough — no explicit
close call needed, matching the RAII idiom Rust FFI code is expected to
use for a C handle with an explicit lifetime.
