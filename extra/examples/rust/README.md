# Rust example

Hand-declared `extern "C"` FFI over the ABI in
[`../../../src/libnfdump/nfdump.h`](../../../src/libnfdump/nfdump.h) —
see `src/main.rs`'s module doc for why it's hand-declared (no `bindgen`)
and why `nfdump_status_t`/`nfdump_field_id_t` are modeled as plain `i32`
constants rather than Rust `enum`s. Zero crate dependencies, so `cargo
build` never needs network access.

## Build & run

```
cargo build
DYLD_LIBRARY_PATH=../../../src/libnfdump/.libs:../../../src/libnffile/.libs ./target/debug/read_flows <nfcapd-file> [max]   # macOS
LD_LIBRARY_PATH=../../../src/libnfdump/.libs:../../../src/libnffile/.libs  ./target/debug/read_flows <nfcapd-file> [max]    # Linux
```

`build.rs` points the linker at the in-tree `libnfdump` build three
directories up (this repo's own build — see the top-level [examples
README](../README.md)). Override with `NFDUMP_ROOT=/path/to/nfdump cargo
build` if yours lives elsewhere. The dynamic loader needs the same
ABI and `libnffile` dependency directories at run time too, hence the env
var above — `build.rs` only
handles link time.

The `Reader` type in `src/main.rs` owns the `nfdump_reader_t*` and closes
it in `Drop`, so a normal Rust scope/`drop()` is enough — no explicit
close call needed, matching the RAII idiom Rust FFI code is expected to
use for a C handle with an explicit lifetime.
