# nfdump read ABI examples

These small readers use the public libnfdump ABI from C, Python, Rust, Go,
and Lua. Each prints file metadata, demonstrates field introspection, and
iterates common 5-tuple and counter fields.

The complete API contract is in src/libnfdump/nfdump.h and `nfdump(3)`.
Each language directory's own README has a short usage sketch — a few
lines showing the shape of the API in that language — before its build
instructions.

## Build and run

Every example resolves nfdump the same way, independently of the nfdump
source tree — none of them reach into `../../../src/...` or need to be
built from inside a checkout:

1. **Installed, found automatically.** C, Rust, and Go (by default) use
   `pkg-config`; Python and Lua use the normal per-platform library
   search (`ctypes.util.find_library`/a bare `ffi.load` name).
2. **Installed at the default prefix (`/usr/local`), found directly**,
   if step 1 didn't find it.
3. **Fails**, clearly, if nfdump isn't at either — a compiler/linker
   error for C/Rust/Go, an `OSError`/Lua `error()` for Python/Lua.

Once resolved, the installed library resolves its own private
dependencies (`libnffile`) at run time on its own — no loader-path
environment variable needed for any of them:

    cd c      && make                          && ./read_flows <nfdump-file>
    cd python && python3 read_flows.py <nfdump-file>
    cd rust   && cargo build                    && ./target/debug/read_flows <nfdump-file>
    cd go     && go build -o read_flows .        && ./read_flows <nfdump-file>
    cd lua    && luajit read_flows.lua <nfdump-file>

Go is the one exception to step 1's automatic `pkg-config` preference:
cgo's `#cgo` directives are static, and a `pkg-config` miss there is a
hard build failure rather than a skippable check, so `go/main.go`
defaults straight to step 2 — see `go/README.md` for how to point it at
`pkg-config` or a non-default prefix instead.

Each language directory's README has the exact environment-variable
override (`PREFIX`/`NFDUMP_LIB`/`PKG_CONFIG`) if your install lives
somewhere unusual.

## Language choices

- c: direct header and library use
- python: standard-library ctypes
- rust: hand-written extern "C" declarations
- go: cgo over the public header
- lua: LuaJIT FFI

The Python, Rust, and Lua declarations mirror the public header. When the ABI
changes, update those mirrors and run their examples.
