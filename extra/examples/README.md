# nfdump read ABI examples

These small readers use the public libnfdump ABI from C, Python, Rust, Go,
and Lua. Each prints file metadata, demonstrates field introspection, and
iterates common 5-tuple and counter fields.

The complete API contract is in src/libnfdump/nfdump.h and nfdump(3).

## Build against this source tree

Build nfdump first. The examples use the in-tree libraries, so the dynamic
loader must also find libnfdump and its libnffile dependency.

    cd c
    make
    make run FILE=<nfdump-file>

    cd ../python
    python3 read_flows.py <nfdump-file>

    cd ../rust
    cargo build
    DYLD_LIBRARY_PATH=../../../src/libnfdump/.libs:../../../src/libnffile/.libs \
        ./target/debug/read_flows <nfdump-file>

    cd ../go
    go build -o read_flows .
    LD_LIBRARY_PATH=../../../src/libnfdump/.libs:../../../src/libnffile/.libs \
        ./read_flows <nfdump-file>

    cd ../lua
    luajit read_flows.lua <nfdump-file>

Use LD_LIBRARY_PATH on Linux and DYLD_LIBRARY_PATH on macOS. Each language
directory has its exact build requirements and supports the documented
environment override when the nfdump tree is elsewhere.

## Build after installation

C applications should use pkg-config:

    cc $(pkg-config --cflags nfdump) -o read_flows read_flows.c \
       $(pkg-config --libs nfdump)

The installed library resolves its private dependencies normally; no loader
path override is needed.

## Language choices

- c: direct header and library use
- python: standard-library ctypes
- rust: hand-written extern "C" declarations
- go: cgo over the public header
- lua: LuaJIT FFI

The Python, Rust, and Lua declarations mirror the public header. When the ABI
changes, update those mirrors and run their examples.
