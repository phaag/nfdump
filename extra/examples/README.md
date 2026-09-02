# nfdump read ABI — usage examples

Small, self-contained examples calling the nfdump read ABI from five
languages: C, Python, Rust, Go, and Lua. Each opens an nfcapd/sfcapd file
read-only, prints its file-level stats, and iterates every flow record.

The ABI itself: [`src/libnffile/nfdump.h`](../../src/libnffile/nfdump.h)
— the full contract (function-by-function) lives in that header's
comments.

## Current build status (read this first)

The ABI is implemented in `nfdump.h` + `src/libnffile/nfdump_abi.c`, and
for now is compiled straight into `libnffile` — there is no separate
`libnfdump-abi` shared library with its own restricted export list yet.
It does, however, install and describe itself correctly: `make install`
puts `nfdump.h` in `$(includedir)` and `nfdump.pc` in `$(libdir)/pkgconfig`, so once
installed, `pkg-config --cflags --libs nfdump` gives a real consumer
everything it needs (`-lnffile` plus the compression/crypto/thread libs
it pulls in) — verified with a `DESTDIR` install and a program built from
nothing but those two flag sets.

The examples in this directory predate that install path and were
written for **building against this repo without installing anything**
(the common case while iterating on the ABI itself), so they still do it
the harder way:

1. link against the **in-tree build** of `libnffile` (`src/libnffile/.libs/`
   after running `make` at the repo root — build nfdump normally first),
   rather than through `pkg-config`, and
2. need the dynamic loader pointed at that same directory at **run
   time** too (`DYLD_LIBRARY_PATH` on macOS, `LD_LIBRARY_PATH` on Linux),
   since nothing is installed yet in that scenario.

Each subdirectory's build file/README follows that pattern; override the
path with the env var it names if your build lives somewhere other than
three directories up (i.e. somewhere other than this repo). If you *have*
run `make install`, the equivalent for the C example is simply:

```
cc $(pkg-config --cflags nfdump) -o read_flows read_flows.c $(pkg-config --libs nfdump)
```

with no `NFDUMP_ROOT`/`DYLD_LIBRARY_PATH` juggling needed.

## Try them

Build nfdump at the repo root first (`./configure && make`, or however
you normally build this tree), then, from this directory:

```
cd c      && make && make run FILE=<nfdump.flowfile>
cd python && python3 read_flows.py <nfdump.flowfile>
cd rust   && cargo build && DYLD_LIBRARY_PATH=../../../src/libnffile/.libs ./target/debug/read_flows <nfdump.flowfile>
cd go     && go build -o read_flows . && LD_LIBRARY_PATH=../../../src/libnffile/.libs ./read_flows <nfdump.flowfile>
cd lua    && luajit read_flows.lua <nfdump.flowfile>
```

(swap `LD_LIBRARY_PATH` for `DYLD_LIBRARY_PATH` on OSX; each
subdirectory's own README/Makefile has the exact invocation.) `1000.nf`
is a small sample file at the repo root during development; point these
at any nfcapd/sfcapd/nfdump-written file instead.

## Per-language notes

| dir | approach | why |
|---|---|---|
| `c/` | includes `nfdump.h` directly | the ABI's native language; no translation layer at all |
| `python/` | hand-written `ctypes` bindings (`nfdump.py`) | zero extra dependencies (`ctypes` is stdlib); struct layouts are hand-kept in sync with `nfdump.h` since `ctypes` can't parse a C header itself — see the module docstring |
| `rust/` | hand-written `extern "C"` FFI, zero crate dependencies | small enough header to hand-declare without pulling in `bindgen`; note the deliberate choice to model `nfdump_status_t`/`nfdump_field_id_t` as plain `i32` constants rather than Rust `enum`s — an FFI enum must never hold a discriminant Rust doesn't know about, and a C `int` return makes that easy to violate by accident |
| `go/` | `cgo` with `#include "nfdump.h"` directly | cgo runs a real C compiler over the header and generates matching Go types itself — nothing to hand-translate or keep in sync, unlike the Python/Rust bindings |
| `lua/` | LuaJIT's `ffi.cdef()`, pasted nearly verbatim from `nfdump.h` | demonstrates the header's own design goal directly: dependency-free enough for a binding generator (or here, `ffi.cdef`) to consume close to as-is — see `nfdump.h`'s header comment. Needs LuaJIT specifically; stock PUC Lua has no built-in FFI |

None of these wrap every field in `nfdump_field_id_t` — each prints a representative subset (5-tuple, byte/packet counters) and shows one
`nfdump_field_describe()` call for introspection. Extending any of them to more fields is straight-forward: add the field's ID (matching `nfdump.h`'s
numbering) and call `nfdump_record_get()`/`nfdump_field_describe()`.
