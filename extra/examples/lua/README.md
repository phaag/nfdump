# Lua example

Uses LuaJIT's `ffi` library over the ABI in
[`../../../src/libnfdump/nfdump.h`](../../../src/libnfdump/nfdump.h).
**Requires LuaJIT**, not stock PUC Lua — plain Lua has no built-in FFI, and
there's no C extension module here to bridge the gap (writing one would
just be the C example wrapped as a Lua module).

The `ffi.cdef[[ ... ]]` block in `read_flows.lua` is close to a direct
copy of `nfdump.h` with the comments and the `NFDUMP_API` visibility
macro stripped out — this is what `nfdump.h`'s own header comment means
by "dependency-free enough for a binding generator to consume standalone":
LuaJIT's FFI is effectively that, live, with no separate generation step.

## Run

```
luajit read_flows.lua <nfcapd-file> [max-records-to-print]
```

`read_flows.lua` looks for the in-tree `libnfdump` build at
`../../../src/libnfdump/.libs/` relative to itself (this repo's own build
— see the top-level [examples README](../README.md)), and preloads its
`libnffile` dependency from `../../../src/libnffile/.libs/` first so the
dynamic loader can resolve it without `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`
being set. Point the ABI library itself elsewhere with:

```
NFDUMP_LIB=/path/to/libnfdump.dylib luajit read_flows.lua ...
```
