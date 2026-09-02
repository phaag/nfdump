# Lua example

Uses LuaJIT's `ffi` library over the ABI in
[`../../../src/libnffile/nfdump.h`](../../../src/libnffile/nfdump.h).
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

`read_flows.lua` looks for the in-tree `libnffile` build at
`../../../src/libnffile/.libs/` relative to itself (this repo's own build
— see the top-level [examples README](../README.md)). Point it elsewhere
with:

```
NFDUMP_LIB=/path/to/libnffile.dylib luajit read_flows.lua ...
```
