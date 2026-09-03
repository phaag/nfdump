# Lua example

Uses LuaJIT's `ffi` library over the ABI in [`nfdump.h`](../../../src/libnfdump/nfdump.h).
**Requires LuaJIT**, not stock PUC Lua — plain Lua has no built-in FFI, and
there's no C extension module here to bridge the gap (writing one would
just be the C example wrapped as a Lua module).

The `ffi.cdef[[ ... ]]` block in `read_flows.lua` is close to a direct
copy of `nfdump.h` with the comments and the `NFDUMP_API` visibility
macro stripped out — this is what `nfdump.h`'s own header comment means
by "dependency-free enough for a binding generator to consume standalone":
LuaJIT's FFI is effectively that, live, with no separate generation step.

## Usage sketch

```lua
local readerPtr = ffi.new("nfdump_reader_t*[1]")
C.nfdump_reader_open(path, nil, readerPtr)
local reader = readerPtr[0]

local proto, srcPort, dstPort = ffi.new("uint8_t[1]"), ffi.new("uint16_t[1]"), ffi.new("uint16_t[1]")
local srcAddr, dstAddr = ffi.new("uint8_t[16]"), ffi.new("uint8_t[16]")
local packets, bytes = ffi.new("uint64_t[1]"), ffi.new("uint64_t[1]")
local rec = ffi.new("nfdump_record_view_t")

while C.nfdump_reader_next(reader, rec) == C.NFDUMP_OK do
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_PROTO, proto, 1)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_SRC_ADDR, srcAddr, 16)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_DST_ADDR, dstAddr, 16)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_SRC_PORT, srcPort, 2)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_DST_PORT, dstPort, 2)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_IN_PACKETS, packets, 8)
    C.nfdump_record_get(reader, C.NFDUMP_FIELD_IN_BYTES, bytes, 8)

    -- addr_to_string() (defined further down in read_flows.lua) turns a
    -- 16-byte buffer into dotted/colon notation, unwrapping IPv4-mapped
    -- addresses along the way.
    print(string.format("proto=%d %s:%d -> %s:%d  packets=%d bytes=%d",
        proto[0], addr_to_string(srcAddr), tonumber(srcPort[0]),
        addr_to_string(dstAddr), tonumber(dstPort[0]),
        tonumber(packets[0]), tonumber(bytes[0])))
end
C.nfdump_reader_close(reader)
```

(no error handling shown — see `read_flows.lua` for the real thing, and
`nfdump(3)` for the full contract.)

## Run

```
luajit read_flows.lua <nfcapd-file> [max-records-to-print]
```

`read_flows.lua` prefers an installed `libnfdump`, found the normal way
for the platform (`ffi.load("nfdump")` with a bare name — ldconfig on
Linux, `DYLD_FALLBACK_LIBRARY_PATH` including `/usr/local/lib` on macOS).
If that doesn't find a working library, it falls back to the default
install prefix (`/usr/local`); if nfdump isn't there either, it errors.
It never looks inside any nfdump source tree. Point it at a specific
library instead with:

```
NFDUMP_LIB=/path/to/libnfdump.dylib luajit read_flows.lua ...
```

Every candidate is verified by actually calling `nfdump_abi_version()`
before being trusted, not just by whether `ffi.load()` raised: `dlopen()`
is lazily bound, so loading an unrelated or stale library at a standard
path can silently "succeed" and only crash later, deep in unrelated code,
the first time a missing symbol is actually called — observed for real
against a stale library while writing this example.
