# Go example

`cgo` over the ABI in [`nfdump.h`](../../../src/libnfdump/nfdump.h) —
`main.go` `#include`s the header directly rather than hand-declaring
struct layouts (unlike the Python/Rust examples): cgo runs a real C
compiler over it and generates matching Go types itself, so there is
nothing to keep in sync by hand here.

## Usage sketch

```go
r, _ := openReader(path)
defer r.Close()

for {
    _, ok, _ := r.next()
    if !ok {
        break
    }
    proto, _ := getScalar[uint8](r, C.NFDUMP_FIELD_PROTO)
    src := getAddr(r, C.NFDUMP_FIELD_SRC_ADDR)
    dst := getAddr(r, C.NFDUMP_FIELD_DST_ADDR)
    srcPort, _ := getScalar[uint16](r, C.NFDUMP_FIELD_SRC_PORT)
    dstPort, _ := getScalar[uint16](r, C.NFDUMP_FIELD_DST_PORT)
    packets, _ := getScalar[uint64](r, C.NFDUMP_FIELD_IN_PACKETS)
    bytes, _ := getScalar[uint64](r, C.NFDUMP_FIELD_IN_BYTES)
    fmt.Printf("proto=%d %s:%d -> %s:%d  packets=%d bytes=%d\n", proto, src, srcPort, dst, dstPort, packets, bytes)
}
```

(`openReader`/`getScalar`/`getAddr` are the small wrapper and helpers
defined in `main.go` — see that file for the real thing, and `nfdump(3)`
for the full contract.)

## Build & run

```
go build -o read_flows .
./read_flows <nfcapd-file> [max]
```

Unlike the other four examples, this one can't automatically prefer
`pkg-config` and fall back to a default path: cgo's `#cgo` directives are
static text, and `#cgo pkg-config: nfdump` is a hard build failure (not a
skippable check) when `pkg-config` can't find the package — confirmed
while writing this example. `main.go` defaults straight to the default
install prefix (`/usr/local`) instead, the same fallback the other
examples use automatically; if nfdump isn't there, the build fails with a
normal compiler/linker error. This file never reaches into the nfdump
source tree.

**If your install lives somewhere other than `/usr/local`**, either set
`CGO_CFLAGS`/`CGO_LDFLAGS` (Go merges these with the file's own `#cgo`
flags, so no source edit needed):

```
CGO_CFLAGS="-I/opt/nfdump/include" CGO_LDFLAGS="-L/opt/nfdump/lib" go build -o read_flows .
```

or, **if `pkg-config` knows about your install**, edit the two `#cgo`
lines at the top of `main.go` to the single line `#cgo pkg-config:
nfdump` instead.

Once built against a genuinely installed nfdump, no loader-path variable
is needed at run time either — the installed library resolves its own
dependencies on its own.

Requires Go 1.21+ (uses generics for the `getScalar[T]` field-access
helper) and a C compiler on `PATH` (cgo needs one either way).
