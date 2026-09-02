# Go example

`cgo` over the ABI in
[`../../../src/libnffile/nfdump.h`](../../../src/libnffile/nfdump.h) —
`main.go` `#include`s the header directly rather than hand-declaring
struct layouts (unlike the Python/Rust examples): cgo runs a real C
compiler over it and generates matching Go types itself, so there is
nothing to keep in sync by hand here.

## Build & run

```
CGO_ENABLED=1 go build -o read_flows .
DYLD_LIBRARY_PATH=../../../src/libnffile/.libs ./read_flows <nfcapd-file> [max]   # macOS
LD_LIBRARY_PATH=../../../src/libnffile/.libs  ./read_flows <nfcapd-file> [max]    # Linux
```

The `#cgo CFLAGS`/`#cgo LDFLAGS` lines in `main.go` use cgo's `${SRCDIR}`
substitution to find the in-tree `libnffile` build three directories up
(this repo's own build — see the top-level [examples README](../README.md)).
Edit those two lines if your build lives elsewhere. The dynamic loader
needs the same directory at run time too, hence the env var above — the
`#cgo LDFLAGS` line only handles link time.

Requires Go 1.21+ (uses generics for the `getScalar[T]` field-access
helper) and a C compiler on `PATH` (cgo needs one either way).
