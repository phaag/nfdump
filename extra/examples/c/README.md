# C example

Includes [`../../../src/libnffile/nfdump.h`](../../../src/libnffile/nfdump.h)
directly — the ABI's native language, no translation layer.

## Build & run

```
make
make run FILE=../../../1000.nf
```

See the comments at the top of the `Makefile` for `NFDUMP_ROOT` (where it
finds the in-tree `libnffile` build — see the top-level [examples
README](../README.md) for why there's no installed library to link
against yet) and the `run` target for why both `DYLD_LIBRARY_PATH` and
`LD_LIBRARY_PATH` get set at run time.
