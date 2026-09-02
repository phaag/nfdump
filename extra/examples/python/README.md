# Python example

`nfdump.py` is a small `ctypes` binding for the ABI in
[`../../../src/libnfdump/nfdump.h`](../../../src/libnfdump/nfdump.h); see
its module docstring for how the struct layouts are kept in sync by hand.
`read_flows.py` is the usage example.

## Run

```
python3 read_flows.py <nfcapd-file> [max-records-to-print]
```

`nfdump.py` looks for the in-tree `libnfdump` build at
`../../../src/libnfdump/.libs/` relative to itself (i.e. this repo's own
build — see the top-level [examples README](../README.md) for why there's
no installed library yet). Point it elsewhere with:

```
NFDUMP_LIB=/path/to/libnfdump.dylib python3 read_flows.py ...
```

## Using it as a library

```python
import nfdump

with nfdump.Reader("nfcapd.202601010000") as r:
    print(r.file_info())
    for rec in r:
        print(rec.ordinal, rec.get_u64(nfdump.FIELD_IN_BYTES), rec.get_addr(nfdump.FIELD_SRC_ADDR))
```

Note on performance: `ctypes` call overhead (roughly 0.1-1 µs per call)
dominates at high record counts — reading 10M records with two
`nfdump_record_get()` calls each takes on the order of 20s in pure Python
here, versus well under a second for the same file/fields in the C or Go
examples. Fine for scripting and analysis; for a high-throughput pipeline,
either batch more work per call or reach for one of the compiled examples.
