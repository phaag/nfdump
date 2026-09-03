# Python example

`nfdump.py` is a small `ctypes` binding for the ABI in [`nfdump.h`](../../../src/libnfdump/nfdump.h); see
its module docstring for how the struct layouts are kept in sync by hand.
`read_flows.py` is the usage example.

## Usage sketch

```python
import nfdump

with nfdump.Reader(path) as r:
    for rec in r:
        proto = rec.get_u8(nfdump.FIELD_PROTO)
        src = rec.get_addr(nfdump.FIELD_SRC_ADDR)
        dst = rec.get_addr(nfdump.FIELD_DST_ADDR)
        src_port = rec.get_u16(nfdump.FIELD_SRC_PORT)
        dst_port = rec.get_u16(nfdump.FIELD_DST_PORT)
        packets = rec.get_u64(nfdump.FIELD_IN_PACKETS)
        bytes_ = rec.get_u64(nfdump.FIELD_IN_BYTES)
        print(f"proto={proto} {src}:{src_port} -> {dst}:{dst_port}  packets={packets} bytes={bytes_}")
```

(no error handling shown — see `read_flows.py` for the real thing, and
`nfdump(3)` for the full contract.)

## Run

```
python3 read_flows.py <nfcapd-file> [max-records-to-print]
```

`nfdump.py` prefers an installed `libnfdump`, found the normal way for
the platform. If that doesn't find it, it falls back to the default
install prefix (`/usr/local`); if nfdump isn't there either, importing
`nfdump` raises `OSError`. It never looks inside any nfdump source tree.
Point it at a specific library instead with:

```
NFDUMP_LIB=/path/to/libnfdump.dylib python3 read_flows.py ...
```

## Note on performance

`ctypes` call overhead (roughly 0.1-1 µs per call)
dominates at high record counts — reading 10M records with two
`nfdump_record_get()` calls each takes on the order of 20s in pure Python
here, versus well under a second for the same file/fields in the C or Go
examples. Fine for scripting and analysis; for a high-throughput pipeline,
either batch more work per call or reach for one of the compiled examples.
