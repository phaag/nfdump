# C example

Includes [`nfdump.h`](../../../src/libnfdump/nfdump.h)
directly — the ABI's native language, no translation layer. This example
replaces the legacy `nfreader` code.

## Usage sketch

```c
nfdump_reader_t *reader;
nfdump_reader_open(path, NULL, &reader);

nfdump_record_view_t record;
while (nfdump_reader_next(reader, &record) == NFDUMP_OK) {
    uint8_t proto, srcAddr[16], dstAddr[16];
    uint16_t srcPort, dstPort;
    uint64_t packets, bytes;

    nfdump_record_get(reader, NFDUMP_FIELD_PROTO, &proto, sizeof(proto));
    nfdump_record_get(reader, NFDUMP_FIELD_SRC_ADDR, srcAddr, sizeof(srcAddr));
    nfdump_record_get(reader, NFDUMP_FIELD_DST_ADDR, dstAddr, sizeof(dstAddr));
    nfdump_record_get(reader, NFDUMP_FIELD_SRC_PORT, &srcPort, sizeof(srcPort));
    nfdump_record_get(reader, NFDUMP_FIELD_DST_PORT, &dstPort, sizeof(dstPort));
    nfdump_record_get(reader, NFDUMP_FIELD_IN_PACKETS, &packets, sizeof(packets));
    nfdump_record_get(reader, NFDUMP_FIELD_IN_BYTES, &bytes, sizeof(bytes));

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, srcAddr, src, sizeof(src));
    inet_ntop(AF_INET6, dstAddr, dst, sizeof(dst));

    printf("proto=%u %s:%u -> %s:%u  packets=%llu bytes=%llu\n", proto, src, srcPort, dst, dstPort, (unsigned long long)packets,
           (unsigned long long)bytes);
}
nfdump_reader_close(reader);
```

(no error handling shown — see `read_flows.c` for the real thing, and
`nfdump(3)` for the full contract.)

## Build & run

```
make
./read_flows <flow-file>
```

The `Makefile` prefers an installed nfdump, found via `pkg-config`. If
`pkg-config` can't find it, it falls back to the default install prefix
(`/usr/local`); if nfdump isn't there either, the build fails with a
normal compiler/linker error. This example never reaches into the nfdump
source tree, so it builds identically whether or not you happen to be
inside a checkout of it. See the comments at the top of the `Makefile`
for the `PREFIX`/`PKG_CONFIG` overrides, and `make run FILE=<flow-file>`
for a target that checks `FILE` is set.
