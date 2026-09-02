#!/usr/bin/env python3
"""
read_flows.py — usage example for the nfdump.py ctypes binding.

    NFDUMP_LIB=/path/to/libnffile.dylib ./read_flows.py nfcapd.file [max]

(NFDUMP_LIB is optional - nfdump.py first tries the in-tree build path
relative to this script; see nfdump.py's _default_search_paths().)
"""
import sys

import nfdump


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <nfcapd-file> [max-records-to-print]", file=sys.stderr)
        return 1
    path = sys.argv[1]
    max_print = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    print(f"nfdump ABI version: {nfdump.abi_version()}\n")

    name, ftype, size = nfdump.field_describe(nfdump.FIELD_IN_BYTES)
    print(f"field #{nfdump.FIELD_IN_BYTES}: name={name} type={ftype} size={size} "
          f"(of {nfdump.field_count()} fields total)\n")

    with nfdump.Reader(path) as reader:
        info = reader.file_info()
        print(f"file: {info}\n")

        count = 0
        total_bytes = 0
        total_packets = 0
        for rec in reader:
            count += 1
            in_bytes = rec.get_u64(nfdump.FIELD_IN_BYTES) or 0
            in_packets = rec.get_u64(nfdump.FIELD_IN_PACKETS) or 0
            total_bytes += in_bytes
            total_packets += in_packets

            if count <= max_print:
                proto = rec.get_u8(nfdump.FIELD_PROTO)
                src = rec.get_addr(nfdump.FIELD_SRC_ADDR)
                dst = rec.get_addr(nfdump.FIELD_DST_ADDR)
                src_port = rec.get_u16(nfdump.FIELD_SRC_PORT)
                dst_port = rec.get_u16(nfdump.FIELD_DST_PORT)
                print(f"#{rec.ordinal:<6} proto={proto:<3} {src}:{src_port} -> {dst}:{dst_port}  "
                      f"bytes={in_bytes} packets={in_packets}")

        print(f"\n{count} records, {total_bytes} bytes, {total_packets} packets")

    return 0


if __name__ == "__main__":
    sys.exit(main())
