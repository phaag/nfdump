/* Minimal nfdump reader example. See nfdump(3) and the local Makefile. */

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "nfdump.h"

static void printAddr(nfdump_reader_t *reader, nfdump_field_id_t field) {
    uint8_t addr[16];
    nfdump_status_t st = nfdump_record_get(reader, field, addr, sizeof(addr));
    if (st == NFDUMP_OK) {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, addr, str, sizeof(str));
        printf("%-15s", str);
    } else {
        printf("%-15s", "?");
    }
}

static uint64_t getU64(nfdump_reader_t *reader, nfdump_field_id_t field) {
    uint64_t v = 0;
    nfdump_record_get(reader, field, &v, sizeof(v)); /* leaves v=0 if NFDUMP_ABSENT */
    return v;
}

static uint16_t getU16(nfdump_reader_t *reader, nfdump_field_id_t field) {
    uint16_t v = 0;
    nfdump_record_get(reader, field, &v, sizeof(v));
    return v;
}

static uint8_t getU8(nfdump_reader_t *reader, nfdump_field_id_t field) {
    uint8_t v = 0;
    nfdump_record_get(reader, field, &v, sizeof(v));
    return v;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <nfcapd-file> [max-records-to-print]\n", argv[0]);
        return 1;
    }
    int maxPrint = argc > 2 ? atoi(argv[2]) : 10;

    printf("nfdump ABI version: %u\n\n", nfdump_abi_version());

    /* Field metadata is available for generic consumers at runtime. */
    nfdump_field_info_t fi = {.struct_size = sizeof(fi)};
    if (nfdump_field_describe(NFDUMP_FIELD_IN_BYTES, &fi) == NFDUMP_OK) {
        printf("field #%d: name=%s type=%d size=%u (of %zu fields total)\n\n", NFDUMP_FIELD_IN_BYTES, fi.name, fi.type, fi.size,
               nfdump_field_count());
    }

    nfdump_reader_t *reader = NULL;
    nfdump_status_t st = nfdump_reader_open(argv[1], NULL /* unencrypted */, &reader);
    if (st != NFDUMP_OK) {
        fprintf(stderr, "nfdump_reader_open('%s') failed: status=%d\n", argv[1], st);
        return 1;
    }

    nfdump_file_info_t info = {.struct_size = sizeof(info)};
    if (nfdump_reader_file_info(reader, &info) == NFDUMP_OK) {
        printf("file: numFlows=%" PRIu64 " numBytes=%" PRIu64 " numPackets=%" PRIu64 " ident=%s\n\n", info.numFlows, info.numBytes,
               info.numPackets, info.ident ? info.ident : "(none)");
    }

    uint64_t count = 0, totalBytes = 0, totalPackets = 0;
    nfdump_record_view_t rec;
    while ((st = nfdump_reader_next(reader, &rec)) == NFDUMP_OK) {
        count++;

        uint64_t inBytes = getU64(reader, NFDUMP_FIELD_IN_BYTES);
        uint64_t inPackets = getU64(reader, NFDUMP_FIELD_IN_PACKETS);
        totalBytes += inBytes;
        totalPackets += inPackets;

        if ((int64_t)count > maxPrint) continue;

        uint8_t proto = getU8(reader, NFDUMP_FIELD_PROTO);
        uint16_t srcPort = getU16(reader, NFDUMP_FIELD_SRC_PORT);
        uint16_t dstPort = getU16(reader, NFDUMP_FIELD_DST_PORT);

        printf("#%-6" PRIu64 "proto=%-3u ", rec.ordinal, proto);
        printAddr(reader, NFDUMP_FIELD_SRC_ADDR);
        printf(":%-5u -> ", srcPort);
        printAddr(reader, NFDUMP_FIELD_DST_ADDR);
        printf(":%-5u  bytes=%-8" PRIu64 " packets=%" PRIu64 "\n", dstPort, inBytes, inPackets);
    }

    if (st != NFDUMP_EOF) {
        fprintf(stderr, "nfdump_reader_next failed: status=%d error=%s\n", st, nfdump_reader_last_error(reader));
        nfdump_reader_close(reader);
        return 1;
    }

    printf("\n%" PRIu64 " records, %" PRIu64 " bytes, %" PRIu64 " packets\n", count, totalBytes, totalPackets);

    nfdump_reader_close(reader);
    return 0;
}
