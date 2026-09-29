/*
 *  Copyright (c) 2026, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */


/*
 * nfgen2 - generate a legacy nfdump 1.7.x (LAYOUT_VERSION_2) flow file.
 *
 * nfdump 1.8.x can read, but no longer write, the 1.7.x file format. This
 * generator creates small deterministic V2 files for the conversion tests.
 * It writes V3 flow records (IPv4 and IPv6) in DATA_BLOCK_TYPE_3 blocks,
 * followed by an uncompressed appendix with the ident and stat record.
 *
 * usage: nfgen2 -w <file> [-z none|lzo|lz4] [-n numFlows] [-b flowsPerBlock]
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LZ4
#include <lz4.h>
#else
#include "compress/lz4.h"
#endif

#include "compress/minilzo.h"
#include "id.h"
#include "nfcommon.h"
#include "nffileV2/nffileV2_def.h"
#include "nffileV2/nfxV3.h"

#define LAYOUT_VERSION_2 2
#define IDENT "nfgen2"

// V2 file header - on-disk layout of nfdump 1.7.x
typedef struct fileHeaderV2_s {
    uint16_t magic;
    uint16_t version;
    uint32_t nfdversion;
    time_t created;
    uint8_t compression;
    uint8_t encryption;
    uint16_t appendixBlocks;
    uint32_t creator;
    off_t offAppendix;
    uint32_t BlockSize;
    uint32_t NumBlocks;
} fileHeaderV2_t;

// V2 generic record header - used by appendix records
typedef struct recordHeaderV2_s {
    uint16_t type;
    uint16_t size;
} recordHeaderV2_t;

#define V3_RECORD_SIZE(numElements, payload) (sizeof(recordHeaderV3_t) + (numElements) * sizeof(elementHeader_t) + (payload))

static void *addElement(uint8_t **ptr, uint16_t type, uint16_t size) {
    elementHeader_t *elementHeader = (elementHeader_t *)*ptr;
    elementHeader->type = type;
    elementHeader->length = sizeof(elementHeader_t) + size;
    *ptr += elementHeader->length;
    return (void *)elementHeader + sizeof(elementHeader_t);
}  // End of addElement

/*
 * Append one V3 flow record at ptr. Every 4th flow is IPv6, all others IPv4.
 * Returns the record size.
 */
static uint16_t addFlow(uint8_t *ptr, uint32_t i, uint64_t msecStart, stat_record_t *stat) {
    int ipv6 = (i % 4) == 3;
    recordHeaderV3_t *recordHeader = (recordHeaderV3_t *)ptr;
    *recordHeader = (recordHeaderV3_t){
        .type = V3Record,
        .numElements = 2,
        .nfversion = 9,
    };
    uint8_t *cur = ptr + sizeof(recordHeaderV3_t);

    EX3genericFlow_t *genericFlow = addElement(&cur, EX3genericFlowID, sizeof(EX3genericFlow_t));
    *genericFlow = (EX3genericFlow_t){
        .msecFirst = msecStart + i * 10,
        .msecLast = msecStart + i * 10 + 1000,
        .msecReceived = msecStart + i * 10 + 2000,
        .inPackets = 1 + (i % 10),
        .inBytes = 100 * (1 + (i % 10)),
        .srcPort = 1024 + (i % 1000),
        .dstPort = (i % 2) ? 443 : 53,
        .proto = (i % 2) ? IPPROTO_TCP : IPPROTO_UDP,
        .tcpFlags = (i % 2) ? 0x1b : 0,
    };

    if (ipv6) {
        EX3ipv6Flow_t *ipv6Flow = addElement(&cur, EX3ipv6FlowID, sizeof(EX3ipv6Flow_t));
        // 2001:db8::<i> -> 2001:db8:1::<i>, host byte order as in nfdump 1.7.x
        ipv6Flow->srcAddr[0] = 0x20010db800000000ULL;
        ipv6Flow->srcAddr[1] = i;
        ipv6Flow->dstAddr[0] = 0x20010db800010000ULL;
        ipv6Flow->dstAddr[1] = i;
    } else {
        EX3ipv4Flow_t *ipv4Flow = addElement(&cur, EX3ipv4FlowID, sizeof(EX3ipv4Flow_t));
        // 10.0.x.y -> 172.16.x.y, host byte order as in nfdump 1.7.x
        ipv4Flow->srcAddr = 0x0a000000 | (i & 0xffff);
        ipv4Flow->dstAddr = 0xac100000 | (i & 0xffff);
    }
    recordHeader->size = (uint16_t)(cur - ptr);

    stat->numflows++;
    stat->numpackets += genericFlow->inPackets;
    stat->numbytes += genericFlow->inBytes;
    if (genericFlow->proto == IPPROTO_TCP) {
        stat->numflows_tcp++;
        stat->numpackets_tcp += genericFlow->inPackets;
        stat->numbytes_tcp += genericFlow->inBytes;
    } else {
        stat->numflows_udp++;
        stat->numpackets_udp += genericFlow->inPackets;
        stat->numbytes_udp += genericFlow->inBytes;
    }
    if (genericFlow->msecFirst < stat->msecFirstSeen) stat->msecFirstSeen = genericFlow->msecFirst;
    if (genericFlow->msecLast > stat->msecLastSeen) stat->msecLastSeen = genericFlow->msecLast;

    return recordHeader->size;
}  // End of addFlow

/*
 * Compress the payload of block in place into out with the V2 compression.
 * Returns the compressed size or 0 on error.
 */
static uint32_t compressBlock(uint8_t compression, dataBlockV2_t *in, dataBlockV2_t *out, uint32_t outCapacity) {
    const uint8_t *src = (const uint8_t *)in + sizeof(dataBlockV2_t);
    uint8_t *dst = (uint8_t *)out + sizeof(dataBlockV2_t);

    switch (compression) {
        case LZO_COMPRESSED_V2: {
            static lzo_align_t wrkmem[(LZO1X_1_MEM_COMPRESS + sizeof(lzo_align_t) - 1) / sizeof(lzo_align_t)];
            lzo_uint outLen = 0;
            if (lzo1x_1_compress(src, in->size, dst, &outLen, wrkmem) != LZO_E_OK) return 0;
            return (uint32_t)outLen;
        }
        case LZ4_COMPRESSED_V2: {
            int outLen = LZ4_compress_default((const char *)src, (char *)dst, (int)in->size, (int)outCapacity);
            return outLen > 0 ? (uint32_t)outLen : 0;
        }
        default:
            return 0;
    }
}  // End of compressBlock

static int writeBlock(int fd, uint8_t compression, dataBlockV2_t *block, dataBlockV2_t *work) {
    dataBlockV2_t *out = block;
    if (compression != NOT_COMPRESSED_V2 && !(block->flags & FLAG_BLOCK_UNCOMPRESSED)) {
        uint32_t size = compressBlock(compression, block, work, BUFFSIZE - sizeof(dataBlockV2_t));
        if (size == 0) {
            fprintf(stderr, "nfgen2: compression failed\n");
            return 0;
        }
        *work = *block;
        work->size = size;
        out = work;
    }
    size_t len = sizeof(dataBlockV2_t) + out->size;
    return write(fd, out, len) == (ssize_t)len;
}  // End of writeBlock

static void usage(const char *name) {
    fprintf(stderr, "usage: %s -w <file> [-z none|lzo|lz4] [-n numFlows] [-b flowsPerBlock]\n", name);
}  // End of usage

int main(int argc, char **argv) {
    const char *wfile = NULL;
    uint8_t compression = LZ4_COMPRESSED_V2;
    uint32_t numFlows = 1000;
    uint32_t flowsPerBlock = 400;

    int c;
    while ((c = getopt(argc, argv, "w:z:n:b:")) != EOF) {
        switch (c) {
            case 'w':
                wfile = optarg;
                break;
            case 'z':
                if (strcmp(optarg, "none") == 0) {
                    compression = NOT_COMPRESSED_V2;
                } else if (strcmp(optarg, "lzo") == 0) {
                    compression = LZO_COMPRESSED_V2;
                } else if (strcmp(optarg, "lz4") == 0) {
                    compression = LZ4_COMPRESSED_V2;
                } else {
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'n':
                numFlows = (uint32_t)strtoul(optarg, NULL, 10);
                break;
            case 'b':
                flowsPerBlock = (uint32_t)strtoul(optarg, NULL, 10);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!wfile || numFlows == 0 || flowsPerBlock == 0) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (compression == LZO_COMPRESSED_V2 && lzo_init() != LZO_E_OK) {
        fprintf(stderr, "nfgen2: lzo_init() failed\n");
        exit(EXIT_FAILURE);
    }

    dataBlockV2_t *block = malloc(BUFFSIZE);
    dataBlockV2_t *work = malloc(BUFFSIZE);
    if (!block || !work) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(wfile, "w");
    if (!fp) {
        perror(wfile);
        exit(EXIT_FAILURE);
    }
    int fd = fileno(fp);

    // reserve space for the header - written last, once all offsets are known
    fileHeaderV2_t fileHeader = {
        .magic = MAGIC,
        .version = LAYOUT_VERSION_2,
        .nfdversion = 0xf1070600,
        .created = 1704067200,  // 2024-01-01 00:00:00 UTC
        .compression = compression,
        .encryption = 0,
        .creator = 0,
        .BlockSize = WRITE_BUFFSIZE,
    };
    if (write(fd, &fileHeader, sizeof(fileHeader)) != sizeof(fileHeader)) {
        perror("write");
        exit(EXIT_FAILURE);
    }

    stat_record_t stat = {.msecFirstSeen = UINT64_MAX};
    uint64_t msecStart = (uint64_t)fileHeader.created * 1000;

    // flow blocks
    uint32_t flow = 0;
    while (flow < numFlows) {
        InitV2DataBlock(block);
        uint8_t *ptr = GetCursorV2(block);
        for (uint32_t i = 0; i < flowsPerBlock && flow < numFlows; i++, flow++) {
            uint16_t size = addFlow(ptr, flow, msecStart, &stat);
            ptr += size;
            block->size += size;
            block->NumRecords++;
        }
        if (!writeBlock(fd, compression, block, work)) {
            perror("write");
            exit(EXIT_FAILURE);
        }
        fileHeader.NumBlocks++;
    }

    // appendix: ident and stat record in one uncompressed block
    fileHeader.offAppendix = lseek(fd, 0, SEEK_CUR);
    InitV2DataBlock(block);
    block->type = DATA_BLOCK_TYPE_3;
    block->flags = FLAG_BLOCK_UNCOMPRESSED;
    uint8_t *ptr = GetCursorV2(block);

    recordHeaderV2_t *recordHeader = (recordHeaderV2_t *)ptr;
    recordHeader->type = TYPE_IDENT;
    recordHeader->size = sizeof(recordHeaderV2_t) + sizeof(IDENT);
    memcpy(ptr + sizeof(recordHeaderV2_t), IDENT, sizeof(IDENT));
    ptr += recordHeader->size;
    block->size += recordHeader->size;
    block->NumRecords++;

    recordHeader = (recordHeaderV2_t *)ptr;
    recordHeader->type = TYPE_STAT;
    recordHeader->size = sizeof(recordHeaderV2_t) + sizeof(stat_record_t);
    memcpy(ptr + sizeof(recordHeaderV2_t), &stat, sizeof(stat_record_t));
    block->size += recordHeader->size;
    block->NumRecords++;

    if (!writeBlock(fd, compression, block, work)) {
        perror("write");
        exit(EXIT_FAILURE);
    }
    fileHeader.appendixBlocks = 1;

    // final header
    if (pwrite(fd, &fileHeader, sizeof(fileHeader), 0) != sizeof(fileHeader)) {
        perror("pwrite");
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    free(block);
    free(work);

    printf("nfgen2: wrote %u flows in %u blocks to %s\n", numFlows, fileHeader.NumBlocks, wfile);
    return 0;
}  // End of main
