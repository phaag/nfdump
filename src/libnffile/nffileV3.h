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

#ifndef _NFFILEV3_H
#define _NFFILEV3_H 1

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * The file format v3 of nffile is based on the previous v2 format.
 * In order to gain more flexibility and future proof stability,
 * the v3 format is still a container based format as v2.
 * The goal is to preserve datablocks, compression, heterogeneous
 * block types, while modernizing the metadata, block headers, and
 * options for indexing so that analytics and an optional V4 columnar
 * conversion becomes dramatically faster and simpler.
 *
 * File layout:
 *   +-----------+-------------+-------------+-----+-------------+-------------+
 *   |Fileheader | datablock 0 | datablock 1 | ... | datablock n | Appdx. Meta |
 *   +-----------+-------------+-------------+-----+-------------+-------------+
 *
 * Metadata region (appendix 2.0)
 * The metadata region may stores data along the record data such es:
 * - exporter table
 * - statistics
 * - schema versions
 * - optional columnar summaries
 *
 * This makes analytics dramatically faster and enables future features without
 * changing the file format.
 *
 */

typedef struct fileHeaderV3_s {
    uint16_t magic;  // 0xA50C
#define LAYOUT_VERSION_3 3
    uint16_t layoutVersion;  // layout v3 with new header
    uint32_t nfdVersion;     // version of nfdump that wrote this file
    uint64_t created;        // file creation timestamp

    uint16_t compression;  // block-level compression
    uint16_t encryption;   // block-level encryption
    uint32_t flags;        // flags - future use

    uint32_t blockSize;  // max uncompressed block size
    uint32_t numBlocks;  // number of datablocks

    uint64_t offFirstBlock;  // offset to first data block
    uint64_t offIndexBlock;  // offset of block index region
    uint64_t offMetadata;    // offset of metadata/appendix region

    uint64_t reserved1;  // reserved for future use
} fileHeaderV3_t;

typedef struct dataBlockV3_s {
    uint32_t blockType;     // flow, geo, tor, index, etc.
    uint32_t blockVersion;  // version of block layout

    uint32_t compressedSize;    // size after compression
    uint32_t uncompressedSize;  // size before compression

    uint32_t numRecords;  // number of records in this block
    uint32_t flags;       // flags for this block

    uint64_t minTimestamp;  // earliest record timestamp
    uint64_t maxTimestamp;  // latest record timestamp

    uint32_t reserved;  // reserved - 0
    uint32_t checksum;  // CRC32 or xxHash
} dataBlockV3_t;
// typedef dataBlockV3_t dataBlock_t;

typedef struct BlockIndexEntry_s {
    uint64_t offset;  // offset of block header
    uint64_t minTimestamp;
    uint64_t maxTimestamp;
    uint32_t blockType;
    uint32_t numRecords;
    uint32_t exporterBitmap;
    uint32_t reserved;
} BlockIndexEntry;

/*
 * array record header for nbar, ifname, vrf name records
 */
typedef struct arrayRecordHeader_s {
    // record header
    uint16_t type;
    uint16_t size;
    uint16_t numElements;
    uint16_t elementSize;
} arrayRecordHeader_t;

#define arrayHeaderSize sizeof(arrayRecordHeader_t)
#define AddArrayHeader(p, h, t, s)                     \
    arrayRecordHeader_t *h = (arrayRecordHeader_t *)p; \
    memset(h, 0, sizeof(arrayRecordHeader_t));         \
    h->type = t;                                       \
    h->size = sizeof(arrayRecordHeader_t);             \
    h->elementSize = s;

#define PushArrayVarElement(h, x, v, s)        \
    x##_t *v = (x##_t *)((void *)h + h->size); \
    memset(v, 0, s);                           \
    h->numElements++;                          \
    h->size += s;

#define PushArrayNextElement(h, p, t) \
    p = (t *)((void *)h + h->size);   \
    h->numElements++;                 \
    h->size += h->elementSize;

#endif