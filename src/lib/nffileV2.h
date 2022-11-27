/*
 *  Copyright (c) 2022, Peter Haag
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

#ifndef _NFFILEV2_H
#define _NFFILEV2_H 1

#include <stddef.h>
#include <sys/types.h>

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/*
 * nfdump binary file layout 2
 * ===========================
 * Each data file starts with a file header, which identifies the file as an nfdump data file.
 * The magic 16bit integer at the beginning of each file must read 0xA50C. This also guarantees
 * that endian dependant files are read correct.
 *
 * Principal layout, recognized as LAYOUT_VERSION_2:
 *
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 *   |Fileheader | datablock 0 | datablock 1 | datablock 2 | ... | datablock n |
 *   +-----------+-------------+-------------+-------------+-----+-------------+
 */

typedef struct fileHeaderV2_s {
    uint16_t magic;  // magic to recognize nfdump file type and endian type
#define MAGIC 0xA50C

    uint16_t version;  // version of binary file layout
#define LAYOUT_VERSION_2 2

    uint32_t nfdversion;  // version of nfdump created this file
#define NFDVERSION 0x01070001
                          // 4bytes 1.6.19-1 0x01061301
    time_t created;  // file create time

    uint8_t compression;
#define NOT_COMPRESSED 0
#define LZO_COMPRESSED 1
#define BZ2_COMPRESSED 2
#define LZ4_COMPRESSED 3

    uint8_t encryption;
#define NOT_ENCRYPTED 0
    uint16_t appendixBlocks;  // number of blocks to read from appendix
                              // on open file for internal data structs
    uint32_t unused;          // unused 0	- reserved for future use
    off_t offAppendix;        // offset in file for appendix blocks with additional data

    uint32_t BlockSize;  // max block size of data blocks
    uint32_t NumBlocks;  // number of data blocks in file
} fileHeaderV2_t;

#define FILE_COMPRESSION(n) ((n)->file_header->compression)
#define FILE_ENCRYPTION(n) ((n)->file_header->encryption)

/*
 *
 * Generic data block
 * ==================
 * Data blocks are generic containers for the any type of data records.
 * Each data block starts with a block header, which specifies the size, the number of records
 * and data block properties. The struct is compatible with type 2 data records
 */

typedef struct dataBlock_s {
    uint32_t NumRecords;  // size of this block in bytes without this header
    uint32_t size;        // size of this block in bytes without this header
    uint16_t type;        // Block type
#define DATA_BLOCK_TYPE_3 3
#define DATA_BLOCK_TYPE_4 4
    uint16_t flags;  // Bit 0: 0: file block compression, 1: block uncompressed
                     // Bit 1: 0: file block encryption, 1: block unencrypted
                     // Bit 2: 0: no autoread, 1: autoread - internal structure
#define FLAG_BLOCK_UNCOMPRESSED 0x1
#define FLAG_BLOCK_UNENCRYPTED 0x2
#define FLAG_BLOCK_AUTOREAD 0x4
} dataBlock_t;

/*
 * Generic data record
 * Contains any type of data, specified by type
 */
typedef struct recordHeader_s {
    // record header
    uint16_t type;  // type of data
    uint16_t size;  // size of record including this header
} recordHeader_t;

#define PushRecord(p, h, t)                  \
    recordHeader_t *h = (recordHeader_t *)p; \
    h->type = t;                             \
    h->size = sizeof(recordHeader_t);

#define TYPE_IDENT 0x8001
#define TYPE_STAT 0x8002

#endif  //_NFFILEV2_H
