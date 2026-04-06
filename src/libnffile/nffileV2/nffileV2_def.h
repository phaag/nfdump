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

#ifndef _NFFILEV2_DEF_H
#define _NFFILEV2_DEF_H 1

#ifndef IDENTLEN
#define IDENTLEN 128
#endif
#ifndef IDENTNONE
#define IDENTNONE "none"
#endif

/*
 * output buffer max size, before writing data to the file
 * used to cache flows before writing to disk. size: tradeoff between
 * size and time to flush to disk. Do not delay collector with long I/O
 */
#define ONEMB 1048576
#define WRITE_BUFFSIZE (2 * ONEMB)
/*
 * use this buffer size to allocate memory for the output buffer
 * data other than flow records, such as histograms, may be larger than
BUFFSIZE and have potentially more time to flush to disk
 */
#define BUFFSIZE (5 * ONEMB)

/* if the output buffer reaches this limit, it gets flushed. This means,
 * that 0.5MB input data may produce max 1MB data in output buffer, otherwise
 * a buffer overflow may occur, and data does not get processed correctly.
 * However, every Process_vx function checks buffer boundaries.
 */

#define MAXRECORDSIZE 1024

/*
 * In file layout format 1: After the file header an
 * implicit stat record follows, which contains the statistics
 * information about all netflow records in this file.
 */

#define DATA_BLOCK_MESSAGE 0x0100

#define GetCursorV2(block) ((void *)(block) + sizeof(dataBlockV2_t))
#define GetCurrentCursor(block) ((void *)(block) + (block)->size + sizeof(dataBlockV2_t))

// V2 compression types - do not match V3 types
#define NOT_COMPRESSED_V2 0
#define LZO_COMPRESSED_V2 1
#define BZ2_COMPRESSED_V2 2
#define LZ4_COMPRESSED_V2 3
#define ZSTD_COMPRESSED_V2 4

#define DATA_BLOCK_TYPE_3 3
#define DATA_BLOCK_TYPE_4 4

#define InitDataBlock(a) \
    (a)->NumRecords = 0; \
    (a)->size = 0;       \
    (a)->flags = 0;      \
    (a)->type = DATA_BLOCK_TYPE_3;

typedef struct dataBlockV2_s {
    uint32_t NumRecords;  // size of this block in bytes without this header
    uint32_t size;        // size of this block in bytes without this header
    uint16_t type;        // Block type

    uint16_t flags;  // Bit 0: 0: file block compression, 1: block uncompressed
                     // Bit 1: 0: file block encryption, 1: block unencrypted
                     // Bit 2: 0: no autoread, 1: autoread - internal structure
#define FLAG_BLOCK_UNCOMPRESSED 0x1
#define FLAG_BLOCK_UNENCRYPTED 0x2
#define FLAG_BLOCK_AUTOREAD 0x4
} dataBlockV2_t;

#endif