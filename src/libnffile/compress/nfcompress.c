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

#include "nfcompress.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#ifdef HAVE_BZ2
#include <bzlib.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#include <lz4hc.h>
#endif

#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif

#ifndef HAVE_LZ4
#include "lz4.h"
#include "lz4hc.h"
#endif

#include "logging.h"
#include "minilzo.h"

// LZO params
#define HEAP_ALLOC(var, size) lzo_align_t __LZO_MMODEL var[((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t)]

static int LZO_initialize(void) {
    if (lzo_init() != LZO_E_OK) {
        // this usually indicates a compiler bug - try recompiling
        // without optimizations, and enable `-DLZO_DEBUG' for diagnostics
        LogError("Compression lzo_init() failed.");
        return 0;
    }

    return 1;

}  // End of LZO_initialize

static int LZ4_initialize(void) {
    // LZ4_compressBound returns 0 if input size is too large for LZ4
    int lz4_buff_size = LZ4_compressBound(BLOCK_SIZE_V3 - sizeof(dataBlockV3_t));
    if (lz4_buff_size == 0) {
        LogError("LZ4_compressBound() error in %s line %d: Block size too large for LZ4", __FILE__, __LINE__);
        return 0;
    }
    return 1;

}  // End of LZ4_initialize

static int BZ2_initialize(void) { return 1; }  // End of BZ2_initialize

static int ZSTD_initialize(void) {
#ifdef HAVE_ZSTD
    // ZSTD_compressBound returns 0 on error (input too large)
    size_t const cBuffSize = ZSTD_compressBound(BLOCK_SIZE_V3 - sizeof(dataBlockV3_t));
    if (cBuffSize == 0) {
        LogError("ZSTD_compressBound() error in %s line %d: Block size too large for ZSTD", __FILE__, __LINE__);
        return 0;
    }
    return 1;
#else
    return 1;
#endif
}  // End of ZSTD_initialize

int InitCompression(void) {
    //
    return LZO_initialize() && LZ4_initialize() && BZ2_initialize() && ZSTD_initialize();
}  // End of InitCompression

int Compress_Block_LZO(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
    unsigned char *in = (unsigned char *)in_block + sizeof(dataBlockV3_t);
    unsigned char *out = (unsigned char *)out_block + sizeof(dataBlockV3_t);

    lzo_uint in_len = in_block->rawSize - sizeof(dataBlockV3_t);
    lzo_uint out_len = 0;
    size_t payload_capacity = out_capacity - sizeof(dataBlockV3_t);

    HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

    int r = lzo1x_1_compress(in, in_len, out, &out_len, wrkmem);
    if (r != LZO_E_OK) {
        LogError("Compress_Block_LZO(): compression failed: %d", r);
        return -1;
    }

    // lzo1x_1_compress has no output capacity parameter — check bounds after
    if (out_len > payload_capacity) {
        LogError("Compress_Block_LZO(): compressed size %lu exceeds buffer %zu", (unsigned long)out_len, payload_capacity);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->discSize = out_len + sizeof(dataBlockV3_t);
    out_block->rawSize = in_block->rawSize;

    return 1;
}  // End of Compress_Block_LZO

int Uncompress_Block_LZO(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
    unsigned char *in = (unsigned char *)in_block + sizeof(dataBlockV3_t);
    unsigned char *out = (unsigned char *)out_block + sizeof(dataBlockV3_t);

    lzo_uint in_len = in_block->discSize - sizeof(dataBlockV3_t);
    lzo_uint out_len = out_capacity - sizeof(dataBlockV3_t);

    if (in_len == 0) {
        LogError("Uncompress_Block_LZO(): compressedSize=0");
        return -1;
    }

    int r = lzo1x_decompress_safe(in, in_len, out, &out_len, NULL);
    if (r != LZO_E_OK) {
        LogError("Uncompress_Block_LZO(): decompression failed: %d", r);
        return -1;
    }

    *out_block = *in_block;
    out_block->rawSize = out_len + sizeof(dataBlockV3_t);
    out_block->discSize = in_block->discSize;

    return 1;
}  // End of Uncompress_Block_LZO

int Compress_Block_LZ4(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity, int level) {
    const char *in = (const char *)in_block + sizeof(dataBlockV3_t);
    char *out = (char *)out_block + sizeof(dataBlockV3_t);

    int in_len = (int)in_block->rawSize - sizeof(dataBlockV3_t);

    int payload_capacity = (int)(out_capacity - sizeof(dataBlockV3_t));
    int out_len;
    if (level > LZ4HC_CLEVEL_MIN)
        out_len = LZ4_compress_HC(in, out, in_len, payload_capacity, level);
    else
        out_len = LZ4_compress_default(in, out, in_len, payload_capacity);

    if (out_len <= 0) {
        LogError("Compress_Block_LZ4(): failed: %d", out_len);
        return -1;
    }

    *out_block = *in_block;
    out_block->discSize = out_len + sizeof(dataBlockV3_t);
    out_block->rawSize = in_block->rawSize;

    return 1;
}  // End of Compress_Block_LZ4

int Uncompress_Block_LZ4(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
    const char *in = (const char *)in_block + sizeof(dataBlockV3_t);
    char *out = (char *)out_block + sizeof(dataBlockV3_t);

    int in_len = in_block->discSize - sizeof(dataBlockV3_t);

    int out_len = LZ4_decompress_safe(in, out, in_len, out_capacity - sizeof(dataBlockV3_t));
    if (out_len <= 0) {
        LogError("Uncompress_Block_LZ4(): failed: %d", out_len);
        return -1;
    }

    *out_block = *in_block;
    out_block->rawSize = out_len + sizeof(dataBlockV3_t);
    out_block->discSize = in_block->discSize;

    return 1;
}  // End of Uncompress_Block_LZ4

int Compress_Block_BZ2(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
#ifdef HAVE_BZ2
    bz_stream bs = {0};
    BZ2_bzCompressInit(&bs, 9, 0, 0);

    bs.next_in = (char *)in_block + sizeof(dataBlockV3_t);
    bs.avail_in = in_block->rawSize - sizeof(dataBlockV3_t);
    bs.next_out = (char *)out_block + sizeof(dataBlockV3_t);
    bs.avail_out = out_capacity - sizeof(dataBlockV3_t);

    for (;;) {
        int r = BZ2_bzCompress(&bs, BZ_FINISH);
        if (r == BZ_FINISH_OK) continue;
        if (r != BZ_STREAM_END) {
            LogError("Compress_Block_BZ2(): failed: %d", r);
            return -1;
        }
        break;
    }

    *out_block = *in_block;
    out_block->discSize = bs.total_out_lo32 + sizeof(dataBlockV3_t);
    out_block->rawSize = in_block->rawSize;

    BZ2_bzCompressEnd(&bs);
    return 1;
#else
    return 0;
#endif
}  // End of Compress_Block_BZ2

int Uncompress_Block_BZ2(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
#ifdef HAVE_BZ2
    bz_stream bs = {0};
    BZ2_bzDecompressInit(&bs, 0, 0);

    bs.next_in = (char *)in_block + sizeof(dataBlockV3_t);
    bs.avail_in = in_block->discSize - sizeof(dataBlockV3_t);
    bs.next_out = (char *)out_block + sizeof(dataBlockV3_t);
    bs.avail_out = out_capacity - sizeof(dataBlockV3_t);

    for (;;) {
        int r = BZ2_bzDecompress(&bs);
        if (r == BZ_OK) continue;
        if (r != BZ_STREAM_END) {
            BZ2_bzDecompressEnd(&bs);
            return -1;
        }
        break;
    }

    *out_block = *in_block;
    out_block->rawSize = bs.total_out_lo32 + sizeof(dataBlockV3_t);
    out_block->discSize = in_block->discSize;

    BZ2_bzDecompressEnd(&bs);
    return 1;
#else
    return 0;
#endif
}  // End of Uncompress_Block_BZ2

int Compress_Block_ZSTD(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity, int level) {
#ifdef HAVE_ZSTD
    const char *in = (const char *)in_block + sizeof(dataBlockV3_t);
    char *out = (char *)out_block + sizeof(dataBlockV3_t);

    size_t in_len = in_block->rawSize - sizeof(dataBlockV3_t);

    if (level == 0) level = ZSTD_CLEVEL_DEFAULT;

    size_t out_len = ZSTD_compress(out, out_capacity - sizeof(dataBlockV3_t), in, in_len, level);
    if (ZSTD_isError(out_len)) {
        LogError("Compress_Block_ZSTD(): %s", ZSTD_getErrorName(out_len));
        return -1;
    }

    *out_block = *in_block;
    out_block->discSize = out_len + sizeof(dataBlockV3_t);
    out_block->rawSize = in_block->rawSize;

    return 1;
#else
    return 0;
#endif
}  // End of Compress_Block_ZSTD

int Uncompress_Block_ZSTD(dataBlockV3_t *in_block, dataBlockV3_t *out_block, size_t out_capacity) {
#ifdef HAVE_ZSTD
    const char *in = (const char *)in_block + sizeof(dataBlockV3_t);
    char *out = (char *)out_block + sizeof(dataBlockV3_t);

    size_t in_len = in_block->discSize - sizeof(dataBlockV3_t);

    size_t out_len = ZSTD_decompress(out, out_capacity - sizeof(dataBlockV3_t), in, in_len);
    if (ZSTD_isError(out_len)) {
        LogError("Uncompress_Block_ZSTD(): %s", ZSTD_getErrorName(out_len));
        return -1;
    }

    *out_block = *in_block;
    out_block->rawSize = out_len + sizeof(dataBlockV3_t);
    out_block->discSize = in_block->discSize;

    return 1;
#else
    return 0;
#endif
}  // End of Uncompress_Block_ZSTD

int ParseCompression(char *arg, uint32_t *compressType, uint32_t *compressLevel) {
    if (arg == NULL) {
        *compressType = LZO_COMPRESSED;
        *compressLevel = 0;
        return 1;
    }

    if (arg[0] == '=') arg++;

    if (strlen(arg) > 16) {
        return -1;
    }

    int level = 0;
    char *s = strchr(arg, ':');
    if (s) {
        *s++ = '\0';
        while (*s && isdigit(*s)) {
            level = 10 * level + (*s++ - 0x30);
        }
        if (*s) {
            LogError("Invalid compression level: %s", s);
            return -1;
        }
        if (level > 100) {
            LogError("Invalid compression level: %u", level);
            return -1;
        }
    }
    *compressLevel = level;

    for (int i = 0; arg[i]; i++) {
        arg[i] = tolower(arg[i]);
    }

    if (strcmp(arg, "0") == 0) {
        *compressType = NOT_COMPRESSED;
        return 1;
    }
    if (strcmp(arg, "lzo") == 0 || strcmp(arg, "1") == 0) {
        *compressType = LZO_COMPRESSED;
        return 1;
    }
    if (strcmp(arg, "lz4") == 0 || strcmp(arg, "3") == 0) {
        if (level <= LZ4HC_CLEVEL_MAX) {
            *compressType = LZ4_COMPRESSED;
            return 1;
        } else {
            LogError("LZ4 max compression level is %d", LZ4HC_CLEVEL_MAX);
            return 0;
        }
    }

    if (strcmp(arg, "bz2") == 0 || strcmp(arg, "bzip2") == 0 || strcmp(arg, "2") == 0) {
#ifdef HAVE_BZ2
        *compressType = BZ2_COMPRESSED;
        return 1;
    }
#else
        LogError("BZIP2 compression not compiled in");
        return 0;
    }
#endif

    if (strcmp(arg, "zstd") == 0 || strcmp(arg, "4") == 0) {
#ifdef HAVE_ZSTD
        if (level <= ZSTD_maxCLevel()) {
            *compressType = ZSTD_COMPRESSED;
            return 1;
        } else {
            LogError("ZSTD max compression level is %d", ZSTD_maxCLevel());
            return 0;
        }
    }
#else
        LogError("ZSTD compression not compiled in");
        return 0;
    }
#endif

    // anything else is invalid
    return 0;

}  // End of ParseCompression
