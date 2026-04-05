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

#include "uncompress.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

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

#include "logging.h"
#include "minilzo.h"
#include "nffileV2_def.h"
#include "util.h"

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
    int lz4_buff_size = LZ4_compressBound(WRITE_BUFFSIZE);
    if (lz4_buff_size > (int)(BUFFSIZE - sizeof(dataBlockV2_t))) {
        LogError("LZ4_compressBound() error in %s line %d: Buffer too small", __FILE__, __LINE__);
        return 0;
    }
    return 1;

}  // End of LZ4_initialize

static int BZ2_initialize(void) { return 1; }  // End of BZ2_initialize

static int ZSTD_initialize(void) {
#ifdef HAVE_ZSTD
    size_t const cBuffSize = ZSTD_compressBound(WRITE_BUFFSIZE);
    if (cBuffSize > (BUFFSIZE - sizeof(dataBlockV2_t))) {
        LogError("LZSTD_compressBound() error in %s line %d: Buffer too small", __FILE__, __LINE__);
        return 0;
    }
    return 1;
#else
    return 1;
#endif
}  // End of ZSTD_initialize

int InitUncompress_V2(void) {
    //
    return LZO_initialize() && LZ4_initialize() && BZ2_initialize() && ZSTD_initialize();
}  // End of InitUncompress_V2

int Uncompress_BlockV2_LZO(dataBlockV2_t *in_block, dataBlockV2_t *out_block, size_t block_size) {
    unsigned char __LZO_MMODEL *in;
    unsigned char __LZO_MMODEL *out;
    lzo_uint in_len;
    lzo_uint out_len;
    int r;

    in = (unsigned char __LZO_MMODEL *)((void *)in_block + sizeof(dataBlockV2_t));
    out = (unsigned char __LZO_MMODEL *)((void *)out_block + sizeof(dataBlockV2_t));
    in_len = in_block->size;
    out_len = block_size;

    if (in_len == 0) {
        LogError("Uncompress_BlockV2_LZO() header length error in %s line %d", __FILE__, __LINE__);
        return -1;
    }
    r = lzo1x_decompress_safe(in, in_len, out, &out_len, NULL);
    if (r != LZO_E_OK) {
        LogError("Uncompress_BlockV2_LZO() error decompression failed in %s line %d: LZO error: %d", __FILE__, __LINE__, r);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Uncompress_BlockV2_LZO

int Uncompress_BlockV2_LZ4(dataBlockV2_t *in_block, dataBlockV2_t *out_block, size_t block_size) {
    const char *in = (const char *)((void *)in_block + sizeof(dataBlockV2_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlockV2_t));
    int in_len = in_block->size;

    int out_len = LZ4_decompress_safe(in, out, in_len, block_size);
    if (out_len == 0) {
        LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }
    if (out_len < 0) {
        LogError("LZ4_decompress_safe() error compression failed in %s line %d: LZ4 : %d", __FILE__, __LINE__, out_len);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;

}  // End of Uncompress_BlockV2_LZ4

int Uncompress_BlockV2_BZ2(dataBlockV2_t *in_block, dataBlockV2_t *out_block, size_t block_size) {
#ifdef HAVE_BZ2
    bz_stream bs = {0};

    BZ2_bzDecompressInit(&bs, 0, 0);

    bs.next_in = (char *)((void *)in_block + sizeof(dataBlockV2_t));
    bs.next_out = (char *)((void *)out_block + sizeof(dataBlockV2_t));
    bs.avail_in = in_block->size;
    bs.avail_out = block_size;

    for (;;) {
        int r = BZ2_bzDecompress(&bs);
        if (r == BZ_OK) {
            continue;
        } else if (r != BZ_STREAM_END) {
            BZ2_bzDecompressEnd(&bs);
            return -1;
        } else {
            break;
        }
    }

    // copy header
    *out_block = *in_block;
    out_block->size = bs.total_out_lo32;

    BZ2_bzDecompressEnd(&bs);

    return 1;
#else
    return 0;
#endif

}  // End of Uncompress_BlockV2_BZ2

int Uncompress_BlockV2_ZSTD(dataBlockV2_t *in_block, dataBlockV2_t *out_block, size_t block_size) {
#ifdef HAVE_ZSTD
    const char *in = (const char *)((void *)in_block + sizeof(dataBlockV2_t));
    char *out = (char *)((void *)out_block + sizeof(dataBlockV2_t));
    int in_len = in_block->size;

    size_t out_len = ZSTD_decompress(out, block_size, in, in_len);
    if (ZSTD_isError(out_len)) {
        LogError("LZ4_decompress_safe() error compression aborted in %s line %d: LZ4 : buffer too small", __FILE__, __LINE__);
        return -1;
    }

    // copy header
    *out_block = *in_block;
    out_block->size = out_len;

    return 1;
#else
    return 0;
#endif
}  // End of Uncompress_BlockV2_ZSTD
