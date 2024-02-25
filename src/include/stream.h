/*
 *  Copyright (c) 2024, Peter Haag
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

#ifndef _STREAM_H
#define _STREAM_H 1

#include <stdint.h>
#include <sys/types.h>

#include "util.h"

// byte stream stream struct
typedef struct ByteStream_s {
    uint8_t *stream;
    uint8_t *ptr;
    uint8_t *last;
    size_t size;
} BytesStream_t;

#define ByteStream_INIT(b, data, len)                                 \
    BytesStream_t b = {0};                                            \
    do {                                                              \
        (b).stream = (uint8_t *)data;                                 \
        (b).ptr = (b).stream;                                         \
        (b).size = len;                                               \
        (b).last = (b).stream != NULL ? (b).stream + (b).size : NULL; \
    } while (0)

#define ByteStream_SET_ERROR(b)                                       \
    do {                                                              \
        (b).last = NULL;                                              \
        LogError("%s():%d ByteStream error", __FUNCTION__, __LINE__); \
    } while (0)

#define ByteStream_IS_ERROR(b) ((b).last == NULL)

#define ByteStream_AVAILABLE(b) ((b).size)

#define ByteStream_SIZE(b) ((b).last != NULL ? (b).last - (b).stream : 0)

#define ByteStream_PTR(b) ((b).ptr)

#define ByteStream_SKIP(b, len)      \
    do {                             \
        if (len <= (b).size) {       \
            (b).ptr += len;          \
            (b).size -= len;         \
        } else                       \
            ByteStream_SET_ERROR(b); \
    } while (0)

#define ByteStream_GET_u8(b, x)      \
    x = 0;                           \
    do {                             \
        if ((b).size > 0) {          \
            x = *(((b).ptr)++);      \
            (b).size--;              \
        } else                       \
            ByteStream_SET_ERROR(b); \
    } while (0)

#define ByteStream_GET_u16(b, x)                                          \
    x = 0;                                                                \
    do {                                                                  \
        if ((b).size >= 2) {                                              \
            x = ((uint16_t)((b).ptr)[0]) << 8 | ((uint16_t)((b).ptr)[1]); \
            (b).ptr += 2;                                                 \
            (b).size -= 2;                                                \
        } else                                                            \
            ByteStream_SET_ERROR(b);                                      \
    } while (0)

#define ByteStream_GET_u24(b, x)                                                                           \
    x = 0;                                                                                                 \
    do {                                                                                                   \
        if ((b).size >= 3) {                                                                               \
            x = ((uint32_t)((b).ptr)[0]) << 16 | ((uint32_t)((b).ptr)[1]) << 8 | ((uint32_t)((b).ptr)[2]); \
            (b).ptr += 3;                                                                                  \
            (b).size -= 3;                                                                                 \
        } else                                                                                             \
            ByteStream_SET_ERROR(b);                                                                       \
    } while (0)

#define ByteStream_GET_u32(b, x)                                                                                                            \
    x = 0;                                                                                                                                  \
    do {                                                                                                                                    \
        if ((b).size >= 4) {                                                                                                                \
            x = ((uint32_t)((b).ptr)[0]) << 24 | ((uint32_t)((b).ptr)[1]) << 16 | ((uint32_t)((b).ptr)[2]) << 8 | ((uint32_t)((b).ptr)[3]); \
            (b).ptr += 4;                                                                                                                   \
            (b).size -= 4;                                                                                                                  \
        } else                                                                                                                              \
            ByteStream_SET_ERROR(b);                                                                                                        \
    } while (0)

#define ByteStream_GET_u64(b, x)                                                                                                                    \
    x = 0;                                                                                                                                          \
    do {                                                                                                                                            \
        if ((b).size >= 8) {                                                                                                                        \
            x = ((uint64_t)((b).ptr)[0]) << 56 | ((uint64_t)((b).ptr)[0]) << 48 | ((uint64_t)((b).ptr)[0]) << 40 | ((uint64_t)((b).ptr)[0]) << 32 | \
                ((uint64_t)((b).ptr)[0]) << 24 | ((uint64_t)((b).ptr)[1]) << 16 | ((uint64_t)((b).ptr)[2]) << 8 | ((uint64_t)((b).ptr)[3]);         \
            (b).ptr += 8;                                                                                                                           \
            (b).size -= 8;                                                                                                                          \
        } else                                                                                                                                      \
            ByteStream_SET_ERROR(b);                                                                                                                \
    } while (0)

#define ByteStream_GET_X(b, x, len)  \
    do {                             \
        if ((b).size >= len) {       \
            memcpy(x, b.ptr, len);   \
            (b).ptr += len;          \
            (b).size -= len;         \
        } else {                     \
            ByteStream_SET_ERROR(b); \
        }                            \
    } while (0)

#endif