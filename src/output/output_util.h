/*
 *  Copyright (c) 2019-2023, Peter Haag
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

#ifndef _OUTPUT_UTIL_H
#define _OUTPUT_UTIL_H 1

#include <stddef.h>
#include <stdint.h>

typedef enum { DIR_IN = 0, DIR_OUT } dirInOut_t;

char *FlagsString(uint16_t flags);

char *biFlowString(uint8_t biFlow);

char *FlowEndString(uint8_t biFlow);

/*
 * Advance a fixed-size format-buffer cursor by an snprintf() result, without
 * ever moving past the space that was actually available.
 *
 * snprintf() returns the number of bytes it *would* have written given
 * unlimited space, not the number it actually wrote. Once the remaining
 * buffer space is smaller than the formatted text, the write is silently
 * truncated but the return value keeps reporting the untruncated length. A
 * bare `streamPtr += len` after such a call walks the cursor past the end of
 * the buffer. On the *next* call, the "remaining space" computation then
 * goes negative; cast to the size_t snprintf() expects, that reappears as a
 * huge unsigned value, so the following snprintf() believes it has virtually
 * unlimited room and can write straight past the buffer - a real overflow,
 * driven by exporter-controlled flow data. Route every
 * `streamPtr += snprintf(...)` in the streaming output formatters through
 * this helper instead.
 */
static inline char *SafeAdvance(char *streamPtr, ptrdiff_t avail, int len) {
    if (len < 0) return streamPtr;                                 // encoding error - nothing written
    if (len >= avail) return streamPtr + (avail > 0 ? avail - 1 : 0);  // truncated - stop at the NUL terminator
    return streamPtr + len;
}

#endif