/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#include "nfxV3.h"

#include <stdint.h>
#include <stdio.h>

#include "id.h"
#include "logging.h"
#include "nffileV2_def.h"
#include "nfxV3.h"
#include "util.h"

int VerifyV3Record(recordHeaderV3_t *recordHeader) {
    if (recordHeader->type != V3Record) {
        dbg_printf("VerifyV3 - not a V3 type: %u\n", recordHeader->type);
        return 0;
    }

    if (recordHeader->size < sizeof(recordHeaderV3_t)) {
        dbg_printf("VerifyV3 - size error: %u\n", recordHeader->size);
        return 0;
    }

    // length of all extensions
    int32_t rlen = recordHeader->size - sizeof(recordHeaderV3_t);

#ifdef DEVEL
    printf("V3 record: size: %u, numElements: %u\n", recordHeader->size, recordHeader->numElements);
    printf("flags: %u, nfversion: %u\n", recordHeader->flags, recordHeader->nfversion);
    printf("engineType: %u, engineID: %u\n", recordHeader->engineType, recordHeader->engineID);
    printf("ext length: %d\n", rlen);
#endif

    int cnt = 0;
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeader + sizeof(recordHeaderV3_t));
    for (int i = 0; i < recordHeader->numElements; i++) {
        if (elementHeader->length > rlen) {
            dbg_printf("VerifyV3 - element length error - left: %u, length: %u\n", rlen, elementHeader->length);
            return 0;
        }
        if (elementHeader->type >= MAXEXTENSIONS) {
            dbg_printf("VerifyV3 - element type error: %u\n", elementHeader->type);
            return 0;
        }
        dbg_printf("VerifyV3 - Next element: %u, length: %u\n", elementHeader->type, elementHeader->length);
        rlen -= elementHeader->length;
        cnt++;
        // next element
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
    }

    if (rlen != 0) {
        dbg_printf("VerifyV3 - record length error - diff: %d\n", rlen);
        return 0;
    }

    if (cnt != recordHeader->numElements) {
        dbg_printf("VerifyV3 - num element error: counted: %u, announced: %u\n", cnt, recordHeader->numElements);
        return 0;
    }

    return 1;

}  // end of VerifyV3Record
