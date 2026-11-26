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

#include "output_util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "nfcommon.h"

char *FlagsString(uint16_t flags) {
    static char string[16];

    string[0] = flags & 128 ? 'C' : '.';  // Congestion window reduced -  CWR
    string[1] = flags & 64 ? 'E' : '.';   // ECN-Echo
    string[2] = flags & 32 ? 'U' : '.';   // Urgent
    string[3] = flags & 16 ? 'A' : '.';   // Ack
    string[4] = flags & 8 ? 'P' : '.';    // Push
    string[5] = flags & 4 ? 'R' : '.';    // Reset
    string[6] = flags & 2 ? 'S' : '.';    // Syn
    string[7] = flags & 1 ? 'F' : '.';    // Fin
    string[8] = '\0';

    return string;
}  // End of FlagsString

char *biFlowString(uint8_t biFlow) {
    switch (biFlow) {
        case 0:
            return "";
            break;
        case 1:
            return "initiator";
            break;
        case 2:
            return "reverseInitiator";
            break;
        case 3:
            return "perimeter";
            break;
    }

    return "undef";

}  // End of biFlowString

char *FlowEndString(uint8_t endReason) {
    switch (endReason) {
        case 0:
            return "";
            break;
        case 1:
            return "idle timeout";
            break;
        case 2:
            return "active timeout";
            break;
        case 3:
            return "end of Flow detected";
            break;
        case 4:
            return "forced end";
            break;
        case 5:
            return "lack of resources";
            break;
    }

    return "undef";

}  // End of FlowEndString

/*
 * Format an NBAR application ID as <engine>..<selector>, or for classification
 * engine 20 (PEN - private enterprise number) as 20..<PEN>..<selector>.
 * All reads are bounded by idLen. Selectors up to 8 bytes are printed as decimal
 * number, longer selectors as hex string ('+' marks a truncated hex string).
 * engineWidth is the minimum field width of the engine number.
 */
char *NbarIDString(char *buff, size_t buffLen, int engineWidth, const uint8_t *id, uint32_t idLen) {
    if (buffLen == 0) return buff;
    buff[0] = '\0';

    if (id == NULL || idLen == 0) {
        snprintf(buff, buffLen, "%*u..0", engineWidth, 0);
        return buff;
    }

    uint32_t index = 1;
    int len;
    if (id[0] == 20 && idLen >= 5) {  // PEN - private enterprise number
        uint32_t pen = ((uint32_t)id[1] << 24) | ((uint32_t)id[2] << 16) | ((uint32_t)id[3] << 8) | (uint32_t)id[4];
        len = snprintf(buff, buffLen, "%*u..%u..", engineWidth, id[0], pen);
        index = 5;
    } else {
        len = snprintf(buff, buffLen, "%*u..", engineWidth, id[0]);
    }
    if (len < 0 || (size_t)len >= buffLen) return buff;

    char *p = buff + len;
    size_t avail = buffLen - len;
    if ((idLen - index) <= 8) {
        uint64_t selector = 0;
        for (; index < idLen; index++) selector = (selector << 8) | id[index];
        snprintf(p, avail, "%llu", (unsigned long long)selector);
    } else {
        // selector does not fit into a 64bit number - print as hex string
        static const char hex[] = "0123456789abcdef";
        if (avail < 4) return buff;
        *p++ = '0';
        *p++ = 'x';
        avail -= 2;
        for (; index < idLen && avail > 3; index++) {
            *p++ = hex[id[index] >> 4];
            *p++ = hex[id[index] & 0xF];
            avail -= 2;
        }
        if (index < idLen) *p++ = '+';
        *p = '\0';
    }

    return buff;

}  // End of NbarIDString
