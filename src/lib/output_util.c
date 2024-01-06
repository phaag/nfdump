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
#include "nfdump.h"
#include "nffile.h"

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
