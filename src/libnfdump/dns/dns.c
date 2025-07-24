/*
 *  Copyright (c) 2025, Peter Haag
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

#include "dns.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "codec.h"
#include "mappings.h"
#include "util.h"

void *dnsPayloadDecode(const void *inPayload, const uint32_t inPayloadLength) {
    size_t bufsize = 512;
    dbg_printf("dnsPayloadDecode() size: %u -> bufsize: %zu\n", inPayloadLength, bufsize);
    void *bufresult = (dns_decoded_t *)malloc(bufsize);
    if (!bufresult) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    do {
        dns_rcode_t rc = dns_decode(bufresult, &bufsize, inPayload, inPayloadLength);
        if (rc == RCODE_OKAY) {
            dbg_printf("=> inPayload bytes used: %zu\n", bufsize);
            // dns_print_result((dns_query_t *)bufresult);
            break;
        } else if (rc == RCODE_NO_MEMORY) {
            bufsize = bufsize << 1;
            if (bufsize > 8192) {
                LogError("dns_decode() = (%d) %s", rc, "possibly malformed packet");
                free(bufresult);
                bufresult = NULL;
                break;
            }
            dbg_printf("Expand memory to %zu\n", bufsize);
            bufresult = (dns_decoded_t *)realloc((void *)bufresult, bufsize);
            continue;
        } else {
            LogError("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
            break;
        }
    } while (1);

    return bufresult;
}  // End of dnsPayloadDecode