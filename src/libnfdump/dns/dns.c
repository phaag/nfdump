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
            // successfully decoded
            dbg_printf("=> inPayload bytes used: %zu\n", bufsize);
            // dns_print_result((dns_query_t *)bufresult);
            ((dns_query_t *)bufresult)->recordSize = bufsize;
            break;
        } else if (rc == RCODE_NO_MEMORY) {
            // memory block too small
            bufsize = bufsize << 1;
            if (bufsize > 8192) {
                // hard limit - virtually all dns decoded packets should fit in 8kB
                LogError("dns_decode() = (%d) %s", rc, "possibly malformed packet");
                free(bufresult);
                bufresult = NULL;
                break;
            }
            // double memory and try again
            dbg_printf("Expand memory to %zu\n", bufsize);
            bufresult = (dns_decoded_t *)realloc((void *)bufresult, bufsize);
            continue;
        } else {
            // other failure to decode dns packet
            LogError("dns_decode() = (%d) %s", rc, dns_rcode_text(rc));
            free(bufresult);
            bufresult = NULL;
            break;
        }
    } while (1);

    return bufresult;
}  // End of dnsPayloadDecode

int dnsSearchName(void *ptr, char *name) {
    dns_query_t *dns_query = (dns_query_t *)ptr;

    dns_question_t *pquest = dns_query->questions;
    for (size_t i = 0; i < dns_query->qdcount; i++) {
        if (strstr(pquest[i].name, name) != 0) return 1;
    }

    return 0;
}  // End of dnsSearchName

int dnsSearchIP(void *ptr, char *name) {
    dns_query_t *dns_query = (dns_query_t *)ptr;

    char ipaddr[INET6_ADDRSTRLEN];
    dns_answer_t *pans = dns_query->answers;
    for (int i = 0; i < dns_query->ancount; i++) {
        switch (pans[i].generic.type) {
            case RR_A:
                inet_ntop(AF_INET, &pans[i].a.address, ipaddr, sizeof(ipaddr));
                if (strstr(ipaddr, name) != 0) return 1;
                break;
            case RR_AAAA:
                inet_ntop(AF_INET6, &pans[i].aaaa.address, ipaddr, sizeof(ipaddr));
                if (strstr(ipaddr, name) != 0) return 1;
                break;
            default:
                break;
        }
    }
    pans = dns_query->additional;
    for (int i = 0; i < dns_query->arcount; i++) {
        switch (pans[i].generic.type) {
            case RR_A:
                inet_ntop(AF_INET, &pans[i].a.address, ipaddr, sizeof(ipaddr));
                if (strstr(ipaddr, name) != 0) return 1;
                break;
            case RR_AAAA:
                inet_ntop(AF_INET6, &pans[i].aaaa.address, ipaddr, sizeof(ipaddr));
                if (strstr(ipaddr, name) != 0) return 1;
                break;
            default:
                break;
        }
    }

    return 0;
}  // End of dnsSearchIP