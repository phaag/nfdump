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

#ifndef _DNS_H
#define _DNS_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct dns_question_t dns_question_t;
typedef union dns_answer_t dns_answer_t;

// this identical struct serves for the offset calculation only
typedef struct dns_query_t {  // RFC-1035
    size_t recordSize;
    int id;
    int opcode;
    bool query;
    bool aa;
    bool tc;
    bool rd;
    bool ra;
    bool z;   // should be zero
    bool ad;  // RFC-2065
    bool cd;  // RFC-2065
    int rcode;
    size_t qdcount;
    size_t ancount;
    size_t nscount;
    size_t arcount;
    dns_question_t *questions;
    dns_answer_t *answers;
    dns_answer_t *nameservers;
    dns_answer_t *additional;
} dns_query_t;

void *dnsPayloadDecode(const void *inPayload, const uint32_t inPayloadLength);

int dnsSearchName(void *ptr, char *name);

int dnsSearchIP(void *ptr, char *name);

#endif