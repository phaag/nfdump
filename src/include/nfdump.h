/*
 *  Copyright (c) 2009-2022, Peter Haag
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

#ifndef _NFDUMP_H
#define _NFDUMP_H 1

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"

#ifndef __has_builtin       // Optional of course.
#define __has_builtin(x) 0  // Compatibility with non-clang compilers.
#endif

#ifndef offsetof

#if __has_builtin(__builtin_offsetof)
#define offsetof(st, m) __builtin_offsetof(st, m)
#endif

#ifndef offsetof
#define offsetof(st, m) ((size_t)((char *)&((st *)0)->m - (char *)0))
#endif

#endif

#include "nfxV3.h"

#define V4 ip_addr._v4
#define V6 ip_addr._v6

// single IP addr for next hop and bgp next hop
typedef struct ip_addr_s {
    union {
        struct {
#ifdef WORDS_BIGENDIAN
            uint32_t fill[3];
            uint32_t _v4;
#else
            uint32_t fill1[2];
            uint32_t _v4;
            uint32_t fill2;
#endif
        };
        uint64_t _v6[2];
    } ip_addr;
#define IP_ADDR_T
} ip_addr_t;

// forward declaration
typedef struct exporter_info_record_s exporter_info_record_t;
typedef struct extension_map_s extension_map_t;

enum { EXlocal = MAXEXTENSIONS, SSLindex, JA3index, JA4index, MAXLISTSIZE };

typedef struct recordHandle_s {
    recordHeaderV3_t *recordHeaderV3;
    void *extensionList[MAXLISTSIZE];
    char geo[16];
#define OFFgeo offsetof(recordHandle_t, geo)
#define OFFgeoSrcIP offsetof(recordHandle_t, geo)
#define OFFgeoDstIP offsetof(recordHandle_t, geo) + 2
#define OFFgeoSrcNatIP offsetof(recordHandle_t, geo) + 4
#define OFFgeoDstNatIP offsetof(recordHandle_t, geo) + 6
#define OFFgeoSrcTunIP offsetof(recordHandle_t, geo) + 8
#define OFFgeoDstTunIP offsetof(recordHandle_t, geo) + 10
#define SizeGEOloc 2
    uint32_t flowCount;
#define OFFflowCount offsetof(recordHandle_t, flowCount)
#define SIZEflowCount MemberSize(recordHandle_t, flowCount)
    uint32_t numElements;
} recordHandle_t;

typedef struct stat_record_s {
    // overall stat
    uint64_t numflows;
    uint64_t numbytes;
    uint64_t numpackets;
    // flow stat
    uint64_t numflows_tcp;
    uint64_t numflows_udp;
    uint64_t numflows_icmp;
    uint64_t numflows_other;
    // bytes stat
    uint64_t numbytes_tcp;
    uint64_t numbytes_udp;
    uint64_t numbytes_icmp;
    uint64_t numbytes_other;
    // packet stat
    uint64_t numpackets_tcp;
    uint64_t numpackets_udp;
    uint64_t numpackets_icmp;
    uint64_t numpackets_other;
    // time window
    uint64_t firstseen;
    uint64_t lastseen;
    // other
    uint64_t sequence_failure;
} stat_record_t;

#define NOGEODB 0

// allocate space for this number of workers
#define MAXWORKERS 64
// If number of CPUs can not be determined
#define DEFAULTWORKERS 4

#endif  //_NFDUMP_H
