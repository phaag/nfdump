/*
 *  Copyright (c) 2024, Peter Haag
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

#ifndef _FILTER_H
#define _FILTER_H 1

#include <stdint.h>
#include <stdio.h>

#include "nfdump.h"
#include "nfxV3.h"
#include "rbtree.h"

typedef enum {
    DIR_UNSPEC = 1,
    DIR_UNSPEC_NAT,
    DIR_UNSPEC_TUN,
    DIR_SRC,
    DIR_DST,
    DIR_SRC_NAT,
    DIR_DST_NAT,
    DIR_SRC_TUN,
    DIR_DST_TUN,
    DIR_IN,
    DIR_OUT,
    DIR_IN_SRC,
    DIR_IN_DST,
    DIR_OUT_SRC,
    DIR_OUT_DST,
    DIR_PREV,
    DIR_NEXT,
    BGP_NEXT,
    DIR_INGRESS,
    DIR_EGRESS,
    SRC_ROUTER
} direction_t;

typedef enum {
    CMP_EQ = 0,
    CMP_GT,
    CMP_LT,
    CMP_GE,
    CMP_LE,
    CMP_IDENT,
    CMP_FLAGS,
    CMP_STRING,
    CMP_BINARY,
    CMP_NET,
    CMP_IPLIST,
    CMP_U64LIST,
    CMP_PAYLOAD,
    CMP_REGEX,
    CMP_GEO,
} comparator_t;

typedef struct FilterParam {
    comparator_t comp;
    direction_t direction;
    int32_t self;
} FilterParam_t;

/*
 * filter functions:
 * For some filter functions, netflow records need to be processed first in order to filter them
 * This involves all data not directly available in the netflow record, such as packets per second etc.
 * The sequence of the enum values must correspond with the entries in the flow_procs array
 */

typedef enum {
    FUNC_NONE = 0,     // no function - just plain filtering - just to be complete here
    FUNC_DURATION,     // function code for duration ( in milliseconds ) filter function
    FUNC_PPS,          // function code for pps ( packet per second ) filter function
    FUNC_BPS,          // function code for bps ( bits per second ) filter function
    FUNC_BPP,          // function code for bpp ( bytes per packet ) filter function
    FUNC_MPLS_LABEL,   // function code for matching an MPLS label
    FUNC_MPLS_EOS,     // function code for matching End of MPLS Stack label
    FUNC_MPLS_EXP,     // function code for matching experimantal value in label
    FUNC_MPLS_ANY,     // function code for matching any MPLS label
    FUNC_PBLOCK,       // function code for matching ports against pblock start
    FUNC_MMAS_LOOKUP,  // function code for optional maxmind AS lookup
} filterFunction_t;

#define FULLMASK FFFFFFFFFFFFFFFFLL

/* Definition of the IP list node */
struct IPListNode {
    RB_ENTRY(IPListNode) entry;
    uint64_t ip[2];
    uint64_t mask[2];
};

/* Definition of the uint64_t list node */
struct U64ListNode {
    RB_ENTRY(U64ListNode) entry;
    uint64_t value;
};

typedef union data_u {
    void *dataPtr;
    int64_t dataVal;
} data_t;

/* IP tree type */
typedef RB_HEAD(IPtree, IPListNode) IPlist_t;

/* uint64_t tree type */
typedef RB_HEAD(U64tree, U64ListNode) U64List_t;

// Insert the RB prototypes here
RB_PROTOTYPE(IPtree, IPListNode, entry, IPNodeCMP);

RB_PROTOTYPE(U64tree, U64ListNode, entry, U64NodeCMP);

int yylex(void);

uint32_t NewElement(uint32_t extID, uint32_t offset, uint32_t length, uint64_t value, comparator_t comp, filterFunction_t function, data_t data);

uint32_t Invert(uint32_t a);

uint32_t Connect_OR(uint32_t b1, uint32_t b2);

uint32_t Connect_AND(uint32_t b1, uint32_t b2);

char *ReadFilter(char *filename);

void *CompileFilter(char *FilterSyntax);

void DisposeFilter(void *engine);

int FilterRecord(void *engine, recordHandle_t *handle, const char *ident);

void DumpEngine(void *arg);

void lex_init(char *buf);

void lex_cleanup(void);

int yyparse(void);

#endif