/*
 *  Copyright (c) 2022, Peter Haag
 *  $OpenBSD: if_pflog.h,v 1.29 2021/01/13 09:13:30 mvs Exp $
 *  Copyright 2001 Niels Provos <provos@citi.umich.edu>
 *
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

#ifndef _PFLOG_H
#define _PFLOG_H 1

#include <stdint.h>
#include <sys/types.h>

#define IFNAMSIZ 16
#define PFLOG_RULESET_NAME_SIZE 16

struct pf_addr {
    union {
        struct in_addr addrV4;
        struct in6_addr addrV6;
        uint8_t addr8[16];
        uint16_t addr16[8];
        uint32_t addr32[4];
    } pfa; /* 128-bit address */
#define addrV4 pfa.addrV4
#define addrV6 pfa.addrV6
#define addr8 pfa.addr8
#define addr16 pfa.addr16
#define addr32 pfa.addr32
};

typedef struct pfloghdr {
    uint8_t length;
    uint8_t af;
    uint8_t action;
    uint8_t reason;
    char ifname[IFNAMSIZ];
    char ruleset[PFLOG_RULESET_NAME_SIZE];
    uint32_t rulenr;
    uint32_t subrulenr;
    uid_t uid;
    pid_t pid;
    uid_t rule_uid;
    pid_t rule_pid;
    uint8_t dir;
    uint8_t rewritten;
    uint8_t naf;
    uint8_t pad[1];
    struct pf_addr saddr;
    struct pf_addr daddr;
    uint16_t sport;
    uint16_t dport;
} pflog_hdr_t;

#define PFLOG_HDRLEN sizeof(struct pfloghdr)
/* used to be minus pad, also used as a signature */
#define PFLOG_REAL_HDRLEN PFLOG_HDRLEN
#define PFLOG_OLD_HDRLEN offsetof(struct pfloghdr, pad)

#endif