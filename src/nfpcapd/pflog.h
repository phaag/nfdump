/*
 *  Copyright (c) 2026, Peter Haag
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

/*
 * Base on original OpenBSD 7.x code
 * As the struct struct pfloghdr is not portable amobe all pf platforms
 * just limit on OpenBSD 7.x
 *
 * #define PFLOG_RULESET_NAME_SIZE	16
 *
 * struct pfloghdr {
 *	u_int8_t	length;
 *	sa_family_t	af;
 *	u_int8_t	action;
 *	u_int8_t	reason;
 *	char		ifname[IFNAMSIZ];
 *	char		ruleset[PFLOG_RULESET_NAME_SIZE];
 *	u_int32_t	rulenr;
 *	u_int32_t	subrulenr;
 *	uid_t		uid;
 *	pid_t		pid;
 *	uid_t		rule_uid;
 *	pid_t		rule_pid;
 *	u_int8_t	dir;
 *	u_int8_t	rewritten;
 *	sa_family_t	naf;
 *	u_int8_t	pad[1];
 *	struct pf_addr	saddr;
 *	struct pf_addr	daddr;
 *	u_int16_t	sport;
 *	u_int16_t	dport;
 * };
 *
 *
 *
 * Fixed Offsets based on OpenBSD DLT_PFLOG (Version 7.x)
 * These are the byte positions in the wire format.
 */

/* OpenBSD constants for pflog */
#define PFLOG_HDRLEN 100
#define PFLOG_IFNAMSIZ 16
#define PFLOG_RULENAMSIZ 16

#define PFLOG_OFF_LEN 0        /* uint8_t  */
#define PFLOG_OFF_AF 1         /* uint8_t  */
#define PFLOG_OFF_ACTION 2     /* uint8_t  */
#define PFLOG_OFF_REASON 3     /* uint8_t  */
#define PFLOG_OFF_IFNAME 4     /* char[16] */
#define PFLOG_OFF_RULESET 20   /* char[16] */
#define PFLOG_OFF_RULENR 36    /* uint32_t */
#define PFLOG_OFF_SUBRULENR 40 /* uint32_t */
#define PFLOG_OFF_UID 44       /* uint32_t */
#define PFLOG_OFF_PID 48       /* int32_t  */
#define PFLOG_OFF_DIR 60       /* uint8_t  */
#define PFLOG_OFF_REWRITTEN 61 /* uint8_t  */

/* Metadata structure to hold extracted values */
typedef struct pf_info_s {
    uint8_t has_pfinfo;
    uint8_t af;
    uint8_t action;
    uint8_t reason;
    uint8_t dir;
    uint8_t rewritten;
    uint16_t _align;
    uint32_t uid;
    int32_t pid;
    uint32_t rulenr;
    uint32_t subrulenr;
    char ifname[16];
} pf_info_t;

/* Actions */
#define PF_PASS 0
#define PF_DROP 1
#define PF_SCRUB 2
#define PF_NOSCRUB 3
#define PF_NAT 4
#define PF_NONAT 5
#define PF_BINAT 6
#define PF_NOBINAT 7
#define PF_RDR 8
#define PF_NORDR 9
#define PF_SYNPROXY 10
#define PF_DEFER 11

/* Directions */
#define PF_IN 1
#define PF_OUT 2

#endif