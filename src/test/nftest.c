/*
 *  Copyright (c) 2009-2021, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define ALIGN_BYTES      \
    (offsetof(           \
         struct {        \
             char x;     \
             uint64_t y; \
         },              \
         y) -            \
     1)

#include "filter.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"
#include "util.h"

typedef struct value64_s {
    union val_s {
        uint64_t val64;
        uint32_t val32[2];
    } val;
    uint8_t data[4];  // .. more data below
} value64_t;

static char *CurrentIdent;
static FilterEngine_t *Engine;

/* exported fuctions */
static int check_filter_block(char *filter, master_record_t *flow_record, int expect);

static void check_offset(char *text, pointer_addr_t offset, pointer_addr_t expect);

static int check_filter_block(char *filter, master_record_t *flow_record, int expect) {
    uint64_t *block = (uint64_t *)flow_record;

    Engine = CompileFilter(filter);
    if (!Engine) {
        exit(254);
    }

    Engine->ident = CurrentIdent;
    Engine->nfrecord = (uint64_t *)flow_record;
    int ret = (*Engine->FilterEngine)(Engine);
    if (ret == expect) {
        printf("Success: Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
    } else {
        printf("**** FAILED **** Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
        DumpEngine(Engine);
        printf("Expected: %i, Found: %i\n", expect, ret);
        printf("Record:\n");
        for (int i = 0; i <= Offset_MR_LAST; i++) {
            printf("%3i %.16llx\n", i, (long long)block[i]);
        }
        if (Engine->IdentList) {
            printf("Current Ident: %s, Ident 0 %s\n", Engine->ident ? Engine->ident : "NULL", Engine->IdentList[0]);
        }
        exit(255);
    }
    return (ret == expect);
}

static void check_offset(char *text, pointer_addr_t offset, pointer_addr_t expect) {
    if (offset == expect) {
        printf("Success: %s: %llu\n", text, (unsigned long long)expect);
    } else {
        printf("**** FAILED **** %s expected %llu, evaluated %llu\n", text, (unsigned long long)expect, (unsigned long long)offset);
        // useless to continue
        exit(255);
    }
}

int main(int argc, char **argv) {
    master_record_t flow_record;
    uint64_t *blocks, l;
    uint32_t in[2];
    time_t now;
    int ret, i;
    value64_t v;

    if (sizeof(struct in_addr) != sizeof(uint32_t)) {
#ifdef HAVE_SIZE_T_Z_FORMAT
        printf("**** FAILED **** Size struct in_addr %zu != sizeof(uint32_t)\n", sizeof(struct in_addr));
#else
        printf("**** FAILED **** Size struct in_addr %lu != sizeof(uint32_t)\n", (unsigned long)sizeof(struct in_addr));
#endif
        exit(255);
    }

    i = 3;
    printf("ALIGN BYTES: %lu\n", (long unsigned)ALIGN_BYTES);
    printf("aligned: %i -> %lu\n", i, (long unsigned)(((u_int)(i) + ALIGN_BYTES) & ~ALIGN_BYTES));

    l = 0x200000000LL;
    v.val.val64 = l;
    in[0] = v.val.val32[0];
    in[1] = v.val.val32[1];
    ret = memcmp(in, &l, sizeof(uint64_t));
    if (ret != 0) {
        printf("**** FAILED **** val32/64 union check failed!\n");
        exit(255);
    }

    memset((void *)&flow_record, 0, sizeof(master_record_t));
    blocks = (uint64_t *)&flow_record;

    check_offset("Src AS   Offset", (unsigned int)((pointer_addr_t)&flow_record.srcas - (pointer_addr_t)&blocks[OffsetAS]), 0);
    check_offset("Dst AS   Offset", (unsigned int)((pointer_addr_t)&flow_record.dstas - (pointer_addr_t)&blocks[OffsetAS]), 4);
    check_offset("Src Port Offset", (unsigned int)((pointer_addr_t)&flow_record.srcPort - (pointer_addr_t)&blocks[OffsetPort]), 0);
    check_offset("Dst Port Offset", (unsigned int)((pointer_addr_t)&flow_record.dstPort - (pointer_addr_t)&blocks[OffsetPort]), 2);
    check_offset("Status   Offset", (unsigned int)((pointer_addr_t)&flow_record.fwd_status - (pointer_addr_t)&blocks[OffsetStatus]), 4);
    check_offset("Flags    Offset", (unsigned int)((pointer_addr_t)&flow_record.tcp_flags - (pointer_addr_t)&blocks[OffsetFlags]), 5);
    check_offset("Protocol Offset", (unsigned int)((pointer_addr_t)&flow_record.proto - (pointer_addr_t)&blocks[OffsetProto]), 6);
    check_offset("tos      Offset", (unsigned int)((pointer_addr_t)&flow_record.tos - (pointer_addr_t)&blocks[OffsetTos]), 7);
    check_offset("packets  Offset", (unsigned int)((pointer_addr_t)&flow_record.inPackets - (pointer_addr_t)&blocks[OffsetPackets]), 0);
    check_offset("bytes    Offset", (unsigned int)((pointer_addr_t)&flow_record.inBytes - (pointer_addr_t)&blocks[OffsetBytes]), 0);

#ifdef HAVE_SIZE_T_Z_FORMAT
    printf("Pointer  Size : %zu\n", sizeof(blocks));
    printf("Time_t   Size : %zu\n", sizeof(now));
    printf("int      Size : %zu\n", sizeof(int));
    printf("long     Size : %zu\n", sizeof(long));
    printf("longlong Size : %zu\n", sizeof(long long));
#else
    printf("Pointer  Size : %lu\n", (unsigned long)sizeof(blocks));
    printf("Time_t   Size : %lu\n", (unsigned long)sizeof(now));
    printf("int      Size : %lu\n", (unsigned long)sizeof(int));
    printf("long     Size : %lu\n", (unsigned long)sizeof(long));
    printf("longlong Size : %lu\n", (unsigned long)sizeof(long long));
#endif

    flow_record.flags = 0;
    flow_record.mflags = 0;
    ret = check_filter_block("ipv4", &flow_record, 1);
    SetFlag(flow_record.mflags, V3_FLAG_IPV6_ADDR);
    ret = check_filter_block("ipv4", &flow_record, 0);
    ret = check_filter_block("ipv6", &flow_record, 1);
    SetFlag(flow_record.mflags, V3_FLAG_IPV6_NH);
    SetFlag(flow_record.mflags, V3_FLAG_IPV6_NHB);
    SetFlag(flow_record.mflags, V3_FLAG_IPV6_EXP);
    ret = check_filter_block("ipv4", &flow_record, 0);
    ret = check_filter_block("ipv6", &flow_record, 1);
    ClearFlag(flow_record.mflags, V3_FLAG_IPV6_ADDR);
    ret = check_filter_block("ipv4", &flow_record, 1);
    ret = check_filter_block("ipv6", &flow_record, 0);

    flow_record.proto = IPPROTO_TCP;
    ret = check_filter_block("any", &flow_record, 1);
    ret = check_filter_block("not any", &flow_record, 0);
    ret = check_filter_block("proto tcp", &flow_record, 1);
    ret = check_filter_block("proto udp", &flow_record, 0);

    flow_record.proto = IPPROTO_UDP;
    ret = check_filter_block("proto tcp", &flow_record, 0);
    ret = check_filter_block("proto udp", &flow_record, 1);
    flow_record.proto = IPPROTO_ESP;
    ret = check_filter_block("proto esp", &flow_record, 1);
    ret = check_filter_block("proto ah", &flow_record, 0);
    flow_record.proto = IPPROTO_AH;
    ret = check_filter_block("proto ah", &flow_record, 1);
    flow_record.proto = IPPROTO_RSVP;
    ret = check_filter_block("proto rsvp", &flow_record, 1);
    flow_record.proto = IPPROTO_GRE;
    ret = check_filter_block("proto gre", &flow_record, 1);
    ret = check_filter_block("proto 47", &flow_record, 1);
    ret = check_filter_block("proto 42", &flow_record, 0);

    flow_record.srcPort = 0xaaaa;
    flow_record.proto = IPPROTO_ICMP;
    flow_record.dstPort = 0xaffa;  // -> icmp type 175, code 250
    flow_record.icmp = flow_record.dstPort;
    flow_record.dstPort = 0xbbbb;
    ret = check_filter_block("icmp-type 175", &flow_record, 1);
    ret = check_filter_block("icmp-type 176", &flow_record, 0);
    ret = check_filter_block("icmp-code 250", &flow_record, 1);
    ret = check_filter_block("icmp-code 251", &flow_record, 0);

    if (flow_record.icmp_type != 175 && flow_record.icmp_code != 250) {
        printf("**** FAILED **** ICMP type check failed!\n");
        printf("ICMP type: %u, code: %u\n", flow_record.icmp_type, flow_record.icmp_code);
        exit(255);
    }

    flow_record.dstPort = 3 << 8;  // -> icmp type 3
    flow_record.icmp = flow_record.dstPort;
    if (flow_record.icmp_type != 3) {
        printf("**** FAILED **** ICMP type check failed!\n");
        printf("ICMP type: %u, code: %u\n", flow_record.icmp_type, flow_record.icmp_code);
        exit(255);
    }
    ret = check_filter_block("icmp-type 3", &flow_record, 1);
    ret = check_filter_block("icmp-type 4", &flow_record, 0);

    flow_record.dstPort = 8;  // -> icmp code 8
    flow_record.icmp = flow_record.dstPort;
    if (flow_record.icmp_code != 8) {
        printf("**** FAILED **** ICMP code check failed!\n");
        printf("ICMP type: %u, code: %u\n", flow_record.icmp_type, flow_record.icmp_code);
        exit(255);
    }
    ret = check_filter_block("icmp-code 8", &flow_record, 1);
    ret = check_filter_block("icmp-code 4", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:5678", flow_record.V6.srcaddr);
    inet_pton(PF_INET6, "fe80::1104:fedc:4321:8765", flow_record.V6.dstaddr);
    flow_record.V6.srcaddr[0] = ntohll(flow_record.V6.srcaddr[0]);
    flow_record.V6.srcaddr[1] = ntohll(flow_record.V6.srcaddr[1]);
    flow_record.V6.dstaddr[0] = ntohll(flow_record.V6.dstaddr[0]);
    flow_record.V6.dstaddr[1] = ntohll(flow_record.V6.dstaddr[1]);
    ret = check_filter_block("src ip fe80::2110:abcd:1234:5678", &flow_record, 1);
    ret = check_filter_block("src ip fe80::2110:abcd:1234:5679", &flow_record, 0);
    ret = check_filter_block("src ip fe80::2111:abcd:1234:5678", &flow_record, 0);
    ret = check_filter_block("dst ip fe80::1104:fedc:4321:8765", &flow_record, 1);
    ret = check_filter_block("dst ip fe80::1104:fedc:4321:8766", &flow_record, 0);
    ret = check_filter_block("dst ip fe80::1105:fedc:4321:8765", &flow_record, 0);
    ret = check_filter_block("ip fe80::2110:abcd:1234:5678", &flow_record, 1);
    ret = check_filter_block("ip fe80::1104:fedc:4321:8765", &flow_record, 1);
    ret = check_filter_block("ip fe80::2110:abcd:1234:5679", &flow_record, 0);
    ret = check_filter_block("ip fe80::1104:fedc:4321:8766", &flow_record, 0);
    ret = check_filter_block("not ip fe80::2110:abcd:1234:5678", &flow_record, 0);
    ret = check_filter_block("not ip fe80::2110:abcd:1234:5679", &flow_record, 1);

    ret = check_filter_block("src ip in [fe80::2110:abcd:1234:5678]", &flow_record, 1);
    ret = check_filter_block("src ip in [fe80::2110:abcd:1234:5679]", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:0", flow_record.V6.srcaddr);
    flow_record.V6.srcaddr[0] = ntohll(flow_record.V6.srcaddr[0]);
    flow_record.V6.srcaddr[1] = ntohll(flow_record.V6.srcaddr[1]);
    ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:ffff", flow_record.V6.srcaddr);
    flow_record.V6.srcaddr[0] = ntohll(flow_record.V6.srcaddr[0]);
    flow_record.V6.srcaddr[1] = ntohll(flow_record.V6.srcaddr[1]);
    ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.V6.srcaddr);
    flow_record.V6.srcaddr[0] = ntohll(flow_record.V6.srcaddr[0]);
    flow_record.V6.srcaddr[1] = ntohll(flow_record.V6.srcaddr[1]);
    ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 0);
    ret = check_filter_block("src net fe80::0/16", &flow_record, 1);
    ret = check_filter_block("src net fe81::0/16", &flow_record, 0);

    flow_record.V6.srcaddr[0] = 0;
    flow_record.V6.srcaddr[1] = 0;

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:0", flow_record.V6.dstaddr);
    flow_record.V6.dstaddr[0] = ntohll(flow_record.V6.dstaddr[0]);
    flow_record.V6.dstaddr[1] = ntohll(flow_record.V6.dstaddr[1]);
    ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1234:ffff", flow_record.V6.dstaddr);
    flow_record.V6.dstaddr[0] = ntohll(flow_record.V6.dstaddr[0]);
    flow_record.V6.dstaddr[1] = ntohll(flow_record.V6.dstaddr[1]);
    ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.V6.dstaddr);
    flow_record.V6.dstaddr[0] = ntohll(flow_record.V6.dstaddr[0]);
    flow_record.V6.dstaddr[1] = ntohll(flow_record.V6.dstaddr[1]);
    ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 0);
    ret = check_filter_block("dst net fe80::0/16", &flow_record, 1);
    ret = check_filter_block("not dst net fe80::0/16", &flow_record, 0);
    ret = check_filter_block("dst net fe81::0/16", &flow_record, 0);
    ret = check_filter_block("not dst net fe81::0/16", &flow_record, 1);

    /* 172.32.7.16 => 0xac200710
     * 10.10.10.11 => 0x0a0a0a0b
     */
    flow_record.V6.srcaddr[0] = 0;
    flow_record.V6.srcaddr[1] = 0;
    flow_record.V6.dstaddr[0] = 0;
    flow_record.V6.dstaddr[1] = 0;
    flow_record.V4.srcaddr = 0xac200710;
    flow_record.V4.dstaddr = 0x0a0a0a0b;
    ret = check_filter_block("src ip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("( src ip 172.32.7.16 ) %MyLabel", &flow_record, 1);
    ret = check_filter_block("%MyLabel( src ip 172.32.7.16 )", &flow_record, 1);
    ret = check_filter_block("src ip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("dst ip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("dst ip 10.10.10.10", &flow_record, 0);
    ret = check_filter_block("ip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("ip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("ip 172.32.7.17", &flow_record, 0);
    ret = check_filter_block("ip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("not ip 172.32.7.16", &flow_record, 0);
    ret = check_filter_block("not ip 172.32.7.17", &flow_record, 1);

    ret = check_filter_block("src host 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("src host 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("dst host 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("dst host 10.10.10.10", &flow_record, 0);
    ret = check_filter_block("host 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("host 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("host 172.32.7.17", &flow_record, 0);
    ret = check_filter_block("host 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("not host 172.32.7.16", &flow_record, 0);
    ret = check_filter_block("not host 172.32.7.17", &flow_record, 1);

    ret = check_filter_block("src ip in [172.32.7.16]", &flow_record, 1);
    ret = check_filter_block("src ip in [172.32.7.17]", &flow_record, 0);
    ret = check_filter_block("src ip in [10.10.10.11]", &flow_record, 0);
    ret = check_filter_block("dst ip in [10.10.10.11]", &flow_record, 1);
    ret = check_filter_block("ip in [10.10.10.11]", &flow_record, 1);
    ret = check_filter_block("ip in [172.32.7.16]", &flow_record, 1);
    ret = check_filter_block("src ip in [172.32.7.16 172.32.7.17 10.10.10.11 10.10.10.12 ]", &flow_record, 1);
    ret = check_filter_block("src ip in [172.32.7.16, 172.32.7.17 10.10.10.11,10.10.10.12 ]", &flow_record, 1);
    ret = check_filter_block("dst ip in [172.32.7.16 172.32.7.17 10.10.10.11 10.10.10.12 ]", &flow_record, 1);
    ret = check_filter_block("ip in [172.32.7.16 172.32.7.17 10.10.10.11 10.10.10.12 ]", &flow_record, 1);
    ret = check_filter_block("ip in [172.32.7.17 172.32.7.18 10.10.10.12 10.10.10.13 ]", &flow_record, 0);
    ret = check_filter_block("src ip in [172.32.7.0/24]", &flow_record, 1);
    ret = check_filter_block("src ip in [172.32.6.0/24]", &flow_record, 0);
    ret = check_filter_block("src ip in [172.32.6.0/23]", &flow_record, 1);
    ret = check_filter_block("src ip in [10.10.10.11 172.32.7.0/24]", &flow_record, 1);
    ret = check_filter_block("src ip in [172.32.7.16 172.32.6.0/24]", &flow_record, 1);
    ret = check_filter_block("src ip in [10.10.10.11 172.32.6.0/24]", &flow_record, 0);

    flow_record.srcPort = 63;
    flow_record.dstPort = 255;
    ret = check_filter_block("src port 63", &flow_record, 1);
    ret = check_filter_block("dst port 255", &flow_record, 1);
    ret = check_filter_block("port 63", &flow_record, 1);
    ret = check_filter_block("port 255", &flow_record, 1);
    ret = check_filter_block("src port 64", &flow_record, 0);
    ret = check_filter_block("dst port 258", &flow_record, 0);
    ret = check_filter_block("port 64", &flow_record, 0);
    ret = check_filter_block("port 258", &flow_record, 0);

    ret = check_filter_block("src port = 63", &flow_record, 1);
    ret = check_filter_block("src port == 63", &flow_record, 1);
    ret = check_filter_block("src port eq 63", &flow_record, 1);
    ret = check_filter_block("src port > 62", &flow_record, 1);
    ret = check_filter_block("src port gt 62", &flow_record, 1);
    ret = check_filter_block("src port > 63", &flow_record, 0);
    ret = check_filter_block("src port < 64", &flow_record, 1);
    ret = check_filter_block("src port lt 64", &flow_record, 1);
    ret = check_filter_block("src port < 63", &flow_record, 0);
    ret = check_filter_block("src port >= 63", &flow_record, 1);
    ret = check_filter_block("src port >= 62", &flow_record, 1);
    ret = check_filter_block("src port <= 255", &flow_record, 1);
    ret = check_filter_block("src port <= 254", &flow_record, 1);
    ret = check_filter_block("src port <= 256", &flow_record, 1);
    ret = check_filter_block("src port >= 64", &flow_record, 0);

    ret = check_filter_block("dst port = 255", &flow_record, 1);
    ret = check_filter_block("dst port == 255", &flow_record, 1);
    ret = check_filter_block("dst port eq 255", &flow_record, 1);
    ret = check_filter_block("dst port > 254", &flow_record, 1);
    ret = check_filter_block("dst port gt 254", &flow_record, 1);
    ret = check_filter_block("dst port > 255", &flow_record, 0);
    ret = check_filter_block("dst port < 256", &flow_record, 1);
    ret = check_filter_block("dst port lt 256", &flow_record, 1);
    ret = check_filter_block("dst port < 255", &flow_record, 0);

    ret = check_filter_block("src port in [ 62 63 64 ]", &flow_record, 1);
    ret = check_filter_block("src port in [ 62 64 65 ]", &flow_record, 0);
    ret = check_filter_block("dst port in [ 254 255 256 ]", &flow_record, 1);
    ret = check_filter_block("dst port in [ 254 256 257 ]", &flow_record, 0);
    ret = check_filter_block("port in [ 62 63 64 ]", &flow_record, 1);
    ret = check_filter_block("port in [ 254 255 256 ]", &flow_record, 1);
    ret = check_filter_block("port in [ 62 63 64 254 255 256 ]", &flow_record, 1);
    ret = check_filter_block("port in [ 62 63 64 254 256 ]", &flow_record, 1);
    ret = check_filter_block("port in [ 62 64 254 256 ]", &flow_record, 0);
    ret = check_filter_block("not port in [ 62 64 254 256 ]", &flow_record, 1);

    flow_record.srcas = 123;
    flow_record.dstas = 456;
    flow_record.bgpNextAdjacentAS = 0x987;
    flow_record.bgpPrevAdjacentAS = 0x789;
    ret = check_filter_block("src as 123", &flow_record, 1);
    ret = check_filter_block("dst as 456", &flow_record, 1);
    ret = check_filter_block("as 123", &flow_record, 1);
    ret = check_filter_block("as 456", &flow_record, 1);
    ret = check_filter_block("src as 124", &flow_record, 0);
    ret = check_filter_block("dst as 457", &flow_record, 0);
    ret = check_filter_block("as 124", &flow_record, 0);
    ret = check_filter_block("as 457", &flow_record, 0);

    ret = check_filter_block("src as > 123", &flow_record, 0);
    ret = check_filter_block("src as > 12", &flow_record, 1);
    ret = check_filter_block("src as < 200", &flow_record, 1);

    ret = check_filter_block("dst as > 457", &flow_record, 0);
    ret = check_filter_block("dst as > 45", &flow_record, 1);
    ret = check_filter_block("dst as < 500", &flow_record, 1);

    ret = check_filter_block("prev as 0x789", &flow_record, 1);
    ret = check_filter_block("previous as 0x789", &flow_record, 1);
    ret = check_filter_block("next as 0x987", &flow_record, 1);
    ret = check_filter_block("prev as 0x788", &flow_record, 0);
    ret = check_filter_block("next as 0x988", &flow_record, 0);

    ret = check_filter_block("src as in [ 122 123 124 ]", &flow_record, 1);
    ret = check_filter_block("dst as in [ 122 124 125 ]", &flow_record, 0);
    ret = check_filter_block("dst as in [ 455 456 457 ]", &flow_record, 1);
    ret = check_filter_block("dst as in [ 455 457 458 ]", &flow_record, 0);
    ret = check_filter_block("as in [ 122 123 124 ]", &flow_record, 1);
    ret = check_filter_block("as in [ 455 456 457 ]", &flow_record, 1);
    ret = check_filter_block("as in [ 122 123 124 455 456 457]", &flow_record, 1);
    ret = check_filter_block("as in [ 122 123 124 455 457]", &flow_record, 1);
    ret = check_filter_block("as in [ 122 124 455 456 457]", &flow_record, 1);
    ret = check_filter_block("as in [ 122 124 455 457]", &flow_record, 0);
    ret = check_filter_block("not as in [ 122 124 455 457]", &flow_record, 1);

    ret = check_filter_block("src net 172.32/16", &flow_record, 1);
    ret = check_filter_block("src net 172.32.7/24", &flow_record, 1);
    ret = check_filter_block("src net 172.32.7.0/27", &flow_record, 1);
    ret = check_filter_block("src net 172.32.7.0/28", &flow_record, 0);
    ret = check_filter_block("src net 172.32.7.0 255.255.255.0", &flow_record, 1);
    ret = check_filter_block("src net 172.32.7.0 255.255.255.240", &flow_record, 0);

    ret = check_filter_block("dst net 10.10/16", &flow_record, 1);
    ret = check_filter_block("dst net 10.10.10/24", &flow_record, 1);
    ret = check_filter_block("dst net 10.10.10.0/28", &flow_record, 1);
    ret = check_filter_block("dst net 10.10.10.0/29", &flow_record, 0);
    ret = check_filter_block("dst net 10.10.10.0 255.255.255.240", &flow_record, 1);
    ret = check_filter_block("dst net 10.10.10.0 255.255.255.248", &flow_record, 0);

    ret = check_filter_block("net 172.32/16", &flow_record, 1);
    ret = check_filter_block("net 172.32.7/24", &flow_record, 1);
    ret = check_filter_block("net 172.32.7.0/27", &flow_record, 1);
    ret = check_filter_block("net 172.32.7.0/28", &flow_record, 0);
    ret = check_filter_block("net 172.32.7.0 255.255.255.0", &flow_record, 1);
    ret = check_filter_block("net 172.32.7.0 255.255.255.240", &flow_record, 0);

    ret = check_filter_block("net 10.10/16", &flow_record, 1);
    ret = check_filter_block("net 10.10.10/24", &flow_record, 1);
    ret = check_filter_block("net 10.10.10.0/28", &flow_record, 1);
    ret = check_filter_block("net 10.10.10.0/29", &flow_record, 0);
    ret = check_filter_block("net 10.10.10.0 255.255.255.240", &flow_record, 1);
    ret = check_filter_block("net 10.10.10.0 255.255.255.240", &flow_record, 1);
    ret = check_filter_block("net 10.10.10.0 255.255.255.248", &flow_record, 0);

    ret = check_filter_block("src ip 172.32.7.16 or src ip 172.32.7.15", &flow_record, 1);
    ret = check_filter_block("src ip 172.32.7.15 or src ip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("src ip 172.32.7.15 or src ip 172.32.7.14", &flow_record, 0);
    ret = check_filter_block("src ip 172.32.7.16 and dst ip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("src ip 172.32.7.15 and dst ip 10.10.10.11", &flow_record, 0);
    ret = check_filter_block("src ip 172.32.7.16 and dst ip 10.10.10.12", &flow_record, 0);

    flow_record.V4.srcaddr = 0;
    flow_record.V4.dstaddr = 0;

    // 172.32.7.16 => 0xac200710
    flow_record.ip_nexthop.V6[0] = 0;
    flow_record.ip_nexthop.V6[1] = 0;
    flow_record.ip_nexthop.V4 = 0xac200710;
    ret = check_filter_block("next ip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("next ip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("next ip in [172.32.7.16 fe80::2110:abcd:1235:ffff]", &flow_record, 1);
    ret = check_filter_block("next ip in [172.32.7.15 fe80::2110:abcd:1235:ffff]", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.ip_nexthop.V6);
    flow_record.ip_nexthop.V6[0] = ntohll(flow_record.ip_nexthop.V6[0]);
    flow_record.ip_nexthop.V6[1] = ntohll(flow_record.ip_nexthop.V6[1]);
    ret = check_filter_block("next ip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("next ip in [172.32.7.16 fe80::2110:abcd:1235:ffff]", &flow_record, 1);
    ret = check_filter_block("next ip in [172.32.7.16 fe80::2110:abcd:1235:fffe]", &flow_record, 0);
    ret = check_filter_block("next ip fe80::2110:abcd:1235:fffe", &flow_record, 0);
    ret = check_filter_block("next ip fe81::2110:abcd:1235:ffff", &flow_record, 0);

    flow_record.ip_nexthop.V6[0] = 0;
    flow_record.ip_nexthop.V6[1] = 0;

    flow_record.bgp_nexthop.V6[0] = 0;
    flow_record.bgp_nexthop.V6[1] = 0;
    flow_record.bgp_nexthop.V4 = 0xac200710;
    ret = check_filter_block("bgpnext ip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("bgpnext ip 172.32.7.15", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.bgp_nexthop.V6);
    flow_record.bgp_nexthop.V6[0] = ntohll(flow_record.bgp_nexthop.V6[0]);
    flow_record.bgp_nexthop.V6[1] = ntohll(flow_record.bgp_nexthop.V6[1]);
    ret = check_filter_block("bgpnext ip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("bgpnext ip fe80::2110:abcd:1235:fffe", &flow_record, 0);
    ret = check_filter_block("bgpnext ip fe81::2110:abcd:1235:ffff", &flow_record, 0);

    flow_record.ip_router.V6[0] = 0;
    flow_record.ip_router.V6[1] = 0;
    flow_record.ip_router.V4 = 0xac200720;
    flow_record.ip_nexthop.V4 = 0xac200720;
    ret = check_filter_block("router ip 172.32.7.32", &flow_record, 1);
    ret = check_filter_block("router ip 172.32.7.33", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.ip_router.V6);
    flow_record.ip_router.V6[0] = ntohll(flow_record.ip_router.V6[0]);
    flow_record.ip_router.V6[1] = ntohll(flow_record.ip_router.V6[1]);
    ret = check_filter_block("router ip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("router ip fe80::2110:abcd:1235:fffe", &flow_record, 0);
    ret = check_filter_block("router ip fe81::2110:abcd:1235:ffff", &flow_record, 0);

    flow_record.engine_type = 5;
    flow_record.engine_id = 6;
    ret = check_filter_block("engine-type 5", &flow_record, 1);
    ret = check_filter_block("engine-type > 1", &flow_record, 1);
    ret = check_filter_block("engine-type > 6", &flow_record, 0);
    ret = check_filter_block("engine-type 6", &flow_record, 0);
    ret = check_filter_block("engine-id 6", &flow_record, 1);
    ret = check_filter_block("engine-id 7", &flow_record, 0);

    flow_record.proto = IPPROTO_TCP;
    flow_record.tcp_flags = 1;
    ret = check_filter_block("flags F", &flow_record, 1);
    ret = check_filter_block("flags S", &flow_record, 0);
    ret = check_filter_block("flags R", &flow_record, 0);
    ret = check_filter_block("flags P", &flow_record, 0);
    ret = check_filter_block("flags A", &flow_record, 0);
    ret = check_filter_block("flags U", &flow_record, 0);
    ret = check_filter_block("flags X", &flow_record, 0);

    flow_record.tcp_flags = 2;  // flags S
    ret = check_filter_block("flags S", &flow_record, 1);
    flow_record.tcp_flags = 4;
    ret = check_filter_block("flags R", &flow_record, 1);
    flow_record.tcp_flags = 8;
    ret = check_filter_block("flags P", &flow_record, 1);
    flow_record.tcp_flags = 16;
    ret = check_filter_block("flags A", &flow_record, 1);
    flow_record.tcp_flags = 32;
    ret = check_filter_block("flags U", &flow_record, 1);
    flow_record.tcp_flags = 63;
    ret = check_filter_block("flags X", &flow_record, 1);

    ret = check_filter_block("not flags RF", &flow_record, 0);

    flow_record.tcp_flags = 3;  // flags SF
    ret = check_filter_block("flags SF", &flow_record, 1);
    ret = check_filter_block("flags 3", &flow_record, 1);
    ret = check_filter_block("flags S and not flags AR", &flow_record, 1);
    flow_record.tcp_flags = 7;
    ret = check_filter_block("flags SF", &flow_record, 1);
    ret = check_filter_block("flags R", &flow_record, 1);
    ret = check_filter_block("flags P", &flow_record, 0);
    ret = check_filter_block("flags A", &flow_record, 0);
    ret = check_filter_block("flags = 7 ", &flow_record, 1);
    ret = check_filter_block("flags > 7 ", &flow_record, 0);
    ret = check_filter_block("flags > 6 ", &flow_record, 1);
    ret = check_filter_block("flags < 7 ", &flow_record, 0);
    ret = check_filter_block("flags < 8 ", &flow_record, 1);

    flow_record.tos = 5;
    flow_record.dst_tos = 7;
    ret = check_filter_block("tos 5", &flow_record, 1);
    ret = check_filter_block("tos = 5", &flow_record, 1);
    ret = check_filter_block("tos > 5", &flow_record, 0);
    ret = check_filter_block("tos < 5", &flow_record, 0);
    ret = check_filter_block("tos > 4", &flow_record, 1);
    ret = check_filter_block("tos < 6", &flow_record, 1);

    ret = check_filter_block("src tos 5", &flow_record, 1);
    ret = check_filter_block("tos 10", &flow_record, 0);
    ret = check_filter_block("dst tos 7", &flow_record, 1);
    ret = check_filter_block("dst tos 10", &flow_record, 0);
    ret = check_filter_block("src or dst tos 7", &flow_record, 1);

    flow_record.input = 5;
    ret = check_filter_block("in if 5", &flow_record, 1);
    ret = check_filter_block("in if 6", &flow_record, 0);
    ret = check_filter_block("out if 6", &flow_record, 0);
    flow_record.output = 6;
    ret = check_filter_block("out if 6", &flow_record, 1);

    flow_record.dir = 1;
    ret = check_filter_block("in if 5", &flow_record, 1);

    /*
     * 172.32.7.17 => 0xac200711
     */
    flow_record.inPackets = 1000;
    ret = check_filter_block("packets 1000", &flow_record, 1);
    ret = check_filter_block("packets = 1000", &flow_record, 1);
    ret = check_filter_block("packets 1010", &flow_record, 0);
    ret = check_filter_block("packets < 1010", &flow_record, 1);
    ret = check_filter_block("packets > 110", &flow_record, 1);
    ret = check_filter_block("in packets 1000", &flow_record, 1);

    flow_record.inBytes = 2000;
    ret = check_filter_block("bytes 2000", &flow_record, 1);
    ret = check_filter_block("bytes  = 2000", &flow_record, 1);
    ret = check_filter_block("bytes 2010", &flow_record, 0);
    ret = check_filter_block("bytes < 2010", &flow_record, 1);
    ret = check_filter_block("bytes > 210", &flow_record, 1);
    ret = check_filter_block("in bytes  = 2000", &flow_record, 1);

    flow_record.inBytes = 2000;
    ret = check_filter_block("bytes 2k", &flow_record, 1);
    ret = check_filter_block("bytes < 2k", &flow_record, 0);
    ret = check_filter_block("bytes > 2k", &flow_record, 0);
    flow_record.inBytes *= 1000;
    ret = check_filter_block("bytes 2m", &flow_record, 1);
    ret = check_filter_block("bytes < 2m", &flow_record, 0);
    ret = check_filter_block("bytes > 2m", &flow_record, 0);
    flow_record.inBytes *= 1000;
    ret = check_filter_block("bytes 2g", &flow_record, 1);
    ret = check_filter_block("bytes < 2g", &flow_record, 0);
    ret = check_filter_block("bytes > 2g", &flow_record, 0);

    flow_record.out_bytes = 3000;
    ret = check_filter_block("out bytes  = 3000", &flow_record, 1);
    ret = check_filter_block("in bytes  = 3000", &flow_record, 0);
    ret = check_filter_block("bytes  = 3000", &flow_record, 0);

    flow_record.out_pkts = 4000;
    ret = check_filter_block("out packets 4000", &flow_record, 1);
    ret = check_filter_block("in packets 4000", &flow_record, 0);
    ret = check_filter_block("packets 4000", &flow_record, 0);

    flow_record.aggr_flows = 5000;
    ret = check_filter_block("flows 5000", &flow_record, 1);
    ret = check_filter_block("flows = 5000", &flow_record, 1);
    ret = check_filter_block("flows 5010", &flow_record, 0);
    ret = check_filter_block("flows < 5001", &flow_record, 1);
    ret = check_filter_block("flows > 4999", &flow_record, 1);

    /*
     * Function tests
     */
    flow_record.msecFirst = 1089534600LL * 1000LL + 10; /* 2004-07-11 10:30:00 */
    flow_record.msecLast = 1089534600LL * 1000LL + 20;  /* 2004-07-11 10:30:00 */

    /* duration 10ms */
    ret = check_filter_block("duration == 10", &flow_record, 1);
    ret = check_filter_block("duration < 11", &flow_record, 1);
    ret = check_filter_block("duration > 9", &flow_record, 1);
    ret = check_filter_block("not duration == 10", &flow_record, 0);
    ret = check_filter_block("duration > 10", &flow_record, 0);
    ret = check_filter_block("duration < 10", &flow_record, 0);

    flow_record.msecFirst = 1089534600LL * 1000LL; /* 2004-07-11 10:30:00 */
    flow_record.msecLast = 1089534610LL * 1000LL;  /* 2004-07-11 10:30:10 */

    /* duration 10s */
    flow_record.inPackets = 1000;
    ret = check_filter_block("duration == 10000", &flow_record, 1);
    ret = check_filter_block("duration < 10001", &flow_record, 1);
    ret = check_filter_block("duration > 9999", &flow_record, 1);
    ret = check_filter_block("not duration == 10000", &flow_record, 0);
    ret = check_filter_block("duration > 10000", &flow_record, 0);
    ret = check_filter_block("duration < 10000", &flow_record, 0);

    ret = check_filter_block("pps == 100", &flow_record, 1);
    ret = check_filter_block("pps < 101", &flow_record, 1);
    ret = check_filter_block("pps > 99", &flow_record, 1);
    ret = check_filter_block("not pps == 100", &flow_record, 0);
    ret = check_filter_block("pps > 100", &flow_record, 0);
    ret = check_filter_block("pps < 100", &flow_record, 0);

    flow_record.inBytes = 1000;
    ret = check_filter_block("bps == 800", &flow_record, 1);
    ret = check_filter_block("bps < 801", &flow_record, 1);
    ret = check_filter_block("bps > 799", &flow_record, 1);
    ret = check_filter_block("not bps == 800", &flow_record, 0);
    ret = check_filter_block("bps > 800", &flow_record, 0);
    ret = check_filter_block("bps < 800", &flow_record, 0);

    flow_record.inBytes = 20000;
    ret = check_filter_block("bps > 1k", &flow_record, 1);
    ret = check_filter_block("bps > 15k", &flow_record, 1);
    ret = check_filter_block("bps > 16k", &flow_record, 0);

    ret = check_filter_block("bpp == 20", &flow_record, 1);
    ret = check_filter_block("bpp < 21", &flow_record, 1);
    ret = check_filter_block("bpp > 19", &flow_record, 1);
    ret = check_filter_block("not bpp == 20", &flow_record, 0);
    ret = check_filter_block("bpp > 20", &flow_record, 0);
    ret = check_filter_block("bpp < 20", &flow_record, 0);

    // ident checks
    CurrentIdent = "channel1";
    ret = check_filter_block("ident channel1", &flow_record, 1);
    ret = check_filter_block("ident channel", &flow_record, 0);
    ret = check_filter_block("ident channel11", &flow_record, 0);
    ret = check_filter_block("not ident channel1", &flow_record, 0);
    ret = check_filter_block("ident none", &flow_record, 0);
    ret = check_filter_block("not ident none", &flow_record, 1);
    CurrentIdent = NULL;
    ret = check_filter_block("ident none", &flow_record, 0);

    // vlan labels
    flow_record.src_vlan = 0;
    flow_record.dst_vlan = 0;

    flow_record.src_vlan = 12345;
    ret = check_filter_block("src vlan 12345", &flow_record, 1);
    ret = check_filter_block("src vlan 12346", &flow_record, 0);
    ret = check_filter_block("vlan 12345", &flow_record, 1);

    flow_record.src_vlan = 0;
    flow_record.dst_vlan = 12346;
    ret = check_filter_block("dst vlan 12346", &flow_record, 1);
    ret = check_filter_block("dst vlan 12345", &flow_record, 0);
    ret = check_filter_block("vlan 12346", &flow_record, 1);
    flow_record.src_vlan = 12345;
    ret = check_filter_block("vlan 12345", &flow_record, 1);

    flow_record.src_mask = 11;
    flow_record.dst_mask = 13;
    ret = check_filter_block("src mask 11", &flow_record, 1);
    ret = check_filter_block("src mask 12", &flow_record, 0);
    ret = check_filter_block("mask 11", &flow_record, 1);
    ret = check_filter_block("dst mask 13", &flow_record, 1);
    ret = check_filter_block("dst mask 14", &flow_record, 0);
    ret = check_filter_block("mask 13", &flow_record, 1);
    ret = check_filter_block("mask 11", &flow_record, 1);

    // mac = 0a:50:56:c0:00:01
    flow_record.in_src_mac = 0x0a5056c00001LL;
    flow_record.in_dst_mac = 0x0b5056c00001LL;
    flow_record.out_src_mac = 0x0c5056c00001LL;
    flow_record.out_dst_mac = 0x0d5056c00001LL;

    ret = check_filter_block("in src mac 0a:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("in src mac 0a:50:56:c0:00:02", &flow_record, 0);
    ret = check_filter_block("in dst mac 0b:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("in dst mac 0b:50:56:c0:00:02", &flow_record, 0);
    ret = check_filter_block("out src mac 0c:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("out src mac 0c:50:56:c0:00:02", &flow_record, 0);
    ret = check_filter_block("out dst mac 0d:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("out dst mac 0d:50:56:c0:00:02", &flow_record, 0);

    ret = check_filter_block("in mac 0a:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("in mac 0b:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("in mac 0c:50:56:c0:00:01", &flow_record, 0);
    ret = check_filter_block("in mac 0d:50:56:c0:00:01", &flow_record, 0);

    ret = check_filter_block("out mac 0c:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("out mac 0d:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("out mac 0a:50:56:c0:00:01", &flow_record, 0);
    ret = check_filter_block("out mac 0b:50:56:c0:00:01", &flow_record, 0);

    ret = check_filter_block("src mac 0a:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("src mac 0c:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("src mac 0b:50:56:c0:00:01", &flow_record, 0);
    ret = check_filter_block("src mac 0d:50:56:c0:00:01", &flow_record, 0);

    ret = check_filter_block("dst mac 0b:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("dst mac 0d:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("dst mac 0a:50:56:c0:00:01", &flow_record, 0);
    ret = check_filter_block("dst mac 0c:50:56:c0:00:01", &flow_record, 0);

    ret = check_filter_block("mac 0a:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0b:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0c:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0d:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0a:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0c:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0b:50:56:c0:00:01", &flow_record, 1);
    ret = check_filter_block("mac 0d:50:56:c0:00:01", &flow_record, 1);

    flow_record.fwd_status = 1;
    ret = check_filter_block("fwdstat 1", &flow_record, 1);
    ret = check_filter_block("fwdstat 2", &flow_record, 0);
    ret = check_filter_block("fwdstat forw", &flow_record, 1);
    ret = check_filter_block("fwdstat noroute", &flow_record, 0);

    flow_record.dir = 1;
    ret = check_filter_block("flowdir 1", &flow_record, 1);
    ret = check_filter_block("flowdir 0", &flow_record, 0);
    ret = check_filter_block("flowdir egress", &flow_record, 1);
    ret = check_filter_block("flowdir ingress", &flow_record, 0);

    for (i = 0; i < 10; i++) {
        flow_record.mpls_label[i] = 0x10;  // init to some value
    }
    for (i = 1; i < 11; i++) {
        char s[64];
        flow_record.mpls_label[i - 1] = 1026 << 4;
        snprintf(s, 63, "mpls label%i 1026", i);

        ret = check_filter_block(s, &flow_record, 1);

        snprintf(s, 63, "mpls label%i 1025", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls label%i 1027", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls label%i < 1026", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls label%i > 1026", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls label%i < 1027", i);
        ret = check_filter_block(s, &flow_record, 1);

        snprintf(s, 63, "mpls label%i > 1025", i);
        ret = check_filter_block(s, &flow_record, 1);

        flow_record.mpls_label[i - 1] = 0x10;  // init to some value
    }

    flow_record.mpls_label[4] = (32 << 4) + 1;
    ret = check_filter_block("mpls eos 32", &flow_record, 1);
    ret = check_filter_block("mpls eos 31", &flow_record, 0);
    ret = check_filter_block("mpls eos 33", &flow_record, 0);
    ret = check_filter_block("mpls eos > 31", &flow_record, 1);
    ret = check_filter_block("mpls eos < 33", &flow_record, 1);

    for (i = 0; i < 10; i++) {
        flow_record.mpls_label[i] = 0x10;  // init to some value
    }
    for (i = 1; i < 11; i++) {
        char s[64];
        flow_record.mpls_label[i - 1] = 4 << 1;
        snprintf(s, 63, "mpls exp%i 4", i);

        ret = check_filter_block(s, &flow_record, 1);

        snprintf(s, 63, "mpls exp%i 3", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls exp%i 5", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls exp%i < 4", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls exp%i > 4", i);
        ret = check_filter_block(s, &flow_record, 0);

        snprintf(s, 63, "mpls exp%i < 5", i);
        ret = check_filter_block(s, &flow_record, 1);

        snprintf(s, 63, "mpls exp%i > 3", i);
        ret = check_filter_block(s, &flow_record, 1);

        flow_record.mpls_label[i - 1] = 0x10;  // init to some value
    }

    flow_record.client_nw_delay_usec = 11;
    flow_record.server_nw_delay_usec = 22;
    flow_record.appl_latency_usec = 33;

    ret = check_filter_block("client latency 11", &flow_record, 1);
    ret = check_filter_block("server latency 22", &flow_record, 1);
    ret = check_filter_block("app latency 33", &flow_record, 1);
    ret = check_filter_block("client latency 12", &flow_record, 0);
    ret = check_filter_block("server latency 23", &flow_record, 0);
    ret = check_filter_block("app latency 34", &flow_record, 0);
    ret = check_filter_block("client latency < 11", &flow_record, 0);
    ret = check_filter_block("client latency > 11", &flow_record, 0);

    flow_record.exporter_sysid = 44;
    ret = check_filter_block("sysid 44", &flow_record, 1);
    ret = check_filter_block("sysid 45", &flow_record, 0);

    // geo location
    flow_record.src_geo[0] = 'A';
    flow_record.src_geo[1] = 'B';
    flow_record.dst_geo[0] = 'C';
    flow_record.dst_geo[1] = 'D';
    ret = check_filter_block("src geo AB", &flow_record, 1);
    ret = check_filter_block("src geo CD", &flow_record, 0);

    ret = check_filter_block("dst geo AB", &flow_record, 0);
    ret = check_filter_block("dst geo CD", &flow_record, 1);

    flow_record.inPayload = "GET /index.html HTTP/1.1\r\n";
    flow_record.inPayloadLength = 26;

    ret = check_filter_block("payload content /GET|POST/", &flow_record, 1);
    ret = check_filter_block("payload content /HT{1,3}P/[0-9].[0-9]/", &flow_record, 1);
    ret = check_filter_block("payload content 'GET /index'", &flow_record, 1);
    ret = check_filter_block("payload content POST", &flow_record, 0);

    char *ja3s = "123456789abcdef0123456789abcdef0";
    char *pos = ja3s;
    uint8_t ja3[16];
    for (int count = 0; count < 16; count++) {
        sscanf(pos, "%2hhx", &ja3[count]);
        pos += 2;
    }

    memcpy((void *)flow_record.ja3, (void *)ja3, 16);
    ret = check_filter_block("payload ja3 123456789abcdef0123456789abcdef0", &flow_record, 1);
    ret = check_filter_block("payload ja3 123456789abcdef0123456789abcdef1", &flow_record, 0);
    ret = check_filter_block("payload ja3 023456789abcdef0123456789abcdef0", &flow_record, 0);

    flow_record.tun_src_ip.V6[0] = 0;
    flow_record.tun_src_ip.V6[1] = 0;
    flow_record.tun_src_ip.V4 = 0xac200710;
    flow_record.tun_dst_ip.V6[0] = 0;
    flow_record.tun_dst_ip.V6[1] = 0;
    flow_record.tun_dst_ip.V4 = 0x0a0a0a0b;
    ret = check_filter_block("src tunip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("src tunip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("dst tunip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("dst tunip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("tunip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("tunip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("tunip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("tunip 10.10.10.12", &flow_record, 0);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.tun_src_ip.V6);
    flow_record.tun_src_ip.V6[0] = ntohll(flow_record.tun_src_ip.V6[0]);
    flow_record.tun_src_ip.V6[1] = ntohll(flow_record.tun_src_ip.V6[1]);
    ret = check_filter_block("src tunip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("src tunip fe80::2110:abcd:1235:fffe", &flow_record, 0);

    flow_record.tun_src_ip.V6[0] = 0;
    flow_record.tun_src_ip.V6[1] = 0;
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:fffe", flow_record.tun_dst_ip.V6);
    flow_record.tun_dst_ip.V6[0] = ntohll(flow_record.tun_dst_ip.V6[0]);
    flow_record.tun_dst_ip.V6[1] = ntohll(flow_record.tun_dst_ip.V6[1]);
    ret = check_filter_block("dst tunip fe80::2110:abcd:1235:fffe", &flow_record, 1);
    ret = check_filter_block("dst tunip fe80::2110:abcd:1235:fffc", &flow_record, 0);
    flow_record.tun_src_ip.V6[0] = 0;
    flow_record.tun_src_ip.V6[1] = 0;
    flow_record.tun_dst_ip.V6[0] = 0;
    flow_record.tun_dst_ip.V6[1] = 0;

    flow_record.tun_proto = IPPROTO_GRE;
    ret = check_filter_block("tun proto gre", &flow_record, 1);
    ret = check_filter_block("tun proto 47", &flow_record, 1);
    ret = check_filter_block("tun proto 42", &flow_record, 0);

    flow_record.tun_proto = IPPROTO_IPIP;
    ret = check_filter_block("tun proto ipip", &flow_record, 1);
    ret = check_filter_block("tun proto 4", &flow_record, 1);
    ret = check_filter_block("tun proto 5", &flow_record, 0);

    flow_record.observationDomainID = 0xcabc;
    ret = check_filter_block("observation domain id 0xcabc", &flow_record, 1);
    ret = check_filter_block("observation domain id 12345", &flow_record, 0);

    flow_record.observationPointID = 0xabcabcabc;
    ret = check_filter_block("observation point id 0xabcabcabc", &flow_record, 1);
    ret = check_filter_block("observation point id 12345", &flow_record, 0);

    ret = check_filter_block("flowlabel NewLabel", &flow_record, 0);
    flow_record.label = "NewLabel";
    ret = check_filter_block("flowlabel NewLabel", &flow_record, 1);
    ret = check_filter_block("flowlabel none", &flow_record, 0);

    flow_record.flowCount = 11;
    ret = check_filter_block("count 11", &flow_record, 1);
    ret = check_filter_block("count 10", &flow_record, 0);
    ret = check_filter_block("count > 10", &flow_record, 1);

    // NSEL/ASA related tests
#ifdef NSEL
    flow_record.event = NSEL_EVENT_IGNORE;
    flow_record.event_flag = FW_EVENT;
    ret = check_filter_block("asa event ignore", &flow_record, 1);
    ret = check_filter_block("asa event create", &flow_record, 0);
    flow_record.event = NSEL_EVENT_CREATE;
    ret = check_filter_block("asa event create", &flow_record, 1);
    flow_record.event = NSEL_EVENT_DELETE;
    ret = check_filter_block("asa event term", &flow_record, 1);
    ret = check_filter_block("asa event delete", &flow_record, 1);
    flow_record.event = NSEL_EVENT_DENIED;
    ret = check_filter_block("asa event deny", &flow_record, 1);
    ret = check_filter_block("asa event create", &flow_record, 0);
    ret = check_filter_block("asa event 3", &flow_record, 1);
    ret = check_filter_block("asa event > 2", &flow_record, 1);
    ret = check_filter_block("asa event > 3", &flow_record, 0);

    flow_record.fwXevent = 1001;
    ret = check_filter_block("asa event denied ingress", &flow_record, 1);
    ret = check_filter_block("asa event denied egress", &flow_record, 0);
    flow_record.fwXevent = 1002;
    ret = check_filter_block("asa event denied egress", &flow_record, 1);
    flow_record.fwXevent = 1003;
    ret = check_filter_block("asa event denied interface", &flow_record, 1);
    flow_record.fwXevent = 1004;
    ret = check_filter_block("asa event denied nosyn", &flow_record, 1);
    ret = check_filter_block("asa event denied ingress", &flow_record, 0);
    flow_record.event = NSEL_EVENT_CREATE;
    ret = check_filter_block("asa event denied nosyn", &flow_record, 0);

    ret = check_filter_block("asa xevent 1004", &flow_record, 1);
    ret = check_filter_block("asa xevent < 1004", &flow_record, 0);
    ret = check_filter_block("asa xevent > 1004", &flow_record, 0);

    flow_record.xlate_src_ip.V6[0] = 0;
    flow_record.xlate_src_ip.V6[1] = 0;
    flow_record.xlate_src_ip.V4 = 0xac200710;
    flow_record.xlate_dst_ip.V6[0] = 0;
    flow_record.xlate_dst_ip.V6[1] = 0;
    flow_record.xlate_dst_ip.V4 = 0x0a0a0a0b;
    ret = check_filter_block("src xip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("src xip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("dst xip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("dst xip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("xip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("xip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("xip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("xip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("src xnet 172.32.7.0/24", &flow_record, 1);
    ret = check_filter_block("src xnet 172.32.8.0/24", &flow_record, 0);
    ret = check_filter_block("dst xnet 10.10.10.0/24", &flow_record, 1);
    ret = check_filter_block("dst xnet 10.10.11.0/24", &flow_record, 0);
    ret = check_filter_block("xnet 172.32.7.0/24", &flow_record, 1);
    ret = check_filter_block("xnet 10.10.10.0/24", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.xlate_src_ip.V6);
    flow_record.xlate_src_ip.V6[0] = ntohll(flow_record.xlate_src_ip.V6[0]);
    flow_record.xlate_src_ip.V6[1] = ntohll(flow_record.xlate_src_ip.V6[1]);
    ret = check_filter_block("src xip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("src xip fe80::2110:abcd:1235:fffe", &flow_record, 0);

    flow_record.xlate_src_ip.V6[0] = 0;
    flow_record.xlate_src_ip.V6[1] = 0;
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:fffe", flow_record.xlate_dst_ip.V6);
    flow_record.xlate_dst_ip.V6[0] = ntohll(flow_record.xlate_dst_ip.V6[0]);
    flow_record.xlate_dst_ip.V6[1] = ntohll(flow_record.xlate_dst_ip.V6[1]);
    ret = check_filter_block("dst xip fe80::2110:abcd:1235:fffe", &flow_record, 1);
    ret = check_filter_block("dst xip fe80::2110:abcd:1235:fffc", &flow_record, 0);
    flow_record.xlate_src_ip.V6[0] = 0;
    flow_record.xlate_src_ip.V6[1] = 0;
    flow_record.xlate_dst_ip.V6[0] = 0;
    flow_record.xlate_dst_ip.V6[1] = 0;

    flow_record.xlate_src_port = 1023;
    flow_record.xlate_dst_port = 32798;
    ret = check_filter_block("src xport 1023", &flow_record, 1);
    ret = check_filter_block("dst xport 32798", &flow_record, 1);
    ret = check_filter_block("src xport > 1022", &flow_record, 1);
    ret = check_filter_block("src xport < 1024", &flow_record, 1);
    ret = check_filter_block("dst xport lt 32799", &flow_record, 1);
    ret = check_filter_block("dst xport gt 32797", &flow_record, 1);
    ret = check_filter_block("src xport > 1023", &flow_record, 0);
    ret = check_filter_block("dst xport gt 32798", &flow_record, 0);
    ret = check_filter_block("src xport 1022", &flow_record, 0);
    ret = check_filter_block("dst xport 32797", &flow_record, 0);
    flow_record.xlate_src_port = 0xffff;
    flow_record.xlate_dst_port = 0xffff;

    flow_record.ingressAcl[0] = 0xaabbcc;
    flow_record.ingressAcl[1] = 0xbbccdd;
    flow_record.ingressAcl[2] = 0xccddee;

    flow_record.egressAcl[0] = 0x112233;
    flow_record.egressAcl[1] = 0x223344;
    flow_record.egressAcl[2] = 0x334455;

    ret = check_filter_block("ingress ACL 0xaabbcc", &flow_record, 1);
    flow_record.event = 255;

    // NEL/NAT related tests
    flow_record.event = NEL_EVENT_INVALID;
    flow_record.event_flag = NAT_EVENT;
    ret = check_filter_block("nat event invalid", &flow_record, 1);
    ret = check_filter_block("nat event add", &flow_record, 0);
    flow_record.event = NEL_EVENT_ADD;
    ret = check_filter_block("nat event add", &flow_record, 1);
    flow_record.event = NEL_EVENT_DELETE;
    ret = check_filter_block("nat event delete", &flow_record, 1);
    ret = check_filter_block("nat event add", &flow_record, 0);
    ret = check_filter_block("nat event 2", &flow_record, 1);
    ret = check_filter_block("nat event > 1", &flow_record, 1);
    ret = check_filter_block("nat event > 2", &flow_record, 0);
    flow_record.event = 255;

    flow_record.ingressVrf = 0xAAAA;
    ret = check_filter_block("ingress vrf 0xAAAA", &flow_record, 1);
    ret = check_filter_block("ingress vrf 100", &flow_record, 0);

    flow_record.egressVrf = 0xBBBB;
    ret = check_filter_block("egress vrf 0xBBBB", &flow_record, 1);
    ret = check_filter_block("egress vrf 0xAAAA", &flow_record, 0);

    flow_record.block_start = 1111;
    ret = check_filter_block("pblock start 1111", &flow_record, 1);
    ret = check_filter_block("pblock start 2222", &flow_record, 0);

    flow_record.block_end = 2222;
    ret = check_filter_block("pblock end 2222", &flow_record, 1);
    ret = check_filter_block("pblock end 3333", &flow_record, 0);

    flow_record.block_step = 3333;
    ret = check_filter_block("pblock step 3333", &flow_record, 1);
    ret = check_filter_block("pblock step 4444", &flow_record, 0);

    flow_record.block_size = 4444;
    ret = check_filter_block("pblock size 4444", &flow_record, 1);
    ret = check_filter_block("pblock size 5555", &flow_record, 0);

    flow_record.srcPort = 63;
    flow_record.dstPort = 255;
    ret = check_filter_block("src port in pblock", &flow_record, 0);
    ret = check_filter_block("dst port in pblock", &flow_record, 0);
    ret = check_filter_block("port in pblock", &flow_record, 0);

    flow_record.srcPort = 1110;
    ret = check_filter_block("src port in pblock", &flow_record, 0);
    ret = check_filter_block("port in pblock", &flow_record, 0);

    flow_record.srcPort = 1111;
    ret = check_filter_block("src port in pblock", &flow_record, 1);
    ret = check_filter_block("port in pblock", &flow_record, 1);

    flow_record.srcPort = 2222;
    ret = check_filter_block("src port in pblock", &flow_record, 1);
    ret = check_filter_block("port in pblock", &flow_record, 1);

    flow_record.srcPort = 2223;
    ret = check_filter_block("src port in pblock", &flow_record, 0);
    ret = check_filter_block("port in pblock", &flow_record, 0);

    flow_record.dstPort = 1110;
    ret = check_filter_block("src port in pblock", &flow_record, 0);
    ret = check_filter_block("dst port in pblock", &flow_record, 0);
    ret = check_filter_block("port in pblock", &flow_record, 0);

    flow_record.dstPort = 1111;
    ret = check_filter_block("dst port in pblock", &flow_record, 1);
    ret = check_filter_block("port in pblock", &flow_record, 1);

    flow_record.dstPort = 2222;
    ret = check_filter_block("dst port in pblock", &flow_record, 1);
    ret = check_filter_block("port in pblock", &flow_record, 1);

    flow_record.dstPort = 2223;
    ret = check_filter_block("dst port in pblock", &flow_record, 0);
    ret = check_filter_block("port in pblock", &flow_record, 0);

    flow_record.srcPort = 1234;
    flow_record.dstPort = 2134;
    ret = check_filter_block("src port in pblock", &flow_record, 1);
    ret = check_filter_block("dst port in pblock", &flow_record, 1);
    ret = check_filter_block("port in pblock", &flow_record, 1);

    flow_record.xlate_src_port = 1023;
    flow_record.xlate_dst_port = 32798;
    ret = check_filter_block("src nport 1023", &flow_record, 1);
    ret = check_filter_block("dst nport 32798", &flow_record, 1);
    ret = check_filter_block("src nport > 1022", &flow_record, 1);
    ret = check_filter_block("src nport < 1024", &flow_record, 1);
    ret = check_filter_block("dst nport lt 32799", &flow_record, 1);
    ret = check_filter_block("dst nport gt 32797", &flow_record, 1);
    ret = check_filter_block("src nport > 1023", &flow_record, 0);
    ret = check_filter_block("dst nport gt 32798", &flow_record, 0);
    ret = check_filter_block("src nport 1022", &flow_record, 0);
    ret = check_filter_block("dst nport 32797", &flow_record, 0);
    flow_record.xlate_src_port = 0xffff;
    flow_record.xlate_dst_port = 0xffff;

    flow_record.xlate_src_ip.V6[0] = 0;
    flow_record.xlate_src_ip.V6[1] = 0;
    flow_record.xlate_src_ip.V4 = 0xac200710;
    flow_record.xlate_dst_ip.V6[0] = 0;
    flow_record.xlate_dst_ip.V6[1] = 0;
    flow_record.xlate_dst_ip.V4 = 0x0a0a0a0b;
    ret = check_filter_block("src nip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("src nip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("dst nip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("dst nip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("nip 172.32.7.16", &flow_record, 1);
    ret = check_filter_block("nip 10.10.10.11", &flow_record, 1);
    ret = check_filter_block("nip 172.32.7.15", &flow_record, 0);
    ret = check_filter_block("nip 10.10.10.12", &flow_record, 0);
    ret = check_filter_block("src nip in [ 172.32.7.16] ", &flow_record, 1);
    ret = check_filter_block("src nip in [ 172.32.7.15] ", &flow_record, 0);
    ret = check_filter_block("dst nip in [ 10.10.10.11] ", &flow_record, 1);
    ret = check_filter_block("dst nip in [ 10.10.10.12] ", &flow_record, 0);
    ret = check_filter_block("nip in [ 10.10.10.11] ", &flow_record, 1);
    ret = check_filter_block("nip in [ 172.32.7.16] ", &flow_record, 1);

    inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.xlate_src_ip.V6);
    flow_record.xlate_src_ip.V6[0] = ntohll(flow_record.xlate_src_ip.V6[0]);
    flow_record.xlate_src_ip.V6[1] = ntohll(flow_record.xlate_src_ip.V6[1]);
    ret = check_filter_block("src nip fe80::2110:abcd:1235:ffff", &flow_record, 1);
    ret = check_filter_block("src nip fe80::2110:abcd:1235:fffe", &flow_record, 0);

    flow_record.xlate_src_ip.V6[0] = 0;
    flow_record.xlate_src_ip.V6[1] = 0;
    inet_pton(PF_INET6, "fe80::2110:abcd:1235:fffe", flow_record.xlate_dst_ip.V6);
    flow_record.xlate_dst_ip.V6[0] = ntohll(flow_record.xlate_dst_ip.V6[0]);
    flow_record.xlate_dst_ip.V6[1] = ntohll(flow_record.xlate_dst_ip.V6[1]);
    ret = check_filter_block("dst nip fe80::2110:abcd:1235:fffe", &flow_record, 1);
    ret = check_filter_block("dst nip fe80::2110:abcd:1235:fffc", &flow_record, 0);

#endif

    return 0;
}
