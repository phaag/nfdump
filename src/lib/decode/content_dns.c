/* vi: set sw=4 ts=4: */
/*
 *  Copyright (c) 2013-2022, Peter Haag
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

#include "config.h"

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <pthread.h>
#include <resolv.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "nfdump.h"
#include "util.h"
// #include "nffile.h"
#include "content_dns.h"
#include "inline.c"

/*
 * Structure for query header.  The order of the fields is machine- and
 * compiler-dependent, depending on the byte/bit order and the layout
 * of bit fields.  We use bit fields only in int variables, as this
 * is all ANSI requires.  This requires a somewhat confusing rearrangement.
 */

typedef struct dns_header_s {
    unsigned id : 16; /* query identification number */
#ifdef WORDS_BIGENDIAN
    /* fields in third byte */
    unsigned qr : 1;     /* response flag */
    unsigned opcode : 4; /* purpose of message */
    unsigned aa : 1;     /* authoritative answer */
    unsigned tc : 1;     /* truncated message */
    unsigned rd : 1;     /* recursion desired */
                         /* fields in fourth byte */
    unsigned ra : 1;     /* recursion available */
    unsigned unused : 3; /* unused bits (MBZ as of 4.9.3a3) */
    unsigned rcode : 4;  /* response code */
#else
    /* fields in third byte */
    unsigned rd : 1;     /* recursion desired */
    unsigned tc : 1;     /* truncated message */
    unsigned aa : 1;     /* authoritative answer */
    unsigned opcode : 4; /* purpose of message */
    unsigned qr : 1;     /* response flag */
                         /* fields in fourth byte */
    unsigned rcode : 4;  /* response code */
    unsigned unused : 3; /* unused bits (MBZ as of 4.9.3a3) */
    unsigned ra : 1;     /* recursion available */
#endif
    /* remaining bytes */
    unsigned qdcount : 16; /* number of question entries */
    unsigned ancount : 16; /* number of answer entries */
    unsigned nscount : 16; /* number of authority entries */
    unsigned arcount : 16; /* number of resource entries */
} dns_header_t;

#define DNS_QUERY_TYPE_A (1)
#define DNS_QUERY_TYPE_AAAA (2)
#define DNS_QUERY_TYPE_SRV (3)

typedef struct dns_host_st {
    struct dns_host_st *next;

    unsigned int type;
    unsigned int class;
    unsigned int ttl;

    void *rr;
} dns_host_t;

typedef struct dns_srv_st {
    unsigned int priority;
    unsigned int weight;
    unsigned int port;
    unsigned int rweight;

    char name[256];
} dns_srv_t;

static void *_a_rr(void **p) {
    struct in_addr in;

    in.s_addr = ntohl(Get_val32(*p));
    return strdup(inet_ntoa(in));
}

static void *_aaaa_rr(void **p) {
    char addr[INET6_ADDRSTRLEN];
    uint64_t sa6[2];

    memcpy((void *)sa6, *p, 16);
    inet_ntop(AF_INET6, (struct sockaddr_storage *)&sa6, addr, sizeof(addr));

    return strdup(addr);
}

static char *typeToChar(uint16_t type) {
    static char unknown[16];

    switch (type) {
        case 1:
            return "A";
            break;
        case 2:
            return "NS";
            break;
        case 5:
            return "CNAME";
            break;
        case 6:
            return "SOA";
            break;
        case 15:
            return "MX";
            break;
        case 16:
            return "TXT";
            break;
        case 28:
            return "AAAA";
            break;
        case 29:
            return "LOC";
            break;
        default:
            unknown[0] = '\0';
            snprintf(unknown, 16, "%u", type);
            return unknown;
    }
    /* not reached */

}  // End of typeToChar

void content_decode_dns(FILE *stream, uint8_t proto, uint8_t *payload, uint32_t payload_size) {
    uint32_t qdcount, ancount;
    void *p, *eod;
#define DN_LENGTH 256
    char dn[DN_LENGTH];
    int i;

    if (proto == IPPROTO_TCP) payload += 2;
    dns_header_t *dns_header = (dns_header_t *)payload;

    if (payload_size < sizeof(dns_header_t)) {
        dn[0] = '\0';
        fprintf(stream, "DNS: <Short packet>\n");
        return;
    }

    // number of of query packets
    qdcount = ntohs(dns_header->qdcount);
    // number of answer packets
    ancount = ntohs(dns_header->ancount);
    // fprintf(stream,"DNS Queries: %u, Answers: %u\n", qdcount, ancount);

    // end of dns packet
    eod = (void *)(payload + payload_size);

    // record pointer
    p = (void *)(payload + sizeof(dns_header_t));
    uint32_t type, class, ttl;
    for (i = 0; i < qdcount && p < eod; i++) {
        int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
        if (len < 0) {
            fprintf(stream, "DNS query: decoding failed!\n");
            return;
        }
        p += len;
        type = Get_val16(p);
        p += 2;
        class = Get_val16(p);
        p += 2;
        fprintf(stream, "DNS Query %i: %s type: %s, class: %u\n", i, dn, typeToChar(type), class);
    }

    for (i = 0; i < ancount && p < eod; i++) {
        int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
        if (len < 0) {
            dn[0] = '\0';
            fprintf(stream, "DNS answer: decoding failed!\n");
            return;
        }
        fprintf(stream, "DNS Answer %i: %s ", i, dn);

        p += len;

        /* extract the various parts of the record */
        type = Get_val16(p);
        p += 2;
        class = Get_val16(p);
        p += 2;
        ttl = Get_val32(p);
        p += 4;
        len = Get_val16(p);
        p += 2;

        fprintf(stream, " Type: %s, class: %u, ttl: %u, len: %u ", typeToChar(type), class, ttl, len);
        /* type-specific processing */
        switch (type) {
            char *s;
#ifdef T_A
            case T_A:
#else
            case ns_t_a:
#endif
                s = _a_rr(&p);
                fprintf(stream, "A: %s", s);
                free(s);
                p += 4;
                break;
#ifdef T_A6
            case T_A6:
#endif
#ifdef T_AAAA
            case T_AAAA:
#else
            case ns_t_a6:
            case ns_t_aaaa:
#endif

                s = _aaaa_rr(&p);
                fprintf(stream, "AAAA: %s", s);
                free(s);
                p += 16;

                break;
#ifdef T_CNAME
            case T_CNAME:
#else
            case ns_t_cname:
#endif
            {
                int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
                fprintf(stream, "CNAME: %s", dn);
                p += len;
            } break;
#ifdef T_NS
            case T_NS:
#else
            case ns_s_ns:
#endif
            {
                int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
                fprintf(stream, "NS: %s", dn);
                p += len;
            } break;
#ifdef T_SOA
            case T_SOA:
#else
            case ns_t_soa:
#endif
            {
                int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
                fprintf(stream, "SOA: %s", dn);
                p += len;
            } break;
#ifdef T_TXT
            case T_TXT:
#else
            case ns_t_txt:
#endif
                if (len < 256 && (p + len) < eod) {
                    char r_txt[256];
                    r_txt[0] = '\0';
                    strncpy(r_txt, p + 1, 256);
                    r_txt[255] = '\0';
                    fprintf(stream, "TXT: %s", r_txt);
                }
                p += len;
                break;
#ifndef T_RRSIG
#define T_RRSIG 46
#endif
            case T_RRSIG:
                fprintf(stream, "RRSIG: %s", "<Signature for a DNSSEC-secured record>");
                break;
            default:
                fprintf(stream, "<unkn> %u", type);
                p += len;
        }
        fprintf(stream, "\n");
    }

}  // End of content_decode_dns
