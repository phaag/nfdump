/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2013, Peter Haag
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
 *  $Author$
 *
 *  $Id$
 *
 *  $LastChangedRevision$
 *  
 */

#include "config.h"

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <resolv.h>
#include <pthread.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "util.h"
#include "nffile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "flowtree.h"
#include "content_dns.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "inline.c"

/*
 * Structure for query header.  The order of the fields is machine- and
 * compiler-dependent, depending on the byte/bit order and the layout
 * of bit fields.  We use bit fields only in int variables, as this
 * is all ANSI requires.  This requires a somewhat confusing rearrangement.
 */

typedef struct dns_header_s {
        unsigned        id :16;         /* query identification number */
#ifdef WORDS_BIGENDIAN
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        rcode :4;       /* response code */
#else
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
} dns_header_t;

#define DNS_QUERY_TYPE_A    (1)
#define DNS_QUERY_TYPE_AAAA (2)
#define DNS_QUERY_TYPE_SRV  (3)

typedef struct dns_host_st {
    struct dns_host_st  *next;

    unsigned int        type;
    unsigned int        class;
    unsigned int        ttl;

    void                *rr;
} dns_host_t;

typedef struct dns_srv_st {
    unsigned int        priority;
    unsigned int        weight;
    unsigned int        port;
    unsigned int        rweight;

    char                name[256];
} dns_srv_t;

static void *_a_rr(void **p) {
struct in_addr in;

	in.s_addr = ntohl(Get_val32(*p)); *p += 4;
    return strdup(inet_ntoa(in));
}

static void *_aaaa_rr(void **p) {
char addr[INET6_ADDRSTRLEN];
uint64_t sa6[2];

	memcpy((void *)sa6, *p, 16);
    inet_ntop(AF_INET6, (struct sockaddr_storage *)&sa6, addr, sizeof(addr));

    return strdup(addr);
}

void content_decode_dns(struct FlowNode	*node, uint8_t *payload, uint32_t payload_size) {
dns_header_t *dns_header = (dns_header_t *)payload;
uint32_t qdcount, ancount;
void *p, *eod;
#define DN_LENGTH 256
char	dn[DN_LENGTH];
int i;

	if ( payload_size < sizeof(dns_header_t) ) {
		LogError("Unable to decode short DNS packet");
		return;
	}

	// no of query packets
	qdcount = ntohs(dns_header->qdcount);
	dbg_printf("DNS Queries: %u\n", qdcount);

    // no of answer packets
    ancount = ntohs(dns_header->ancount);
	dbg_printf("DNS Answers: %u\n", ancount);

    // end of dns packet
    eod = (void *)(payload + payload_size);

    // reord pointer
    p = (void *)(payload + sizeof(dns_header_t));

	for (i=0; i<qdcount && p < eod; i++ ) {
		int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
		if (len < 0) {
            LogError("dn_expand() failed: %s", "");
		} 
		dbg_printf("DNS Query dn_expand: %s\n", dn);
        p = (void *) (p + len + 4);	// + 4 bytes of fixed data in query
	}

	for (i=0; i<ancount && p < eod; i++ ) {
		uint32_t type, class, ttl;
        int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
        if(len < 0) {
            LogError("dn_expand() failed: %s", "");
        }
		dbg_printf("DNS Answer %i dn_expand: %s ", i, dn);

        p += len;

        /* extract the various parts of the record */
		type  = Get_val16(p); p += 2;
		class = Get_val16(p); p += 2;
		ttl   = Get_val32(p); p += 4;
		len   = Get_val16(p); p += 2;

		dbg_printf(" Type: %u, class: %u, ttl: %u, len: %u ", type, class, ttl, len);
        /* type-specific processing */
        switch(type) {
			char *s;
#ifdef T_A
            case T_A:
#else
            case ns_t_a:
#endif
                s = _a_rr(&p);
				dbg_printf("A: %s\n", s);
				free(s);
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
				dbg_printf("AAAA: %s\n", s);
				free(s);
                break;
#ifdef T_CNAME
            case T_CNAME: {
#else
			case ns_t_cname: {
#endif
        		int32_t len = dn_expand(payload, eod, p, dn, DN_LENGTH);
				dbg_printf("CNAME: %s\n", dn);
                p = (void *)(p + len);
                } break;

            default:
				dbg_printf("<unkn>\n");
                p = (void *)(p + len);
                continue;
        }

    }

} // End of content_decode_dns

