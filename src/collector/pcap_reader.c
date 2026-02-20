/*
 *  Copyright (c) 2009-2026, Peter Haag
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

#ifdef HAVE_NET_ETHERNET_H
// FreeBSD needs sys/types in include ethernet.h
#if defined __FreeBSD__
#include <sys/types.h>
#endif
#include <net/ethernet.h>
#endif

#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

#define __FAVOR_BSD 1

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "pcap_reader.h"
#include "util.h"

// define potential missing types
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#ifndef DLT_NFLOG
#define DLT_NFLOG 239
#endif

#ifndef DLT_PFLOG
#define DLT_PFLOG 117
#endif

#define PROTO_ERSPAN 0x88be
#define PROTO_ERSPANIII 0x22be

static pcap_t *pcap_handle;
static int linktype = 0;
static int linkoffset = 0;

/*
 * Function prototypes
 */

static int setup_pcap(char *filter);

static ssize_t decode_packet(const struct pcap_pkthdr *hdr, const uint8_t *pkt, void *buffer, size_t buffer_size, struct sockaddr_storage *sock,
                             struct timeval *tv);

/*
 * Minimal pcap decoder for NetFlow/IPFIX debugging.
 * Strips link layer → IPv4 → UDP → payload.
 * single VLAN tag stripping.
 */

static int setup_pcap(char *filter) {
    struct bpf_program bpfFilter;

    if (filter) {
        if (pcap_compile(pcap_handle, &bpfFilter, filter, 1, 0) < 0 || pcap_setfilter(pcap_handle, &bpfFilter) < 0) {
            LogError("pcap filter error: %s", pcap_geterr(pcap_handle));
            return 0;
        }
    }

    linktype = pcap_datalink(pcap_handle);

    switch (linktype) {
        case DLT_EN10MB:
            linkoffset = 14;
            break;
        case DLT_LINUX_SLL:
            linkoffset = 16;
            break;
        case DLT_LINUX_SLL2:
            linkoffset = 20;
            break;
        case DLT_NULL:
        case DLT_LOOP:
            linkoffset = 4;
            break;
        case DLT_RAW:
            linkoffset = 0;
            break;
        case DLT_PPP:
            linkoffset = 2;
            break;
        case DLT_PPP_SERIAL:
            linkoffset = 4;
            break;
        case DLT_NFLOG:
        case DLT_PFLOG:
            linkoffset = 0;
            break;
        default:
            LogError("Unsupported linktype %d", linktype);
            return 0;
    }

    return 1;
}

// Decode IPv4 + UDP
static ssize_t decode_ipv4_udp(const uint8_t *data, const uint8_t *end, void *buffer, size_t buffer_size, struct sockaddr_storage *sock) {
    if (data + sizeof(struct ip) > end) return -1;

    const struct ip *ip = (const struct ip *)data;
    if (ip->ip_v != 4) {
        LogError("Expected IPv4 but found IP version: %u", ip->ip_v);
        return 0;
    }

    size_t ip_hlen = ip->ip_hl << 2;
    if (ip_hlen < 20 || data + ip_hlen > end) {
        LogError("Size error decoding IPv4 packet");
        return -1;
    }

    // real IPV4 sender
    struct sockaddr_in *in = (struct sockaddr_in *)sock;
    memset(in, 0, sizeof(*in));
    in->sin_family = AF_INET;
    in->sin_addr = ip->ip_src;

    data += ip_hlen;

    // Only UDP supported
    if (ip->ip_p != IPPROTO_UDP) {
        LogError("IP proto not proto UDP: %u", ip->ip_p);
        return 0;
    }

    if (data + sizeof(struct udphdr) > end) {
        LogError("Size error decoding UDP packet");
        return -1;
    }

    const struct udphdr *udp = (const struct udphdr *)data;
    uint16_t ulen = ntohs(udp->uh_ulen);

    if (ulen < sizeof(struct udphdr)) {
        LogError("Size error decoding UDP payload");
        return -1;
    }

    size_t payload_len = ulen - sizeof(struct udphdr);
    const uint8_t *payload = data + sizeof(struct udphdr);

    if (payload + payload_len > end) {
        LogError("UDP payload length error");
        return -1;
    }

    if (payload_len > buffer_size) {
        LogError("UDP payload length error");
        return -1;
    }

    memcpy(buffer, payload, payload_len);

    in->sin_port = udp->uh_sport;

    return payload_len;
}  // End of decode_ipv4_udp

// Decode IPv6 + UDP
static ssize_t decode_ipv6_udp(const uint8_t *data, const uint8_t *end, void *buffer, size_t buffer_size, struct sockaddr_storage *sock) {
    if (data + sizeof(struct ip6_hdr) > end) {
        LogError("Size error decoding IPv6 packet");
        return -1;
    }

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)data;

    // Fill real IPV6 sender
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sock;
    memset(in6, 0, sizeof(*in6));
    in6->sin6_family = AF_INET6;
    memcpy(&in6->sin6_addr, &ip6->ip6_src, sizeof(struct in6_addr));

    uint8_t next = ip6->ip6_nxt;
    data += sizeof(struct ip6_hdr);

    // Minimal extension header skipping
    while (1) {
        if (next == IPPROTO_UDP) break;

        // Known extension headers
        if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING || next == IPPROTO_DSTOPTS || next == IPPROTO_FRAGMENT || next == IPPROTO_AH ||
            next == IPPROTO_ESP) {
            if (data + 2 > end) {
                LogError("Size error decoding IPv6 option header");
                return -1;
            }

            uint8_t hdrlen = data[1];
            size_t ext_len = (hdrlen + 1) * 8;

            if (data + ext_len > end) {
                LogError("Size error decoding IPv6 option header length");
                return -1;
            }

            next = data[0];
            data += ext_len;
            continue;
        }

        // Unknown next header → unsupported */
        LogError("Error decoding unsupported IPv6 option header: %u", next);
        return 0;
    }

    // UDP proto
    if (data + sizeof(struct udphdr) > end) {
        LogError("Size error decoding UDP6");
        return -1;
    }

    const struct udphdr *udp = (const struct udphdr *)data;
    uint16_t ulen = ntohs(udp->uh_ulen);

    if (ulen < sizeof(struct udphdr)) {
        LogError("Size error decoding UDP6 payload length");
        return -1;
    }

    size_t payload_len = ulen - sizeof(struct udphdr);
    const uint8_t *payload = data + sizeof(struct udphdr);

    if (payload + payload_len > end) {
        LogError("Size error decoding UDP6 payload length");
        return -1;
    }

    if (payload_len > buffer_size) {
        LogError("Size error decoding UDP6 payload length");
        return -1;
    }

    memcpy(buffer, payload, payload_len);

    in6->sin6_port = udp->uh_sport;

    return payload_len;
}  // End of decode_ipv6_udp

// IPV6 dispatcher: link layer → VLAN → IPv4/IPv6 ------------------ */
static ssize_t decode_packet(const struct pcap_pkthdr *hdr, const uint8_t *pkt, void *buffer, size_t buffer_size, struct sockaddr_storage *sock,
                             struct timeval *tv) {
    const uint8_t *data = pkt;
    const uint8_t *end = pkt + hdr->caplen;

    if (hdr->caplen < hdr->len) {
        LogError("Short packet - caplen(%u) < packet len(%u)\n", hdr->caplen, hdr->len);
        return -1;
    }

    /* Timestamp */
    tv->tv_sec = hdr->ts.tv_sec;
    tv->tv_usec = hdr->ts.tv_usec;

    /* Skip link layer */
    data += linkoffset;

    /* Determine EtherType */
    uint16_t proto = 0;

    switch (linktype) {
        case DLT_EN10MB:
            proto = (pkt[12] << 8) | pkt[13];
            break;

        case DLT_LINUX_SLL:
            proto = (pkt[14] << 8) | pkt[15];
            break;

        case DLT_LINUX_SLL2:
            proto = (pkt[0] << 8) | pkt[1];
            break;

        case DLT_NULL:
        case DLT_LOOP: {
            uint32_t h = *(uint32_t *)pkt;
            proto = (h == 2) ? 0x0800 : 0;
            break;
        }

        case DLT_RAW:
        case DLT_PPP:
        case DLT_PPP_SERIAL:
            proto = 0x0800;
            break;

        default:
            LogError("Unsupported linktype: %u", linktype);
            return 0;
    }

    // VLAN stripping - most likely never needed
    if (proto == 0x8100) {
        if (data + 4 > end) return -1;
        proto = ntohs(*(uint16_t *)(data + 2));
        data += 4;
    }

    // Decode IPv4/IPv6
    if (proto == 0x0800) return decode_ipv4_udp(data, end, buffer, buffer_size, sock);

    if (proto == 0x86DD) return decode_ipv6_udp(data, end, buffer, buffer_size, sock);

    // unsupported EtherType
    LogError("Unsupported ethertype: %u", proto);
    return 0;

}  // End of decode_packet

// Public interface
ssize_t NextPacket(void *buffer, size_t buffer_size, struct sockaddr_storage *sock, socklen_t *size, struct timeval *tv) {
    struct pcap_pkthdr *hdr;
    const uint8_t *pkt;

    int rc = pcap_next_ex(pcap_handle, &hdr, &pkt);
    if (rc == 1) {
        *size = sizeof(struct sockaddr_in);
        return decode_packet(hdr, pkt, buffer, buffer_size, sock, tv);
    }

    if (rc == -2) /* EOF */
        return -2;

    if (rc == -1) {
        LogError("pcap_next_ex() failed: %s", pcap_geterr(pcap_handle));
        return -1;
    }

    /* rc == 0 → timeout (live capture) */
    return 0;
}  // End of NextPacket

// Setup linktype and offset
int setup_pcap_offline(char *fname, char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the packet capturing file
    pcap_handle = pcap_open_offline(fname, errbuf);
    if (!pcap_handle) {
        LogError("pcap_open_offline(): %s", errbuf);
        return 0;
    }

    return setup_pcap(filter);

} /* End of setup_pcap_offline */

// live device
int setup_pcap_live(char *device, char *filter, unsigned bufflen) {
    pcap_t *p;
    char errbuf[PCAP_ERRBUF_SIZE];

    errbuf[0] = '\0';
    pcap_handle = NULL;

    /*
     *  Open the packet capturing device with the following values:
     *
     *  SNAPLEN: User defined or 1600 bytes
     *  PROMISC: on
     *  The interface needs to be in promiscuous mode to capture all
     *		network traffic on the localnet.
     *  TO_MS: 100ms
     *		this value specifies how long to wait, if a packet arrives
     *		until the application may request it. longer time have the advantage
     * 		in processing multiple packets - less interrupts but more packet loss
     */
    p = pcap_create(device, errbuf);
    if (!p) {
        LogError("pcap_create() failed on %s: %s", device, errbuf);
        return 0;
    }

    int snaplen = 1900;
    if (pcap_set_snaplen(p, snaplen)) {
        LogError("pcap_set_snaplen() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    int promisc = 1;
    if (pcap_set_promisc(p, promisc)) {
        LogError("pcap_set_promisc() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    int to_ms = 100;
    if (pcap_set_timeout(p, to_ms)) {
        LogError("pcap_set_timeout() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    unsigned buffsize = 256 * 1024;
    if (bufflen) buffsize = bufflen;
    if (pcap_set_buffer_size(p, (int)buffsize) < 0) {
        LogError("pcap_set_buffer_size() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }

    if (pcap_activate(p)) {
        LogError("pcap_activate() failed: %s", pcap_geterr(p));
        pcap_close(p);
        return 0;
    }
    pcap_handle = p;

    return setup_pcap(filter);

} /* setup_pcap_live */