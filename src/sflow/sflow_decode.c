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

/*
 * sfcapd makes use of code originated from sflowtool by InMon Corp.
 * Those parts of the code are distributed under the InMon Public License below.
 * All other/additional code is published under BSD license.
 *
 * Redesign goals vs. the original sflow_process.c:
 *   - Replace setjmp/longjmp (SFABORT) with inline bounds-checked XDR
 *     accessors that return false on EOS; parse errors are per-sample.
 *   - Lean SFSample struct: ~420 bytes instead of ~1500 (no string buffers,
 *     no jmp_buf, no ifCounters).
 *   - Remove dead code: app-layer decoders (memcache, http, APP*), DEVEL-only
 *     counter block decoders, writeFlowLine, etc.
 *   - Tunnel decode follows nfpcapd model: GRE (standard + PPTP + ERSPAN
 *     II/III + TAP), IPIP, 6-in-4.  VXLAN/Geneve excluded (use explicit
 *     SFLFLOW_EX_VNI_* records instead).
 *   - Socket extended records no longer overwrite the decoded 5-tuple.
 *   - VNI is now captured and forwarded to StoreSflowRecord.
 */

/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include "sflow_decode.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "logging.h"
#include "nfdump.h"
#include "sflow.h"         // sFlow v5 protocol constants
#include "sflow_nfdump.h"  // StoreSflowRecord
#include "sflow_v2v4.h"    // sFlow v2/v4 constants
#include "util.h"

// -----------------------------------------------------------------------
// Minimal IP / L4 header overlays (local copies; safe on unaligned data)
// -----------------------------------------------------------------------
struct sf_iphdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct sf_ip6hdr {
    uint8_t version_tc;  // version (4 bits) + traffic class high (4 bits)
    uint8_t tc_flow1;    // traffic class low (4 bits) + flow label high
    uint8_t flow2;
    uint8_t flow3;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
};

struct sf_tcphdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t off_res;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

struct sf_udphdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t ulen;
    uint16_t sum;
};

struct sf_icmphdr {
    uint8_t type;
    uint8_t code;
};

struct sf_grehdr {
    uint16_t flags;
    uint16_t proto;
};

// -----------------------------------------------------------------------
// GRE protocol-type constants used in tunnel detection
// -----------------------------------------------------------------------
#define ETHERTYPE_IP 0x0800u
#define ETHERTYPE_IPV6 0x86DDu
#define ETHERTYPE_8021Q 0x8100u  // standard 802.1Q VLAN tag
#define PROTO_ERSPAN2 0x88BEu    // ERSPAN Type II
#define PROTO_ERSPAN3 0x22EBu    // ERSPAN Type III
#define PROTO_GRE_TAP 0x6558u    // Transparent Ethernet Bridging over GRE
#define PROTO_PPTP 0x880Bu       // PPTP / Enhanced GRE payload

// Ethernet header size
#define NFT_ETHHDR_SIZ 14u
// Maximum 802.3 payload length (larger values are EtherTypes)
#define NFT_MAX_8023_LEN 1500u

// YES/NO helpers kept for readability
#define YES 1
#define NO 0

// -----------------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------------
static bool sfGetU32(SFSample *s, uint32_t *out);
static bool sfGetU32NBS(SFSample *s, uint32_t *out);
static bool sfSkip(SFSample *s, uint32_t bytes);
static bool sfGetBytes(SFSample *s, void *dest, uint32_t len);
static bool sfGetAddress(SFSample *s, SFLAddress *addr);
static bool sfSkipString(SFSample *s);

static void decodeL2Header(SFSample *sample);
static void decodeIPv4Header(SFSample *sample);
static void decodeIPv6Header(SFSample *sample);
static void decodeL4(SFSample *sample, const uint8_t *ptr, const uint8_t *end);
static void decodeGRETunnel(SFSample *sample, const uint8_t *ptr, const uint8_t *end);

static void decodeFlowHeader(SFSample *sample);
static void decodeFlowEthernet(SFSample *sample);
static void decodeFlowIPv4(SFSample *sample);
static void decodeFlowIPv6(SFSample *sample);

static void decodeExtSwitch(SFSample *sample);
static void decodeExtRouter(SFSample *sample);
static void decodeExtGateway_v2(SFSample *sample);
static void decodeExtGateway(SFSample *sample);
static void decodeExtMpls(SFSample *sample);
static void decodeMplsLabelStack(SFSample *sample);
static void decodeExtNat(SFSample *sample);
static void decodeExtNatPort(SFSample *sample);
static void decodeExtVNI(SFSample *sample);
static void decodeExtSocket4(SFSample *sample);
static void decodeExtSocket6(SFSample *sample);

static void readFlowSample(SFSample *sample, int expanded, FlowSource_t *fs, int verbose);
static void readFlowSample_v2v4(SFSample *sample, FlowSource_t *fs, int verbose);

// -----------------------------------------------------------------------
// XDR primitive accessors
// All return false and set sample->error on bounds overrun; on success
// they advance sample->datap by the consumed quads.
// -----------------------------------------------------------------------

// Read one big-endian uint32, advance datap by one quad.
static inline bool sfGetU32(SFSample *s, uint32_t *out) {
    if ((uint8_t *)s->datap >= s->endp) {
        s->error = SF_ERR_EOS;
        return false;
    }
    *out = ntohl(*s->datap++);
    return true;
}  // End of sfGetU32

// Read one uint32 without byte-swapping (for network-byte-order fields
// already stored in native byte order by the protocol).
static inline bool sfGetU32NBS(SFSample *s, uint32_t *out) {
    if ((uint8_t *)s->datap >= s->endp) {
        s->error = SF_ERR_EOS;
        return false;
    }
    *out = *s->datap++;
    return true;
}  // End of sfGetU32NBS

// Skip 'bytes' of payload, rounded up to the next quad boundary.
static inline bool sfSkip(SFSample *s, uint32_t bytes) {
    uint32_t quads = (bytes + 3u) >> 2;
    if ((uint8_t *)(s->datap + quads) > s->endp) {
        s->error = SF_ERR_EOS;
        return false;
    }
    s->datap += quads;
    return true;
}  // End of sfSkip

// Copy 'len' bytes out of the XDR stream, advancing by the padded quad count.
static inline bool sfGetBytes(SFSample *s, void *dest, uint32_t len) {
    uint32_t quads = (len + 3u) >> 2;
    if ((uint8_t *)(s->datap + quads) > s->endp) {
        s->error = SF_ERR_EOS;
        return false;
    }
    memcpy(dest, s->datap, len);
    s->datap += quads;
    return true;
}  // End of sfGetBytes

// Read an SFLAddress (type u32 followed by 4 or 16 bytes).
static bool sfGetAddress(SFSample *s, SFLAddress *addr) {
    uint32_t type;
    if (!sfGetU32(s, &type)) return false;
    addr->type = type;
    switch (type) {
        case SFLADDRESSTYPE_IP_V4:
            return sfGetU32NBS(s, &addr->address.ip_v4.addr);
        case SFLADDRESSTYPE_IP_V6:
            return sfGetBytes(s, addr->address.ip_v6.addr, 16);
        default:
            LogError("SFLOW: sfGetAddress() unknown address type %u", type);
            s->error = SF_ERR_DECODE;
            return false;
    }
}  // End of sfGetAddress

// Skip an XDR-encoded string (length u32 + padded bytes).
static bool sfSkipString(SFSample *s) {
    uint32_t len;
    if (!sfGetU32(s, &len)) return false;
    return sfSkip(s, len);
}  // End of sfSkipString

// -----------------------------------------------------------------------
// Cursor-limited section: temporarily restrict datap/endp to one element
// so that element overruns are caught without aborting the whole sample.
//
// Usage:
//   const uint32_t *saved_endp = s->endp;
//   s->endp = (uint8_t *)s->datap + ROUND4(length);
//   decode_something(s);
//   s->datap = (uint32_t *)saved_endp_for_element;   // skip to element end
//   s->endp = saved_endp;
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Layer-4 decoder — called from decodeIPv4Header / decodeIPv6Header
// with a pointer range [ptr, end) covering the L4 payload.
// -----------------------------------------------------------------------
static void decodeL4(SFSample *sample, const uint8_t *ptr, const uint8_t *end) {
    if (ptr >= end) return;

    switch (sample->dcd_ipProtocol) {
        case IPPROTO_ICMP: {
            // ICMP: type in sport, code in dport
            if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_icmphdr)) return;
            struct sf_icmphdr icmp;
            memcpy(&icmp, ptr, sizeof(icmp));
            sample->dcd_sport = icmp.type;
            sample->dcd_dport = icmp.code;
            sample->offsetToPayload = (int)(ptr + sizeof(icmp) - sample->header);
        } break;

        case IPPROTO_TCP: {
            if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_tcphdr)) return;
            struct sf_tcphdr tcp;
            memcpy(&tcp, ptr, sizeof(tcp));
            sample->dcd_sport = ntohs(tcp.sport);
            sample->dcd_dport = ntohs(tcp.dport);
            sample->dcd_tcpFlags = tcp.flags;
            uint32_t hdrBytes = (uint32_t)(tcp.off_res >> 4) * 4u;
            if (hdrBytes < sizeof(struct sf_tcphdr)) hdrBytes = sizeof(struct sf_tcphdr);
            sample->offsetToPayload = (int)(ptr + hdrBytes - sample->header);
        } break;

        case IPPROTO_UDP: {
            if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_udphdr)) return;
            struct sf_udphdr udp;
            memcpy(&udp, ptr, sizeof(udp));
            sample->dcd_sport = ntohs(udp.sport);
            sample->dcd_dport = ntohs(udp.dport);
            sample->offsetToPayload = (int)(ptr + sizeof(udp) - sample->header);
        } break;

        case IPPROTO_GRE:
            // GRE tunnel — only decoded when parse_tun is set
            if (sample->parse_tun) {
                decodeGRETunnel(sample, ptr, end);
            }
            break;

        case IPPROTO_IPV6:  // 6-in-4 encapsulation
            if (sample->parse_tun && (end - ptr) >= (ptrdiff_t)sizeof(struct sf_ip6hdr)) {
                // save outer addresses as tunnel endpoints
                if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
                    sample->tun_ipsrc = sample->ipsrc;
                    sample->tun_ipdst = sample->ipdst;
                    sample->tun_proto = IPPROTO_IPV6;
                }
                // decode the inner IPv6 header
                sample->header = ptr;
                sample->headerLen = (uint32_t)(end - ptr);
                sample->gotIPV6 = YES;
                sample->offsetToIPV6 = 0;
                decodeIPv6Header(sample);
            }
            break;

        case IPPROTO_IPIP:  // IPv4-in-IPv4
            if (sample->parse_tun && (end - ptr) >= (ptrdiff_t)sizeof(struct sf_iphdr)) {
                if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
                    sample->tun_ipsrc = sample->ipsrc;
                    sample->tun_ipdst = sample->ipdst;
                    sample->tun_proto = IPPROTO_IPIP;
                }
                sample->header = ptr;
                sample->headerLen = (uint32_t)(end - ptr);
                sample->gotIPV4 = YES;
                sample->offsetToIPV4 = 0;
                decodeIPv4Header(sample);
            }
            break;

        default:
            sample->offsetToPayload = (int)(ptr - sample->header);
            break;
    }
}  // End of decodeL4

// -----------------------------------------------------------------------
// GRE tunnel decoder (nfpcapd model)
// Handles: standard raw-IP GRE, PPTP/Enhanced GRE, ERSPAN II/III, GRE TAP
// ptr/end span the GRE header and its payload within the sampled header.
// -----------------------------------------------------------------------
static void decodeGRETunnel(SFSample *sample, const uint8_t *ptr, const uint8_t *end) {
    if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_grehdr)) return;

    struct sf_grehdr gre;
    memcpy(&gre, ptr, sizeof(gre));
    uint16_t gre_flags = ntohs(gre.flags);
    uint16_t gre_proto = ntohs(gre.proto);
    ptr += sizeof(gre);

    // optional GRE fields: Checksum (flag 0x8000), Key (0x2000), Sequence (0x1000)
    size_t skip = 0;
    if (gre_flags & 0x8000u) skip += 4;
    if (gre_flags & 0x2000u) skip += 4;
    if (gre_flags & 0x1000u) skip += 4;
    if (skip && (end - ptr) < (ptrdiff_t)skip) return;
    ptr += skip;

    // PPTP / Enhanced GRE (version field = 1) — just record port from key
    if ((gre_flags & 0x0007u) == 1) {
        // callID occupies the key field position; skip it
        if ((end - ptr) < 4) return;
        // record as GRE tunnel; inner payload is L2TP PPP — no further decode
        if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
            sample->tun_ipsrc = sample->ipsrc;
            sample->tun_ipdst = sample->ipdst;
            sample->tun_proto = IPPROTO_GRE;
        }
        return;
    }

    // ERSPAN Type II — 4-byte ERSPAN header follows GRE
    if (gre_proto == PROTO_ERSPAN2) {
        if ((end - ptr) < 4) return;
        ptr += 4;  // skip 4-byte ERSPAN II header
        // inner frame is Ethernet
        if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
            sample->tun_ipsrc = sample->ipsrc;
            sample->tun_ipdst = sample->ipdst;
            sample->tun_proto = IPPROTO_GRE;
        }
        sample->header = ptr;
        sample->headerLen = (uint32_t)(end - ptr);
        decodeL2Header(sample);
        return;
    }

    // ERSPAN Type III — 12-byte ERSPAN header
    if (gre_proto == PROTO_ERSPAN3) {
        if ((end - ptr) < 12) return;
        ptr += 12;
        if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
            sample->tun_ipsrc = sample->ipsrc;
            sample->tun_ipdst = sample->ipdst;
            sample->tun_proto = IPPROTO_GRE;
        }
        sample->header = ptr;
        sample->headerLen = (uint32_t)(end - ptr);
        decodeL2Header(sample);
        return;
    }

    // GRE Transparent Ethernet Bridge — inner Ethernet frame
    if (gre_proto == PROTO_GRE_TAP) {
        if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
            sample->tun_ipsrc = sample->ipsrc;
            sample->tun_ipdst = sample->ipdst;
            sample->tun_proto = IPPROTO_GRE;
        }
        sample->header = ptr;
        sample->headerLen = (uint32_t)(end - ptr);
        decodeL2Header(sample);
        return;
    }

    // Standard GRE over IPv4 or IPv6
    if (gre_proto == ETHERTYPE_IP || gre_proto == ETHERTYPE_IPV6) {
        if (sample->tun_ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
            sample->tun_ipsrc = sample->ipsrc;
            sample->tun_ipdst = sample->ipdst;
            sample->tun_proto = IPPROTO_GRE;
        }
        if (gre_proto == ETHERTYPE_IP) {
            if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_iphdr)) return;
            sample->header = ptr;
            sample->headerLen = (uint32_t)(end - ptr);
            sample->gotIPV4 = YES;
            sample->offsetToIPV4 = 0;
            decodeIPv4Header(sample);
        } else {
            if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_ip6hdr)) return;
            sample->header = ptr;
            sample->headerLen = (uint32_t)(end - ptr);
            sample->gotIPV6 = YES;
            sample->offsetToIPV6 = 0;
            decodeIPv6Header(sample);
        }
        return;
    }

    dbg_printf("GRE: unsupported inner protocol 0x%04x\n", gre_proto);
}  // End of decodeGRETunnel

// -----------------------------------------------------------------------
// IPv4 header decoder
// Reads from sample->header + sample->offsetToIPV4.
// -----------------------------------------------------------------------
static void decodeIPv4Header(SFSample *sample) {
    if (!sample->gotIPV4) return;

    const uint8_t *start = sample->header + sample->offsetToIPV4;
    const uint8_t *end = sample->header + sample->headerLen;

    if ((end - start) < (ptrdiff_t)sizeof(struct sf_iphdr)) return;

    struct sf_iphdr ip;
    memcpy(&ip, start, sizeof(ip));

    // basic sanity
    if ((ip.version_ihl >> 4) != 4) return;
    uint32_t ihl = (uint32_t)(ip.version_ihl & 0x0fu) * 4u;
    if (ihl < sizeof(ip)) return;

    // fill in the decoded 5-tuple
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4.addr = ip.saddr;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4.addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    // Store the full frag_off word: bits 15-13 = flags (DF=0x4000, MF=0x2000),
    // bits 12-0 = fragment offset.  StoreSflowRecord extracts both parts.
    sample->ip_fragmentOffset = ntohs(ip.frag_off);

    // Skip L4 decode if this is a non-first fragment (offset > 0) or if
    // more-fragments flag is set (first fragment in a fragmented datagram).
    if (sample->ip_fragmentOffset & 0x3FFFu) return;

    const uint8_t *l4 = start + ihl;
    if (l4 >= end) return;
    decodeL4(sample, l4, end);
}  // End of decodeIPv4Header

// -----------------------------------------------------------------------
// IPv6 header decoder
// Reads from sample->header + sample->offsetToIPV6.
// -----------------------------------------------------------------------
static void decodeIPv6Header(SFSample *sample) {
    if (!sample->gotIPV6) return;

    const uint8_t *start = sample->header + sample->offsetToIPV6;
    const uint8_t *end = sample->header + sample->headerLen;

    if ((end - start) < (ptrdiff_t)sizeof(struct sf_ip6hdr)) return;

    struct sf_ip6hdr ip6;
    memcpy(&ip6, start, sizeof(ip6));

    if ((ip6.version_tc >> 4) != 6) return;

    sample->dcd_ipTos = ((ip6.version_tc & 0x0fu) << 4) | (ip6.tc_flow1 >> 4);
    sample->dcd_ipTTL = ip6.hop_limit;

    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(sample->ipsrc.address.ip_v6.addr, ip6.src, 16);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(sample->ipdst.address.ip_v6.addr, ip6.dst, 16);

    // skip any extension headers
    uint8_t nextHdr = ip6.next_hdr;
    const uint8_t *ptr = start + sizeof(ip6);

    while (nextHdr == 0 ||   // Hop-by-Hop
           nextHdr == 43 ||  // Routing
           nextHdr == 44 ||  // Fragment
           nextHdr == 51 ||  // Authentication
           nextHdr == 60) {  // Destination Options
        if ((end - ptr) < 2) return;
        uint8_t optLen = 8u * (ptr[1] + 1u);
        nextHdr = ptr[0];
        ptr += optLen;
        if (ptr > end) return;
    }
    sample->dcd_ipProtocol = nextHdr;
    decodeL4(sample, ptr, end);
}  // End of decodeIPv6Header

// -----------------------------------------------------------------------
// Ethernet / Layer-2 decoder
// Reads from sample->header / sample->headerLen.
// Sets sample->gotIPV4 / gotIPV6 and the corresponding offsets.
// -----------------------------------------------------------------------
static void decodeL2Header(SFSample *sample) {
    const uint8_t *start = sample->header;
    const uint8_t *end = start + sample->headerLen;
    const uint8_t *ptr = start;

    sample->gotIPV4 = NO;
    sample->gotIPV6 = NO;
    sample->mpls_num_labels = 0;

    if ((end - ptr) < (ptrdiff_t)NFT_ETHHDR_SIZ) return;

    // MAC addresses
    memcpy(sample->eth_dst, ptr, 6);
    ptr += 6;
    memcpy(sample->eth_src, ptr, 6);
    ptr += 6;

    uint16_t type_len = (uint16_t)((ptr[0] << 8) | ptr[1]);
    ptr += 2;

    // peel 802.1Q / QinQ VLAN tags
    while (type_len == 0x8100u || type_len == 0x88A8u || type_len == 0x9100u || type_len == 0x9200u || type_len == 0x9300u) {
        if ((end - ptr) < 4) return;
        sample->in_vlan = ((uint32_t)(ptr[0] << 8) | ptr[1]) & 0x0FFFu;
        ptr += 2;
        type_len = (uint16_t)((ptr[0] << 8) | ptr[1]);
        ptr += 2;
    }

    // 802.3 length + SNAP / LLC handling
    if (type_len <= NFT_MAX_8023_LEN) {
        if ((end - ptr) < 3) return;
        if (ptr[0] == 0xAAu && ptr[1] == 0xAAu && ptr[2] == 0x03u) {
            // SNAP
            ptr += 3;
            if ((end - ptr) < 5) return;
            if (ptr[0] || ptr[1] || ptr[2]) return;  // vendor-specific OUI
            ptr += 3;
            type_len = (uint16_t)((ptr[0] << 8) | ptr[1]);
            ptr += 2;
        } else if (ptr[0] == 0x06u && ptr[1] == 0x06u && (ptr[2] & 0x01u)) {
            // IP-over-802.2
            ptr += 3;
            type_len = 0x0800u;
        } else {
            return;
        }
    }

    // MPLS label stack
    if (type_len == 0x8847u) {
        int n = 0;
        while ((end - ptr) >= 4) {
            uint32_t lbl = ntohl(*(const uint32_t *)ptr);
            if (n < 10) sample->mpls_label[n] = lbl >> 8;
            n++;
            ptr += 4;
            if (lbl & 0x01u) break;  // bottom-of-stack
        }
        sample->mpls_num_labels = (n > 10) ? 10 : n;
        if ((end - ptr) < 1) return;
        if ((*ptr >> 4) == 4)
            type_len = 0x0800u;
        else if ((*ptr >> 4) == 6)
            type_len = 0x86DDu;
        else
            return;
    }

    sample->eth_type = type_len;

    if (type_len == 0x0800u) {
        if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_iphdr)) return;
        if ((*ptr >> 4) != 4 || (*ptr & 0x0fu) < 5) return;
        sample->gotIPV4 = YES;
        sample->offsetToIPV4 = (int)(ptr - start);
    } else if (type_len == 0x86DDu) {
        if ((end - ptr) < (ptrdiff_t)sizeof(struct sf_ip6hdr)) return;
        if ((*ptr >> 4) != 6) return;
        sample->gotIPV6 = YES;
        sample->offsetToIPV6 = (int)(ptr - start);
    }
}  // End of decodeL2Header

// -----------------------------------------------------------------------
// SFLFLOW_HEADER — raw sampled packet header (Ethernet or bare IP)
// -----------------------------------------------------------------------
static void decodeFlowHeader(SFSample *sample) {
    uint32_t headerProtocol, frameLen, stripped, headerLen;

    if (!sfGetU32(sample, &headerProtocol)) return;
    if (!sfGetU32(sample, &frameLen)) return;
    if (sample->datagramVersion > 4) {
        if (!sfGetU32(sample, &stripped)) return;
        sample->stripped = stripped;
    }
    if (!sfGetU32(sample, &headerLen)) return;

    // point sample->header at the inline header bytes in the XDR stream
    sample->headerProtocol = headerProtocol;
    sample->sampledPacketSize = frameLen;
    sample->headerLen = headerLen;
    sample->header = (uint8_t *)sample->datap;

    if (!sfSkip(sample, headerLen)) return;

    sample->gotIPV4 = NO;
    sample->gotIPV6 = NO;

    switch (headerProtocol) {
        case SFLHEADER_ETHERNET_ISO8023:
            decodeL2Header(sample);
            break;
        case SFLHEADER_IPv4:
            sample->gotIPV4 = YES;
            sample->offsetToIPV4 = 0;
            break;
        case SFLHEADER_IPv6:
            sample->gotIPV6 = YES;
            sample->offsetToIPV6 = 0;
            break;
        // 802.11 and other header types: no decode in sfcapd
        default:
            dbg_printf("SFLOW: no decode for headerProtocol=%u\n", headerProtocol);
            return;
    }

    if (sample->gotIPV4)
        decodeIPv4Header(sample);
    else if (sample->gotIPV6)
        decodeIPv6Header(sample);
}  // End of decodeFlowHeader

// -----------------------------------------------------------------------
// SFLFLOW_ETHERNET — decoded Ethernet header struct
// -----------------------------------------------------------------------
static void decodeFlowEthernet(SFSample *sample) {
    uint32_t ethLen;
    if (!sfGetU32(sample, &ethLen)) return;
    if (!sfGetBytes(sample, sample->eth_src, 6)) return;
    if (!sfSkip(sample, 2)) return;  // 2 pad bytes in SFLSampled_ethernet
    if (!sfGetBytes(sample, sample->eth_dst, 6)) return;
    if (!sfSkip(sample, 2)) return;  // 2 pad bytes
    uint32_t ethType;
    if (!sfGetU32(sample, &ethType)) return;
    sample->eth_type = ethType;
}  // End of decodeFlowEthernet

// -----------------------------------------------------------------------
// SFLFLOW_IPV4 — pre-decoded IPv4 5-tuple (the common hot path)
// -----------------------------------------------------------------------
static void decodeFlowIPv4(SFSample *sample) {
    // inline SFLSampled_ipv4: length, protocol, src, dst, sport, dport, flags, tos
    uint32_t length, protocol, sport, dport, tcpFlags, tos;
    uint32_t srcAddr, dstAddr;

    if (!sfGetU32(sample, &length)) return;
    if (!sfGetU32(sample, &protocol)) return;
    if (!sfGetU32NBS(sample, &srcAddr)) return;
    if (!sfGetU32NBS(sample, &dstAddr)) return;
    if (!sfGetU32(sample, &sport)) return;
    if (!sfGetU32(sample, &dport)) return;
    if (!sfGetU32(sample, &tcpFlags)) return;
    if (!sfGetU32(sample, &tos)) return;

    sample->sampledPacketSize = length;
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
    sample->ipsrc.address.ip_v4.addr = srcAddr;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
    sample->ipdst.address.ip_v4.addr = dstAddr;
    sample->dcd_ipProtocol = protocol;
    sample->dcd_ipTos = tos;
    sample->dcd_sport = sport;
    sample->dcd_dport = dport;
    sample->dcd_tcpFlags = tcpFlags;
}  // End of decodeFlowIPv4

// -----------------------------------------------------------------------
// SFLFLOW_IPV6 — pre-decoded IPv6 5-tuple
// -----------------------------------------------------------------------
static void decodeFlowIPv6(SFSample *sample) {
    // inline SFLSampled_ipv6: length, protocol, src[16], dst[16],
    // sport, dport, flags, priority
    uint32_t length, protocol, sport, dport, tcpFlags, priority;

    if (!sfGetU32(sample, &length)) return;
    if (!sfGetU32(sample, &protocol)) return;

    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    if (!sfGetBytes(sample, sample->ipsrc.address.ip_v6.addr, 16)) return;
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    if (!sfGetBytes(sample, sample->ipdst.address.ip_v6.addr, 16)) return;

    if (!sfGetU32(sample, &sport)) return;
    if (!sfGetU32(sample, &dport)) return;
    if (!sfGetU32(sample, &tcpFlags)) return;
    if (!sfGetU32(sample, &priority)) return;

    sample->sampledPacketSize = length;
    sample->dcd_ipProtocol = protocol;
    sample->dcd_sport = sport;
    sample->dcd_dport = dport;
    sample->dcd_tcpFlags = tcpFlags;
    sample->dcd_ipTos = priority;
}  // End of decodeFlowIPv6

// -----------------------------------------------------------------------
// Extended-data decoders
// -----------------------------------------------------------------------

// SFLFLOW_EX_SWITCH
static void decodeExtSwitch(SFSample *sample) {
    uint32_t inVlan, inPri, outVlan, outPri;
    if (!sfGetU32(sample, &inVlan)) return;
    if (!sfGetU32(sample, &inPri)) return;
    if (!sfGetU32(sample, &outVlan)) return;
    if (!sfGetU32(sample, &outPri)) return;
    sample->in_vlan = inVlan;
    sample->out_vlan = outVlan;
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
    dbg_printf("extSwitch in_vlan=%u out_vlan=%u\n", inVlan, outVlan);
}  // End of decodeExtSwitch

// SFLFLOW_EX_ROUTER
static void decodeExtRouter(SFSample *sample) {
    if (!sfGetAddress(sample, &sample->nextHop)) return;
    if (!sfGetU32(sample, &sample->srcMask)) return;
    if (!sfGetU32(sample, &sample->dstMask)) return;
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;
}  // End of decodeExtRouter

// SFLFLOW_EX_GATEWAY (sFlow v2 variant)
static void decodeExtGateway_v2(SFSample *sample) {
    uint32_t myAs, srcAs, srcPeerAs, pathLen;
    if (!sfGetU32(sample, &myAs)) return;
    if (!sfGetU32(sample, &srcAs)) return;
    if (!sfGetU32(sample, &srcPeerAs)) return;
    if (!sfGetU32(sample, &pathLen)) return;

    sample->src_as = srcAs;
    sample->src_peer_as = srcPeerAs;
    sample->dst_peer_as = 0;
    sample->dst_as = 0;

    // path is a flat array of AS numbers (v2 has no segment type)
    for (uint32_t i = 0; i < pathLen; i++) {
        uint32_t asn;
        if (!sfGetU32(sample, &asn)) return;
        if (i == 0) sample->dst_peer_as = asn;
        if (i == pathLen - 1u) sample->dst_as = asn;
    }
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
}  // End of decodeExtGateway_v2

// SFLFLOW_EX_GATEWAY (sFlow v5 variant)
static void decodeExtGateway(SFSample *sample) {
    if (sample->datagramVersion >= 5) {
        if (!sfGetAddress(sample, &sample->bgp_nextHop)) return;
    }
    uint32_t myAs, srcAs, srcPeerAs, numSegments;
    if (!sfGetU32(sample, &myAs)) return;
    if (!sfGetU32(sample, &srcAs)) return;
    if (!sfGetU32(sample, &srcPeerAs)) return;
    if (!sfGetU32(sample, &numSegments)) return;

    sample->src_as = srcAs;
    sample->src_peer_as = srcPeerAs;
    sample->dst_peer_as = 0;
    sample->dst_as = 0;

    for (uint32_t seg = 0; seg < numSegments; seg++) {
        uint32_t segType, segLen;
        if (!sfGetU32(sample, &segType)) return;
        if (!sfGetU32(sample, &segLen)) return;
        for (uint32_t i = 0; i < segLen; i++) {
            uint32_t asn;
            if (!sfGetU32(sample, &asn)) return;
            if (i == 0 && seg == 0) sample->dst_peer_as = asn;
            if (seg == numSegments - 1u && i == segLen - 1u) sample->dst_as = asn;
        }
    }

    // communities: skip count + array
    uint32_t commLen;
    if (!sfGetU32(sample, &commLen)) return;
    if (commLen > UINT32_MAX / 4u) { sample->error = SF_ERR_DECODE; return; }
    if (!sfSkip(sample, commLen * 4u)) return;

    // localpref: skip
    uint32_t localpref;
    if (!sfGetU32(sample, &localpref)) return;

    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
}  // End of decodeExtGateway

// SFLFLOW_EX_MPLS — decode in/out label stacks; store in sample->mpls_label
static void decodeMplsLabelStack(SFSample *sample) {
    uint32_t depth;
    if (!sfGetU32(sample, &depth)) return;
    // only the first stack call populates mpls_label; second call (output stack) is skipped
    for (uint32_t i = 0; i < depth; i++) {
        uint32_t lbl;
        if (!sfGetU32(sample, &lbl)) return;
        if (sample->mpls_num_labels < 10) sample->mpls_label[sample->mpls_num_labels++] = lbl;
    }
}  // End of decodeMplsLabelStack

static void decodeExtMpls(SFSample *sample) {
    SFLAddress mpls_nextHop;
    if (!sfGetAddress(sample, &mpls_nextHop)) return;  // nextHop — not stored
    decodeMplsLabelStack(sample);                      // input stack  → mpls_label[]
    decodeMplsLabelStack(sample);                      // output stack → ignored
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}  // End of decodeExtMpls

// SFLFLOW_EX_NAT
static void decodeExtNat(SFSample *sample) {
    if (!sfGetAddress(sample, &sample->nat_src)) return;
    if (!sfGetAddress(sample, &sample->nat_dst)) return;
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}  // End of decodeExtNat

// SFLFLOW_EX_NAT_PORT
static void decodeExtNatPort(SFSample *sample) {
    if (!sfGetU32(sample, &sample->nat_src_port)) return;
    if (!sfGetU32(sample, &sample->nat_dst_port)) return;
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT_PORT;
}  // End of decodeExtNatPort

// SFLFLOW_EX_VNI_OUT / SFLFLOW_EX_VNI_IN
// Both carry a single u32 VNI.  The first one seen wins (typically OUT).
static void decodeExtVNI(SFSample *sample) {
    uint32_t vni;
    if (!sfGetU32(sample, &vni)) return;
    if (sample->vni == 0) sample->vni = vni;  // keep first (outermost) VNI
    sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VNI;
    dbg_printf("VNI %u\n", vni);
}  // End of decodeExtVNI

/*
 * SFLFLOW_EX_SOCKET4 / SFLFLOW_EX_SOCKET6
 * These carry the application-layer (post-tunnel/NAT) socket 5-tuple.
 * In the old code they overwrote ipsrc/ipdst, which destroyed the already-
 * decoded packet 5-tuple.  We now skip them to preserve the sampled-packet
 * addresses; the data can be forwarded once a dedicated EX extension exists.
 */
static void decodeExtSocket4(SFSample *sample) {
    // protocol + src_ip + dst_ip + src_port + dst_port = 5 × u32
    sfSkip(sample, 5u * 4u);
}  // End of decodeExtSocket4

static void decodeExtSocket6(SFSample *sample) {
    // protocol (u32) + src_ip (16) + dst_ip (16) + src_port (u32) + dst_port (u32)
    sfSkip(sample, 4u + 16u + 16u + 4u + 4u);
}  // End of decodeExtSocket6

// -----------------------------------------------------------------------
// v5 flow sample (expanded or compact)
// -----------------------------------------------------------------------
static void readFlowSample(SFSample *sample, int expanded, FlowSource_t *fs, int verbose) {
    uint32_t sampleLength, seqNo, numElements;
    if (!sfGetU32(sample, &sampleLength)) return;

    // remember start position to skip to element end if any decode ran short
    uint32_t *sampleStart = sample->datap;

    if (!sfGetU32(sample, &seqNo)) return;

    if (expanded) {
        if (!sfGetU32(sample, &sample->ds_class)) return;
        if (!sfGetU32(sample, &sample->ds_index)) return;
    } else {
        uint32_t samplerId;
        if (!sfGetU32(sample, &samplerId)) return;
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00FFFFFFu;
    }

    if (!sfGetU32(sample, &sample->meanSkipCount)) return;

    // samplePool and dropEvents — read but not forwarded
    uint32_t samplePool, dropEvents;
    if (!sfGetU32(sample, &samplePool)) return;
    if (!sfGetU32(sample, &dropEvents)) return;

    if (expanded) {
        if (!sfGetU32(sample, &sample->inputPortFormat)) return;
        if (!sfGetU32(sample, &sample->inputPort)) return;
        if (!sfGetU32(sample, &sample->outputPortFormat)) return;
        if (!sfGetU32(sample, &sample->outputPort)) return;
    } else {
        uint32_t inp, outp;
        if (!sfGetU32(sample, &inp)) return;
        if (!sfGetU32(sample, &outp)) return;
        sample->inputPortFormat = inp >> 30;
        sample->outputPortFormat = outp >> 30;
        sample->inputPort = inp & 0x3FFFFFFFu;
        sample->outputPort = outp & 0x3FFFFFFFu;
    }

    if (!sfGetU32(sample, &numElements)) return;

    for (uint32_t el = 0; el < numElements; el++) {
        uint32_t tag, length;
        if (!sfGetU32(sample, &tag)) return;
        if (!sfGetU32(sample, &length)) return;

        // Restrict datap/endp to this element so an overrun stops at its
        // boundary rather than consuming bytes from the next element.
        uint32_t *elemStart = sample->datap;
        const uint8_t *savedEndp = sample->endp;
        uint32_t elemQuads = (length + 3u) >> 2;

        if ((uint8_t *)(sample->datap + elemQuads) > sample->endp) {
            LogError("SFLOW: element tag 0x%08x length %u overruns sample", tag, length);
            return;
        }
        sample->endp = (uint8_t *)(sample->datap + elemQuads);

        switch (tag) {
            // ---- flow record types ----
            case SFLFLOW_HEADER:
                decodeFlowHeader(sample);
                break;
            case SFLFLOW_ETHERNET:
                decodeFlowEthernet(sample);
                break;
            case SFLFLOW_IPV4:
                decodeFlowIPv4(sample);
                break;
            case SFLFLOW_IPV6:
                decodeFlowIPv6(sample);
                break;

            // ---- extended records ----
            case SFLFLOW_EX_SWITCH:
                decodeExtSwitch(sample);
                break;
            case SFLFLOW_EX_ROUTER:
                decodeExtRouter(sample);
                break;
            case SFLFLOW_EX_GATEWAY:
                decodeExtGateway(sample);
                break;
            case SFLFLOW_EX_MPLS:
                decodeExtMpls(sample);
                break;
            case SFLFLOW_EX_NAT:
                decodeExtNat(sample);
                break;
            case SFLFLOW_EX_NAT_PORT:
                decodeExtNatPort(sample);
                break;
            case SFLFLOW_EX_VNI_OUT:
            case SFLFLOW_EX_VNI_IN:
                decodeExtVNI(sample);
                break;
            case SFLFLOW_EX_SOCKET4:
                decodeExtSocket4(sample);
                break;
            case SFLFLOW_EX_SOCKET6:
                decodeExtSocket6(sample);
                break;

            // ---- MPLS tunnel / VC / FTN / LDP — tag only, no nfxV4 output ----
            case SFLFLOW_EX_MPLS_TUNNEL:
            case SFLFLOW_EX_MPLS_VC:
            case SFLFLOW_EX_MPLS_FTN:
            case SFLFLOW_EX_MPLS_LDP_FEC:
            // ---- VLAN tunnel — tag only ----
            case SFLFLOW_EX_VLAN_TUNNEL:
            // ---- proxy sockets — skip (same layout as socket4/6) ----
            case SFLFLOW_EX_PROXYSOCKET4:
            case SFLFLOW_EX_PROXYSOCKET6:
            // ---- user / URL — strings, no nfxV4 output ----
            case SFLFLOW_EX_USER:
            case SFLFLOW_EX_URL:
            // ---- app layer — memcache / http / APP* — no nfxV4 output ----
            case SFLFLOW_MEMCACHE:
            case SFLFLOW_HTTP:
            case SFLFLOW_HTTP2:
            case SFLFLOW_APP:
            case SFLFLOW_APP_CTXT:
            case SFLFLOW_APP_ACTOR_INIT:
            case SFLFLOW_APP_ACTOR_TGT:
            // ---- 802.11 wifi payload / rx / tx — no nfxV4 output ----
            case SFLFLOW_EX_80211_PAYLOAD:
            case SFLFLOW_EX_80211_RX:
            case SFLFLOW_EX_80211_TX:
            // ---- tunnel IP structs — no separate nfxV4 output ----
            case SFLFLOW_EX_L2_TUNNEL_OUT:
            case SFLFLOW_EX_L2_TUNNEL_IN:
            case SFLFLOW_EX_IPV4_TUNNEL_OUT:
            case SFLFLOW_EX_IPV4_TUNNEL_IN:
            case SFLFLOW_EX_IPV6_TUNNEL_OUT:
            case SFLFLOW_EX_IPV6_TUNNEL_IN:
            // ---- decap offset / tcp info — no nfxV4 output yet ----
            case SFLFLOW_EX_DECAP_OUT:
            case SFLFLOW_EX_DECAP_IN:
            case SFLFLOW_EX_TCP_INFO:
                // all fall through to the default skip below
                break;

            default:
                dbg_printf("SFLOW: skipping unknown flow element tag 0x%08x len %u\n", tag, length);
                break;
        }

        // advance past this element regardless of how much was decoded
        sample->datap = (uint32_t *)(elemStart + elemQuads);
        sample->endp = savedEndp;
    }

    // advance past any trailing bytes in the sample
    sample->datap = sampleStart + ((sampleLength + 3u) >> 2);

    // if the sample had no usable IP data, skip it
    if (sample->ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
        dbg_printf("SFLOW: no IP data in flow sample — skipping\n");
        return;
    }

    StoreSflowRecord(sample, fs);
}  // End of readFlowSample

// -----------------------------------------------------------------------
// v2/v4 flow sample
// -----------------------------------------------------------------------
static void readFlowSample_v2v4(SFSample *sample, FlowSource_t *fs, int verbose) {
    uint32_t samplingRate, samplePool, numExtended;
    uint32_t numSamplesGenerated, samplerIdent;
    uint32_t packetDataTag;

    dbg_printf("sampleType FLOWSAMPLE (v2/v4)\n");

    if (!sfGetU32(sample, &numSamplesGenerated)) return;
    if (!sfGetU32(sample, &samplerIdent)) return;
    sample->ds_class = samplerIdent >> 24;
    sample->ds_index = samplerIdent & 0x00FFFFFFu;

    if (!sfGetU32(sample, &samplingRate)) return;
    sample->meanSkipCount = samplingRate;
    if (!sfGetU32(sample, &samplePool)) return;

    uint32_t inpRaw, outpRaw;
    if (!sfGetU32(sample, &inpRaw)) return;
    if (!sfGetU32(sample, &outpRaw)) return;
    sample->inputPort = inpRaw & 0x3FFFFFFFu;
    sample->outputPort = outpRaw & 0x3FFFFFFFu;

    // packet data: tag selects header, IPv4, or IPv6 struct
    if (!sfGetU32(sample, &packetDataTag)) return;

    switch (packetDataTag) {
        case INMPACKETTYPE_HEADER:
            decodeFlowHeader(sample);
            break;
        case INMPACKETTYPE_IPV4:
            decodeFlowIPv4(sample);
            break;
        case INMPACKETTYPE_IPV6:
            decodeFlowIPv6(sample);
            break;
        default:
            LogError("SFLOW v2/v4: unknown packet data tag %u", packetDataTag);
            return;
    }

    // extended data blocks
    if (!sfGetU32(sample, &numExtended)) return;

    for (uint32_t ext = 0; ext < numExtended; ext++) {
        uint32_t extType;
        if (!sfGetU32(sample, &extType)) return;

        switch (extType) {
            case INMEXTENDED_SWITCH:
                decodeExtSwitch(sample);
                break;
            case INMEXTENDED_ROUTER:
                decodeExtRouter(sample);
                break;
            case INMEXTENDED_GATEWAY:
                if (sample->datagramVersion == 2)
                    decodeExtGateway_v2(sample);
                else
                    decodeExtGateway(sample);
                break;
            case INMEXTENDED_USER:
                // src_user_len + src_user + dst_user_len + dst_user — skip
                if (!sfSkipString(sample)) return;
                if (!sfSkipString(sample)) return;
                break;
            case INMEXTENDED_URL:
                // direction + url_len + url — skip
                if (!sfSkip(sample, 4u)) return;
                if (!sfSkipString(sample)) return;
                break;
            default:
                LogError("SFLOW v2/v4: unrecognised extended data type %u", extType);
                return;
        }
    }

    if (sample->ipsrc.type == SFLADDRESSTYPE_UNDEFINED) {
        dbg_printf("SFLOW v2/v4: no IP data in flow sample — skipping\n");
        return;
    }

    StoreSflowRecord(sample, fs);
}  // End of readFlowSample_v2v4

// -----------------------------------------------------------------------
// Main entry point — called once per received UDP datagram
// -----------------------------------------------------------------------
void readSFlowDatagram(SFSample *sample, FlowSource_t *fs, int verbose) {
    uint32_t datagramVersion, samplesInPacket;
    SFLAddress agentAddr;

    // datagram version
    if (!sfGetU32(sample, &datagramVersion)) {
        LogError("SFLOW: datagram too short for version field");
        return;
    }
    sample->datagramVersion = datagramVersion;

    if (datagramVersion != 2 && datagramVersion != 4 && datagramVersion != 5) {
        char ipStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, sample->sourceIP.bytes, ipStr, sizeof(ipStr));
        LogError("SFLOW: unexpected datagram version %u from %s", datagramVersion, ipStr);
        return;
    }

    // agent address (not forwarded to nfxV4; agentSubId is used for exporter identity)
    if (!sfGetAddress(sample, &agentAddr)) return;

    // agent sub-id (v5 only)
    if (datagramVersion >= 5) {
        if (!sfGetU32(sample, &sample->agentSubId)) return;
    }

    // sequence number and uptime — skip
    uint32_t seqNo, sysUpTime;
    if (!sfGetU32(sample, &seqNo)) return;
    if (!sfGetU32(sample, &sysUpTime)) return;

    // number of samples in this datagram
    if (!sfGetU32(sample, &samplesInPacket)) return;

    dbg_printf("sFlow v%u from agent, %u sample(s)\n", datagramVersion, samplesInPacket);

    // per-sample reset block: everything at/after sampleDataOffset is
    // cleared between samples so datagram-level fields are preserved.
    char *perSampleStart = (char *)sample + sampleDataOffset;
    size_t perSampleSize = sizeof(SFSample) - sampleDataOffset;
    int parseTun = sample->parse_tun;

    for (uint32_t samp = 0; samp < samplesInPacket; samp++) {
        // reset per-sample state, restore the parse_tun flag
        memset(perSampleStart, 0, perSampleSize);
        sample->parse_tun = parseTun;

        if ((uint8_t *)sample->datap >= sample->endp) {
            LogError("SFLOW: unexpected end of datagram after sample %u of %u", samp, samplesInPacket);
            return;
        }

        uint32_t sampleType;
        if (!sfGetU32(sample, &sampleType)) return;

        if (datagramVersion >= 5) {
            switch (sampleType) {
                case SFLFLOW_SAMPLE:
                    readFlowSample(sample, NO, fs, verbose);
                    break;
                case SFLFLOW_SAMPLE_EXPANDED:
                    readFlowSample(sample, YES, fs, verbose);
                    break;
                // counter samples and RT metric/flow: skip entirely in production
                default: {
                    uint32_t skipLen;
                    if (!sfGetU32(sample, &skipLen)) return;
                    if (!sfSkip(sample, skipLen)) return;
                    break;
                }
            }
        } else {
            switch (sampleType) {
                case FLOWSAMPLE:
                    readFlowSample_v2v4(sample, fs, verbose);
                    break;
                // counter samples: skip
                default: {
                    uint32_t skipLen;
                    if (!sfGetU32(sample, &skipLen)) return;
                    if (!sfSkip(sample, skipLen)) return;
                    break;
                }
            }
        }
    }
}  // End of readSFlowDatagram
