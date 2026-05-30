/*
 *  Copyright (c) 2026, Peter Haag
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
 * packet_frame.c
 *
 * Decoder for IPFIX IE #315 dataLinkFrameSection.
 *
 * Architecture:
 *   - Self-contained: all link/IP/transport decoders are inlined in this
 *     translation unit so they do not share code with nfpcapd and cannot
 *     affect nfpcapd's hot path.
 *   - Adapted from src/nfpcapd/decode_{link,proto,ip,transport}.c and
 *     src/sflow/sflow_nfdump.c (StoreSflowRecord pattern).
 *   - cursor_t bounds-checks every read; any overrun returns 0 (skip).
 *   - No dynamic memory allocation: the tmp frame buffer is stack-local
 *     (max FRAME_DECODE_MAXBYTES bytes) and the output record is written
 *     directly into the caller's data block.
 *   - VLAN stacking, MPLS, PPPoE, GRE (including ERSPAN), IP-in-IP tunnels
 *     are all decoded.  IP fragment reassembly is NOT performed; the first
 *     fragment is decoded as a partial record.
 */

#include "packet_frame.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <string.h>

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

#include "id.h"
#include "logging.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "util.h"

/* -----------------------------------------------------------------------
 * Constants and missing defines
 * --------------------------------------------------------------------- */

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS 0x8847
#endif
#ifndef ETHERTYPE_PPPOE
#define ETHERTYPE_PPPOE 0x8864
#endif
#ifndef ETHERTYPE_PPPOEDISC
#define ETHERTYPE_PPPOEDISC 0x8863
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

/* GRE encapsulations */
#define ETHERTYPE_TRANSETHER 0x6558 /* GRE Ethernet bridge */
#define PROTO_ERSPAN_II 0x88BE
#define PROTO_ERSPAN_III 0x22EB

/* Fragment flag bits stored in EXipInfo */
#define FRAG_FLAG_MF 0x20u
#define FRAG_FLAG_DF 0x40u

/* Maximum frame bytes we will attempt to decode.
 * Covers: 18 (Eth+VLAN) + 40 (IPv6) + 20 (TCP options) + payload up to cap.
 * We copy the full captured frame so we decode payload too. */
#define FRAME_DECODE_MAXBYTES 65536u

/* Maximum MPLS labels to track */
#define MPLSMAX 10

/* -----------------------------------------------------------------------
 * Cursor — identical interface to nfpcapd's cursor_t
 * --------------------------------------------------------------------- */

typedef struct {
    const uint8_t *ptr;
    const uint8_t *end;
} pf_cursor_t;

static inline __attribute__((always_inline)) ptrdiff_t pf_cursor_size(const pf_cursor_t *c) { return c->end - c->ptr; }

static inline __attribute__((always_inline)) int pf_cursor_advance(pf_cursor_t *c, size_t n) {
    if (c->ptr + n > c->end) return 0;
    c->ptr += n;
    return 1;
}

static inline __attribute__((always_inline)) int pf_cursor_read(pf_cursor_t *c, void *dst, size_t n) {
    if (c->ptr + n > c->end) return 0;
    memcpy(dst, c->ptr, n);
    c->ptr += n;
    return 1;
}

/* Read 6-byte MAC into a uint64 in host byte order */
static inline uint64_t pf_read_mac(pf_cursor_t *c) {
    uint8_t b[6] = {0};
    pf_cursor_read(c, b, 6);
    return ((uint64_t)b[0] << 40) | ((uint64_t)b[1] << 32) | ((uint64_t)b[2] << 24) | ((uint64_t)b[3] << 16) | ((uint64_t)b[4] << 8) | (uint64_t)b[5];
}

static inline __attribute__((always_inline)) int pf_cursor_get(const pf_cursor_t *c, void *dst, size_t n) {
    if (c->ptr + n > c->end) return 0;
    memcpy(dst, c->ptr, n);
    return 1;
}

/* -----------------------------------------------------------------------
 * Decoded packet information — intermediate representation
 * --------------------------------------------------------------------- */

typedef struct pf_decoded_s {
    /* Generic flow */
    uint8_t ipVersion; /* 4 or 6 */
    uint8_t IPproto;   /* IPPROTO_TCP/UDP/ICMP/… */
    uint8_t tcpFlags;
    uint8_t srcTos;
    uint16_t srcPort;
    uint16_t dstPort; /* also ICMP type<<8|code */
    uint64_t inBytes;
    uint32_t inPackets;
    uint8_t minTTL;
    uint8_t maxTTL;
    uint8_t fragmentFlags; /* FRAG_FLAG_MF / FRAG_FLAG_DF */
    uint8_t truncated;     /* set if captured frame was shorter than original */

    /* IP addresses (IPv4-mapped-IPv6 for v4) */
    uint8_t srcAddr[16];
    uint8_t dstAddr[16];

    /* MAC addresses (48-bit stored in 64-bit, host byte order) */
    uint64_t srcMac;
    uint64_t dstMac;

    /* VLAN */
    uint16_t vlanID;
    uint16_t postVlanID;

    /* MPLS — up to MPLSMAX labels (network byte order each) */
    uint32_t numMPLS;
    uint32_t mplsLabel[MPLSMAX];

    /* Tunnel (outer IP when GRE/IPIP) */
    uint8_t tunProto;
    uint8_t tunIPversion;
    uint8_t tunSrcAddr[16];
    uint8_t tunDstAddr[16];

    /* Payload pointer and length (points into the tmp frame buffer) */
    const uint8_t *payload;
    uint32_t payloadLen;
} pf_decoded_t;

/* -----------------------------------------------------------------------
 * Decode state
 * --------------------------------------------------------------------- */

typedef enum {
    PF_DECODE_LINK,
    PF_DECODE_ETHERTYPE,
    PF_DECODE_IP,
    PF_DECODE_TRANSPORT,
    PF_DECODE_DONE,
    PF_DECODE_SKIP,    /* truncated / benign skip */
    PF_DECODE_UNKNOWN, /* unsupported protocol */
} pf_state_t;

typedef struct pf_ctx_s {
    pf_cursor_t cur;
    pf_state_t state;
    uint16_t protocol; /* current EtherType / next-proto */
    uint16_t linktype; /* DLT_EN10MB or virtual raw-IP */
    uint16_t origSize; /* original (uncaptured) frame size */
    pf_decoded_t dec;
    /* tunnel re-entry: save outer addrs before overwriting with inner */
    int tunSaved;
    /* VLAN stacking depth guard */
    int vlanDepth;
} pf_ctx_t;

/* -----------------------------------------------------------------------
 * Forward declarations for all decode stages
 * --------------------------------------------------------------------- */
static pf_state_t pf_decode_link(pf_ctx_t *ctx);
static pf_state_t pf_decode_ethertype(pf_ctx_t *ctx);
static pf_state_t pf_decode_ip(pf_ctx_t *ctx);
static pf_state_t pf_decode_ipv4(pf_ctx_t *ctx);
static pf_state_t pf_decode_ipv6(pf_ctx_t *ctx);
static pf_state_t pf_decode_transport(pf_ctx_t *ctx);
static pf_state_t pf_decode_udp(pf_ctx_t *ctx);
static pf_state_t pf_decode_tcp(pf_ctx_t *ctx);
static pf_state_t pf_decode_icmp(pf_ctx_t *ctx);
static pf_state_t pf_decode_icmpv6(pf_ctx_t *ctx);
static pf_state_t pf_decode_gre(pf_ctx_t *ctx);
static pf_state_t pf_decode_ipip(pf_ctx_t *ctx);
static pf_state_t pf_decode_tunnel_ipv6(pf_ctx_t *ctx);
static pf_state_t pf_decode_other(pf_ctx_t *ctx);

/* -----------------------------------------------------------------------
 * Link layer decoder — Ethernet (IPFIX linkType=1), raw IPv4 (11), raw IPv6 (12)
 * --------------------------------------------------------------------- */

static pf_state_t pf_decode_link(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;

    switch (ctx->linktype) {
        case DATALINK_ETHERNET: {
            /* Ethernet II: 6 dst + 6 src + 2 EtherType = 14 bytes */
            if (pf_cursor_size(c) < 14) {
                LogVerbose("dataLinkFrameSection: Ethernet header too short");
                return PF_DECODE_SKIP;
            }
            ctx->dec.dstMac = pf_read_mac(c);
            ctx->dec.srcMac = pf_read_mac(c);
            uint16_t proto;
            pf_cursor_read(c, &proto, 2);
            ctx->protocol = ntohs(proto);
            if (ctx->protocol <= 1500) {
                /* IEEE 802.3 length field — LLC/SNAP, not supported */
                return PF_DECODE_UNKNOWN;
            }
            return PF_DECODE_ETHERTYPE;
        }

        case DATALINK_RAW_IPV4:
            ctx->protocol = ETHERTYPE_IP;
            return PF_DECODE_ETHERTYPE;

        case DATALINK_RAW_IPV6:
            ctx->protocol = ETHERTYPE_IPV6;
            return PF_DECODE_ETHERTYPE;

        default:
            LogVerbose("dataLinkFrameSection: unsupported linkType %u", ctx->linktype);
            return PF_DECODE_UNKNOWN;
    }
}

/* -----------------------------------------------------------------------
 * EtherType / encapsulation decoder
 * --------------------------------------------------------------------- */

static pf_state_t pf_decode_ethertype(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;

    for (;;) {
        switch (ctx->protocol) {
            case ETHERTYPE_IP:
            case ETHERTYPE_IPV6:
                return PF_DECODE_IP;

            case ETHERTYPE_VLAN: /* 0x8100 */
            case 0x88A8: {       /* QinQ / 802.1ad */
                if (++ctx->vlanDepth > 4) {
                    LogVerbose("dataLinkFrameSection: VLAN depth exceeded");
                    return PF_DECODE_SKIP;
                }
                uint16_t tci, inner_type;
                if (!pf_cursor_read(c, &tci, 2) || !pf_cursor_read(c, &inner_type, 2)) {
                    return PF_DECODE_SKIP;
                }
                uint16_t vid = ntohs(tci) & 0x0FFF;
                if (ctx->dec.vlanID == 0)
                    ctx->dec.vlanID = vid;
                else
                    ctx->dec.postVlanID = vid;
                ctx->protocol = ntohs(inner_type);
                /* loop */
                break;
            }

            case ETHERTYPE_MPLS: {
                ctx->dec.numMPLS = 0;
                uint32_t label;
                do {
                    if (!pf_cursor_read(c, &label, 4)) return PF_DECODE_SKIP;
                    if (ctx->dec.numMPLS < MPLSMAX) ctx->dec.mplsLabel[ctx->dec.numMPLS++] = label; /* keep NBO */
                } while ((ntohl(label) & 0x100) == 0); /* bottom-of-stack */
                if (pf_cursor_size(c) < 1) return PF_DECODE_SKIP;
                uint8_t nxHdr = c->ptr[0];
                ctx->protocol = ((nxHdr >> 4) == 4) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
                /* loop */
                break;
            }

            case ETHERTYPE_PPPOE: {
                /* PPPoE session: VersionType(1) Code(1) SessionID(2) Len(2) PPPProto(2) */
                uint8_t vt, code;
                uint16_t ppp_proto;
                if (!pf_cursor_read(c, &vt, 1) || !pf_cursor_read(c, &code, 1)) return PF_DECODE_SKIP;
                if (!pf_cursor_advance(c, 4) || !pf_cursor_read(c, &ppp_proto, 2)) return PF_DECODE_SKIP;
                ppp_proto = ntohs(ppp_proto);
                if (vt != 0x11 || code != 0) return PF_DECODE_UNKNOWN;
                if (ppp_proto != 0x0021 && ppp_proto != 0x0057) return PF_DECODE_UNKNOWN;
                ctx->protocol = (ppp_proto == 0x0021) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
                /* loop */
                break;
            }

            case ETHERTYPE_TRANSETHER: {
                /* GRE Ethernet bridge: inner Ethernet frame */
                uint16_t inner;
                ctx->dec.dstMac = pf_read_mac(c);
                ctx->dec.srcMac = pf_read_mac(c);
                if (!pf_cursor_read(c, &inner, 2)) return PF_DECODE_SKIP;
                ctx->protocol = ntohs(inner);
                /* loop */
                break;
            }

            case ETHERTYPE_PPPOEDISC:
            case ETHERTYPE_ARP:
            default:
                return PF_DECODE_UNKNOWN;
        }
    }
}

/* -----------------------------------------------------------------------
 * IP layer dispatcher
 * --------------------------------------------------------------------- */

static pf_state_t pf_decode_ip(pf_ctx_t *ctx) {
    if (pf_cursor_size(&ctx->cur) < 1) return PF_DECODE_SKIP;
    uint8_t version = ctx->cur.ptr[0] >> 4;
    if (version == 4) return pf_decode_ipv4(ctx);
    if (version == 6) return pf_decode_ipv6(ctx);
    return PF_DECODE_UNKNOWN;
}

/* -----------------------------------------------------------------------
 * IPv4 decoder
 * --------------------------------------------------------------------- */

/* IPv4-mapped IPv6 prefix */
static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static pf_state_t pf_decode_ipv4(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;

    struct ip ip4;
    if (!pf_cursor_get(c, &ip4, sizeof(ip4))) {
        LogVerbose("dataLinkFrameSection: IPv4 header too short");
        return PF_DECODE_SKIP;
    }
    int hlen = ip4.ip_hl << 2;
    if (hlen < (int)sizeof(struct ip)) {
        LogVerbose("dataLinkFrameSection: IPv4 ihl malformed");
        return PF_DECODE_SKIP;
    }
    if (!pf_cursor_advance(c, hlen)) return PF_DECODE_SKIP;

    ctx->dec.ipVersion = 4;
    ctx->dec.IPproto = ip4.ip_p;
    ctx->dec.srcTos = ip4.ip_tos;
    ctx->dec.minTTL = ip4.ip_ttl;
    ctx->dec.maxTTL = ip4.ip_ttl;

    /* Bytes = total IP length; packets = 1 */
    ctx->dec.inBytes = ntohs(ip4.ip_len);
    ctx->dec.inPackets = 1;

    /* Fragment flags */
    uint16_t ip_off = ntohs(ip4.ip_off);
    if (ip_off & IP_DF) ctx->dec.fragmentFlags |= FRAG_FLAG_DF;
    if ((ip_off & IP_MF) || (ip_off & IP_OFFMASK)) ctx->dec.fragmentFlags |= FRAG_FLAG_MF;

    /* Store addresses IPv4-mapped */
    memcpy(ctx->dec.srcAddr, v4mapped, 12);
    memcpy(ctx->dec.dstAddr, v4mapped, 12);
    memcpy(ctx->dec.srcAddr + 12, &ip4.ip_src.s_addr, 4);
    memcpy(ctx->dec.dstAddr + 12, &ip4.ip_dst.s_addr, 4);

    /* Payload bounds: clamp to what is actually captured */
    ptrdiff_t ip_payload_len = (ptrdiff_t)ntohs(ip4.ip_len) - hlen;
    if (ip_payload_len < 0) ip_payload_len = 0;
    const uint8_t *ip_payload_end = c->ptr + ip_payload_len;
    if (ip_payload_end > c->end) {
        /* truncated capture — decode what we have */
        ip_payload_end = c->end;
        ctx->dec.truncated = 1;
    }
    /* Re-bound cursor to IP payload */
    c->end = ip_payload_end;

    /* Non-first fragment: no transport header available */
    if (ip_off & IP_OFFMASK) {
        /* Store raw payload bytes for partial-fragment records */
        ctx->dec.payload = c->ptr;
        ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
        return PF_DECODE_DONE;
    }

    return PF_DECODE_TRANSPORT;
}

/* -----------------------------------------------------------------------
 * IPv6 decoder
 * --------------------------------------------------------------------- */

static pf_state_t pf_decode_ipv6(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;

    struct ip6_hdr ip6;
    if (!pf_cursor_read(c, &ip6, sizeof(ip6))) {
        LogVerbose("dataLinkFrameSection: IPv6 header too short");
        return PF_DECODE_SKIP;
    }

    ctx->dec.ipVersion = 6;
    ctx->dec.srcTos = (ntohl(ip6.ip6_flow) >> 20) & 0xFF; /* traffic class */
    uint8_t ttl = ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim;
    ctx->dec.minTTL = ttl;
    ctx->dec.maxTTL = ttl;
    ctx->dec.inPackets = 1;
    ctx->dec.inBytes = sizeof(struct ip6_hdr) + ntohs(ip6.ip6_plen);

    memcpy(ctx->dec.srcAddr, ip6.ip6_src.s6_addr, 16);
    memcpy(ctx->dec.dstAddr, ip6.ip6_dst.s6_addr, 16);

    /* Walk extension headers */
    ctx->dec.IPproto = ip6.ip6_nxt;
    uint16_t plen = ntohs(ip6.ip6_plen);
    while (ctx->dec.IPproto == IPPROTO_HOPOPTS || ctx->dec.IPproto == IPPROTO_ROUTING || ctx->dec.IPproto == IPPROTO_DSTOPTS ||
           ctx->dec.IPproto == IPPROTO_AH) {
        struct {
            uint8_t nxt;
            uint8_t len;
        } ext;
        if (!pf_cursor_read(c, &ext, 2)) return PF_DECODE_SKIP;
        size_t skip = (size_t)(ext.len + 1) << 3;
        if (skip > plen) return PF_DECODE_SKIP;
        plen -= (uint16_t)skip;
        if (!pf_cursor_advance(c, skip - 2)) return PF_DECODE_SKIP;
        ctx->dec.IPproto = ext.nxt;
    }

    /* Fragment header */
    if (ctx->dec.IPproto == IPPROTO_FRAGMENT) {
        struct ip6_frag frag;
        if (!pf_cursor_read(c, &frag, sizeof(frag))) return PF_DECODE_SKIP;
        ctx->dec.IPproto = frag.ip6f_nxt;
        ctx->dec.fragmentFlags |= FRAG_FLAG_MF;
        /* No reassembly — partial decode */
        ctx->dec.payload = c->ptr;
        ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
        return PF_DECODE_DONE;
    }

    /* Clamp payload to what was captured */
    const uint8_t *ip_payload_end = c->ptr + plen;
    if (ip_payload_end > c->end) {
        ip_payload_end = c->end;
        ctx->dec.truncated = 1;
    }
    c->end = ip_payload_end;

    return PF_DECODE_TRANSPORT;
}

/* -----------------------------------------------------------------------
 * Transport layer dispatcher
 * --------------------------------------------------------------------- */

static pf_state_t pf_decode_transport(pf_ctx_t *ctx) {
    switch (ctx->dec.IPproto) {
        case IPPROTO_TCP:
            return pf_decode_tcp(ctx);
        case IPPROTO_UDP:
            return pf_decode_udp(ctx);
        case IPPROTO_ICMP:
            return pf_decode_icmp(ctx);
        case IPPROTO_ICMPV6:
            return pf_decode_icmpv6(ctx);
        case IPPROTO_GRE:
            return pf_decode_gre(ctx);
        case IPPROTO_IPIP:
            return pf_decode_ipip(ctx);
        case IPPROTO_IPV6:
            return pf_decode_tunnel_ipv6(ctx);
        default:
            return pf_decode_other(ctx);
    }
}

static pf_state_t pf_decode_tcp(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;
    struct tcphdr tcp;
    if (!pf_cursor_get(c, &tcp, sizeof(tcp))) {
        LogVerbose("dataLinkFrameSection: TCP header too short");
        return PF_DECODE_SKIP;
    }
    uint32_t hlen = (uint32_t)tcp.th_off << 2;
    if (hlen < sizeof(struct tcphdr) || !pf_cursor_advance(c, hlen)) return PF_DECODE_SKIP;

    ctx->dec.srcPort = ntohs(tcp.th_sport);
    ctx->dec.dstPort = ntohs(tcp.th_dport);
    ctx->dec.tcpFlags = tcp.th_flags;
    ctx->dec.payload = c->ptr;
    ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
    return PF_DECODE_DONE;
}

static pf_state_t pf_decode_udp(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;
    struct udphdr udp;
    if (!pf_cursor_read(c, &udp, sizeof(udp))) {
        LogVerbose("dataLinkFrameSection: UDP header too short");
        return PF_DECODE_SKIP;
    }
    ctx->dec.srcPort = ntohs(udp.uh_sport);
    ctx->dec.dstPort = ntohs(udp.uh_dport);
    ctx->dec.payload = c->ptr;
    ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
    return PF_DECODE_DONE;
}

static pf_state_t pf_decode_icmp(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;
    uint8_t hdr[4];
    if (!pf_cursor_read(c, hdr, 4)) return PF_DECODE_SKIP;
    /* dstPort encodes type<<8|code — same as nfpcapd / IPFIX convention */
    ctx->dec.dstPort = ((uint16_t)hdr[0] << 8) | hdr[1];
    ctx->dec.payload = c->ptr;
    ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
    return PF_DECODE_DONE;
}

static pf_state_t pf_decode_icmpv6(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;
    struct icmp6_hdr icmp6;
    if (!pf_cursor_read(c, &icmp6, sizeof(icmp6))) return PF_DECODE_SKIP;
    ctx->dec.dstPort = ((uint16_t)icmp6.icmp6_type << 8) | icmp6.icmp6_code;
    ctx->dec.payload = c->ptr;
    ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
    return PF_DECODE_DONE;
}

static pf_state_t pf_decode_other(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;
    ctx->dec.payload = c->ptr;
    ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
    return PF_DECODE_DONE;
}

/* -----------------------------------------------------------------------
 * Tunnel decoders — save outer IP, re-enter at IP layer
 * --------------------------------------------------------------------- */

/* Save outer IP addresses into tunnel fields */
static void pf_save_tunnel(pf_ctx_t *ctx, uint8_t tunProto) {
    if (!ctx->tunSaved) {
        ctx->dec.tunProto = tunProto;
        ctx->dec.tunIPversion = ctx->dec.ipVersion;
        memcpy(ctx->dec.tunSrcAddr, ctx->dec.srcAddr, 16);
        memcpy(ctx->dec.tunDstAddr, ctx->dec.dstAddr, 16);
        ctx->tunSaved = 1;
    }
}

static pf_state_t pf_decode_ipip(pf_ctx_t *ctx) {
    pf_save_tunnel(ctx, IPPROTO_IPIP);
    return PF_DECODE_IP;
}

static pf_state_t pf_decode_tunnel_ipv6(pf_ctx_t *ctx) {
    pf_save_tunnel(ctx, IPPROTO_IPV6);
    return PF_DECODE_IP;
}

static pf_state_t pf_decode_gre(pf_ctx_t *ctx) {
    pf_cursor_t *c = &ctx->cur;

    struct {
        uint16_t flags;
        uint16_t type;
    } gre;
    if (!pf_cursor_read(c, &gre, sizeof(gre))) return PF_DECODE_SKIP;

    uint16_t gre_flags = ntohs(gre.flags);
    uint16_t gre_type = ntohs(gre.type);

    /* Skip optional GRE fields (Checksum, Key, Sequence) */
    size_t opt_skip = 0;
    if (gre_flags & 0x8000) opt_skip += 4;
    if (gre_flags & 0x2000) opt_skip += 4;
    if (gre_flags & 0x1000) opt_skip += 4;
    if (opt_skip && !pf_cursor_advance(c, opt_skip)) return PF_DECODE_SKIP;

    uint8_t version = gre_flags & 0x0007;
    if (version == 1) {
        /* PPTP / Enhanced GRE — not further decoded */
        ctx->dec.payload = c->ptr;
        ctx->dec.payloadLen = (uint32_t)pf_cursor_size(c);
        return PF_DECODE_DONE;
    }

    /* ERSPAN Type II: 4-byte GRE-seq + 8-byte ERSPAN header, then Ethernet */
    if (gre_type == PROTO_ERSPAN_II) {
        if (!pf_cursor_advance(c, 8)) return PF_DECODE_SKIP;
        pf_save_tunnel(ctx, IPPROTO_GRE);
        ctx->linktype = DATALINK_ETHERNET;
        return PF_DECODE_LINK;
    }
    /* ERSPAN Type III: 20-byte ERSPAN header, then Ethernet */
    if (gre_type == PROTO_ERSPAN_III) {
        if (!pf_cursor_advance(c, 20)) return PF_DECODE_SKIP;
        pf_save_tunnel(ctx, IPPROTO_GRE);
        ctx->linktype = DATALINK_ETHERNET;
        return PF_DECODE_LINK;
    }
    /* Transparent Ethernet bridge (GRE tap) */
    if (gre_type == ETHERTYPE_TRANSETHER) {
        pf_save_tunnel(ctx, IPPROTO_GRE);
        ctx->linktype = DATALINK_ETHERNET;
        return PF_DECODE_LINK;
    }
    /* Standard GRE IP tunnel */
    if (gre_type == ETHERTYPE_IP || gre_type == ETHERTYPE_IPV6) {
        pf_save_tunnel(ctx, IPPROTO_GRE);
        ctx->protocol = gre_type;
        return PF_DECODE_ETHERTYPE;
    }

    return PF_DECODE_UNKNOWN;
}

/* -----------------------------------------------------------------------
 * State machine driver
 * --------------------------------------------------------------------- */

static pf_state_t pf_run(pf_ctx_t *ctx) {
    /* Guard against infinite loops in tunnel/VLAN re-entry */
    int iterations = 0;
    while (iterations++ < 32) {
        switch (ctx->state) {
            case PF_DECODE_LINK:
                ctx->state = pf_decode_link(ctx);
                break;
            case PF_DECODE_ETHERTYPE:
                ctx->state = pf_decode_ethertype(ctx);
                break;
            case PF_DECODE_IP:
                ctx->state = pf_decode_ip(ctx);
                break;
            case PF_DECODE_TRANSPORT:
                ctx->state = pf_decode_transport(ctx);
                break;
            case PF_DECODE_DONE:
            case PF_DECODE_SKIP:
            case PF_DECODE_UNKNOWN:
                return ctx->state;
        }
    }
    /* Exceeded iteration guard — malformed / deeply nested */
    LogVerbose("dataLinkFrameSection: decode iteration limit exceeded");
    return PF_DECODE_SKIP;
}

/* -----------------------------------------------------------------------
 * Record builder — mirrors StoreSflowRecord() in sflow_nfdump.c
 * --------------------------------------------------------------------- */

/*
 * Build a v4 flow record into outBuff from the decoded packet.
 * Returns the record size on success, 0 on insufficient buffer.
 */
static int pf_build_record(void *outBuff, size_t buffAvail, const pf_decoded_t *dec, const pf_ctx_t *ctx, uint64_t msecReceived,
                           uint16_t exporterSysID, FlowSource_t *fs) {
    /* ----------------------------------------------------------------
     * 1.  Determine which extensions to include
     * -------------------------------------------------------------- */
    uint64_t bitMap = 0;
    uint32_t extSize = 0;

    /* Generic flow is always present */
    BitMapSet(bitMap, EXgenericFlowID);
    extSize += EXgenericFlowSize;

    /* IP addresses */
    int isV4 = (dec->ipVersion == 4);
    int isV6 = (dec->ipVersion == 6);
    if (isV4) {
        BitMapSet(bitMap, EXipv4FlowID);
        extSize += EXipv4FlowSize;
    }
    if (isV6) {
        BitMapSet(bitMap, EXipv6FlowID);
        extSize += EXipv6FlowSize;
    }

    /* MAC addresses (present when Ethernet link type) */
    int hasMac = (dec->srcMac != 0 || dec->dstMac != 0);
    if (hasMac) {
        BitMapSet(bitMap, EXinMacAddrID);
        extSize += EXinMacAddrSize;
    }

    /* VLAN */
    int hasVlan = (dec->vlanID != 0);
    if (hasVlan) {
        BitMapSet(bitMap, EXvLanID);
        extSize += EXvLanSize;
    }

    /* MPLS */
    int hasMpls = (dec->numMPLS > 0);
    if (hasMpls) {
        BitMapSet(bitMap, EXmplsID);
        extSize += EXmplsSize;
    }

    /* IP info (TTL, fragment flags) */
    int hasIPinfo = (dec->minTTL != 0 || dec->fragmentFlags != 0);
    if (hasIPinfo) {
        BitMapSet(bitMap, EXipInfoID);
        extSize += EXipInfoSize;
    }

    /* Tunnel */
    int hasTunV4 = (ctx->tunSaved && dec->tunIPversion == 4);
    int hasTunV6 = (ctx->tunSaved && dec->tunIPversion == 6);
    if (hasTunV4) {
        BitMapSet(bitMap, EXtunnelV4ID);
        extSize += EXtunnelV4Size;
    }
    if (hasTunV6) {
        BitMapSet(bitMap, EXtunnelV6ID);
        extSize += EXtunnelV6Size;
    }

    /* Payload — variable length */
    int hasPayload = (dec->payload != NULL && dec->payloadLen > 0);
    if (hasPayload) {
        BitMapSet(bitMap, EXinPayloadID);
        extSize += sizeof(uint32_t) + dec->payloadLen; /* EXinPayload: length + bytes */
        extSize = (extSize + 7) & ~7u;                 /* align */
    }

    /* Exporter IP */
    int isV4src = (fs->sa_family == AF_INET);
    if (isV4src) {
        BitMapSet(bitMap, EXipReceivedV4ID);
        extSize += EXipReceivedV4Size;
    } else {
        BitMapSet(bitMap, EXipReceivedV6ID);
        extSize += EXipReceivedV6Size;
    }

    /* ----------------------------------------------------------------
     * 2.  Check output buffer fits
     * -------------------------------------------------------------- */
    uint32_t numExt = (uint32_t)__builtin_popcountll(bitMap);
    uint32_t tableSize = ALIGN8(numExt * sizeof(uint16_t));
    uint32_t baseOffset = sizeof(recordHeaderV4_t) + tableSize;
    uint32_t totalSize = baseOffset + extSize;

    if (totalSize > buffAvail) {
        LogError("dataLinkFrameSection: output record buffer too small (%u > %zu)", totalSize, buffAvail);
        return 0;
    }

    /* ----------------------------------------------------------------
     * 3.  Write record header
     * -------------------------------------------------------------- */
    recordHeaderV4_t *hdr = AddV4Header(outBuff);
    hdr->exporterID = exporterSysID;
    hdr->nfVersion = 10; /* IPFIX */
    hdr->extBitmap = bitMap;
    hdr->numExtensions = numExt;
    memset((uint8_t *)outBuff + sizeof(recordHeaderV4_t), 0, tableSize);

    /* ----------------------------------------------------------------
     * 4.  Fill extensions via bitmap walk (same pattern as StoreSflowRecord)
     * -------------------------------------------------------------- */
    uint8_t *base = (uint8_t *)outBuff;
    uint16_t *offTable = (uint16_t *)(base + sizeof(recordHeaderV4_t));
    uint32_t nextOff = baseOffset;
    uint64_t bm = bitMap;
    uint32_t slot = 0;

    while (bm) {
        uint32_t extID = (uint32_t)__builtin_ctzll(bm);
        bm &= bm - 1;
        offTable[slot++] = (uint16_t)nextOff;
        uint8_t *ext = base + nextOff;

        switch (extID) {
            case EXgenericFlowID: {
                EXgenericFlow_t *gf = (EXgenericFlow_t *)ext;
                *gf = (EXgenericFlow_t){
                    .msecFirst = msecReceived,
                    .msecLast = msecReceived,
                    .msecReceived = msecReceived,
                    .proto = dec->IPproto,
                    .tcpFlags = dec->tcpFlags,
                    .srcPort = dec->srcPort,
                    .dstPort = dec->dstPort,
                    .srcTos = dec->srcTos,
                    .inPackets = dec->inPackets,
                    .inBytes = dec->inBytes,
                };
                nextOff += EXgenericFlowSize;
            } break;

            case EXipv4FlowID: {
                EXipv4Flow_t *ip4f = (EXipv4Flow_t *)ext;
                memcpy(&ip4f->srcAddr, dec->srcAddr + 12, 4);
                memcpy(&ip4f->dstAddr, dec->dstAddr + 12, 4);
                ip4f->srcAddr = ntohl(ip4f->srcAddr);
                ip4f->dstAddr = ntohl(ip4f->dstAddr);
                nextOff += EXipv4FlowSize;
            } break;

            case EXipv6FlowID: {
                EXipv6Flow_t *ip6f = (EXipv6Flow_t *)ext;
                uint64_t w[2];
                memcpy(w, dec->srcAddr, 16);
                ip6f->srcAddr[0] = ntohll(w[0]);
                ip6f->srcAddr[1] = ntohll(w[1]);
                memcpy(w, dec->dstAddr, 16);
                ip6f->dstAddr[0] = ntohll(w[0]);
                ip6f->dstAddr[1] = ntohll(w[1]);
                nextOff += EXipv6FlowSize;
            } break;

            case EXinMacAddrID: {
                EXinMacAddr_t *mac = (EXinMacAddr_t *)ext;
                mac->inSrcMac = dec->srcMac;
                mac->outDstMac = dec->dstMac;
                nextOff += EXinMacAddrSize;
            } break;

            case EXvLanID: {
                EXvLan_t *vl = (EXvLan_t *)ext;
                vl->srcVlan = dec->vlanID;
                vl->dstVlan = dec->postVlanID;
                nextOff += EXvLanSize;
            } break;

            case EXmplsID: {
                EXmpls_t *mpls = (EXmpls_t *)ext;
                memset(mpls, 0, sizeof(*mpls));
                uint32_t n = dec->numMPLS < 10 ? dec->numMPLS : 10;
                for (uint32_t i = 0; i < n; i++) mpls->label[i] = dec->mplsLabel[i];
                nextOff += EXmplsSize;
            } break;

            case EXipInfoID: {
                EXipInfo_t *ii = (EXipInfo_t *)ext;
                ii->minTTL = dec->minTTL;
                ii->maxTTL = dec->maxTTL;
                ii->fragmentFlags = dec->fragmentFlags;
                nextOff += EXipInfoSize;
            } break;

            case EXtunnelV4ID: {
                EXtunnelV4_t *tun = (EXtunnelV4_t *)ext;
                uint32_t s, d;
                memcpy(&s, dec->tunSrcAddr + 12, 4);
                memcpy(&d, dec->tunDstAddr + 12, 4);
                tun->srcAddr = ntohl(s);
                tun->dstAddr = ntohl(d);
                tun->proto = dec->tunProto;
                nextOff += EXtunnelV4Size;
            } break;

            case EXtunnelV6ID: {
                EXtunnelV6_t *tun = (EXtunnelV6_t *)ext;
                uint64_t w[2];
                memcpy(w, dec->tunSrcAddr, 16);
                tun->srcAddr[0] = ntohll(w[0]);
                tun->srcAddr[1] = ntohll(w[1]);
                memcpy(w, dec->tunDstAddr, 16);
                tun->dstAddr[0] = ntohll(w[0]);
                tun->dstAddr[1] = ntohll(w[1]);
                tun->proto = dec->tunProto;
                nextOff += EXtunnelV6Size;
            } break;

            case EXinPayloadID: {
                /* Variable-length: uint32_t length then bytes, 8-byte aligned */
                uint32_t plen = dec->payloadLen;
                memcpy(ext, &plen, sizeof(uint32_t));
                memcpy(ext + sizeof(uint32_t), dec->payload, plen);
                uint32_t aligned = (sizeof(uint32_t) + plen + 7) & ~7u;
                nextOff += aligned;
            } break;

            case EXipReceivedV4ID: {
                EXipReceivedV4_t *rip = (EXipReceivedV4_t *)ext;
                uint32_t ip4;
                memcpy(&ip4, fs->ipAddr.bytes + 12, 4);
                rip->ip = ntohl(ip4);
                nextOff += EXipReceivedV4Size;
            } break;

            case EXipReceivedV6ID: {
                EXipReceivedV6_t *rip = (EXipReceivedV6_t *)ext;
                uint64_t w[2];
                memcpy(w, fs->ipAddr.bytes, 16);
                rip->ip[0] = ntohll(w[0]);
                rip->ip[1] = ntohll(w[1]);
                nextOff += EXipReceivedV6Size;
            } break;

            default:
                break;
        }
    }

    hdr->size = nextOff;
    return (int)nextOff;
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

int DecodePacketFrame(void *outBuff, size_t buffAvail, const uint8_t *frameData, uint32_t frameLen, uint16_t linkType, uint16_t origFrameSize,
                      uint64_t msecReceived, uint16_t exporterSysID, FlowSource_t *fs) {
    if (frameLen == 0 || !frameData || !outBuff) return 0;

    /* Clamp to our decode buffer size (should never exceed it for valid data) */
    if (frameLen > FRAME_DECODE_MAXBYTES) {
        LogVerbose("dataLinkFrameSection: frame length %u clamped to %u", frameLen, FRAME_DECODE_MAXBYTES);
        frameLen = FRAME_DECODE_MAXBYTES;
    }

    /* Map IPFIX linkType to internal linktype */
    uint16_t lt;
    switch (linkType) {
        case DATALINK_ETHERNET:
            lt = DATALINK_ETHERNET;
            break;
        case DATALINK_RAW_IPV4:
            lt = DATALINK_RAW_IPV4;
            break;
        case DATALINK_RAW_IPV6:
            lt = DATALINK_RAW_IPV6;
            break;
        default:
            LogVerbose("dataLinkFrameSection: unsupported IPFIX linkType %u — skipping", linkType);
            return 0;
    }

    /* Initialise decode context */
    pf_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cur.ptr = frameData;
    ctx.cur.end = frameData + frameLen;
    ctx.linktype = lt;
    ctx.origSize = origFrameSize;
    ctx.state = PF_DECODE_LINK;

    /* Mark as truncated if captured length < original frame size */
    if (frameLen < (uint32_t)origFrameSize) ctx.dec.truncated = 1;

    /* Run the decode state machine */
    pf_state_t result = pf_run(&ctx);

    if (result == PF_DECODE_SKIP || result == PF_DECODE_UNKNOWN) {
        return 0;
    }

    /* Build the output v4 record */
    return pf_build_record(outBuff, buffAvail, &ctx.dec, &ctx, msecReceived, exporterSysID, fs);
}
