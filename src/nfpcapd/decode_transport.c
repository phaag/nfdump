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

//
// Transport layer decoding - TCP, UDP, ICMP, tunnels (GRE, IPIP)
// Static functions - included directly into pcaproc.c
//

typedef struct gre_flags_s {
    int C : 1;
    int R : 1;
    int K : 1;
    int S : 1;
    int s : 1;
    int Recur : 3;
    int A : 1;
    int flag : 4;
    int version : 3;
} gre_flags_t;

typedef struct gre_hdr_s {
    uint16_t flags;
    uint16_t type;
} gre_hdr_t;

// static prototypes
static decode_state_t decode_udp(decode_ctx_t *ctx);

static decode_state_t decode_tcp(decode_ctx_t *ctx);

static decode_state_t decode_icmp(decode_ctx_t *ctx);

static decode_state_t decode_icmpv6(decode_ctx_t *ctx);

static decode_state_t decode_tunnel_ipv6(decode_ctx_t *ctx);

static decode_state_t decode_tunnel_ipip(decode_ctx_t *ctx);

static decode_state_t decode_gre(decode_ctx_t *ctx);

static decode_state_t decode_other(decode_ctx_t *ctx);

// Process transport layer protocol
// Handles TCP, UDP, ICMP, ICMPv6, GRE, IP-in-IP
// Returns next state
static decode_state_t decode_transport(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    // Sanity check payload bounds
    if (ctx->ipPayloadEnd < cur->ptr || ctx->ipPayloadEnd > cur->end) {
        LogError("ProcessPacket() payload data length error line: %u", __LINE__);
        return DECODE_ERROR;
    }

    // transport protocol processing
    switch (ctx->IPproto) {
        case IPPROTO_UDP:
            return decode_udp(ctx);
        case IPPROTO_TCP:
            return decode_tcp(ctx);
        case IPPROTO_ICMP:
            return decode_icmp(ctx);
        case IPPROTO_ICMPV6:
            return decode_icmpv6(ctx);
        case IPPROTO_IPV6:
            return decode_tunnel_ipv6(ctx);
        case IPPROTO_IPIP:
            return decode_tunnel_ipip(ctx);
        case IPPROTO_GRE:
        case 0x6558:
            return decode_gre(ctx);
        default:
            return decode_other(ctx);
    }
}  // End of decode_transport

static inline decode_state_t decode_udp(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    struct udphdr udp;

    if (!cursor_read(cur, &udp, sizeof(struct udphdr))) {
        LogVerbose("Length error decoding UDP header");
        return DECODE_SKIP;
    }

    uint16_t UDPlen = ntohs(udp.uh_ulen);
    if (UDPlen < 8) {
        LogError("UDP payload length error: %u bytes < 8", UDPlen);
        return DECODE_ERROR;
    }

    // UDP payload size from header (excludes 8-byte UDP header)
    uint16_t udpPayloadLen = UDPlen - 8;

    // Available data from IP layer
    ptrdiff_t availableLen = ctx->ipPayloadEnd - cur->ptr;

    // Consistency check: UDP header length vs available IP payload
    // Use the smaller of the two to handle:
    // - Padding (availableLen > udpPayloadLen): use UDP length
    // - Truncation (availableLen < udpPayloadLen): use available
    if (availableLen < 0) availableLen = 0;

    if ((ptrdiff_t)udpPayloadLen > availableLen) {
        // UDP header claims more data than available - truncated capture or corrupt
        dbg_printf("  UDP: header len %u > available %zd, using available\n", udpPayloadLen, availableLen);
        ctx->payloadSize = (size_t)availableLen;
    } else {
        // Normal case or padding present - use UDP header length
        ctx->payloadSize = udpPayloadLen;
    }

    ctx->hotNode->flags = 0;
    ctx->hotNode->flowKey.src_port = ntohs(udp.uh_sport);
    ctx->hotNode->flowKey.dst_port = ntohs(udp.uh_dport);

    if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

    dbg_printf("  UDP: size: %u, payloadsize: %zu, SRC: %i, DST: %i\n", UDPlen, ctx->payloadSize, ntohs(udp.uh_sport), ntohs(udp.uh_dport));

    ProcessUDPFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
    return DECODE_DONE;
}  // End of decode_udp

static inline decode_state_t decode_tcp(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    struct tcphdr tcp;

    if (!cursor_get(cur, &tcp, sizeof(struct tcphdr))) {
        LogVerbose("Length error decoding tcp header");
        return DECODE_SKIP;
    }

    // strip tcp headers
    uint32_t size_tcp = tcp.th_off << 2;
    if (size_tcp < sizeof(struct tcphdr)) {
        LogVerbose("Length error decoding tcp header - malformed header length");
        return DECODE_ERROR;
    }

    if (!cursor_advance(cur, size_tcp)) {
        LogVerbose("Length error decoding tcp header");
        return DECODE_SKIP;
    }

    ctx->payloadSize = (ptrdiff_t)(ctx->ipPayloadEnd - cur->ptr);
    if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

#ifdef DEVEL
    printf("  Size TCP header: %u, size TCP payload: %zu ", size_tcp, ctx->payloadSize);
    printf("  src port %i, dst port %i, flags %i : \n", ntohs(tcp.th_sport), ntohs(tcp.th_dport), tcp.th_flags);
    if (tcp.th_flags & TH_SYN) printf("SYN ");
    if (tcp.th_flags & TH_ACK) printf("ACK ");
    if (tcp.th_flags & TH_URG) printf("URG ");
    if (tcp.th_flags & TH_PUSH) printf("PUSH ");
    if (tcp.th_flags & TH_FIN) printf("FIN ");
    if (tcp.th_flags & TH_RST) printf("RST ");
    printf("\n");
#endif
    ctx->hotNode->flags = tcp.th_flags;
    ctx->hotNode->flowKey.src_port = ntohs(tcp.th_sport);
    ctx->hotNode->flowKey.dst_port = ntohs(tcp.th_dport);
    ctx->hotNode->flush = ((tcp.th_flags & (TH_FIN | TH_RST)) != 0);

    ProcessTCPFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
    return DECODE_DONE;
}  // End of decode_tcp

static decode_state_t decode_icmp(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    // Only read the 8-byte ICMP header, not full struct icmp (which is 28 bytes on BSD)
    uint8_t icmp_hdr[8];
    if (!cursor_read(cur, &icmp_hdr, 8)) {
        LogVerbose("Length error decoding icmp header");
        return DECODE_SKIP;
    }
    uint8_t icmp_type = icmp_hdr[0];
    uint8_t icmp_code = icmp_hdr[1];

    ctx->payloadSize = (ptrdiff_t)(ctx->ipPayloadEnd - cur->ptr);
    if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

    ctx->hotNode->flowKey.dst_port = (icmp_type << 8) + icmp_code;
    dbg_printf("  IPv%d ICMP: type: %u, code: %u\n", ctx->ipVersion, icmp_type, icmp_code);

    ProcessICMPFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
    return DECODE_DONE;
}  // End of decode_icmp

static decode_state_t decode_icmpv6(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    struct icmp6_hdr icmp6;

    if (!cursor_read(cur, &icmp6, sizeof(struct icmp6_hdr))) {
        LogVerbose("Length error decoding icmp6 header");
        return DECODE_SKIP;
    }

    ctx->payloadSize = (ptrdiff_t)(ctx->ipPayloadEnd - cur->ptr);
    if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

    ctx->hotNode->flowKey.dst_port = (icmp6.icmp6_type << 8) + icmp6.icmp6_code;
    dbg_printf("  IPv%d ICMP: type: %u, code: %u\n", ctx->ipVersion, icmp6.icmp6_type, icmp6.icmp6_code);

    ProcessICMPFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
    return DECODE_DONE;
}  // End of decode_icmpv6

static decode_state_t decode_tunnel_ipv6(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    if (cursor_size(cur) < (ptrdiff_t)sizeof(struct ip6_hdr)) {
        dbg_printf("  IPIPv6 tunnel Short packet: %u, Check line: %u\n", ctx->hdr->caplen, __LINE__);
        return DECODE_SKIP;
    }

    // move IP to tun IP
    ctx->coldNode->tun_src_addr = ctx->hotNode->flowKey.src_addr;
    ctx->coldNode->tun_dst_addr = ctx->hotNode->flowKey.dst_addr;
    ctx->coldNode->tun_proto = IPPROTO_IPV6;
    ctx->coldNode->tun_ip_version = ctx->hotNode->flowKey.version;

    dbg_printf("  IPIPv6 tunnel - inner IPv6:\n");

    // redo proto evaluation - process inner IP
    return DECODE_IP_LAYER;
}  // End of decode_tunnel_ipv6

static decode_state_t decode_tunnel_ipip(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    struct ip ip4;
    if (!cursor_get(cur, &ip4, sizeof(ip4))) {
        dbg_printf("  IPIP tunnel Short packet: %u, Check line: %u\n", ctx->hdr->caplen, __LINE__);
        return DECODE_SKIP;
    }

    uint32_t size_inner_ip = (ip4.ip_hl << 2);
    if (cursor_size(cur) < size_inner_ip) {
        dbg_printf("  IPIP tunnel Short packet: %u, Check line: %u\n", ctx->hdr->caplen, __LINE__);
        return DECODE_SKIP;
    }

    // STore tunnel metadata
    ctx->coldNode->tun_src_addr = ctx->hotNode->flowKey.src_addr;
    ctx->coldNode->tun_dst_addr = ctx->hotNode->flowKey.dst_addr;
    ctx->coldNode->tun_proto = IPPROTO_IPIP;
    ctx->coldNode->tun_ip_version = ctx->hotNode->flowKey.version;

    dbg_printf("  IPIP tunnel - inner IP:\n");

    // redo proto evaluation - process inner IP
    return DECODE_IP_LAYER;
}  // End of decode_tunnel_ipip

static decode_state_t decode_gre(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    gre_hdr_t gre;

    if (!cursor_read(cur, &gre, sizeof(gre_hdr_t))) {
        LogVerbose("Length error decoding GRE header");
        return DECODE_SKIP;
    }

    uint16_t gre_flags = ntohs(gre.flags);
    uint16_t gre_proto = ntohs(gre.type);

    // 1. Handle GRE Optional Fields (Checksum, Key, Sequence)
    // Order matters: Checksum (4) -> Key (4) -> Sequence (4)
    // Checksum + Reserved
    // Alternative: compute total skip size
    size_t skip = 0;
    if (gre_flags & 0x8000) skip += 4;  // Checksum
    if (gre_flags & 0x2000) skip += 4;  // Key
    if (gre_flags & 0x1000) skip += 4;  // Sequence
    if (skip && !cursor_advance(cur, skip)) {
        LogVerbose("Length error decoding GRE optional fields");
        return DECODE_SKIP;
    }

    dbg_printf("  GRE proto encapsulation: type: 0x%x\n", gre_proto);

    // 2. Handle Routing/Version (PPTP/VPN)
    uint8_t version = gre_flags & 0x0007;
    if (version == 1) {
        // PPTP / Enhanced GRE
        uint16_t callID;
        if (!cursor_advance(cur, 2) || !cursor_read(cur, &callID, sizeof(uint16_t))) {
            LogVerbose("Length error decoding GRE PPTP header");
            return DECODE_SKIP;
        }
        ctx->hotNode->flowKey.dst_port = ntohs(callID);
        if (gre_proto != 0x880b) {
            LogError("Unexpected protocol in LLTP GRE header: 0x%x", gre_proto);
            return DECODE_ERROR;
        }

        // pptp - vpn
        // 2 bytes key payload length, 2 byte call ID
        if (gre_flags & 0x0080 && !cursor_advance(cur, 4)) {
            LogVerbose("Length error decoding GRE opptional fields");
            return DECODE_SKIP;
        }

        ctx->payloadSize = (ptrdiff_t)(ctx->ipPayloadEnd - cur->ptr);
        if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

        ProcessOtherFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
        return DECODE_DONE;
    }

    // 3. Handle ERSPAN (Encapsulated Remote SPAN)
    if (gre_proto == PROTO_ERSPAN) {  // ERSPAN Type II
        // Skip 8-byte ERSPAN Header
        if (!cursor_advance(cur, 8)) {
            LogVerbose("Length error decoding GRE ERSPAN Header");
            return DECODE_SKIP;
        }
        ctx->linktype = DLT_EN10MB;
        return DECODE_LINK_LAYER;      // Start over as Ethernet
    } else if (gre_proto == 0x22EB) {  // ERSPAN Type III
        // Skip 20-byte ERSPAN Header
        if (!cursor_advance(cur, 20)) {
            LogVerbose("Length error decoding GRE ERSPAN Header");
            return DECODE_SKIP;
        }
        ctx->linktype = DLT_EN10MB;
        return DECODE_LINK_LAYER;
    }

    // 4. Handle Transparent Ethernet Bridge (GRE Tap)
    if (gre_proto == 0x6558) {
        ctx->linktype = DLT_EN10MB;
        return DECODE_LINK_LAYER;
    }

    // 5. Standard GRE Tunnel (Raw IP)
    if (gre_proto == ETHERTYPE_IP || gre_proto == ETHERTYPE_IPV6) {
        ctx->protocol = gre_proto;

        // Store Tunnel Metadata (Important for Flow Tracking)
        ctx->coldNode->tun_src_addr = ctx->hotNode->flowKey.src_addr;
        ctx->coldNode->tun_dst_addr = ctx->hotNode->flowKey.dst_addr;
        ctx->coldNode->tun_proto = IPPROTO_GRE;
        ctx->coldNode->tun_ip_version = ctx->hotNode->flowKey.version;

        return DECODE_ETHERTYPE;  // Process internal IP packet
    }

    dbg_printf("Unsupported GRE protocol: 0x%x\n", gre_proto);
    return DECODE_SKIP;
}  // End of decode_gre

static decode_state_t decode_other(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    // not handled transport protocol - raw flow
    ctx->payloadSize = (ptrdiff_t)(ctx->ipPayloadEnd - cur->ptr);
    if (ctx->payloadSize > 0) ctx->payload = (void *)cur->ptr;

    dbg_printf("  raw proto: %u, payload size: %zu\n", ctx->IPproto, ctx->payloadSize);

    ProcessOtherFlow(ctx->packetParam, ctx->hotNode, ctx->coldNode, ctx->payload, ctx->payloadSize);
    return DECODE_DONE;
}  // End of decode_other
