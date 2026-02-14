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
// IP layer decoding - IPv4 and IPv6 with fragmentation
// Static functions - included directly into pcaproc.c
//

// remember the last SlotSize packets with len and hash
// for duplicate check
#define SlotSize 8
static struct {
    uint32_t len;
    uint64_t hash;
} lastPacketStat[SlotSize] = {0};
static uint32_t packetSlot = 0;

// function prototypes
static decode_state_t decode_ipv4(decode_ctx_t *ctx);

static decode_state_t decode_ipv6(decode_ctx_t *ctx);

static int is_duplicate(const uint8_t *data_ptr, const uint32_t len);

#include "metrohash.c"

// Process IP layer (IPv4 or IPv6)
// Handles extension headers, fragmentation, populates flow node
// Returns next state
static decode_state_t decode_ip_layer(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    // Free any previous defragmented buffer (nested IP-in-IP case)
    if (ctx->defragmented) {
        free(ctx->defragmented);
        ctx->defragmented = NULL;
        dbg_printf("Freed outer defragmented buffer for nested IP processing\n");
    }

    uint8_t ipVersion;
    if (!cursor_get(cur, &ipVersion, sizeof(uint8_t))) {
        LogError("Length error decoding IP version");
        return DECODE_SKIP;
    }
    ipVersion = ipVersion >> 4;
    ctx->ipVersion = ipVersion;

    if (likely(ipVersion == 4)) {
        return decode_ipv4(ctx);
    } else if (ipVersion == 6) {
        return decode_ipv6(ctx);
    } else {
        dbg_printf("ProcessPacket() Unsupported protocol version: %i\n", ipVersion);
        return DECODE_UNKNOWN;
    }
}  // End of decode_ip_layer

// Decode IPv6 header and extension headers
static decode_state_t decode_ipv6(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
#ifdef DEVEL
    char s1[64];
    char s2[64];
#endif

    struct ip6_hdr *ip6_ptr = (struct ip6_hdr *)cur->ptr;
    struct ip6_hdr ip6;
    if (!cursor_read(cur, &ip6, sizeof(struct ip6_hdr))) {
        LogVerbose("Length error decoding IPv6 header");
        return DECODE_SKIP;
    }

    // IPv6 duplicate check
    // duplicate check starts from the IP header over the rest of the packet
    // vlan, mpls and layer 1 headers are ignored
    if (unlikely(ctx->packetParam->doDedup && ctx->redoLink == 0)) {
        // check for de-dup
        uint32_t hopLimit = ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim;
        ip6_ptr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0;
        uint16_t len = ntohs(ip6.ip6_ctlun.ip6_un1.ip6_un1_plen);
        if (is_duplicate((const uint8_t *)ip6_ptr, len + 40)) {
            ctx->packetParam->proc_stat.duplicates++;
            return DECODE_DONE;
        }
        ip6_ptr->ip6_ctlun.ip6_un1.ip6_un1_hlim = hopLimit;
        // prevent recursive dedup checks with IP in IP packets
        ctx->redoLink++;
    }

    uint16_t remaining_plen = ntohs(ip6.ip6_plen);

    // ipv6 Extension headers
    ctx->IPproto = ip6.ip6_nxt;
    while (ctx->IPproto == IPPROTO_HOPOPTS || ctx->IPproto == IPPROTO_ROUTING || ctx->IPproto == IPPROTO_DSTOPTS || ctx->IPproto == IPPROTO_AH) {
        struct {
            uint8_t nxt;
            uint8_t len;
        } ext;
        if (!cursor_read(cur, &ext, 2)) return DECODE_SKIP;
        size_t skip = (ext.len + 1) << 3;  // Length in 8-byte units
        if (skip > remaining_plen) return DECODE_ERROR;
        remaining_plen -= skip;
        if (!cursor_advance(cur, skip - 2)) return DECODE_SKIP;
        ctx->IPproto = ext.nxt;
    }

    uint8_t fragment_flag = 0;
    if (unlikely(ctx->IPproto == IPPROTO_FRAGMENT)) {
        struct ip6_frag ip6_frag_hdr;
        if (!cursor_get(cur, &ip6_frag_hdr, sizeof(struct ip6_frag))) return DECODE_ERROR;

        ctx->IPproto = ip6_frag_hdr.ip6f_nxt;
        uint32_t reassembledLength = 0;
        void *payload = ProcessIP6Fragment(ip6_ptr, &ip6_frag_hdr, cur->end, &reassembledLength);
        if (payload == NULL) {
            // not yet complete
            dbg_printf("IPv6 de-fragmentation not yet completed\n");
            return DECODE_DONE;
        }
        ctx->defragmented = payload;
        ctx->ipPayloadLength = reassembledLength;
        cur->ptr = payload;
        cur->end = cur->ptr + ctx->ipPayloadLength;
        fragment_flag = flagMF;
    } else {
        ctx->ipPayloadLength = remaining_plen;
    }

    ctx->ipPayloadEnd = cur->ptr + ctx->ipPayloadLength;

    // Sanity check: ipPayloadEnd must not exceed captured data
    if (ctx->ipPayloadEnd > cur->end) {
        LogVerbose("IPv6 payload length exceeds captured data");
        return DECODE_SKIP;
    }

    dbg_printf("Packet IPv6, SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET6, &ip6.ip6_src, s1, sizeof(s1)),
               inet_ntop(AF_INET6, &ip6.ip6_dst, s2, sizeof(s2)), (ptrdiff_t)(cur->end - ctx->ipPayloadEnd));

    ctx->hotNode->flowKey.version = AF_INET6;
    ctx->hotNode->t_first.tv_sec = ctx->hdr->ts.tv_sec;
    ctx->hotNode->t_last.tv_sec = ctx->hdr->ts.tv_sec;
    ctx->hotNode->t_first.tv_usec = ctx->hdr->ts.tv_usec;
    ctx->hotNode->t_last.tv_usec = ctx->hdr->ts.tv_usec;
    // Use ipPayloadLength which is correct after defragmentation
    ctx->hotNode->bytes = ctx->ipPayloadLength + sizeof(struct ip6_hdr);
    ctx->hotNode->packets = 1;

    uint8_t ttl = ip6.ip6_ctlun.ip6_un1.ip6_un1_hlim;
    ctx->coldNode->minTTL = ttl;
    ctx->coldNode->maxTTL = ttl;
    ctx->coldNode->fragmentFlags = fragment_flag;

    memcpy(ctx->hotNode->flowKey.src_addr.bytes, ip6.ip6_src.s6_addr, 16);
    memcpy(ctx->hotNode->flowKey.dst_addr.bytes, ip6.ip6_dst.s6_addr, 16);

    return DECODE_TRANSPORT;
}  // End of decode_ipv6

// Decode IPv4 header
static decode_state_t decode_ipv4(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
#ifdef DEVEL
    char s1[64];
    char s2[64];
#endif

    void *ip = cur->ptr;
    struct ip ip4;
    if (!cursor_get(cur, &ip4, sizeof(struct ip))) {
        LogVerbose("Length error decoding IPv4 header");
        return DECODE_SKIP;
    }

    int size_ip4 = (ip4.ip_hl << 2);
    if (size_ip4 < (int)sizeof(struct ip)) {
        // Malformed: Header length cannot be less than 20
        LogVerbose("Length error decoding IPv4 header - malformed length");
        return DECODE_ERROR;
    }

    if (!cursor_advance(cur, size_ip4)) {
        LogVerbose("Length error decoding IPv4 header");
        return DECODE_SKIP;
    }
    ctx->ipPayloadLength = ntohs(ip4.ip_len) - size_ip4;
    ctx->ipPayloadEnd = cur->ptr + ctx->ipPayloadLength;

    // IPv4 duplicate check
    // duplicate check starts from the IP header over the rest of the packet
    // vlan, mpls and layer 1 headers are ignored
    uint8_t fragment_flag = 0;
    if (unlikely(ctx->packetParam->doDedup && ctx->redoLink == 0)) {
        struct ip *iph = (struct ip *)ip;
        uint8_t old_ttl = iph->ip_ttl;
        uint16_t old_sum = iph->ip_sum;
        // check for de-dup
        iph->ip_ttl = 0;
        iph->ip_sum = 0;
        if (is_duplicate((const uint8_t *)ip, ntohs(iph->ip_len))) {
            ctx->packetParam->proc_stat.duplicates++;
            return DECODE_DONE;
        }
        iph->ip_ttl = old_ttl;  // RESTORE
        iph->ip_sum = old_sum;  // RESTORE
        // prevent recursive dedup checks with IP in IP packets
        ctx->redoLink++;
    }

    ctx->IPproto = ip4.ip_p;
    dbg_printf("Packet IPv4 SRC %s, DST %s, padding %zu\n", inet_ntop(AF_INET, &ip4.ip_src, s1, sizeof(s1)),
               inet_ntop(AF_INET, &ip4.ip_dst, s2, sizeof(s2)), (ptrdiff_t)(cur->end - ctx->ipPayloadEnd));

    // IPv4 defragmentation
    uint16_t ip_off = ntohs(ip4.ip_off);
    uint32_t frag_offset = (ip_off & IP_OFFMASK) << 3U;
    if ((ip_off & IP_MF) || frag_offset) {
        // fragmented packet
        uint32_t reassembledLength = 0;
        void *payload = ProcessIP4Fragment(ip, cur->end, &reassembledLength);
        if (payload == NULL) {
            // not yet complete
            dbg_printf("IPv4 de-fragmentation not yet completed\n");
            return DECODE_DONE;
        }

        // packet defragmented - set payload to defragmented data
        ctx->defragmented = payload;
        ctx->ipPayloadLength = reassembledLength;
        cur->ptr = payload;
        cur->end = cur->ptr + ctx->ipPayloadLength;
        fragment_flag = flagMF;
    } else {
        // Non-fragmented: All already set
    }
    ctx->ipPayloadEnd = cur->ptr + ctx->ipPayloadLength;

    // Sanity check: ipPayloadEnd must not exceed captured data
    if (ctx->ipPayloadLength < 0 || ctx->ipPayloadEnd > cur->end) {
        LogVerbose("IPv4 payload length exceeds captured data");
        return DECODE_SKIP;
    }

    ctx->hotNode->flowKey.version = AF_INET;
    ctx->hotNode->t_first.tv_sec = ctx->hdr->ts.tv_sec;
    ctx->hotNode->t_last.tv_sec = ctx->hdr->ts.tv_sec;
    ctx->hotNode->t_first.tv_usec = ctx->hdr->ts.tv_usec;
    ctx->hotNode->t_last.tv_usec = ctx->hdr->ts.tv_usec;
    ctx->hotNode->packets = 1;
    // Use ipPayloadLength + header size, correct after defragmentation
    ctx->hotNode->bytes = ctx->ipPayloadLength + size_ip4;

    static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
    memcpy(ctx->hotNode->flowKey.src_addr.bytes, prefix, 12);
    memcpy(ctx->hotNode->flowKey.dst_addr.bytes, prefix, 12);
    memcpy(ctx->hotNode->flowKey.src_addr.bytes + 12, &ip4.ip_src.s_addr, 4);
    memcpy(ctx->hotNode->flowKey.dst_addr.bytes + 12, &ip4.ip_dst.s_addr, 4);

    ctx->coldNode->minTTL = ip4.ip_ttl;
    ctx->coldNode->maxTTL = ip4.ip_ttl;
    ctx->coldNode->fragmentFlags = fragment_flag;
    if (ip_off & IP_DF) ctx->coldNode->fragmentFlags |= flagDF;

    return DECODE_TRANSPORT;
}  // End of decode_ipv4

static int is_duplicate(const uint8_t *data_ptr, const uint32_t len) {
    uint64_t hash = metrohash64_1(data_ptr, len, 0);

    for (int i = 0; i < SlotSize; i++) {
        if (lastPacketStat[i].len == len && lastPacketStat[i].hash == hash) return 1;
    }

    // not found - add to next slot round robin
    lastPacketStat[packetSlot].len = len;
    lastPacketStat[packetSlot].hash = hash;
    packetSlot = (packetSlot + 1) & (SlotSize - 1);
    return 0;
}  // End of is_duplicate
