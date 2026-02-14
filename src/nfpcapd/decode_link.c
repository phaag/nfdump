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
// Link layer packet decoding
// Static functions - included directly into pcaproc.c
//

// Standardized Link-Type Wire Values - defined them locally as they may differ
// on different platforms
#define LT_NULL 0
#define LT_RAW 101
#define LT_LOOP 108
#define LT_IEEE802_11_RADIO 127
// Often used by OpenBSD
#define LT_BSD_LOOP 12
#define LT_OPENBSD_RAW 14

// Forward declaration for NFLOG helper
static inline void parse_pflog(const uint8_t *ptr, pf_info_t *pf_info);

static inline decode_state_t decode_nflog(decode_ctx_t *ctx, uint16_t *protocol);

// Decode link layer header, set ctx->protocol and advance cursor
// Returns next state: DECODE_ETHERTYPE on success, DECODE_SKIP/ERROR on failure
static decode_state_t decode_link_layer(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;
    uint16_t protocol = 0;

    switch (ctx->linktype) {
        case LT_NULL: {
            // DLT_NULL uses HOST byte order of the capturing system.
            // Heuristic: If the high 16 bits are non-zero, it's likely swapped.
            uint32_t header;
            if (!cursor_read(cur, &header, 4)) {
                LogInfo("Packet: %u: LT_NULL: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }

            // Corrected Precedence and Manual Swap
            if ((header & 0xFFFF0000) != 0) {
                header = ((header >> 24) & 0xff) | ((header << 8) & 0xff0000) | ((header >> 8) & 0xff00) | ((header << 24) & 0xff000000);
            }

            if (header == 2) {
                protocol = 0x0800;  // IPv4 EtherType
                dbg_printf("Linktype: LT_NULL - IPv4\n");
            } else if (header == 24 || header == 28 || header == 30) {
                protocol = 0x86DD;  // IPv6 EtherType
                dbg_printf("Linktype: LT_NULL - IPv6\n");
            }
        } break;

        case LT_LOOP:
        case LT_BSD_LOOP: {
            // Lookahead check for mislabeled RAW data
            if (ctx->linktype == LT_BSD_LOOP && cur->ptr < cur->end) {
                uint8_t first_byte = cur->ptr[0];
                if (first_byte == 0x45 || (first_byte & 0xf0) == 0x60) {
                    protocol = (first_byte == 0x45) ? 0x0800 : 0x86DD;
                    dbg_printf("Linktype: LT_BSD_LOOP (RAW fallback) - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");
                    break;  // Payload starts here, no 4-byte header to skip
                }
            }

            uint32_t header;
            if (!cursor_read(cur, &header, 4)) {
                LogInfo("Packet: %u: LT_LOOP: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            header = ntohl(header);  // DLT_LOOP is always Big Endian

            // Map PF_ values to EtherTypes
            if (header == 2) {
                protocol = 0x0800;
            } else if (header == 24 || header == 28 || header == 30) {
                protocol = 0x86DD;
            }
            dbg_printf("Linktype: %u - Protocol: 0x%04X\n", ctx->linktype, protocol);
        } break;

        case LT_RAW:
        case LT_OPENBSD_RAW: {
            // Raw IP - no link layer header, starts directly with IP
            if (cursor_size(cur) < 1) {
                LogInfo("Packet: %u: LT_RAW: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            uint8_t version = (cur->ptr[0] >> 4);
            if (version == 4) {
                protocol = 0x0800;  // IPv4
            } else if (version == 6) {
                protocol = 0x86DD;  // IPv6
            } else {
                LogInfo("Packet: %u: LT_RAW: unsupported IP version: %u", ctx->pkg_cnt, version);
                return DECODE_UNKNOWN;
            }
            dbg_printf("Linktype: LT_RAW - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");
        } break;

        case DLT_EN10MB: {
            if (cursor_size(cur) < 14) {
                LogInfo("Packet: %u: DLT_EN10MB: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            cursor_read(cur, &ctx->dstMac, 6);
            cursor_read(cur, &ctx->srcMac, 6);
            cursor_read(cur, &protocol, 2);
            protocol = ntohs(protocol);
            int IEEE802 = protocol <= 1500;
            if (IEEE802) {
                return DECODE_UNKNOWN;
            }
            dbg_printf("Linktype: DLT_EN10MB\n");
        } break;

        case DLT_PPP:
            protocol = 0x800;
            if (!cursor_advance(cur, 2)) {
                LogInfo("Packet: %u: DLT_PPP: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            dbg_printf("Linktype: DLT_PPP\n");
            break;

        case DLT_PPP_SERIAL:
            protocol = 0x800;
            if (!cursor_advance(cur, 2)) {
                LogInfo("Packet: %u: DLT_PPP_SERIAL: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            dbg_printf("Linktype: DLT_PPP_SERIAL\n");
            break;

        case DLT_LINUX_SLL:
            if (!cursor_advance(cur, 14) || !cursor_read(cur, &protocol, 2)) {
                LogInfo("Packet: %u: DLT_LINUX_SLL: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            protocol = ntohs(protocol);
            dbg_printf("Linktype: DLT_LINUX_SSL\n");
            break;

        case DLT_IEEE802_11:
            protocol = 0x800;
            if (!cursor_advance(cur, 22)) {
                LogInfo("Packet: %u: DLT_IEEE802_11: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            dbg_printf("Linktype: DLT_IEEE802_11\n");
            break;

        case DLT_NFLOG: {
            decode_state_t result = decode_nflog(ctx, &protocol);
            if (result != DECODE_ETHERTYPE) return result;
        } break;

        case DLT_PFLOG: {
            if (cursor_size(cur) < 62) {
                LogInfo("Packet: %u: PFLOG: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
            uint8_t pf_len = cur->ptr[0];
            if (pf_len == PFLOG_HDRLEN) {
                parse_pflog(cur->ptr, &ctx->pflog);
            } else {
                LogInfo("Packet: %u: PFLOG: not an OpenBSD pflog header", ctx->pkg_cnt);
                return DECODE_UNKNOWN;
            }

            if (!cursor_advance(cur, pf_len)) {
                LogInfo("Packet: %u: PFLOG: not enough data", ctx->pkg_cnt);
                return DECODE_SKIP;
            }

            // pflog.af is in host byte order
            if (ctx->pflog.af == 2)
                protocol = 0x0800;
            else
                protocol = 0x86DD;

            dbg_printf("Linktype: DLT_PFLOG - %s\n", protocol == 0x0800 ? "IPv4" : "IPv6");
        } break;

        case LT_IEEE802_11_RADIO: {
            uint16_t it_len;

            // The Radiotap header length is at offset 2 (2nd and 3rd bytes)
            // Header structure: version (1), pad (1), length (2)
            if (cur->ptr + 4 > cur->end) {
                LogInfo("Packet: %u: Radiotap: header too short", ctx->pkg_cnt);
                return DECODE_SKIP;
            }

            // Radiotap length is always Little Endian
            // Use pointer arithmetic to get the 16-bit length at offset 2
            it_len = cur->ptr[2] | (cur->ptr[3] << 8);

            dbg_printf("Linktype: IEEE802_11_RADIO (Radiotap len: %u)\n", it_len);

            if (!cursor_advance(cur, it_len)) {
                LogInfo("Packet: %u: Radiotap: skip error", ctx->pkg_cnt);
                return DECODE_SKIP;
            }

            // Now at the start of the 802.11 MAC header.
            // Note: 802.11 requires complex parsing to find the payload.
            // For a simple 'assumed' IP payload over WiFi:
            protocol = 0x0800;

            // Skip common MAC (24) + LLC/SNAP (8)
            if (!cursor_advance(cur, 32)) {
                LogInfo("Packet: %u: Radiotap: skip error", ctx->pkg_cnt);
                return DECODE_SKIP;
            }
        } break;

        default:
            LogInfo("Packet: %u: unsupported link type: 0x%x", ctx->pkg_cnt, ctx->linktype);
            return DECODE_UNKNOWN;
    }

    ctx->protocol = protocol;
    return DECODE_ETHERTYPE;
}  // End of decode_link_layer

static inline void parse_pflog(const uint8_t *ptr, pf_info_t *pf_info) {
    // 1-byte fields (No Endianness issues)
    pf_info->af = ptr[PFLOG_OFF_AF];
    pf_info->action = ptr[PFLOG_OFF_ACTION];
    pf_info->reason = ptr[PFLOG_OFF_REASON];
    pf_info->dir = ptr[PFLOG_OFF_DIR];
    pf_info->rewritten = ptr[PFLOG_OFF_REWRITTEN];

    // Multi-byte fields (Network Byte Order -> Host Byte Order)
    // Using memcpy to avoid alignment/bus errors on ARM/Strict-align CPUs
    uint32_t tmp32;
    memcpy(&tmp32, ptr + PFLOG_OFF_RULENR, 4);
    pf_info->rulenr = ntohl(tmp32);

    memcpy(&tmp32, ptr + PFLOG_OFF_SUBRULENR, 4);
    pf_info->subrulenr = ntohl(tmp32);

    memcpy(&tmp32, ptr + PFLOG_OFF_UID, 4);
    pf_info->uid = ntohl(tmp32);

    memcpy(&tmp32, ptr + PFLOG_OFF_PID, 4);
    pf_info->pid = (int32_t)ntohl(tmp32);

    // Strings
    memcpy(pf_info->ifname, ptr + PFLOG_OFF_IFNAME, 16);
    pf_info->ifname[15] = '\0';

    pf_info->has_pfinfo = 1;
}  // End of parse_pflog

// Helper for NFLOG decoding (complex TLV parsing)
static decode_state_t decode_nflog(decode_ctx_t *ctx, uint16_t *protocol) {
    cursor_t *cur = &ctx->cur;
    nflog_hdr_t nflog_hdr;

    if (!cursor_read(cur, &nflog_hdr, sizeof(nflog_hdr_t))) {
        LogInfo("Packet: %u: DLT_NFLOG: not enough data", ctx->pkg_cnt);
        return DECODE_SKIP;
    }

    if (nflog_hdr.nflog_version != 0) {
        LogInfo("Packet: %u: unsupported NFLOG version: %d", ctx->pkg_cnt, nflog_hdr.nflog_version);
        return DECODE_UNKNOWN;
    }

    // Set protocol based on family immediately
    switch (nflog_hdr.nflog_family) {
        case 2:
            *protocol = 0x0800;  // IPv4
            dbg_printf("Linktype DLT_NFLOG: IPv4, rid: %u\n", ntohs(nflog_hdr.nflog_rid));
            break;
        case 10:
            *protocol = 0x86DD;  // IPv6
            dbg_printf("Linktype DLT_NFLOG: IPv6, rid: %u\n", ntohs(nflog_hdr.nflog_rid));
            break;
        default:
            LogError("Linktype DLT_NFLOG: unknown family: %u\n", nflog_hdr.nflog_family);
            return DECODE_ERROR;
    }

    // TLVs following
    nflog_tlv_t tlv;
    while (cursor_read(cur, &tlv, sizeof(nflog_tlv_t))) {
        dbg_printf("NFLOG: tlv type: %u, length: %u\n", tlv.tlv_type, tlv.tlv_length);

        // Validation: TLV length must at least include itself
        if (tlv.tlv_length < sizeof(nflog_tlv_t)) {
            LogInfo("Packet: %u: NFLOG: Malformed TLV length", ctx->pkg_cnt);
            return DECODE_SKIP;
        }

        if (tlv.tlv_type == NFULA_PAYLOAD) {
            // Payload found! Cursor is now positioned at start of IP header
            // because cursor_read moved us past the TLV header.
            dbg_printf("Linktype DLT_NFLOG: %s, payload found\n", *protocol == 0x0800 ? "IPv4" : "IPv6");
            break;
        }

        // skip the current TLV including optional padding
        size_t aligned_size = (tlv.tlv_length + 3) & ~3;
        // Subtract the 4 bytes we already read via cursor_read
        size_t remaining_to_skip = aligned_size - sizeof(nflog_tlv_t);

        if (!cursor_advance(cur, remaining_to_skip)) {
            LogInfo("Packet: %u: NFLOG: tlv skip error", ctx->pkg_cnt);
            return DECODE_SKIP;
        }
    }

    return DECODE_ETHERTYPE;
}  // End of decode_nflog
