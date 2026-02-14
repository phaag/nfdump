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
// EtherType and encapsulation protocol decoding
// Handles VLAN, MPLS, PPPoE, GRE tap bridge
// Static functions - included directly into pcaproc.c
//

typedef struct vlan_hdr_s {
    uint16_t vlan_id;
    uint16_t type;
} vlan_hdr_t;

// Process ethertype/protocol after link layer
// May loop (VLAN stacking, MPLS) or transition to IP layer
// Returns next state
static decode_state_t decode_ethertype(decode_ctx_t *ctx) {
    cursor_t *cur = &ctx->cur;

    dbg_printf("Next protocol: 0x%x\n", ctx->protocol);

    // IEEE 802.3 check
    int IEEE802 = ctx->protocol <= 1500;
    if (IEEE802) {
        return DECODE_UNKNOWN;
    }

    switch (ctx->protocol) {
        case ETHERTYPE_IP:    // IPv4
        case ETHERTYPE_IPV6:  // IPv6
            return DECODE_IP_LAYER;

        case ETHERTYPE_VLAN: {  // VLAN
            do {
                vlan_hdr_t vlan_hdr;
                if (!cursor_read(cur, &vlan_hdr, sizeof(vlan_hdr_t))) {
                    LogError("Length error decoding vlan");
                    return DECODE_SKIP;
                }
                dbg_printf("VLAN ID: %u, type: 0x%x\n", ntohs(vlan_hdr.vlan_id), ntohs(vlan_hdr.type));
                ctx->protocol = ntohs(vlan_hdr.type);
                ctx->vlanID = ntohs(vlan_hdr.vlan_id) & 0xFFF;
            } while (ctx->protocol == 0x8100 || ctx->protocol == 0x88A8);

            // redo protocol evaluation
            return DECODE_ETHERTYPE;
        }

        case ETHERTYPE_MPLS: {  // MPLS
            // unwrap MPLS label stack
            ctx->numMPLS = 0;
            uint32_t label;
            do {
                if (!cursor_read(cur, &label, sizeof(uint32_t))) {
                    LogError("Length error decoding mpls stack");
                    return DECODE_SKIP;
                }
                if (ctx->numMPLS < MPLSMAX) {
                    ctx->mplsLabel[ctx->numMPLS++] = label;
                    dbg_printf("MPLS label %u: %x\n", ctx->numMPLS, ntohl(label) >> 8);
                }
            } while ((ntohl(label) & 0x100) == 0);  // check for bottom of stack

            if (cursor_size(cur) < 1) {
                LogError("Length error decoding mpls next header");
                return DECODE_SKIP;
            }
            uint8_t nxHdr = cur->ptr[0];
            if ((nxHdr >> 4) == 4)
                ctx->protocol = ETHERTYPE_IP;  // IPv4
            else if ((nxHdr >> 4) == 6)
                ctx->protocol = ETHERTYPE_IPV6;  // IPv6
            else {
                LogInfo("Unsupported next protocol in mpls: 0x%x\n", nxHdr >> 4);
                return DECODE_UNKNOWN;
            }
            // redo protocol evaluation
            return DECODE_ETHERTYPE;
        }

        case ETHERTYPE_TRANSETHER: {  // GRE ethernet bridge
            dbg_printf("  GRE tap tunnel\n");
            uint16_t nextProtocol = 0;
            if (!cursor_read(cur, &ctx->dstMac, 6) || !cursor_read(cur, &ctx->srcMac, 6) || !cursor_read(cur, &nextProtocol, sizeof(uint16_t))) {
                LogError("Length error decoding GRE tap tunnel");
                return DECODE_SKIP;
            }

            ctx->protocol = ntohs(nextProtocol);
            return DECODE_ETHERTYPE;
        }

        case ETHERTYPE_PPPOE: {
            uint8_t VersionType = 0;
            uint8_t Code = 0;
            uint16_t pppProto = 0;

            if (!cursor_read(cur, &VersionType, 1) || !cursor_read(cur, &Code, 1)) {
                LogError("Length error decoding ethertype PPPoE");
                return DECODE_SKIP;
            }
            if (!cursor_advance(cur, 4) || !cursor_read(cur, &pppProto, sizeof(uint16_t))) {
                LogError("Length error decoding ethertype PPPoE");
                return DECODE_SKIP;
            }

            pppProto = ntohs(pppProto);

            if (VersionType != 0x11) {
                LogError("Unsupported ppp Version/Type: 0x%x", VersionType);
                return DECODE_UNKNOWN;
            }
            if (Code != 0) {
                // skip packets other than session data
                return DECODE_UNKNOWN;
            }
            if (pppProto != 0x0021 /* v4 */ && pppProto != 0x0057 /* v6 */) {
                LogError("Unsupported ppp proto: 0x%x", pppProto);
                return DECODE_UNKNOWN;
            }
            ctx->protocol = (pppProto == 0x0021) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
            return DECODE_ETHERTYPE;
        }

        case ETHERTYPE_PPPOEDISC: {
            // skip PPPoE discovery messages
            return DECODE_UNKNOWN;
        }

        case ETHERTYPE_ARP:          // skip ARP
        case ETHERTYPE_LOOPBACK:     // skip Loopback
        case ETHERTYPE_LLDP:         // skip LLDP
        case ETHERTYPE_FLOWCONTROL:  // skip flow control
            return DECODE_UNKNOWN;

        default:
            LogError("Unsupported link protocol: 0x%x, packet: %u", ctx->protocol, ctx->pkg_cnt);
            return DECODE_UNKNOWN;
    }
}  // End of decode_ethertype
