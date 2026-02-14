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
// Packet decoding context and state machine definitions
// Internal header - included only by pcaproc.c and decode_*.c files
//
#ifndef DECODE_CTX_H
#define DECODE_CTX_H

#include <stdint.h>
#include <string.h>

#include "pflog.h"

// Maximum MPLS labels to track
#define MPLSMAX 10

// Decoding state machine states
typedef enum {
    DECODE_LINK_LAYER,  // Process link layer header
    DECODE_ETHERTYPE,   // Process protocol/ethertype after link layer
    DECODE_IP_LAYER,    // Process IPv4/IPv6 header
    DECODE_TRANSPORT,   // Process TCP/UDP/ICMP/tunnels
    DECODE_DONE,        // Packet fully processed
    DECODE_SKIP,        // Skip packet - cursor error/truncated (short_snap)
    DECODE_ERROR,       // Protocol decoding error (decoding_errors)
    DECODE_UNKNOWN      // Unknown/unsupported protocol (unknown)
} decode_state_t;

// Decoding context - passed between decoder functions
typedef struct decode_ctx_s {
    // State machine
    decode_state_t state;

    // Cursor for packet data
    cursor_t cur;

    // Link layer info
    uint32_t linktype;
    uint16_t protocol;  // EtherType / next protocol
    uint64_t srcMac;
    uint64_t dstMac;

    // VLAN/MPLS
    uint32_t vlanID;
    uint32_t numMPLS;
    uint32_t mplsLabel[MPLSMAX];

    // PFLOG header (if present)
    pf_info_t pflog;

    // IP layer info
    uint16_t IPproto;           // Transport protocol
    uint8_t ipVersion;          // 4 or 6
    ptrdiff_t ipPayloadLength;  // IP payload length
    uint8_t *ipPayloadEnd;      // End of IP payload
    uint8_t fragmentFlags;      // Fragment flags for flow

    // Defragmentation
    void *defragmented;  // Reassembled fragment buffer (must free)

    // For de-dup and nested IP-in-IP detection
    int redoLink;

    // Packet metadata
    const struct pcap_pkthdr *hdr;
    unsigned pkg_cnt;

    // Flow nodes to populate
    hotNode_t *hotNode;
    coldNode_t *coldNode;

    // Packet parameters
    packetParam_t *packetParam;

    // Payload extraction
    void *payload;
    size_t payloadSize;

} decode_ctx_t;

#endif  // DECODE_CTX_H
