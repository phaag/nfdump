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
 */

/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef _SFLOW_DECODE_H
#define _SFLOW_DECODE_H 1

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <netinet/in.h>

#include "collector.h"
#include "nfdump.h"
#include "sflow.h"

// -----------------------------------------------------------------------
// Extended-data presence flags  (bit positions in SFSample.extended_data_tag)
// -----------------------------------------------------------------------
#define SASAMPLE_EXTENDED_DATA_SWITCH 0x0001u    // EX_SWITCH
#define SASAMPLE_EXTENDED_DATA_ROUTER 0x0004u    // EX_ROUTER
#define SASAMPLE_EXTENDED_DATA_GATEWAY 0x0008u   // EX_GATEWAY
#define SASAMPLE_EXTENDED_DATA_MPLS 0x0040u      // EX_MPLS
#define SASAMPLE_EXTENDED_DATA_NAT 0x0080u       // EX_NAT
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 0x2000u  // EX_NAT_PORT
#define SASAMPLE_EXTENDED_DATA_VNI 0x4000u       // EX_VNI

// -----------------------------------------------------------------------
// Lean SFSample — replaces the original 1500-byte struct from sflow_process.h.
// jmp_buf / setjmp / longjmp are gone; parse errors are signalled through
// the 'error' field and propagated via return values instead.
//
// Layout: datagram-level fields first (preserved across per-sample resets),
// then per-sample fields starting at sampleDataOffset.
// -----------------------------------------------------------------------
typedef struct _SFSample {
    // ------------------------------------------------------------------
    // XDR parse cursor — valid for the full lifetime of the datagram
    // ------------------------------------------------------------------
    uint8_t *rawSample;     // pointer to the raw UDP payload
    uint32_t rawSampleLen;  // length of the raw UDP payload
    const uint8_t *endp;    // one byte past the last valid byte
    uint32_t *datap;        // current XDR decode position
    int error;              // SF_ERR_* — set on parse failure

    // ------------------------------------------------------------------
    // Datagram-level fields (set once per datagram, not reset per sample)
    // ------------------------------------------------------------------
    ip128_t sourceIP;          // collector IP address (from FlowSource)
    uint32_t agentSubId;       // sFlow agent sub-id (v5 only)
    uint32_t datagramVersion;  // 2, 4, or 5

    // ------------------------------------------------------------------
    // Per-sample fields — zero-filled between samples via sampleDataOffset
    // ------------------------------------------------------------------

    // sample metadata
    uint32_t ds_class;           // data-source class (for EXobservation)
    uint32_t ds_index;           // data-source index (for EXobservation)
    uint32_t sampledPacketSize;  // original packet size on the wire
    uint32_t meanSkipCount;      // sampling interval (1 in N)
    uint32_t inputPort;          // ingress interface ifIndex
    uint32_t outputPort;         // egress interface ifIndex
    uint32_t inputPortFormat;    // port format: 0=ifIndex 1=drop 2=multi
    uint32_t outputPortFormat;   // port format: same encoding

    // IP 5-tuple decoded from SFLFLOW_HEADER, SFLFLOW_IPV4, or SFLFLOW_IPV6
    SFLAddress ipsrc;            // source IP address (v4 or v6)
    SFLAddress ipdst;            // destination IP address (v4 or v6)
    uint32_t dcd_ipProtocol;     // IP protocol number
    uint32_t dcd_ipTos;          // IP ToS / DSCP byte
    uint32_t dcd_ipTTL;          // IP TTL (for EXipInfoID)
    uint32_t dcd_sport;          // L4 source port / ICMP type
    uint32_t dcd_dport;          // L4 destination port / ICMP code
    uint32_t dcd_tcpFlags;       // TCP flags byte
    uint32_t ip_fragmentOffset;  // raw IPv4 frag_off word: bits 15-13 = flags
                                 // (DF=0x4000, MF=0x2000), 12-0 = offset

    // Layer-2 fields decoded from SFLFLOW_HEADER or SFLFLOW_ETHERNET
    uint32_t eth_type;   // EtherType (for EXlayer2ID)
    uint8_t eth_src[6];  // source MAC address
    uint8_t eth_dst[6];  // destination MAC address
    uint32_t in_vlan;    // ingress 802.1Q VLAN id
    uint32_t out_vlan;   // egress 802.1Q VLAN id

    // MPLS label stack (from SFLFLOW_HEADER or EX_MPLS)
    int mpls_num_labels;      // number of labels decoded (0..10)
    uint32_t mpls_label[10];  // label values, index 0 = outermost

    // Extended-data presence bitmap
    uint32_t extended_data_tag;

    // IP routing (from SFLFLOW_EX_ROUTER)
    SFLAddress nextHop;  // next-hop router IP
    uint32_t srcMask;    // source prefix mask bits
    uint32_t dstMask;    // destination prefix mask bits

    // BGP info (from SFLFLOW_EX_GATEWAY)
    SFLAddress bgp_nextHop;  // BGP next-hop router IP
    uint32_t src_as;         // origin AS of the source prefix
    uint32_t dst_as;         // destination AS
    uint32_t src_peer_as;    // peer AS of source (for EXasAdjacentID)
    uint32_t dst_peer_as;    // peer AS of destination

    // NAT translation (from SFLFLOW_EX_NAT / SFLFLOW_EX_NAT_PORT)
    SFLAddress nat_src;     // post-NAT source address
    SFLAddress nat_dst;     // post-NAT destination address
    uint32_t nat_src_port;  // post-NAT source port
    uint32_t nat_dst_port;  // post-NAT destination port

    // Tunnel outer endpoints (GRE/IPIP from header decode)
    int parse_tun;         // 1 = follow GRE/IPIP into inner packet
    SFLAddress tun_ipsrc;  // outer tunnel source IP
    SFLAddress tun_ipdst;  // outer tunnel destination IP
    uint32_t tun_proto;    // outer tunnel IP protocol

    // VXLAN VNI (from SFLFLOW_EX_VNI_OUT / SFLFLOW_EX_VNI_IN)
    uint32_t vni;  // Virtual Network Identifier

    // ------------------------------------------------------------------
    // Internal state for SFLFLOW_HEADER raw-packet decode
    // (pointer into rawSample — valid only during header decode phase)
    // ------------------------------------------------------------------
    const uint8_t *header;    // pointer to start of sampled header
    uint32_t headerLen;       // byte length of sampled header
    uint32_t headerProtocol;  // SFLHeader_protocol enum value
    uint32_t stripped;        // bytes stripped before the header
    int gotIPV4;              // set when IPv4 header successfully decoded
    int gotIPV6;              // set when IPv6 header successfully decoded
    int offsetToIPV4;         // byte offset from header start to IP hdr
    int offsetToIPV6;         // byte offset from header start to IPv6 hdr
    int offsetToPayload;      // byte offset from header start to L4 payload
} SFSample;

// Offset to the first per-sample field — everything at/after this offset
// is cleared between samples in a multi-sample datagram.
#define sampleDataOffset offsetof(SFSample, ds_class)

// -----------------------------------------------------------------------
// Parse-error codes  (stored in SFSample.error, replaces longjmp codes)
// -----------------------------------------------------------------------
#define SF_ERR_OK 0      // no error
#define SF_ERR_EOS 1     // cursor overran declared boundary
#define SF_ERR_LENGTH 2  // element length mismatch
#define SF_ERR_DECODE 3  // protocol-level decode error

// -----------------------------------------------------------------------
// Entry point — called once per received UDP datagram
// -----------------------------------------------------------------------
void readSFlowDatagram(SFSample *sample, FlowSource_t *fs, int verbose);

#endif  // _SFLOW_DECODE_H
