/*
 *  Copyright (c) 2024, Peter Haag
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

#ifndef _NFDUMP_1_6_x_H
#define _NFDUMP_1_6_x_H 1

#include <stdint.h>
#include <sys/types.h>

#include "nfxV3.h"

// forward declaration
typedef struct exporter_info_record_s exporter_info_record_t;
typedef struct extension_map_s extension_map_t;

/* the master record contains all possible records unpacked */
typedef struct master_record_s {
    // common information from all netflow versions
    // 							// interpreted as uint64_t[]

    uint8_t flags;  // 0xff00 0000 0000 0000
    // copy of V3 records flags
    uint8_t nfversion;  // 0x00ff 0000 0000 0000
    uint16_t mflags;    // 0x0000'ffff'0000'0000
#define V3_FLAG_IPV6_ADDR 1
#define V3_FLAG_IPV6_NH 2
#define V3_FLAG_IPV6_NHB 4
#define V3_FLAG_IPV6_EXP 8
    uint16_t size;         // 0x0000'0000'ffff'0000
    uint16_t numElements;  // 0x0000'0000'0000'ffff

    uint64_t msecFirst;     // 0xffff'ffff'ffff'ffff
    uint64_t msecLast;      // 0xffff'ffff'ffff'ffff
    uint64_t msecReceived;  // 0xffff'ffff'ffff'ffff

    uint64_t inPackets;  // 0xffff'ffff'ffff'ffff
    uint64_t inBytes;    // 0xffff'ffff'ffff'ffff

    uint16_t srcPort;  // 0xffff'0000'0000'0000
    union {
        uint16_t dstPort;  // 0x0000'ffff'0000'0000
        struct {
#ifdef WORDS_BIGENDIAN
            uint8_t icmpType;  // 0x0000'ff00'0000'0000
            uint8_t icmpCode;  // 0x0000'00ff'0000'0000
#else
            uint8_t icmpCode;
            uint8_t icmpType;
#endif
        };
    };
    uint8_t fwd_status;  // 0x0000'0000'ff00'0000
    uint8_t tcp_flags;   // 0x0000'0000'00ff'0000
    uint8_t proto;       // 0x0000'0000'0000'ff00
    uint8_t tos;         // 0x0000'0000'0000'00ff

    uint16_t exporter_sysid;  // 0xffff'0000'0000'0000
    uint8_t engine_type;      // 0x0000'ff00'0000'0000
    uint8_t engine_id;        // 0x0000'00ff'0000'0000
    uint16_t sec_group_tag;   // 0x0000'0000'ffff'0000
    uint16_t exporterSampler;
    uint64_t selectorID;

    uint8_t biFlowDir;
    uint8_t flowEndReason;
    uint8_t revTcpFlags;
    uint8_t fragmentFlags;

    uint32_t flowCount;

    uint32_t input;   // 0xffff'ffff'0000'0000
    uint32_t output;  // 0x0000'0000'ffff'ffff

    uint32_t srcas;  // 0xffff'ffff'0000'0000
    uint32_t dstas;  // 0x0000'0000'ffff'ffff

    // IP address block
    union {
        struct _ipv4_s {
#ifdef WORDS_BIGENDIAN
            uint32_t fill1[3];  // <empty>		0xffff'ffff'ffff'ffff
                                // <empty>		0xffff'ffff'0000'0000
            uint32_t srcaddr;   // srcaddr      0x0000'0000'ffff'ffff
            uint32_t fill2[3];  // <empty>		0xffff'ffff'ffff'ffff
                                // <empty>		0xffff'ffff'0000'0000
            uint32_t dstaddr;   // dstaddr      0x0000'0000'ffff'ffff
#else
            uint32_t fill1[2];  // <empty>		0xffff'ffff'ffff'ffff
            uint32_t srcaddr;   // srcaddr      0xffff'ffff'0000'0000
            uint32_t fill2;     // <empty>		0x0000'0000'ffff'ffff
            uint32_t fill3[2];  // <empty>		0xffff'ffff'ffff'ffff
            uint32_t dstaddr;   // dstaddr      0xffff'ffff'0000'0000
            uint32_t fill4;     // <empty>		0xffff'ffff'0000'0000
#endif
        } _v4;
        struct _ipv6_s {
            uint64_t srcaddr[2];  // srcaddr[0-1] 0xffff'ffff'ffff'ffff
                                  // srcaddr[2-3] 0xffff'ffff'ffff'ffff
            uint64_t dstaddr[2];  // dstaddr[0-1] 0xffff'ffff'ffff'ffff
                                  // dstaddr[2-3] 0xffff'ffff'ffff'ffff
        } _v6;
        struct _ip64_s {
            uint64_t addr[4];
        } _ip_64;
    } ip_addr;

    char src_geo[4];
    char dst_geo[4];

    ip_addr_t ip_nexthop;  // ipv4 0x0000'0000'ffff'ffff
                           // ipv6	0xffff'ffff'ffff'ffff
                           // ipv6	0xffff'ffff'ffff'ffff

    ip_addr_t bgp_nexthop;  // ipv4 0x0000'0000'ffff'ffff
                            // ipv6 0xffff'ffff'ffff'ffff
                            // ipv6	0xffff'ffff'ffff'ffff

    union {
        struct {
            uint8_t dst_tos;   // 0xff00'0000'0000'0000
            uint8_t dir;       // 0x00ff'0000'0000'0000
            uint8_t src_mask;  // 0x0000'ff00'0000'0000
            uint8_t dst_mask;  // 0x0000'00ff'0000'0000
        };
        uint32_t any;
    };

    // extension 13
    uint16_t src_vlan;  // 0x0000'0000'ffff'0000
    uint16_t dst_vlan;  // 0x0000'0000'0000'ffff

    uint64_t out_pkts;    // 0xffff'ffff'ffff'ffff
    uint64_t out_bytes;   // 0xffff'ffff'ffff'ffff
    uint64_t aggr_flows;  // 0xffff'ffff'ffff'ffff

    uint64_t in_src_mac;   // 0xffff'ffff'ffff'ffff
    uint64_t out_dst_mac;  // 0xffff'ffff'ffff'ffff
    uint64_t in_dst_mac;   // 0xffff'ffff'ffff'ffff
    uint64_t out_src_mac;  // 0xffff'ffff'ffff'ffff
    uint32_t mpls_label[10];
    uint16_t etherType;
    uint16_t etherfill[3];

    ip_addr_t ip_router;  // ipv4 0x0000'0000'ffff'ffff
                          // ipv6	0xffff'ffff'ffff'ffff
                          // ipv6	0xffff'ffff'ffff'ffff

    // BGP next/prev AS
    uint32_t bgpNextAdjacentAS;  // 0xffff'ffff'0000'0000
    uint32_t bgpPrevAdjacentAS;  // 0x0000'0000'ffff'ffff

    // latency extension
    uint64_t client_nw_delay_usec;  // index LATENCY_BASE_OFFSET 0xffff'ffff'ffff'ffff
    uint64_t server_nw_delay_usec;  // index LATENCY_BASE_OFFSET + 1 0xffff'ffff'ffff'ffff
    uint64_t appl_latency_usec;     // index LATENCY_BASE_OFFSET + 2 0xffff'ffff'ffff'ffff

    ip_addr_t tun_src_ip;  // ipv4  OffsetTUNSRCIP +1	0x0000'0000'ffff'ffff
                           // ipv6	 OffsetTUNSRCIP		0xffff'ffff'ffff'ffff
                           // ipv6	 OffsetTUNSRCIP		0xffff'ffff'ffff'ffff

    ip_addr_t tun_dst_ip;  // ipv4  OffsetTUNDSTIP +1	0x0000'0000'ffff'ffff
                           // ipv6	 OffsetTUNDSTIP		0xffff'ffff'ffff'ffff
                           // ipv6	 OffsetTUNDSTIP		0xffff'ffff'ffff'ffff

    uint32_t tun_ip_version;
    uint32_t tun_proto;

// NSEL extensions
#ifdef NSEL
    // common block
    uint32_t connID;  // index OffsetConnID    0xffff'ffff'0000'0000
    uint8_t event;    // index OffsetConnID    0x0000'0000'ff00'0000
#define FW_EVENT 1
#define NAT_EVENT 2
    uint8_t event_flag;  // index OffsetConnID    0x0000'0000'00ff'0000
    uint16_t fwXevent;   // index OffsetConnID    0x0000'0000'0000'ffff
    uint64_t msecEvent;  // index OffsetConnID +1 0x1111'1111'1111'1111

    // xlate ip/port
    uint16_t xlate_src_port;  // index OffsetXLATEPort 0xffff'0000'0000'0000
    uint16_t xlate_dst_port;  // index OffsetXLATEPort 0x0000'ffff'0000'0000
    uint32_t xlate_flags;
    ip_addr_t xlate_src_ip;  // ipv4  OffsetXLATESRCIP +1 0x0000'0000'ffff'ffff
                             // ipv6	 OffsetXLATESRCIP 	 0xffff'ffff'ffff'ffff
                             // ipv6	 OffsetXLATESRCIP	 0xffff'ffff'ffff'ffff

    ip_addr_t xlate_dst_ip;  // ipv4  OffsetXLATEDSTIP +1 0x0000'0000'ffff'ffff
                             // ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff
                             // ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff

    // ingress/egress ACL id
    uint32_t ingressAcl[3];  // index OffsetIngressAclId   0xffff'ffff'0000'0000
                             // index OffsetIngressAceId   0x0000'0000'ffff'ffff
                             // index OffsetIngressGrpId   0xffff'ffff'0000'0000
    uint32_t egressAcl[3];   // index OffsetEgressAclId	  0x0000'0000'ffff'ffff
                             // index OffsetEgressAceId	  0xffff'ffff'0000'0000
                             // index OffsetEgressGrpId	  0x0000'0000'ffff'ffff
                             // username
    char username[72];

    // NAT extensions
    // NAT event is mapped into ASA event
    // common block
    // Port block allocation
    uint16_t block_start;  // OffsetPortBlock 0xffff'0000'0000'0000
    uint16_t block_end;    // OffsetPortBlock 0x0000'ffff'0000'0000
    uint16_t block_step;   // OffsetPortBlock 0x0000'0000'ffff'0000
    uint16_t block_size;   // OffsetPortBlock 0x0000'0000'0000'ffff

#endif

    // ingress/egress
    uint32_t ingressVrf;  // OffsetIVRFID	   0xffff'ffff'0000'0000
    uint32_t egressVrf;   // OffsetEVRFID	   0x0000'0000'ffff'ffff

    uint64_t observationPointID;
    uint32_t observationDomainID;
    uint32_t align;

    // nbar AppID
    uint8_t nbarAppIDlen;
#define MAX_NBAR_LENGTH 7
    uint8_t nbarAppID[MAX_NBAR_LENGTH];

    // ja3 from payload
    uint8_t ja3[16];

    // pflog
    uint8_t pfAction;
    uint8_t pfReason;
    uint8_t pfDir;
    uint8_t pfRewritten;
    uint32_t pfRulenr;
    char pfIfName[16];

    // payload data
    uint32_t inPayloadLength;
    uint32_t outPayloadLength;

    char *inPayload;
    char *outPayload;

    // last entry in master record
    char *label;

    // list of all extensions in raw record
    uint16_t exElementList[MAXEXTENSIONS];

    // reference to exporter
    exporter_info_record_t *exp_ref;
} master_record_t;

#endif  //_NFDUMP_H
