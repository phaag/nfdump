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

#ifndef _NFXV3_H
#define _NFXV3_H 1

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define TYPE_IDENT 0x8001
#define TYPE_STAT 0x8002

#ifndef IDENTLEN
#define IDENTLEN 128
#endif
#ifndef IDENTNONE
#define IDENTNONE "none"
#endif

/*
 * Generic data record
 * Contains any type of data, specified by type
 */
typedef struct recordHeader_s {
    // record header
    uint16_t type;  // type of data
    uint16_t size;  // size of record including this header
} recordHeader_t;

/*
 * Extension element header
 */
typedef struct elementHeader_s {
    uint16_t type;
    uint16_t length;
} elementHeader_t;

/*
 * V3 data record
 * ==============
 *
 */
typedef struct recordHeaderV3_s {
    // record header
    uint16_t type;
    uint16_t size;
    uint16_t numElements;
    uint8_t engineType;
    uint8_t engineID;
    uint16_t exporterID;
    uint8_t flags;
#define V3_FLAG_EVENT 1
#define V3_FLAG_SAMPLED 2
#define V3_FLAG_ANON 4
#define V3_FLAG_PASSED 128

    uint8_t nfversion;
} recordHeaderV3_t;

typedef struct EX3genericFlow_s {
#define EX3genericFlowID 1
    uint64_t msecFirst;
    uint64_t msecLast;
    uint64_t msecReceived;
    uint64_t inPackets;
    uint64_t inBytes;
    uint16_t srcPort;
#ifdef GOLANG
    uint16_t dstPort;
#else
    union {
        uint16_t dstPort;
        struct {
#ifdef WORDS_BIGENDIAN
            uint8_t icmpType;
            uint8_t icmpCode;
#else
            uint8_t icmpCode;
            uint8_t icmpType;
#endif
        };
    };
#endif
    uint8_t proto;
    uint8_t tcpFlags;
    uint8_t fwdStatus;
    uint8_t srcTos;
} EX3genericFlow_t;

typedef struct EX3ipv4Flow_s {
#define EX3ipv4FlowID 2
    uint32_t srcAddr;
    uint32_t dstAddr;
} EX3ipv4Flow_t;

typedef struct EX3ipv6Flow_s {
#define EX3ipv6FlowID 3
    uint64_t srcAddr[2];
    uint64_t dstAddr[2];
} EX3ipv6Flow_t;

typedef struct EX3flowMisc_s {
#define EX3flowMiscID 4
    uint32_t input;
    uint32_t output;
    uint8_t srcMask;
    uint8_t dstMask;
    uint8_t dir;
    uint8_t dstTos;
    uint8_t biFlowDir;
    uint8_t flowEndReason;
    uint16_t align;
} EX3flowMisc_t;

typedef struct EX3cntFlow_s {
#define EX3cntFlowID 5
    uint64_t flows;
    uint64_t outPackets;
    uint64_t outBytes;
} EX3cntFlow_t;

typedef struct EX3vLan_s {
#define EX3vLanID 6
    uint32_t srcVlan;
    uint32_t dstVlan;
} EX3vLan_t;

typedef struct EX3asRouting_s {
#define EX3asRoutingID 7
    uint32_t srcAS;
    uint32_t dstAS;
} EX3asRouting_t;

typedef struct EX3bgpNextHopV4_s {
#define EX3bgpNextHopV4ID 8
    uint32_t ip;
} EX3bgpNextHopV4_t;

typedef struct EX3bgpNextHopV6_s {
#define EX3bgpNextHopV6ID 9
    uint64_t ip[2];
} EX3bgpNextHopV6_t;

typedef struct EX3ipNextHopV4_s {
#define EX3ipNextHopV4ID 10
    uint32_t ip;
} EX3ipNextHopV4_t;

typedef struct EX3ipNextHopV6_s {
#define EX3ipNextHopV6ID 11
    uint64_t ip[2];
} EX3ipNextHopV6_t;

typedef struct EX3ipReceivedV4_s {
#define EX3ipReceivedV4ID 12
    uint32_t ip;
} EX3ipReceivedV4_t;

typedef struct EX3ipReceivedV6_s {
#define EX3ipReceivedV6ID 13
    uint64_t ip[2];
} EX3ipReceivedV6_t;

typedef struct EX3mplsLabel_s {
#define EX3mplsLabelID 14
    uint32_t mplsLabel[10];
} EX3mplsLabel_t;

typedef struct EX3macAddr_s {
#define EX3macAddrID 15
    uint64_t inSrcMac;
    uint64_t outDstMac;
    uint64_t inDstMac;
    uint64_t outSrcMac;
} EX3macAddr_t;

typedef struct EX3asAdjacent_s {
#define EX3asAdjacentID 16
    uint32_t nextAdjacentAS;  // NF_F_BGP_ADJ_NEXT_AS(128)
    uint32_t prevAdjacentAS;  // NF_F_BGP_ADJ_PREV_AS(129)
} EX3asAdjacent_t;

typedef struct EX3latency_s {
#define EX3latencyID 17
    uint64_t usecClientNwDelay;  // NF_NPROBE_CLIENT_NW_DELAY_SEC(57554) + NF_NPROBE_CLIENT_NW_DELAY_USEC(57555)
    uint64_t usecServerNwDelay;  // NF_NPROBE_SERVER_NW_DELAY_SEC(57556) + NF_NPROBE_SERVER_NW_DELAY_USEC(57557)
    uint64_t usecApplLatency;    // NF_NPROBE_APPL_LATENCY_SEC(57558) + NF_NPROBE_APPL_LATENCY_USEC(57559)
} EX3latency_t;

typedef struct EX3samplerInfo_s {
#define EX3samplerInfoID 18
    uint64_t selectorID;      // #302 id assigned by the exporting device
    uint16_t exporter_sysid;  // internal reference to exporter
    uint16_t align;
} EX3samplerInfo_t;

typedef struct EX3nselCommon_s {
#define EX3nselCommonID 19
    uint64_t msecEvent;  // NF_F_EVENT_TIME_MSEC(323)
    uint32_t connID;     // NF_F_CONN_ID(148)
    uint16_t fwXevent;   // NF_F_FW_EXT_EVENT(33002)
    uint8_t fwEvent;     // NF_F_FW_EVENT(233), NF_F_FW_EVENT_84(40005)
    uint8_t fill;
} EX3nselCommon_t;

typedef struct EX3natXlateIPv4_s {
#define EX3natXlateIPv4ID 20
    uint32_t xlateSrcAddr;  // NF_F_XLATE_SRC_ADDR_IPV4(225), NF_F_XLATE_SRC_ADDR_84(40001)
    uint32_t xlateDstAddr;  // NF_F_XLATE_DST_ADDR_IPV4(226), NF_F_XLATE_DST_ADDR_84(40002)
} EX3natXlateIPv4_t;

typedef struct EX3natXlateIPv6_s {
#define EX3natXlateIPv6ID 21
    uint64_t xlateSrcAddr[2];  // NF_F_XLATE_SRC_ADDR_IPV6(281),
    uint64_t xlateDstAddr[2];  // NF_F_XLATE_DST_ADDR_IPV6(282),
} EX3natXlateIPv6_t;

typedef struct EX3natXlatePort_s {
#define EX3natXlatePortID 22
    uint16_t xlateSrcPort;  // NF_F_XLATE_SRC_PORT(227), NF_F_XLATE_SRC_PORT_84(40003)
    uint16_t xlateDstPort;  //  NF_F_XLATE_DST_PORT(228), NF_F_XLATE_DST_PORT_84(40004)
} EX3natXlatePort_t;

typedef struct EX3nselAcl_s {
#define EX3nselAclID 23
    uint32_t ingressAcl[3];  // NF_F_INGRESS_ACL_ID(33000)
    uint32_t egressAcl[3];   // NF_F_EGRESS_ACL_ID(33001)
} EX3nselAcl_t;

typedef struct EX3nselUser_s {
#define EX3nselUserID 24
    char username[66];  // NF_F_USERNAME(40000),
    uint16_t fill2;
} EX3nselUser_t;

// NAT event logging
typedef struct EX3natCommon_s {
#define EX3natCommonID 25
    uint64_t msecEvent;  // NF_F_EVENT_TIME_MSEC(323)
    uint32_t natPoolID;  // NF_N_NATPOOL_ID(283)
    uint8_t natEvent;    // NAT_EVENT(230)
    uint8_t fill1;
    uint16_t fill2;
} EX3natCommon_t;

typedef struct EX3natPortBlock_s {
#define EX3natPortBlockID 26
    uint16_t blockStart;  // NF_F_XLATE_PORT_BLOCK_START(361)
    uint16_t blockEnd;    // NF_F_XLATE_PORT_BLOCK_END(362)
    uint16_t blockStep;   // NF_F_XLATE_PORT_BLOCK_STEP(363)
    uint16_t blockSize;   // NF_F_XLATE_PORT_BLOCK_SIZE(364)
} EX3natPortBlock_t;

typedef struct EX3nbarApp_s {
#define EX3nbarAppID 27
    uint8_t id[4];
} EX3nbarApp_t;

#define EX3inPayload_t void
#define EX3inPayloadID 29
#define EX3inPayloadSize sizeof(elementHeader_t)

#define EX3outPayload_t void
#define EX3outPayloadID 30
#define EX3outPayloadSize sizeof(elementHeader_t)

typedef struct EX3tunIPv4_s {
#define EX3tunIPv4ID 31
    uint32_t tunSrcAddr;
    uint32_t tunDstAddr;
    uint32_t tunProto;
} EX3tunIPv4_t;

typedef struct EX3tunIPv6_s {
#define EX3tunIPv6ID 32
    uint64_t tunSrcAddr[2];
    uint64_t tunDstAddr[2];
    uint32_t tunProto;
} EX3tunIPv6_t;

typedef struct EX3observation_s {
#define EX3observationID 33
    uint64_t pointID;
    uint32_t domainID;
} EX3observation_t;

typedef struct EX3inmonMeta_s {
#define EX3inmonMetaID 34
    uint16_t frameSize;
    uint16_t linkType;
} EX3inmonMeta_t;

typedef struct EX3inmonFrame_s {
#define EX3inmonFrameID 35
    uint8_t packet[4];
} EX3inmonFrame_t;

typedef struct EX3vrf_s {
#define EX3vrfID 36
    uint32_t egressVrf;   // EGRESS_VRFID(235)
    uint32_t ingressVrf;  // INGRESS_VRFID(234)
} EX3vrf_t;

typedef struct EX3pfinfo_s {
#define EX3pfinfoID 37
    uint8_t action;
    uint8_t reason;
    uint8_t dir;
    uint8_t rewritten;
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    char ifname[4];
} EX3pfinfo_t;

typedef struct EX3layer2_s {
#define EX3layer2ID 38
    uint16_t vlanID;
    uint16_t customerVlanId;
    uint16_t postVlanID;
    uint16_t postCustomerVlanId;
    uint32_t ingress;
    uint32_t egress;
    uint64_t vxLan;
    uint16_t etherType;
    uint8_t ipVersion;
    uint8_t fill[5];
} EX3layer2_t;

typedef struct EX3flowId_s {
#define EX3flowIdID 39
    uint64_t flowId;  // IPFIX_flowId
} EX3flowId_t;

typedef struct EX3nokiaNat_s {
#define EX3nokiaNatID 40
    uint16_t inServiceID;
    uint16_t outServiceID;
} EX3nokiaNat_t;

typedef struct EX3nokiaNatString_s {
#define EX3nokiaNatStringID 41
    char natSubString[4];
} EX3nokiaNatString_t;

#define EX3ipInfoID 42
typedef struct EX3ipInfo_s {
    uint8_t fill;
#ifndef flagMF
#define flagMF 0x20
#endif
#ifndef flagDF
#define flagDF 0x40
#endif
    uint8_t fragmentFlags;
    uint8_t minTTL;  // unused for nfpcapd
    uint8_t maxTTL;  // unused for nfpcapd
} EX3ipInfo_t;

// max possible V3 elements
#define MAXV3EXTENSIONS 43

int VerifyV3Record(recordHeaderV3_t *recordHeader);

#endif