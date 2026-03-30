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

#ifndef _NFXV4_H
#define _NFXV4_H 1

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ip128.h"

#define ALIGN8(x) (((x) + 7U) & ~7U)

#define MemberSize(type, member) sizeof(((type *)0)->member)

enum {
    EXnull = 0,
    EXgenericFlowID,
    EXipv4FlowID,
    EXipv6FlowID,
    EXinterfaceID,
    EXflowMiscID,
    EXcntFlowID,
    EXvLanID,
    EXasInfoID,
    EXasRoutingV4ID,
    EXasRoutingV6ID,
    EXipReceivedV4ID,
    EXipReceivedV6ID,
    EXmplsID,
    EXinMacAddrID,
    EXoutMacAddrID,
    EXasAdjacentID,
    EXlatencyID,
    EXnatXlateV4ID,
    EXnatXlateV6ID,
    EXnatXlatePortID,
    EXnselCommonID,
    EXnselAclID,
    EXnselUserID,
    EXnatPortBlockID,
    EXnbarAppID,
    EXinPayloadID,
    EXoutPayloadID,
    EXtunnelID,
    EXobservationID,
    EXinmonMetaID,
    EXinmonFrameID,
    EXvrfID,
    EXpfinfoID,
    EXlayer2ID,
    EXflowIdID,
    EXnokiaNatID,
    EXnokiaNatStringID,
    EXipInfoID,
    MAXEXTENSIONS  // max possible elements
};

/*
 * A v4 flow record consists of a V4Record header, followed by the extension directory
 * followed by the extensions. All parts of a record must be 8byte aligned.
 *
 * [RecordHeader] - [recordHeaderV4_t]
 *             |-> bitfield for extensions
 * The offset table order must follow the bitmap rank order
 * [Offset Table] - [off ext1][off ext2]..[off extN] - follows bitfield order
 * The extension data may not follow in any order, based on offsets
 * [extData]      - [extDataX][extDataY]..[extDataN] - maybe in any order
 *
 * The extension directory is a list of numextensions of extEntry_t which identifies
 * type, length and offset relative to start of recordHeaderV4_t
 */

typedef struct recordHeaderV4_s {
    // V4Record
    uint16_t type;           // record type - V4Record
    uint16_t size;           // of of the record including ext. entry and all extensions
    uint16_t numExtensions;  // number of extensions in this record
    uint16_t flags;          // record flags
#define V4_FLAG_EVENT 0x01
#define V4_FLAG_SAMPLED 0x02
#define V4_FLAG_ANON 0x04
#define V4_FLAG_PASSED 0x80

    uint32_t exporterID;  // nfdump assigned 32bit ID
#define OFFexporterID offsetof(recordHeaderV4_t, exporterID)
#define SIZEexporterID MemberSize(recordHeaderV4_t, exporterID)

    uint8_t engineType;  // exporter type
    uint8_t engineID;    // exporter ID
#define OFFengineType offsetof(recordHeaderV4_t, engineType)
#define SIZEengineType MemberSize(recordHeaderV4_t, engineType)
#define OFFengineID offsetof(recordHeaderV4_t, engineID)
#define SIZEengineID MemberSize(recordHeaderV4_t, engineID)

    uint8_t nfVersion;  // netflow version 1,5,7,9,10, 0x80 sflow, 0x40 nfpcad
    uint8_t fill;
    uint64_t extBitmap;  // extension bitmap field
} recordHeaderV4_t;
#define V4HeaderRecordSize sizeof(recordHeaderV4_t)
_Static_assert((sizeof(recordHeaderV4_t) & 7) == 0, "recordHeaderV4 for 8 byte aligned");

/*
 * Extension elements
 */

#define VARLENGTH 0xFFFF

typedef struct EXgenericFlow_s {
    uint64_t msecFirst;
    uint64_t msecLast;
#define OFFmsecFirst offsetof(EXgenericFlow_t, msecFirst)
#define SIZEmsecFirst MemberSize(EXgenericFlow_t, msecFirst)
#define OFFmsecLast offsetof(EXgenericFlow_t, msecLast)
#define SIZEmsecLast MemberSize(EXgenericFlow_t, msecLast)
    uint64_t msecReceived;
#define OFFmsecReceived offsetof(EXgenericFlow_t, msecReceived)
#define SIZEmsecReceived MemberSize(EXgenericFlow_t, msecReceived)
    uint64_t inPackets;
    uint64_t inBytes;
#define OFFinPackets offsetof(EXgenericFlow_t, inPackets)
#define SIZEinPackets MemberSize(EXgenericFlow_t, inPackets)
#define OFFinBytes offsetof(EXgenericFlow_t, inBytes)
#define SIZEinBytes MemberSize(EXgenericFlow_t, inBytes)
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
#define OFFsrcPort offsetof(EXgenericFlow_t, srcPort)
#define SIZEsrcPort MemberSize(EXgenericFlow_t, srcPort)
#define OFFdstPort offsetof(EXgenericFlow_t, dstPort)
#define SIZEdstPort MemberSize(EXgenericFlow_t, dstPort)
#define OFFicmpCode offsetof(EXgenericFlow_t, icmpCode)
#define SIZEicmpCode MemberSize(EXgenericFlow_t, icmpCode)
#define OFFicmpType offsetof(EXgenericFlow_t, icmpType)
#define SIZEicmpType MemberSize(EXgenericFlow_t, icmpType)
    uint8_t proto;
#define OFFproto offsetof(EXgenericFlow_t, proto)
#define SIZEproto MemberSize(EXgenericFlow_t, proto)
    uint8_t tcpFlags;
#define OFFtcpFlags offsetof(EXgenericFlow_t, tcpFlags)
#define SIZEtcpFlags MemberSize(EXgenericFlow_t, tcpFlags)
    uint8_t fwdStatus;
#define OFFfwdStatus offsetof(EXgenericFlow_t, fwdStatus)
#define SIZEfwdStatus MemberSize(EXgenericFlow_t, fwdStatus)
    uint8_t srcTos;
#define OFFsrcTos offsetof(EXgenericFlow_t, srcTos)
#define SIZEsrcTos MemberSize(EXgenericFlow_t, srcTos)
} EXgenericFlow_t;
#define EXgenericFlowSize sizeof(EXgenericFlow_t)

typedef struct EXipv4Flow_s {
    uint32_t srcAddr;
    uint32_t dstAddr;
#define OFFsrc4Addr offsetof(EXipv4Flow_t, srcAddr)
#define SIZEsrc4Addr MemberSize(EXipv4Flow_t, srcAddr)
#define OFFdst4Addr offsetof(EXipv4Flow_t, dstAddr)
#define SIZEdst4Addr MemberSize(EXipv4Flow_t, dstAddr)
} EXipv4Flow_t;
#define EXipv4FlowSize sizeof(EXipv4Flow_t)
_Static_assert((sizeof(EXipv4Flow_t) & 7) == 0, "alignment");

typedef struct EXipv6Flow_s {
    uint64_t srcAddr[2];
    uint64_t dstAddr[2];
#define OFFsrc6Addr offsetof(EXipv6Flow_t, srcAddr)
#define SIZEsrc6Addr MemberSize(EXipv6Flow_t, srcAddr)
#define OFFdst6Addr offsetof(EXipv6Flow_t, dstAddr)
#define SIZEdst6Addr MemberSize(EXipv6Flow_t, dstAddr)
} EXipv6Flow_t;
#define EXipv6FlowSize sizeof(EXipv6Flow_t)

typedef struct EXinterface_s {
    uint32_t input;
    uint32_t output;
#define OFFinput offsetof(EXinterface_t, input)
#define SIZEinput MemberSize(EXinterface_t, input)
#define OFFoutput offsetof(EXinterface_t, output)
#define SIZEoutput MemberSize(EXinterface_t, output)
} EXinterface_t;
#define EXinterfaceSize sizeof(EXinterface_t)

typedef struct EXflowMisc_s {
    uint8_t srcMask;
    uint8_t dstMask;
#define OFFsrcMask offsetof(EXflowMisc_t, srcMask)
#define SIZEsrcMask MemberSize(EXflowMisc_t, srcMask)
#define OFFdstMask offsetof(EXflowMisc_t, dstMask)
#define SIZEdstMask MemberSize(EXflowMisc_t, dstMask)

    uint8_t direction;
#define OFFdir offsetof(EXflowMisc_t, direction)
#define SIZEdir MemberSize(EXflowMisc_t, direction)

    uint8_t biFlowDir;
#define OFFbiFlowDir offsetof(EXflowMisc_t, biFlowDir)
#define SIZEbiFlowDir MemberSize(EXflowMisc_t, biFlowDir)

    uint8_t dstTos;
#define OFFdstTos offsetof(EXflowMisc_t, dstTos)
#define SIZEdstTos MemberSize(EXflowMisc_t, dstTos)

    uint8_t flowEndReason;
#define OFFflowEndReason offsetof(EXflowMisc_t, flowEndReason)
#define SIZEflowEndReason MemberSize(EXflowMisc_t, flowEndReason)

    uint16_t align;
} EXflowMisc_t;
#define EXflowMiscSize sizeof(EXflowMisc_t)

typedef struct EXcntFlow_s {
    uint64_t flows;
#define OFFflows offsetof(EXcntFlow_t, flows)
#define SIZEflows MemberSize(EXcntFlow_t, flows)
    uint64_t outPackets;
    uint64_t outBytes;
#define OFFoutPackets offsetof(EXcntFlow_t, outPackets)
#define SIZEoutPackets MemberSize(EXcntFlow_t, outPackets)
#define OFFoutBytes offsetof(EXcntFlow_t, outBytes)
#define SIZEoutBytes MemberSize(EXcntFlow_t, outBytes)
} EXcntFlow_t;
#define EXcntFlowSize sizeof(EXcntFlow_t)

typedef struct EXvLan_s {
    uint32_t srcVlan;
    uint32_t dstVlan;
#define OFFsrcVlan offsetof(EXvLan_t, srcVlan)
#define SIZEsrcVlan MemberSize(EXvLan_t, srcVlan)
#define OFFdstVlan offsetof(EXvLan_t, dstVlan)
#define SIZEdstVlan MemberSize(EXvLan_t, dstVlan)
} EXvLan_t;
#define EXvLanSize sizeof(EXvLan_t)

typedef struct EXasInfo_s {
    uint32_t srcAS;
    uint32_t dstAS;
#define OFFsrcAS offsetof(EXasInfo_t, srcAS)
#define SIZEsrcAS MemberSize(EXasInfo_t, srcAS)
#define OFFdstAS offsetof(EXasInfo_t, dstAS)
#define SIZEdstAS MemberSize(EXasInfo_t, dstAS)
} EXasInfo_t;
#define EXasInfoSize sizeof(EXasInfo_t)

typedef struct EXasRoutingV4_s {
    uint32_t nextHop;
    uint32_t bgpNextHop;
#define OFFnextHopIPV4 offsetof(EXasRoutingV4_t, nextHop)
#define SIZEnextHopIPV4 MemberSize(EXasRoutingV4_t, nextHop)
#define OFFbgpNextHopV4 offsetof(EXasRoutingV4_t, bgpNextHop)
#define SIZEbgpNextHopV4 MemberSize(EXasRoutingV4_t, bgpNextHop)
} EXasRoutingV4_t;
#define EXasRoutingV4Size sizeof(EXasRoutingV4_t)

typedef struct EXasRoutingV6_s {
    uint64_t nextHop[2];
    uint64_t bgpNextHop[2];
#define OFFnextHopIPV6 offsetof(EXasRoutingV6_t, nextHop)
#define SIZEnextHopIPV6 MemberSize(EXasRoutingV6_t, nextHop)
#define OFFbgpNextHopV6 offsetof(EXasRoutingV6_t, bgpNextHop)
#define SIZEbgpNextHopV6 MemberSize(EXasRoutingV6_t, bgpNextHop)
} EXasRoutingV6_t;
#define EXasRoutingV6Size sizeof(EXasRoutingV6_t)

typedef struct EXipReceivedV4_s {
    uint32_t ip;
    uint32_t align;
#define OFFReceived4IP offsetof(EXipReceivedV4_t, ip)
#define SIZEReceived4IP MemberSize(EXipReceivedV4_t, ip)
} EXipReceivedV4_t;
#define EXipReceivedV4Size sizeof(EXipReceivedV4_t)

typedef struct EXipReceivedV6_s {
    uint64_t ip[2];
#define OFFReceived6IP offsetof(EXipReceivedV6_t, ip)
#define SIZEReceived6IP MemberSize(EXipReceivedV6_t, ip)
} EXipReceivedV6_t;
#define EXipReceivedV6Size sizeof(EXipReceivedV6_t)

typedef struct EXmpls_s {
    uint32_t label[10];
#define OFFmplsLabel1 offsetof(EXmpls_t, label[0])
#define SIZEmplsLabel1 MemberSize(EXmpls_t, label[0])
#define OFFmplsLabel2 offsetof(EXmpls_t, label[1])
#define SIZEmplsLabel2 MemberSize(EXmpls_t, label[1])
#define OFFmplsLabel3 offsetof(EXmpls_t, label[2])
#define SIZEmplsLabel3 MemberSize(EXmpls_t, label[2])
#define OFFmplsLabel4 offsetof(EXmpls_t, label[3])
#define SIZEmplsLabel4 MemberSize(EXmpls_t, label[3])
#define OFFmplsLabel5 offsetof(EXmpls_t, label[4])
#define SIZEmplsLabel5 MemberSize(EXmpls_t, label[4])
#define OFFmplsLabel6 offsetof(EXmpls_t, label[5])
#define SIZEmplsLabel6 MemberSize(EXmpls_t, label[5])
#define OFFmplsLabel7 offsetof(EXmpls_t, label[6])
#define SIZEmplsLabel7 MemberSize(EXmpls_t, label[6])
#define OFFmplsLabel8 offsetof(EXmpls_t, label[7])
#define SIZEmplsLabel8 MemberSize(EXmpls_t, label[7])
#define OFFmplsLabel9 offsetof(EXmpls_t, label[8])
#define SIZEmplsLabel9 MemberSize(EXmpls_t, label[8])
#define OFFmplsLabel10 offsetof(EXmpls_t, label[9])
#define SIZEmplsLabel10 MemberSize(EXmpls_t, label[9])
} EXmpls_t;
#define EXmplsSize sizeof(EXmpls_t)

typedef struct EXinMacAddr_s {
    uint64_t inSrcMac;
    uint64_t outDstMac;
#define OFFinSrcMac offsetof(EXinMacAddr_t, inSrcMac)
#define SIZEinSrcMac MemberSize(EXinMacAddr_t, inSrcMac)
#define OFFoutDstMac offsetof(EXinMacAddr_t, outDstMac)
#define SIZEoutDstMac MemberSize(EXinMacAddr_t, outDstMac)
} EXinMacAddr_t;
#define EXinMacAddrSize sizeof(EXinMacAddr_t)

typedef struct EXoutMacAddr_s {
    uint64_t inDstMac;
    uint64_t outSrcMac;
#define OFFinDstMac offsetof(EXoutMacAddr_t, inDstMac)
#define SIZEinDstMac MemberSize(EXoutMacAddr_t, inDstMac)
#define OFFoutSrcMac offsetof(EXoutMacAddr_t, outSrcMac)
#define SIZEoutSrcMac MemberSize(EXoutMacAddr_t, outSrcMac)
} EXoutMacAddr_t;
#define EXoutMacAddrSize sizeof(EXoutMacAddr_t)

typedef struct EXasAdjacent_s {
    uint32_t nextAdjacentAS;  // NF_F_BGP_ADJ_NEXT_AS(128)
    uint32_t prevAdjacentAS;  // NF_F_BGP_ADJ_PREV_AS(129)
#define OFFnextAdjacentAS offsetof(EXasAdjacent_t, nextAdjacentAS)
#define SIZEnextAdjacentAS MemberSize(EXasAdjacent_t, nextAdjacentAS)
#define OFFprevAdjacentAS offsetof(EXasAdjacent_t, prevAdjacentAS)
#define SIZEprevAdjacentAS MemberSize(EXasAdjacent_t, prevAdjacentAS)
} EXasAdjacent_t;
#define EXasAdjacentSize sizeof(EXasAdjacent_t)

// latency record, filled by nfpcapd
typedef struct EXlatency_s {
    uint64_t msecClientNwDelay;
    uint64_t msecServerNwDelay;
    uint64_t msecApplLatency;
#define OFFmsecClientNwDelay offsetof(EXlatency_t, msecClientNwDelay)
#define SIZEmsecClientNwDelay MemberSize(EXlatency_t, msecClientNwDelay)
#define OFFmsecServerNwDelay offsetof(EXlatency_t, msecServerNwDelay)
#define SIZEmsecServerNwDelay MemberSize(EXlatency_t, msecServerNwDelay)
#define OFFmsecApplLatency offsetof(EXlatency_t, msecApplLatency)
#define SIZEmsecApplLatency MemberSize(EXlatency_t, msecApplLatency)
} EXlatency_t;
#define EXlatencySize sizeof(EXlatency_t)

typedef struct EXnatXlateV4_s {
    uint32_t xlateSrcAddr;  // NF_F_XLATE_SRC_ADDR_IPV4(225)
                            // NF_F_XLATE_SRC_ADDR_84(40001)
    uint32_t xlateDstAddr;  // NF_F_XLATE_DST_ADDR_IPV4(226)
                            // NF_F_XLATE_DST_ADDR_84(40002)
#define OFFxlateSrcAddrV4 offsetof(EXnatXlateV4_t, xlateSrcAddr)
#define SIZExlateSrcAddrV4 MemberSize(EXnatXlateV4_t, xlateSrcAddr)
#define OFFxlateDstAddrV4 offsetof(EXnatXlateV4_t, xlateDstAddr)
#define SIZExlateDstAddrV4 MemberSize(EXnatXlateV4_t, xlateDstAddr)

} EXnatXlateV4_t;
#define EXnatXlateV4Size sizeof(EXnatXlateV4_t)

typedef struct EXnatXlateV6_s {
    uint64_t xlateSrcAddr[2];  // NF_F_XLATE_SRC_ADDR_IPV6(281)
    uint64_t xlateDstAddr[2];  // NF_F_XLATE_DST_ADDR_IPV6(282),
#define OFFxlateSrcAddrV6 offsetof(EXnatXlateV6_t, xlateSrcAddr)
#define SIZExlateSrcAddrV6 MemberSize(EXnatXlateV6_t, xlateSrcAddr)
#define OFFxlateDstAddrV6 offsetof(EXnatXlateV6_t, xlateDstAddr)
#define SIZExlateDstAddrV6 MemberSize(EXnatXlateV6_t, xlateDstAddr)

} EXnatXlateV6_t;
#define EXnatXlateV6Size sizeof(EXnatXlateV6_t)

typedef struct EXnatXlatePort_s {
    uint16_t xlateSrcPort;  // NF_F_XLATE_SRC_PORT(227), NF_F_XLATE_SRC_PORT_84(40003)
    uint16_t xlateDstPort;  // NF_F_XLATE_DST_PORT(228), NF_F_XLATE_DST_PORT_84(40004)
    uint32_t align;
#define OFFxlateSrcPort offsetof(EXnatXlatePort_t, xlateSrcPort)
#define SIZExlateSrcPort MemberSize(EXnatXlatePort_t, xlateSrcPort)
#define OFFxlateDstPort offsetof(EXnatXlatePort_t, xlateDstPort)
#define SIZExlateDstPort MemberSize(EXnatXlatePort_t, xlateDstPort)
} EXnatXlatePort_t;
#define EXnatXlatePortSize sizeof(EXnatXlatePort_t)

// NAT event logging
// NSEL ASA event logging
typedef struct EXnselCommon_s {
    uint64_t msecEvent;  // NF_F_EVENT_TIME_MSEC(323)
#define OFFmsecEvent offsetof(EXnselCommon_t, msecEvent)
#define SIZEmsecEvent MemberSize(EXnselCommon_t, msecEvent)

    uint32_t connID;    // NF_F_CONN_ID(148)
    uint16_t fwXevent;  // NF_F_FW_EXT_EVENT(33002)
    uint8_t fwEvent;    // NF_F_FW_EVENT(233), NF_F_FW_EVENT_84(40005)
#define OFFconnID offsetof(EXnselCommon_t, connID)
#define SIZEconnID MemberSize(EXnselCommon_t, connID)
#define OFFfwXevent offsetof(EXnselCommon_t, fwXevent)
#define SIZEfwXevent MemberSize(EXnselCommon_t, fwXevent)
#define OFFfwEvent offsetof(EXnselCommon_t, fwEvent)
#define SIZEfwEvent MemberSize(EXnselCommon_t, fwEvent)

    uint16_t type;  // NSEL event logging / NAT
#define NSEL_LOGGING 1
#define NSEL_NAT 2
    uint16_t natEvent;   // NAT_EVENT(230)
    uint32_t natPoolID;  // NF_N_NATPOOL_ID(283)
#define OFFnatEvent offsetof(EXnselCommon_t, natEvent)
#define SIZEnatEvent MemberSize(EXnselCommon_t, natEvent)
#define OFFnatPoolID offsetof(EXnselCommon_t, natPoolID)
#define SIZEnatPoolID MemberSize(EXnselCommon_t, natPoolID)

} EXnselCommon_t;
#define EXnselCommonSize sizeof(EXnselCommon_t)

typedef struct EXnselAcl_s {
    uint32_t ingressAcl[3];  // NF_F_INGRESS_ACL_ID(33000)
    uint32_t egressAcl[3];   // NF_F_EGRESS_ACL_ID(33001)
#define OFFingressAcl offsetof(EXnselAcl_t, ingressAcl)
#define SIZEingressAcl MemberSize(EXnselAcl_t, ingressAcl)
#define OFFegressAcl offsetof(EXnselAcl_t, egressAcl)
#define SIZEegressAcl MemberSize(EXnselAcl_t, egressAcl)
} EXnselAcl_t;
#define EXnselAclSize sizeof(EXnselAcl_t)

typedef struct EXnselUser_s {
    char username[72];  // NF_F_USERNAME(40000),
#define OFFusername offsetof(EXnselUser_t, username)
#define SIZEusername MemberSize(EXnselUser_t, username)
} EXnselUser_t;
#define EXnselUserSize sizeof(EXnselUser_t)

typedef struct EXnatPortBlock_s {
    uint16_t blockStart;  // NF_F_XLATE_PORT_BLOCK_START(361)
    uint16_t blockEnd;    // NF_F_XLATE_PORT_BLOCK_END(362)
    uint16_t blockStep;   // NF_F_XLATE_PORT_BLOCK_STEP(363)
    uint16_t blockSize;   // NF_F_XLATE_PORT_BLOCK_SIZE(364)
#define OFFnelblockStart offsetof(EXnatPortBlock_t, blockStart)
#define SIZEnelblockStart MemberSize(EXnatPortBlock_t, blockStart)
#define OFFnelblockEnd offsetof(EXnatPortBlock_t, blockEnd)
#define SIZEnelblockEnd MemberSize(EXnatPortBlock_t, blockEnd)
#define OFFnelblockStep offsetof(EXnatPortBlock_t, blockStep)
#define SIZEnelblockStep MemberSize(EXnatPortBlock_t, blockStep)
#define OFFnelblockSize offsetof(EXnatPortBlock_t, blockSize)
#define SIZEnelblockSize MemberSize(EXnatPortBlock_t, blockSize)
} EXnatPortBlock_t;
#define EXnatPortBlockSize sizeof(EXnatPortBlock_t)

typedef struct EXnbarApp_s {
    uint32_t length;
    uint8_t id[];
#define OFFnbarAppID offsetof(EXnbarApp_t, id)
#define SIZEnbarAppID VARLENGTH
} EXnbarApp_t;
#define EXnbarAppSize VARLENGTH

typedef struct EXifName_s {
    uint32_t length;
    char name[4];
#define OFFifName offsetof(EXifName_t, name)
#define SIZEifName VARLENGTH
} EXifName_t;
#define EXifNameSize VARLENGTH

typedef struct EXPayload_s {
    uint32_t size;
    uint8_t payload[];
} EXPayload_t;
typedef EXPayload_t EXinPayload_t;
typedef EXPayload_t EXoutPayload_t;
#define EXinPayloadSize VARLENGTH
#define EXoutPayloadSize VARLENGTH

// unified extension for IPv4/IPv6
// ::ffff:IPv4 or IPv6
typedef struct EXtunnel_s {
    uint8_t tunSrcAddr[16];
    uint8_t tunDstAddr[16];
    uint32_t tunProto;
    uint32_t align;
#define OFFtunSrcAddr offsetof(EXtunnel_t, tunSrcAddr)
#define SIZEtunSrcAddr MemberSize(EXtunnel_t, tunSrcAddr)
#define OFFtunDstAddr offsetof(EXtunnel_t, tunDstAddr)
#define SIZEtunDstAddr MemberSize(EXtunnel_t, tunDstAddr)
#define OFFtunProto offsetof(EXtunnel_t, tunProto)
#define SIZEtunProto MemberSize(EXtunnel_t, tunProto)
} EXtunnel_t;
#define EXtunnelSize sizeof(EXtunnel_t)

typedef struct EXobservation_s {
    uint64_t pointID;
    uint64_t domainID;
#define OFFpointID offsetof(EXobservation_t, pointID)
#define SIZEpointID MemberSize(EXobservation_t, pointID)
#define OFFdomainID offsetof(EXobservation_t, domainID)
#define SIZEdomainID MemberSize(EXobservation_t, domainID)
} EXobservation_t;
#define EXobservationSize sizeof(EXobservation_t)

typedef struct EXinmonMeta_s {
    uint16_t frameSize;
    uint16_t linkType;
#define OFFinmonFrameSize offsetof(EXinmonMeta_t, frameSize)
#define SIZEinmonFrameSize MemberSize(EXinmonMeta_t, frameSize)
#define OFFinmonLinkType offsetof(EXinmonMeta_t, linkType)
#define SIZEinmonLinkType MemberSize(EXinmonMeta_t, linkType)
    uint32_t align;
} EXinmonMeta_t;
#define EXinmonMetaSize sizeof(EXinmonMeta_t)

typedef struct EXinmonFrame_s {
    uint32_t length;
    uint8_t packet[4];
} EXinmonFrame_t;
#define EXinmonFrameSize VARLENGTH

typedef struct EXinmon_s {
    uint16_t frameSize;
    uint16_t linkType;
    uint32_t length;
    uint8_t packet[4];
} EXinmon_t;

typedef struct EXvrf_s {
    uint32_t egressVrf;   // EGRESS_VRFID(235)
    uint32_t ingressVrf;  // INGRESS_VRFID(234)
#define OFFegressVrf offsetof(EXvrf_t, egressVrf)
#define SIZEegressVrf MemberSize(EXvrf_t, egressVrf)
#define OFFingressVrf offsetof(EXvrf_t, ingressVrf)
#define SIZEingressVrf MemberSize(EXvrf_t, ingressVrf)
} EXvrf_t;
#define EXvrfSize sizeof(EXvrf_t)

typedef struct EXpfinfo_s {
    uint8_t action;
    uint8_t reason;
    uint8_t dir;
    uint8_t rewritten;
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    char ifname[4];
} EXpfinfo_t;
#define OFFpfAction offsetof(EXpfinfo_t, action)
#define SIZEpfAction MemberSize(EXpfinfo_t, action)
#define OFFpfReason offsetof(EXpfinfo_t, reason)
#define SIZEpfReason MemberSize(EXpfinfo_t, reason)
#define OFFpfDir offsetof(EXpfinfo_t, dir)
#define SIZEpfDir MemberSize(EXpfinfo_t, dir)
#define OFFpfIfName offsetof(EXpfinfo_t, ifname)
#define SIZEpfIfName MemberSize(EXpfinfo_t, ifname)
#define OFFpfRuleNr offsetof(EXpfinfo_t, rulenr)
#define SIZEpfRuleNr MemberSize(EXpfinfo_t, rulenr)
#define EXpfinfoSize sizeof(EXpfinfo_t)

typedef struct EXlayer2_s {
    uint16_t vlanID;
    uint16_t customerVlanId;
    uint16_t postVlanID;
    uint16_t postCustomerVlanId;
#define OFFvlanID offsetof(EXlayer2_t, vlanID)
#define SIZEvlanID MemberSize(EXlayer2_t, vlanID)
#define OFFpostVlanID offsetof(EXlayer2_t, postVlanID)
#define SIZEpostVlanID MemberSize(EXlayer2_t, postVlanID)
#define OFFcustomerVlanId offsetof(EXlayer2_t, customerVlanId)
#define SIZEcustomerVlanId MemberSize(EXlayer2_t, customerVlanId)
#define OFFpostCustomerVlanId offsetof(EXlayer2_t, postCustomerVlanId)
#define SIZEpostCustomerVlanId MemberSize(EXlayer2_t, postCustomerVlanId)
    uint32_t ingress;
    uint32_t egress;
#define OFFphysIngress offsetof(EXlayer2_t, ingress)
#define SIZEphysIngress MemberSize(EXlayer2_t, ingress)
#define OFFphysEgress offsetof(EXlayer2_t, egress)
#define SIZEphysEgress MemberSize(EXlayer2_t, egress)
    uint64_t vxLan;
    uint16_t etherType;
    uint8_t ipVersion;
#define OFFetherType offsetof(EXlayer2_t, etherType)
#define SIZEetherType MemberSize(EXlayer2_t, etherType)
#define OFFipVersion offsetof(EXlayer2_t, ipVersion)
#define SIZEipVersion MemberSize(EXlayer2_t, ipVersion)
    uint8_t fill[5];
} EXlayer2_t;
#define EXlayer2Size sizeof(EXlayer2_t)

typedef struct EXflowId_s {
    uint64_t flowId;  // IPFIX_flowId
#define OFFflowId offsetof(EXflowId_t, flowId)
#define SIZEflowId MemberSize(EXflowId_t, flowId)
} EXflowId_t;
#define EXflowIdSize sizeof(EXflowId_t)

typedef struct EXnokiaNat_s {
    uint16_t inServiceID;
    uint16_t outServiceID;
    uint32_t align;
#define OFFinServiceID offsetof(EXnokiaNat_t, inServiceID)
#define SIZEinServiceID MemberSize(EXnokiaNat_t, inServiceID)
#define OFFoutServiceID offsetof(EXnokiaNat_t, outServiceID)
#define SIZEoutServiceID MemberSize(EXnokiaNat_t, outServiceID)
} EXnokiaNat_t;
#define EXnokiaNatSize sizeof(EXnokiaNat_t)

typedef struct EXnokiaNatString_s {
    char natSubString[4];
#define OFFnatSubString offsetof(EXnokiaNatString_t, natSubString)
#define SIZEnatSubString VARLENGTH
} EXnokiaNatString_t;
#define EXnokiaNatStringSize sizeof(EXnokiaNatString_t)

typedef struct EXipInfo_s {
#define flagMF 0x20
#define flagDF 0x40
    uint8_t fragmentFlags;
#define OFFfragmentFlags offsetof(EXipInfo_t, fragmentFlags)
#define SIZEfragmentFlags MemberSize(EXipInfo_t, fragmentFlags)
    uint8_t minTTL;  // unused for nfpcapd
    uint8_t maxTTL;  // unused for nfpcapd
#define OFFminTTL offsetof(EXipInfo_t, minTTL)
#define SIZEminTTL MemberSize(EXipInfo_t, minTTL)
#define OFFmaxTTL offsetof(EXipInfo_t, maxTTL)
#define SIZEmaxTTL MemberSize(EXipInfo_t, maxTTL)
    uint8_t fill;
    uint32_t align;
} EXipInfo_t;
#define EXipInfoSize sizeof(EXipInfo_t)

#define BitMapSet(map, id) (map |= (1ULL << (id)))

#define AddV4Header(p)                                  \
    ({                                                  \
        recordHeaderV4_t *_h = (recordHeaderV4_t *)(p); \
        memset(_h, 0, sizeof(recordHeaderV4_t));        \
        _h->type = V4Record;                            \
        _h->size = sizeof(recordHeaderV4_t);            \
        _h->numExtensions = 0;                          \
        _h->extBitmap = 0;                              \
        _h;                                             \
    })

#define V4OffsetTable(h) ((uint16_t *)((uint8_t *)(h) + sizeof(recordHeaderV4_t)))

/*
 * h: v4 header
 * typeName: EX... (without _t)
 * varName:  predefined local variable name
 */
#define GetExtension(h, typeName)                                          \
    ({                                                                     \
        typeName##_t *_ret = NULL;                                         \
        uint64_t _bit = (1ULL << typeName##ID);                            \
                                                                           \
        if ((h)->extBitmap & _bit) {                                       \
            uint64_t _mask = _bit - 1;                                     \
            uint32_t _rank = __builtin_popcountll((h)->extBitmap & _mask); \
            uint16_t *_offsets = V4OffsetTable(h);                         \
            _ret = (typeName##_t *)((uint8_t *)(h) + _offsets[_rank]);     \
        }                                                                  \
                                                                           \
        _ret;                                                              \
    })

// macro assumes, that extBitmap in v4Header is alreay properly set
#define AddV4Extension(h, nextOffset, typeName)                                                 \
    ({                                                                                          \
        /* __builtin_popcountll = count all bits set in bitmap */                               \
        /* up to new extensio ##ID. => mask with bitmap */                                      \
        /* index into offset table */                                                           \
        uint32_t _slot = __builtin_popcountll((h)->extBitmap & ((1ULL << (typeName##ID)) - 1)); \
        uint16_t *_offsets = V4OffsetTable(h);                                                  \
        _offsets[_slot] = (nextOffset);                                                         \
                                                                                                \
        typeof(typeName##_t) *_ptr = (typeof(typeName##_t) *)((uint8_t *)(h) + (nextOffset));   \
        memset(_ptr, 0, sizeof(*_ptr));                                                         \
                                                                                                \
        (nextOffset) += sizeof(*_ptr);                                                          \
        (h)->size += sizeof(*_ptr);                                                             \
                                                                                                \
        _ptr;                                                                                   \
    })

// #define EXTENSION(s) {s##ID, s##Size, #s}
#define EXTENSION(s) [s##ID] = {s##ID, s##Size, #s}

static const struct extensionTable_s {
    uint32_t id;    // id number
    uint32_t size;  // number of bytes incl. header, 0xFFFF for dyn length
    char *name;     // name of extension
} extensionTable[] = {{0, 0, "EXnull"},          EXTENSION(EXgenericFlow),    EXTENSION(EXipv4Flow),    EXTENSION(EXipv6Flow),
                      EXTENSION(EXinterface),    EXTENSION(EXflowMisc),       EXTENSION(EXcntFlow),     EXTENSION(EXvLan),
                      EXTENSION(EXasInfo),       EXTENSION(EXasRoutingV4),    EXTENSION(EXasRoutingV6), EXTENSION(EXipReceivedV4),
                      EXTENSION(EXipReceivedV6), EXTENSION(EXmpls),           EXTENSION(EXinMacAddr),   EXTENSION(EXoutMacAddr),
                      EXTENSION(EXasAdjacent),   EXTENSION(EXlatency),        EXTENSION(EXnatXlateV4),  EXTENSION(EXnatXlateV6),
                      EXTENSION(EXnatXlatePort), EXTENSION(EXnselCommon),     EXTENSION(EXnselAcl),     EXTENSION(EXnselUser),
                      EXTENSION(EXnatPortBlock), EXTENSION(EXnbarApp),        EXTENSION(EXinPayload),   EXTENSION(EXoutPayload),
                      EXTENSION(EXtunnel),       EXTENSION(EXobservation),    EXTENSION(EXinmonMeta),   EXTENSION(EXinmonFrame),
                      EXTENSION(EXvrf),          EXTENSION(EXpfinfo),         EXTENSION(EXlayer2),      EXTENSION(EXflowId),
                      EXTENSION(EXnokiaNat),     EXTENSION(EXnokiaNatString), EXTENSION(EXipInfo)};

// pipeline example
#define MAX_SUB_DEPTH 8

#define BitMapSet(map, id) (map |= (1ULL << (id)))

#define TRANSFORM_LIST(TR)                                                             \
    TR(NOP)             /* no transformation */                                        \
    TR(SKIP_INPUT)      /* skip input */                                               \
    TR(RESERVE)         /* add offset entry to offset table */                         \
    TR(MOVE_NUMBER)     /* endian aware copy input/output*/                            \
    TR(MOVE_BYTES)      /* byte copy */                                                \
    TR(MOVE_IPV6)       /* endian aware copy of IPv6 128bit addr */                    \
    TR(MOVE_V9_TIME)    /* msec time with v9 header Sysup and UNIX time */             \
    TR(MOVE_IPFIX_TIME) /* msec time of #21, #22 with sysuptimemsec #160 */            \
    TR(MOVE_IPFIX_USEC) /* negative usec time of  #158, #159 to header export time  */ \
    TR(MOVE_SYSUP)      /* move sysuptime #160 into runtime sysuptime */               \
    TR(MOVE_TIMESEC)    /* time in sec */                                              \
    TR(MOVE_IPV4_RVD)   /* add IPv4 received from runtime*/                            \
    TR(MOVE_IPV6_RVD)   /* add IPv6 received from runtime*/                            \
    TR(MOVE_TIME_RVD)   /* add time received from runtime*/                            \
    TR(REGISTER_0)      /* copy to runtime register 0 instead of output stream */      \
    TR(REGISTER_1)      /* copy to runtime register 1 instead of output stream */      \
    TR(REGISTER_2)      /* copy to runtime register 2 instead of output stream */      \
    TR(SUBTEMPLATE)     /* process sub template */

// generate enum
typedef enum {
#define AS_ENUM(name) name,
    TRANSFORM_LIST(AS_ENUM)
#undef AS_ENUM
        NUM_TRANSFORMS
} transform_t;

// generate symbole table
static const struct trTable_s {
    uint32_t trID;
    const char *trName;
} trTable[] = {
#define AS_TABLE(name) [name] = {name, #name},
    TRANSFORM_LIST(AS_TABLE)
#undef AS_TABLE
};

#define PIPELINE_OP_LIST(OP)                                                                   \
    OP(OP_NULL)            /* NULL */                                                          \
    OP(OP_COPY_1)          /* Copy 1 byte */                                                   \
    OP(OP_COPY_BE_2)       /* Copy 2 bytes byte-endian */                                      \
    OP(OP_COPY_BE_4)       /* Copy 4 bytes byte-endian */                                      \
    OP(OP_COPY_BE_8)       /* Copy 8 bytes byte-endian */                                      \
    OP(OP_COPY_BE_2_4)     /* Copy 2 bytes byte-endian into 4 byte destination */              \
    OP(OP_COPY_BE_4_8)     /* Copy 4 bytes byte-endian into 8 byte destination */              \
    OP(OP_COPY_BE_6_8)     /* Copy 6 bytes byte-endian into 8 byte destination */              \
    OP(OP_COPY_16)         /* copy 16 bytes byte stream */                                     \
    OP(OP_COPY_IPV6)       /* copy 16 bytes IPv6 addr */                                       \
    OP(OP_ALLOC_EXT)       /* allocate slot in offset table for extension */                   \
    OP(OP_COPY_N)          /* copy N bytes byte stream */                                      \
    OP(OP_COPY_VAR)        /* copy var length elements */                                      \
    OP(OP_COPY_V9_TIME)    /* copy 4 bytes v9 time stamps and add v9 header sysup/unix time */ \
    OP(OP_COPY_IPFIX_USEC) /* copy 4 bytes time stamps offset to header export time */         \
    OP(OP_COPY_SYSUP_TIME) /* copy 8 bytes sysup time into runtime */                          \
    OP(OP_COPY_IPV4_RVD)   /* copy 4bytes IPv4 received from runtime */                        \
    OP(OP_COPY_IPV6_RVD)   /* copy 16bytes IPv6 received from runtime */                       \
    OP(OP_COPY_TIME_RVD)   /* copy time received from runtime */                               \
    OP(OP_SKIP)            /* skip fixed input bytes */                                        \
    OP(OP_SKIP_VAR)        /* skip var length input bytes */                                   \
    OP(OP_INIT)            /* init space for extension, added later */                         \
    OP(OP_CALL)            /* reserved - unused */                                             \
    OP(OP_ADD_8)           /* add with argument in instruction */                              \
    OP(OP_ADD_SYSUP)       /* add with sysUptime in runtime */                                 \
    OP(OP_MUL_8)           /* multiply with argument in instruction */                         \
    OP(OP_LOAD_1)          /* load 1 byte into tmp register */                                 \
    OP(OP_LOAD_2)          /* load 2 byte into tmp register */                                 \
    OP(OP_LOAD_4)          /* load 4 byte into tmp register */                                 \
    OP(OP_LOAD_8)          /* load 8 byte into tmp register */                                 \
    OP(OP_STORE_0)         /* store temp register into runtime register 0 */                   \
    OP(OP_STORE_1)         /* store temp register into runtime register 1 */                   \
    OP(OP_STORE_2)         /* store temp register into runtime register 2 */                   \
    OP(OP_END)             /* end of pipeline processing */

typedef enum {
#define AS_ENUM(name) name,
    PIPELINE_OP_LIST(AS_ENUM)
#undef AS_ENUM
        NUM_PIPELINE_OPS
} pipelineOp_t;

static const struct opTable_s {
    uint32_t opID;       // op ID in pipelineOp_t
    const char *opName;  // symbolic name
} opTable[] = {
#define AS_TABLE(name) [name] = {name, #name},
    PIPELINE_OP_LIST(AS_TABLE)
#undef AS_TABLE
};

typedef struct __attribute__((aligned(16))) pipelineInstr_s {
    uint16_t type;       // type of element
    uint16_t inLength;   // length of input element
    uint16_t extID;      // extension ID for this value
    uint16_t dstOffset;  // offset in output rel to extension
    uint16_t outLength;  // size of value in output stream
    uint8_t op;          // type of operation - pipelineOp_t
    uint8_t transform;   // optional value transformation
    uint32_t argument;   // argument calculation OPs
} pipelineInstr_t;

typedef struct pipeline_s {
    uint64_t extBitmap;   // bitmap field for v4 record
    uint16_t baseOffset;  // baseOffset of first extension after offset table

    uint16_t numExtensions;  // __builtin_popcountll(bitMap);
    uint16_t templateID;     // template ID

    uint16_t numInstructions;  // number of allocated instructions

#define NUMFIXUPS 2
    // fixup register needed to apply sysUptime #160 in any order
    // to first/last switched #021 #022 - max 2 registers
    // each fixup register helds the orig instruction
    pipelineInstr_t *fixUp[NUMFIXUPS];  // fixup register
    uint32_t numFixup;                  // number of fixup instructions

    uint32_t recordSize;            // expected output record size
    pipelineInstr_t instruction[];  // instruction array
} pipeline_t;

typedef struct pipelineRuntime_s {
    // input to pipeline
    uint64_t SysUptime;     // Time in milliseconds since this device was first booted
    uint32_t unix_secs;     // UNIX seconds
    uint32_t secExported;   // ipfix header tme exported
    ip128_t ipReceived;     // points to ip128_t from flowsource
    uint64_t msecReceived;  // time msec packet received

    void *genericRecord;  // return generic record in runtime
    void *cntRecord;      // return counter record in runtime
    // output from pipeline
    uint64_t rtRegister[3];  // runtime register for output values
} pipelineRuntime_t;

pipeline_t *PipelineCompile(const pipelineInstr_t *instruction, uint32_t templateID, uint32_t numInstructions);

#define PIP_ERR_SHORT_INPUT (ssize_t) - 1
#define PIP_ERR_SHORT_OUTPUT (ssize_t) - 2
#define PIP_ERR_RUNTIME_INPUT (ssize_t) - 3
#define PIP_ERR_RUNTIME_ERROR (ssize_t) - 4
ssize_t PipelineRun(const pipeline_t *restrict pipeline, const uint8_t *restrict in, size_t inSize, uint8_t *restrict out, size_t outSize,
                    pipelineRuntime_t *restrict runtime);

void PrintPipeline(pipeline_t *pipeline);

int VerifyV4Record(const recordHeaderV4_t *hdr);

#endif