/*
 *  Copyright (c) 2020, Peter Haag
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

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <stdbool.h>

/*
 * V3 extension format
 * ===================
 * 
 * The goal of the V3 extension format:
 *  - simpler and more robust storage format.
 *  - independant of extension records. No specific ordering required.
 *    makes it much easier for multi theaded data processing.
 *  - more flexible record handling, allows variable length records/
 *
 */

/*
 * V3 data record
 * ==============
 *
 */
typedef struct recordHeaderV3_s {
 	// record header
 	uint16_t	type;
 	uint16_t	size;
 	uint16_t	numElements;
 	uint8_t		engineType;
 	uint8_t		engineID;
	uint16_t	exporterID;
	uint8_t		flags;
#define	V3_FLAG_EVENT	1
#define V3_FLAG_SAMPLED	2
#define V3_FLAG_ANON  	4

	uint8_t		nfversion;
} recordHeaderV3_t;
#define V3HeaderRecordSize sizeof(recordHeaderV3_t)
#define AddV3Header(p, h) \
	recordHeaderV3_t *h = (recordHeaderV3_t *)p; \
	memset(h, 0, sizeof(recordHeaderV3_t)); \
	h->type = V3Record; \
	h->size = sizeof(recordHeaderV3_t);

/*
 * Extension element header
 */
typedef struct elementHeader_s {
	uint16_t	type;
	uint16_t	length;
} __attribute__((__packed__ )) elementHeader_t;

// Identifier for new V3Record 
#define V3Record	11

/*
 * Extension elements
 */

#define EXnull 0

/*
#define str(s) #s lose(s)
#define foo 4
str (foo)
expands to `"foo" lose(4)'.
#define FOO(A) ({int retval; retval = do_something(A); retval;})
*/

#define MemberSize(type, member) sizeof(((type *)0)->member)

#define VARLENGTH 0xFFFF

typedef struct EXgenericFlow_s {
#define EXgenericFlowID 1
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
	union {
		uint16_t dstPort;
		uint8_t icmp[2];
	};
#define OFFsrcPort offsetof(EXgenericFlow_t, srcPort)
#define SIZEsrcPort MemberSize(EXgenericFlow_t, srcPort)
#define OFFdstPort offsetof(EXgenericFlow_t, dstPort)
#define SIZEdstPort MemberSize(EXgenericFlow_t, dstPort)
#define OFFicmpCode offsetof(EXgenericFlow_t, icmp[0])
#define SIZEicmpCode MemberSize(EXgenericFlow_t, icmp[0])
#define OFFicmpType offsetof(EXgenericFlow_t, icmp[1])
#define SIZEicmpType MemberSize(EXgenericFlow_t, icmp[1])
  	uint8_t	 proto;
#define OFFproto offsetof(EXgenericFlow_t, proto)
#define SIZEproto MemberSize(EXgenericFlow_t, proto)
	uint8_t tcpFlags;
#define OFFtcpFlags offsetof(EXgenericFlow_t, tcpFlags)
#define SIZEtcpFlags MemberSize(EXgenericFlow_t, tcpFlags)
 	uint8_t	 fwdStatus;
#define OFFfwdStatus offsetof(EXgenericFlow_t, fwdStatus)
#define SIZEfwdStatus MemberSize(EXgenericFlow_t, fwdStatus)
 	uint8_t	 srcTos;
#define OFFsrcTos offsetof(EXgenericFlow_t, srcTos)
#define SIZEsrcTos MemberSize(EXgenericFlow_t, srcTos)
} EXgenericFlow_t;
#define EXgenericFlowSize (sizeof(EXgenericFlow_t) + sizeof(elementHeader_t))

typedef struct EXipv4Flow_s {
#define EXipv4FlowID 2
	uint32_t	srcAddr;
	uint32_t	dstAddr;
#define OFFsrc4Addr offsetof(EXipv4Flow_t, srcAddr)
#define SIZEsrc4Addr MemberSize(EXipv4Flow_t, srcAddr)
#define OFFdst4Addr offsetof(EXipv4Flow_t, dstAddr)
#define SIZEdst4Addr MemberSize(EXipv4Flow_t, dstAddr)
} EXipv4Flow_t;
#define EXipv4FlowSize (sizeof(EXipv4Flow_t) + sizeof(elementHeader_t))

typedef struct EXipv6Flow_s {
#define EXipv6FlowID 3
	uint64_t	srcAddr[2];
	uint64_t	dstAddr[2];
#define OFFsrc6Addr offsetof(EXipv6Flow_t, srcAddr)
#define SIZEsrc6Addr MemberSize(EXipv6Flow_t, srcAddr)
#define OFFdst6Addr offsetof(EXipv6Flow_t, dstAddr)
#define SIZEdst6Addr MemberSize(EXipv6Flow_t, dstAddr)
} EXipv6Flow_t;
#define EXipv6FlowSize (sizeof(EXipv6Flow_t) + sizeof(elementHeader_t))

typedef struct EXflowMisc_s {
#define EXflowMiscID 4
	uint32_t	input;
	uint32_t	output;
#define OFFinput offsetof(EXflowMisc_t, input)
#define SIZEinput MemberSize(EXflowMisc_t, input)
#define OFFoutput offsetof(EXflowMisc_t, output)
#define SIZEoutput MemberSize(EXflowMisc_t, output)
	uint8_t	 srcMask;
	uint8_t	 dstMask;
#define OFFsrcMask offsetof(EXflowMisc_t, srcMask)
#define SIZEsrcMask MemberSize(EXflowMisc_t, srcMask)
#define OFFdstMask offsetof(EXflowMisc_t, dstMask)
#define SIZEdstMask MemberSize(EXflowMisc_t, dstMask)
	uint8_t	 dir;
#define OFFdir offsetof(EXflowMisc_t, dir)
#define SIZEdir MemberSize(EXflowMisc_t, dir)
 	uint8_t	 dstTos;
#define OFFdstTos offsetof(EXflowMisc_t, dstTos)
#define SIZEdstTos MemberSize(EXflowMisc_t, dstTos)
} EXflowMisc_t;
#define EXflowMiscSize (sizeof(EXflowMisc_t) + sizeof(elementHeader_t))

typedef struct EXcntFlow_s {
#define EXcntFlowID 5
	uint64_t	flows;
#define OFFflows offsetof(EXcntFlow_t, flows)
#define SIZEflows MemberSize(EXcntFlow_t, flows)
	uint64_t	outPackets;
	uint64_t	outBytes;
#define OFFoutPackets offsetof(EXcntFlow_t, outPackets)
#define SIZEoutPackets MemberSize(EXcntFlow_t, outPackets)
#define OFFoutBytes offsetof(EXcntFlow_t, outBytes)
#define SIZEoutBytes MemberSize(EXcntFlow_t, outBytes)
} EXcntFlow_t;
#define EXcntFlowSize (sizeof(EXcntFlow_t) + sizeof(elementHeader_t))

typedef struct EXvLan_s {
#define EXvLanID 6
	uint32_t	srcVlan;
	uint32_t	dstVlan;
#define OFFsrcVlan offsetof(EXvLan_t, srcVlan)
#define SIZEsrcVlan MemberSize(EXvLan_t, srcVlan)
#define OFFdstVlan offsetof(EXvLan_t, dstVlan)
#define SIZEdstVlan MemberSize(EXvLan_t, dstVlan)
} EXvLan_t;
#define EXvLanSize (sizeof(EXvLan_t) + sizeof(elementHeader_t))

typedef struct EXasRouting_s {
#define EXasRoutingID 7
	uint32_t	srcAS;
	uint32_t	dstAS;
#define OFFsrcAS offsetof(EXasRouting_t, srcAS)
#define SIZEsrcAS MemberSize(EXasRouting_t, srcAS)
#define OFFdstAS offsetof(EXasRouting_t, dstAS)
#define SIZEdstAS MemberSize(EXasRouting_t, dstAS)
} EXasRouting_t;
#define EXasRoutingSize (sizeof(EXasRouting_t) + sizeof(elementHeader_t))

typedef struct EXbgpNextHopV4_s {
#define EXbgpNextHopV4ID 8
	uint32_t	ip;
#define OFFbgp4NextIP offsetof(EXbgpNextHopV4_t, ip)
#define SIZEbgp4NextIP MemberSize(EXbgpNextHopV4_t, ip)
} EXbgpNextHopV4_t;
#define EXbgpNextHopV4Size (sizeof(EXbgpNextHopV4_t) + sizeof(elementHeader_t))

typedef struct EXbgpNextHopV6_s {
#define EXbgpNextHopV6ID 9
	uint64_t	ip[2];
#define OFFbgp6NextIP offsetof(EXbgpNextHopV6_t, ip)
#define SIZEbgp6NextIP MemberSize(EXbgpNextHopV6_t, ip)
} EXbgpNextHopV6_t;
#define EXbgpNextHopV6Size (sizeof(EXbgpNextHopV6_t) + sizeof(elementHeader_t))

typedef struct EXipNextHopV4_s {
#define EXipNextHopV4ID 10
	uint32_t	ip;
#define OFFNext4HopIP offsetof(EXipNextHopV4_t, ip)
#define SIZENext4HopIP MemberSize(EXipNextHopV4_t, ip)
} EXipNextHopV4_t;
#define EXipNextHopV4Size (sizeof(EXipNextHopV4_t) + sizeof(elementHeader_t))

typedef struct EXipNextHopV6_s {
#define EXipNextHopV6ID 11
	uint64_t	ip[2];
#define OFFNext6HopIP offsetof(EXipNextHopV6_t, ip)
#define SIZENext6HopIP MemberSize(EXipNextHopV6_t, ip)
} EXipNextHopV6_t;
#define EXipNextHopV6Size (sizeof(EXipNextHopV6_t) + sizeof(elementHeader_t))

typedef struct EXipReceivedV4_s {
#define EXipReceivedV4ID 12
	uint32_t	ip;
#define OFFReceived4IP offsetof(EXipReceivedV4_t, ip)
#define SIZEReceived4IP MemberSize(EXipReceivedV4_t, ip)
} EXipReceivedV4_t;
#define EXipReceivedV4Size (sizeof(EXipReceivedV4_t) + sizeof(elementHeader_t))

typedef struct EXipReceivedV6_s {
#define EXipReceivedV6ID 13
	uint64_t	ip[2];
#define OFFReceived6IP offsetof(EXipReceivedV6_t, ip)
#define SIZEReceived6IP MemberSize(EXipReceivedV6_t, ip)
} EXipReceivedV6_t;
#define EXipReceivedV6Size (sizeof(EXipReceivedV6_t) + sizeof(elementHeader_t))

typedef struct EXmplsLabel_s {
#define EXmplsLabelID 14
	uint32_t	mplsLabel[10];
#define OFFmplsLabel1 offsetof(EXmplsLabel_t, mplsLabel[0])
#define SIZEmplsLabel1 MemberSize(EXmplsLabel_t, mplsLabel[0])
#define OFFmplsLabel2 offsetof(EXmplsLabel_t, mplsLabel[1])
#define SIZEmplsLabel2 MemberSize(EXmplsLabel_t, mplsLabel[1])
#define OFFmplsLabel3 offsetof(EXmplsLabel_t, mplsLabel[2])
#define SIZEmplsLabel3 MemberSize(EXmplsLabel_t, mplsLabel[2])
#define OFFmplsLabel4 offsetof(EXmplsLabel_t, mplsLabel[3])
#define SIZEmplsLabel4 MemberSize(EXmplsLabel_t, mplsLabel[3])
#define OFFmplsLabel5 offsetof(EXmplsLabel_t, mplsLabel[4])
#define SIZEmplsLabel5 MemberSize(EXmplsLabel_t, mplsLabel[4])
#define OFFmplsLabel6 offsetof(EXmplsLabel_t, mplsLabel[5])
#define SIZEmplsLabel6 MemberSize(EXmplsLabel_t, mplsLabel[5])
#define OFFmplsLabel7 offsetof(EXmplsLabel_t, mplsLabel[6])
#define SIZEmplsLabel7 MemberSize(EXmplsLabel_t, mplsLabel[6])
#define OFFmplsLabel8 offsetof(EXmplsLabel_t, mplsLabel[7])
#define SIZEmplsLabel8 MemberSize(EXmplsLabel_t, mplsLabel[7])
#define OFFmplsLabel9 offsetof(EXmplsLabel_t, mplsLabel[8])
#define SIZEmplsLabel9 MemberSize(EXmplsLabel_t, mplsLabel[8])
#define OFFmplsLabel10 offsetof(EXmplsLabel_t, mplsLabel[9])
#define SIZEmplsLabel10 MemberSize(EXmplsLabel_t, mplsLabel[9])
} EXmplsLabel_t;
#define EXmplsLabelSize (sizeof(EXmplsLabel_t) + sizeof(elementHeader_t))

typedef struct EXmacAddr_s {
#define EXmacAddrID 15
	uint64_t	inSrcMac;
	uint64_t	outDstMac;
	uint64_t	inDstMac;
	uint64_t	outSrcMac;
#define OFFinSrcMac offsetof(EXmacAddr_t, inSrcMac)
#define SIZEinSrcMac MemberSize(EXmacAddr_t, inSrcMac)
#define OFFoutDstMac offsetof(EXmacAddr_t, outDstMac)
#define SIZEoutDstMac MemberSize(EXmacAddr_t, outDstMac)
#define OFFinDstMac offsetof(EXmacAddr_t, inDstMac)
#define SIZEinDstMac MemberSize(EXmacAddr_t, inDstMac)
#define OFFoutSrcMac offsetof(EXmacAddr_t, outSrcMac)
#define SIZEoutSrcMac MemberSize(EXmacAddr_t, outSrcMac)
} EXmacAddr_t;
#define EXmacAddrSize (sizeof(EXmacAddr_t) + sizeof(elementHeader_t))

typedef struct EXasAdjacent_s {
#define EXasAdjacentID 16
	uint32_t	nextAdjacentAS; // NF_F_BGP_ADJ_NEXT_AS(128)
	uint32_t	prevAdjacentAS; // NF_F_BGP_ADJ_PREV_AS(129)
#define OFFnextAdjacentAS offsetof(EXasAdjacent_t, nextAdjacentAS)
#define SIZEnextAdjacentAS MemberSize(EXasAdjacent_t, nextAdjacentAS)
#define OFFprevAdjacentAS offsetof(EXasAdjacent_t, prevAdjacentAS)
#define SIZEprevAdjacentAS MemberSize(EXasAdjacent_t, prevAdjacentAS)
} EXasAdjacent_t;
#define EXasAdjacentSize (sizeof(EXasAdjacent_t) + sizeof(elementHeader_t))

typedef struct EXlatency_s {
#define EXlatencyID 17
    uint64_t    usecClientNwDelay; // NF_NPROBE_CLIENT_NW_DELAY_SEC(57554) + NF_NPROBE_CLIENT_NW_DELAY_USEC(57555)
    uint64_t    usecServerNwDelay; // NF_NPROBE_SERVER_NW_DELAY_SEC(57556) + NF_NPROBE_SERVER_NW_DELAY_USEC(57557)
    uint64_t    usecApplLatency; // NF_NPROBE_APPL_LATENCY_SEC(57558) + NF_NPROBE_APPL_LATENCY_USEC(57559)
#define OFFusecClientNwDelay offsetof(EXlatency_t, usecClientNwDelay)
#define SIZEusecClientNwDelay MemberSize(EXlatency_t, usecClientNwDelay)
#define OFFusecServerNwDelay offsetof(EXlatency_t, usecServerNwDelay)
#define SIZEusecServerNwDelay MemberSize(EXlatency_t, usecServerNwDelay)
#define OFFusecApplLatency offsetof(EXlatency_t, usecApplLatency)
#define SIZEusecApplLatency MemberSize(EXlatency_t, usecApplLatency)
} EXlatency_t;
#define EXlatencySize (sizeof(EXlatency_t) + sizeof(elementHeader_t))

typedef struct EXsamplerInfo_s {
#define EXsamplerInfoID 18
	int32_t		id;				// id assigned by the exporting device
	uint32_t	interval;		// sampling interval
	uint16_t	mode;			// sampling mode
	uint16_t	exporter_sysid; // internal reference to exporter
#define OFFsampID offsetof(EXsamplerInfo_t, id)
#define SIZEsampID MemberSize(EXsamplerInfo_t, id)
#define OFFsampInterval offsetof(EXsamplerInfo_t, interval)
#define SIZEsampInterval MemberSize(EXsamplerInfo_t, interval)
#define OFFsampMode offsetof(EXsamplerInfo_t, mode)
#define SIZEsampMode MemberSize(EXsamplerInfo_t, mode)
#define OFFsampExporter offsetof(EXsamplerInfo_t, exporter_sysid)
#define SIZEsampExporter MemberSize(EXsamplerInfo_t, exporter_sysid)
} EXsamplerInfo_t;
#define EXsamplerInfoSize (sizeof(EXsamplerInfo_t) + sizeof(elementHeader_t))

typedef struct EXnselCommon_s {
#define EXnselCommonID 19
	uint64_t	msecEvent;	// NF_F_EVENT_TIME_MSEC(323)
	uint32_t	connID;		// NF_F_CONN_ID(148)
	uint16_t	fwXevent;	// NF_F_FW_EXT_EVENT(33002)
	uint8_t		fwEvent;	// NF_F_FW_EVENT(233), NF_F_FW_EVENT_84(40005)
	uint8_t		fill;
#define OFFmsecEvent offsetof(EXnselCommon_t, msecEvent)
#define SIZEmsecEvent MemberSize(EXnselCommon_t, msecEvent)
#define OFFconnID offsetof(EXnselCommon_t, connID)
#define SIZEconnID MemberSize(EXnselCommon_t, connID)
#define OFFfwXevent offsetof(EXnselCommon_t, fwXevent)
#define SIZEfwXevent MemberSize(EXnselCommon_t, fwXevent)
#define OFFfwEvent offsetof(EXnselCommon_t, fwEvent)
#define SIZEfwEvent MemberSize(EXnselCommon_t, fwEvent)
} EXnselCommon_t;
#define EXnselCommonSize (sizeof(EXnselCommon_t) + sizeof(elementHeader_t))

typedef struct EXnselXlateIPv4_s {
#define EXnselXlateIPv4ID 20
	uint32_t	xlateSrcAddr; // NF_F_XLATE_SRC_ADDR_IPV4(225), NF_F_XLATE_SRC_ADDR_84(40001)
	uint32_t	xlateDstAddr; // NF_F_XLATE_DST_ADDR_IPV4(226), NF_F_XLATE_DST_ADDR_84(40002)
#define OFFxlateSrc4Addr offsetof(EXnselXlateIPv4_t, xlateSrcAddr)
#define SIZExlateSrc4Addr MemberSize(EXnselXlateIPv4_t, xlateSrcAddr)
#define OFFxlateDst4Addr offsetof(EXnselXlateIPv4_t, xlateDstAddr)
#define SIZExlateDst4Addr MemberSize(EXnselXlateIPv4_t, xlateDstAddr)
} EXnselXlateIPv4_t;
#define EXnselXlateIPv4Size (sizeof(EXnselXlateIPv4_t) + sizeof(elementHeader_t))

typedef struct EXnselXlateIPv6_s {
#define EXnselXlateIPv6ID 21
	uint32_t	xlateSrcAddr[2]; // NF_F_XLATE_SRC_ADDR_IPV6(281), 
	uint32_t	xlateDstAddr[2]; // NF_F_XLATE_DST_ADDR_IPV6(282), 
#define OFFxlateSrc6Addr offsetof(EXnselXlateIPv6_t, xlateSrcAddr)
#define SIZExlateSrc6Addr MemberSize(EXnselXlateIPv6_t, xlateSrcAddr)
#define OFFxlateDst6Addr offsetof(EXnselXlateIPv6_t, xlateDstAddr)
#define SIZExlateDst6Addr MemberSize(EXnselXlateIPv6_t, xlateDstAddr)
} EXnselXlateIPv6_t;
#define EXnselXlateIPv6Size (sizeof(EXnselXlateIPv6_t) + sizeof(elementHeader_t))

typedef struct EXnselXlatePort_s {
#define EXnselXlatePortID 22
	uint16_t	xlateSrcPort; // NF_F_XLATE_SRC_PORT(227), NF_F_XLATE_SRC_PORT_84(40003)
	uint16_t	xlateDstPort; //  NF_F_XLATE_DST_PORT(228), NF_F_XLATE_DST_PORT_84(40004)
#define OFFxlateSrcPort offsetof(EXnselXlatePort_t, xlateSrcPort)
#define SIZExlateSrcPort MemberSize(EXnselXlatePort_t, xlateSrcPort)
#define OFFxlateDstPort offsetof(EXnselXlatePort_t, xlateDstPort)
#define SIZExlateDstPort MemberSize(EXnselXlatePort_t, xlateDstPort)
} EXnselXlatePort_t;
#define EXnselXlatePortSize (sizeof(EXnselXlatePort_t) + sizeof(elementHeader_t))

typedef struct EXnselAcl_s {
#define EXnselAclID 23
	uint32_t	ingressAcl[3]; // NF_F_INGRESS_ACL_ID(33000)
	uint32_t	egressAcl[3];  // NF_F_EGRESS_ACL_ID(33001)
#define OFFingressAcl offsetof(EXnselAcl_t, ingressAcl)
#define SIZEingressAcl MemberSize(EXnselAcl_t, ingressAcl)
#define OFFegressAcl offsetof(EXnselAcl_t, egressAcl)
#define SIZEegressAcl MemberSize(EXnselAcl_t, egressAcl)
} EXnselAcl_t;
#define EXnselAclSize (sizeof(EXnselAcl_t) + sizeof(elementHeader_t))

typedef struct EXnselUser_s {
#define EXnselUserID 24
	char	 username[66]; // NF_F_USERNAME(40000), 
	uint16_t fill2;
#define OFFusername offsetof(EXnselUser_t, username)
#define SIZEusername MemberSize(EXnselUser_t, username)
} EXnselUser_t;
#define EXnselUserSize (sizeof(EXnselUser_t) + sizeof(elementHeader_t))

// NEL
typedef struct EXnelCommon_s {
#define EXnelCommonID 25
	uint64_t msecEvent;	// NF_F_EVENT_TIME_MSEC(323)
	uint32_t egressVrf;	// NF_N_EGRESS_VRFID(235)
	uint32_t ingressVrf; // NF_N_INGRESS_VRFID(234)
	uint32_t natPoolID; // NF_N_NATPOOL_ID(283)
	uint8_t  natEvent;	// NAT_EVENT(230)
	uint8_t  fill1;
	uint16_t fill2;
#define OFFnelMsecEvent offsetof(EXnelCommon_t, msecEvent)
#define SIZEnelMsecEvent MemberSize(EXnelCommon_t, msecEvent)
#define OFFegressVrf offsetof(EXnelCommon_t, egressVrf)
#define SIZEegressVrf MemberSize(EXnelCommon_t, egressVrf)
#define OFFingressVrf offsetof(EXnelCommon_t, ingressVrf)
#define SIZEingressVrf MemberSize(EXnelCommon_t, ingressVrf)
#define OFFnatPoolID offsetof(EXnelCommon_t, natPoolID)
#define SIZEnatPoolID MemberSize(EXnelCommon_t, natPoolID)
#define OFFnatEvent offsetof(EXnelCommon_t, natEvent)
#define SIZEnatEvent MemberSize(EXnelCommon_t, natEvent)
} EXnelCommon_t;
#define EXnelCommonSize (sizeof(EXnelCommon_t) + sizeof(elementHeader_t))

typedef struct EXnelXlatePort_s {
#define EXnelXlatePortID 26
	uint16_t	blockStart; // NF_F_XLATE_PORT_BLOCK_START(361)
	uint16_t	blockEnd; // NF_F_XLATE_PORT_BLOCK_END(362)
	uint16_t	blockStep; // NF_F_XLATE_PORT_BLOCK_STEP(363)
	uint16_t	blockSize; // NF_F_XLATE_PORT_BLOCK_SIZE(364)
#define OFFnelblockStart offsetof(EXnelXlatePort_t, blockStart)
#define SIZEnelblockStart MemberSize(EXnelXlatePort_t, blockStart)
#define OFFnelblockEnd offsetof(EXnelXlatePort_t, blockEnd)
#define SIZEnelblockEnd MemberSize(EXnelXlatePort_t, blockEnd)
#define OFFnelblockStep offsetof(EXnelXlatePort_t, blockStep)
#define SIZEnelblockStep MemberSize(EXnelXlatePort_t, blockStep)
#define OFFnelblockSize offsetof(EXnelXlatePort_t, blockSize)
#define SIZEnelblockSize MemberSize(EXnelXlatePort_t, blockSize)
} EXnelXlatePort_t;
#define EXnelXlatePortSize (sizeof(EXnelXlatePort_t) + sizeof(elementHeader_t))

typedef struct EXnbarApp_s {
#define EXnbarAppID 27
	uint8_t	id[1];
#define OFFnbarAppID offsetof(EXnbarApp_t, id)
#define SIZEnbarAppID VARLENGTH
} EXnbarApp_t;
#define EXnbarAppSize VARLENGTH

typedef struct EXlabel_s {
#define EXlabelID 28
	char *label;
#define OFFlabel offsetof(Exlabel_t, label)
#define SIZElabel VARLENGTH
} EXlabel_t;
#define EXlabelSize VARLENGTH

// max possible elements
#define MAXELEMENTS 28

#define PushExtension(h, x, v) { \
	elementHeader_t *elementHeader = (elementHeader_t *)((void *)h + h->size); \
	elementHeader->type = x ## ID; \
	elementHeader->length = x ## Size; \
	h->size += sizeof(elementHeader_t); } \
	x ## _t *v = (x ## _t *)((void *)h + h->size); \
	memset(v, 0, sizeof(x ## _t)); \
	h->numElements++; \
	h->size += sizeof(x ## _t);
	
#define PushVarLengthExtension(h, x, v, s) { \
	elementHeader_t *elementHeader = (elementHeader_t *)((void *)h + h->size); \
	elementHeader->type = x ## ID; \
	elementHeader->length = s; \
	h->size += sizeof(elementHeader_t); } \
	x ## _t *v = (x ## _t *)((void *)h + h->size); \
	memset(v, 0, s); \
	h->numElements++; \
	h->size += s;
	

#define EXTENSION(s) { s ## ID, s ## Size, #s} 

static const struct extensionTable_s {
    uint32_t    id;         // id number
    uint32_t    size;       // number of bytes incl. header, 0xFFFF for dyn length
    char        *name;		// name of extension
} extensionTable[] = {
	{ 0, 0, "ExNull" },
	EXTENSION(EXgenericFlow),
	EXTENSION(EXipv4Flow),
	EXTENSION(EXipv6Flow),
	EXTENSION(EXflowMisc),
	EXTENSION(EXcntFlow),
	EXTENSION(EXvLan),
	EXTENSION(EXasRouting),
	EXTENSION(EXbgpNextHopV4),
	EXTENSION(EXbgpNextHopV6),
	EXTENSION(EXipNextHopV4),
	EXTENSION(EXipNextHopV6),
	EXTENSION(EXipReceivedV4),
	EXTENSION(EXipReceivedV6),
	EXTENSION(EXmplsLabel),
	EXTENSION(EXmacAddr),
	EXTENSION(EXasAdjacent),
	EXTENSION(EXlatency),
	EXTENSION(EXsamplerInfo),
	EXTENSION(EXnselCommon),
	EXTENSION(EXnselXlateIPv4),
	EXTENSION(EXnselXlateIPv6),
	EXTENSION(EXnselXlatePort),
	EXTENSION(EXnselAcl),
	EXTENSION(EXnselUser),
	EXTENSION(EXnelCommon),
	EXTENSION(EXnelXlatePort),
	EXTENSION(EXnbarApp),
	EXTENSION(EXlabel)
};

typedef struct sequence_s {
	uint16_t		inputType;
	uint16_t		inputLength;
#define NumberCopy 1
#define ByteCopy   2
	uint16_t		copyMode;
	uint16_t		extensionID;
	unsigned long	offsetRel;
	uint16_t		outputLength;
	uint16_t		stackID;
} sequence_t;

typedef struct sequencer_s {
	void		*offsetCache[MAXELEMENTS];
	sequence_t	*sequenceTable;
	uint16_t	ExtSize[MAXELEMENTS];
	uint32_t	numSequences;
	uint32_t	numElements;
	bool		hasVarLength;
	size_t		inLength;
	size_t		outLength;
} sequencer_t;


uint16_t *SetupSequencer(sequencer_t *sequencer, sequence_t *sequenceTable, uint32_t numSequences);

void ClearSequencer(sequencer_t *sequencer);

int CalcOutRecordSize(sequencer_t *sequencer, void *in, size_t inSize);

int SequencerRun(sequencer_t *sequencer, void *inBuff, size_t inSize, void *outBuff, size_t outSize, uint64_t *stack);

void PrintSequencer(sequencer_t *sequencer);

#endif //_NFXV3_H
