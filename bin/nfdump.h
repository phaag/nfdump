/*
 *  Copyright (c) 2009-2020, Peter Haag
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

#ifndef _NFDUMP_H
#define _NFDUMP_H 1

#include "config.h"

#ifdef WORDS_BIGENDIAN
#	error "Big endian CPU not supported"
#endif

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#define V4 ip_union._v4
#define V6 ip_union._v6

// single IP addr for next hop and bgp next hop
typedef struct ip_addr_s {
	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint32_t	fill[3];
			uint32_t	_v4;
#else
			uint32_t	fill1[2];
			uint32_t	_v4;
			uint32_t	fill2;
#endif
		};
		uint64_t		_v6[2];
	} ip_union;
#define IP_ADDR_T
} ip_addr_t;

// forward declaration
typedef struct exporter_info_record_s exporter_info_record_t;
typedef struct extension_map_s extension_map_t;

/* the master record contains all possible records unpacked */
typedef struct master_record_s {
	// common information from all netflow versions
	// 							// interpreted as uint64_t[]

	uint8_t		flags;			// 0xff00 0000 0000 0000
	uint8_t		nfversion;		// 0x00ff 0000 0000 0000
	uint16_t	mflags; 		// 0x0000'ffff'0000'0000
#define V3_FLAG_IPV6_ADDR	1
#define V3_FLAG_IPV6_NH		2
#define V3_FLAG_IPV6_NHB	4
#define V3_FLAG_IPV6_EXP	8
	uint16_t	size;			// 0x0000'0000'ffff'0000
	uint16_t	numElements;	// 0x0000'0000'0000'ffff

#	define OffsetRecordMFlags 	0
#	define OffsetRecordVersion 	0
#ifdef WORDS_BIGENDIAN
#	define MaskRecordMFlags  	0x0000ffff00000000LL
#	define ShiftRecordMFlags 	32

#	define MaskRecordVersion  	0x00ff000000000000LL
#	define ShiftRecordVersion 	48

#else
#	define MaskRecordMFlags  	0x00000000ffff0000LL
#	define ShiftRecordMFlags 	16

#	define MaskRecordVersion  	0x000000000000ff00LL
#	define ShiftRecordVersion 	8

#endif

	// 8 bytes offset in master record to first
#define INDEX_BASE   (offsetof(master_record_t, msecFirst) >> 3)

	uint64_t	msecFirst;		// 0xffff'ffff'ffff'ffff
	uint64_t	msecLast;		// 0xffff'ffff'ffff'ffff
	uint64_t	msecReceived;	// 0xffff'ffff'ffff'ffff

	uint64_t	inPackets;		// 0xffff'ffff'ffff'ffff
	uint64_t	inBytes;		// 0xffff'ffff'ffff'ffff

	uint16_t	srcPort;		// 0xffff'0000'0000'0000
	uint16_t	dstPort;		// 0x0000'ffff'0000'0000

	uint8_t		fwd_status;		// 0x0000'0000'ff00'0000
	uint8_t		tcp_flags;		// 0x0000'0000'00ff'0000
	uint8_t		proto;			// 0x0000'0000'0000'ff00
	uint8_t		tos;			// 0x0000'0000'0000'00ff

#	define OffsetPackets 		(offsetof(master_record_t, inPackets) >> 3)
#	define OffsetBytes 			(offsetof(master_record_t, inBytes) >> 3)
#	define OffsetPort 			(offsetof(master_record_t, srcPort) >> 3)
#	define OffsetStatus 		(offsetof(master_record_t, fwd_status) >> 3)
#	define OffsetFlags 			(offsetof(master_record_t, tcp_flags) >> 3)
#	define OffsetProto 			(offsetof(master_record_t, proto) >> 3)
#	define OffsetTos			(offsetof(master_record_t, tos) >> 3)

#	define MaskPackets  		0xffffffffffffffffLL
#	define ShiftPackets 		0
#	define MaskBytes  			0xffffffffffffffffLL
#	define ShiftBytes 			0

#ifdef WORDS_BIGENDIAN
#	define MaskSrcPort			0xffff000000000000LL
#	define ShiftSrcPort			48

#	define MaskDstPort			0x0000ffff00000000LL
#	define ShiftDstPort 		32	

#	define MaskStatus  			0x00000000ff000000LL
#	define ShiftStatus  		24

#	define MaskFlags   			0x0000000000ff0000LL
#	define ShiftFlags  			16

#	define MaskProto   			0x000000000000ff00LL
#	define ShiftProto  			8

#	define MaskTos	   			0x00000000000000ffLL
#	define ShiftTos  			0

#else
#	define MaskSrcPort			0x000000000000ffffLL
#	define ShiftSrcPort			0

#	define MaskDstPort			0x00000000ffff0000LL
#	define ShiftDstPort 		16

#	define MaskStatus  			0x000000ff00000000LL
#	define ShiftStatus  		32

#	define MaskFlags   			0x0000ff0000000000LL
#	define ShiftFlags  			40

#	define MaskProto   			0x00ff000000000000LL
#	define ShiftProto  			48

#	define MaskTos	   			0xff00000000000000LL
#	define ShiftTos  			56
#endif

	uint16_t	exporter_sysid;	// 0xffff'0000'0000'0000
	uint8_t		engine_type;	// 0x0000'ff00'0000'0000
	uint8_t		engine_id;		// 0x0000'00ff'0000'0000
	uint16_t	sec_group_tag;	// 0x0000'0000'ffff'0000

	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint8_t		icmp_type;	// 0x0000'0000'0000'ff00
			uint8_t		icmp_code;	// 0x0000'0000'0000'00ff
#else
			uint8_t		icmp_code;
			uint8_t		icmp_type;
#endif
		};
		uint16_t icmp;
	};

#	define OffsetExporterSysID	(offsetof(master_record_t, exporter_sysid) >> 3)
#	define OffsetRouterID		(offsetof(master_record_t, engine_type) >> 3)
#	define OffsetICMP			(offsetof(master_record_t, icmp) >> 3)

#ifdef WORDS_BIGENDIAN
#	define MaskExporterSysID  	0xffff000000000000LL
#	define ShiftExporterSysID 	48

#	define MaskEngineType		0x0000FF0000000000LL
#	define ShiftEngineType		40

#	define MaskEngineID			0x000000FF00000000LL
#	define ShiftEngineID		32


#	define MaskICMPtype			0x000000000000ff00LL
#	define ShiftICMPtype 		8

#	define MaskICMPcode			0x00000000000000ffLL
#	define ShiftICMPcode 		0

#else
#	define MaskExporterSysID  	0x000000000000ffffLL
#	define ShiftExporterSysID 	0

#	define MaskEngineType		0x0000000000FF0000LL
#	define ShiftEngineType		16

#	define MaskEngineID			0x00000000FF000000LL
#	define ShiftEngineID		24

#	define MaskICMPtype			0xff00000000000000LL
#	define ShiftICMPtype 		56

#	define MaskICMPcode			0x00ff000000000000LL
#	define ShiftICMPcode 		48
#endif

	uint8_t	biFlowDir;
	uint8_t flowEndReason;
	uint8_t fill[6];
#	define OffsetbiFlowDir	(offsetof(master_record_t, biFlowDir) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskbiFlowDir    	0xff00000000000000LL
#	define ShiftbiFlowDir      	56
#	define MaskflowEndReason   	0x00ff000000000000LL
#	define ShiftflowEndReason  	48

#else
#	define MaskbiFlowDir       	0x00000000000000ffLL
#	define ShiftbiFlowDir      	0
#	define MaskflowEndReason  	0x000000000000ff00LL
#	define ShiftflowEndReason  	8

#endif

	uint32_t	input;			// 0xffff'ffff'0000'0000
	uint32_t	output;			// 0x0000'0000'ffff'ffff
#	define OffsetInOut     		(offsetof(master_record_t, input) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskInput       		0xffffffff00000000LL
#	define ShiftInput      		32
#	define MaskOutput      		0x00000000ffffffffLL
#	define ShiftOutput     		0

#else
#	define MaskInput      		0x00000000ffffffffLL
#	define ShiftInput      		0
#	define MaskOutput       	0xffffffff00000000LL
#	define ShiftOutput     		32
#endif

	uint32_t	srcas;			// 0xffff'ffff'0000'0000
	uint32_t	dstas;			// 0x0000'0000'ffff'ffff
#	define OffsetAS 			(offsetof(master_record_t, srcas) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskSrcAS 			0xffffffff00000000LL
#	define ShiftSrcAS 			32

#	define MaskDstAS 			0x00000000ffffffffLL
#	define ShiftDstAS 			0

#else
#	define MaskSrcAS 			0x00000000ffffffffLL
#	define ShiftSrcAS 			0

#	define MaskDstAS 			0xffffffff00000000LL
#	define ShiftDstAS 			32
#endif

	// IP address block 
	union {						
		struct _ipv4_s {
#ifdef WORDS_BIGENDIAN
			uint32_t	fill1[3];	// <empty>		0xffff'ffff'ffff'ffff
									// <empty>		0xffff'ffff'0000'0000
			uint32_t	srcaddr;	// srcaddr      0x0000'0000'ffff'ffff
			uint32_t	fill2[3];	// <empty>		0xffff'ffff'ffff'ffff
									// <empty>		0xffff'ffff'0000'0000
			uint32_t	dstaddr;	// dstaddr      0x0000'0000'ffff'ffff
#else
			uint32_t	fill1[2];	// <empty>		0xffff'ffff'ffff'ffff
			uint32_t	srcaddr;	// srcaddr      0xffff'ffff'0000'0000
			uint32_t	fill2;		// <empty>		0x0000'0000'ffff'ffff
			uint32_t	fill3[2];	// <empty>		0xffff'ffff'ffff'ffff
			uint32_t	dstaddr;	// dstaddr      0xffff'ffff'0000'0000
			uint32_t	fill4;		// <empty>		0xffff'ffff'0000'0000
#endif
		} _v4;	
		struct _ipv6_s {
			uint64_t	srcaddr[2];	// srcaddr[0-1] 0xffff'ffff'ffff'ffff
									// srcaddr[2-3] 0xffff'ffff'ffff'ffff
			uint64_t	dstaddr[2];	// dstaddr[0-1] 0xffff'ffff'ffff'ffff
									// dstaddr[2-3] 0xffff'ffff'ffff'ffff
		} _v6;
		struct _ip64_s {
			uint64_t	addr[4];
		} _ip_64;
	} ip_union;

#	define OffsetSrcIPv4 		(offsetof(master_record_t, ip_union._v4.srcaddr) >> 3)
#	define OffsetDstIPv4 		(offsetof(master_record_t, ip_union._v4.dstaddr) >> 3)
#	define OffsetSrcIPv6a 		(offsetof(master_record_t, ip_union._v6.srcaddr[0]) >> 3)
#	define OffsetSrcIPv6b 		(offsetof(master_record_t, ip_union._v6.srcaddr[1]) >> 3)
#	define OffsetDstIPv6a 		(offsetof(master_record_t, ip_union._v6.dstaddr[0]) >> 3)
#	define OffsetDstIPv6b 		(offsetof(master_record_t, ip_union._v6.dstaddr[1]) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskSrcIPv4  		0x00000000ffffffffLL
#	define ShiftSrcIPv4 		0

#	define MaskDstIPv4  		0x00000000ffffffffLL
#	define ShiftDstIPv4  		0	

#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0

#else
#	define MaskSrcIPv4  		0xffffffff00000000LL
#	define ShiftSrcIPv4 		32

#	define MaskDstIPv4  		0xffffffff00000000LL
#	define ShiftDstIPv4  		32

#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0
#endif


	ip_addr_t	ip_nexthop;		// ipv4 0x0000'0000'ffff'ffff
								// ipv6	0xffff'ffff'ffff'ffff
								// ipv6	0xffff'ffff'ffff'ffff

#	define OffsetNexthopv4 		(offsetof(master_record_t, ip_nexthop.ip_union._v4) >> 3)
#	define OffsetNexthopv6a		(offsetof(master_record_t, ip_nexthop.ip_union._v6[0]) >> 3)
#	define OffsetNexthopv6b		(offsetof(master_record_t, ip_nexthop.ip_union._v6[1]) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskNexthopv4  		0x00000000ffffffffLL
#	define ShiftNexthopv4 		0

// MaskIPv6 and ShiftIPv6 already defined

#else
#	define MaskNexthopv4  		0xffffffff00000000LL
#	define ShiftNexthopv4 		0
#endif

	ip_addr_t	bgp_nexthop;	// ipv4 0x0000'0000'ffff'ffff
								// ipv6 0xffff'ffff'ffff'ffff
								// ipv6	0xffff'ffff'ffff'ffff

#	define OffsetBGPNexthopv4 	(offsetof(master_record_t, bgp_nexthop.ip_union._v4) >> 3)
#	define OffsetBGPNexthopv6a	(offsetof(master_record_t, bgp_nexthop.ip_union._v6[0]) >> 3)
#	define OffsetBGPNexthopv6b	(offsetof(master_record_t, bgp_nexthop.ip_union._v6[1]) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskBGPNexthopv4  	0x00000000ffffffffLL
#	define ShiftBGPNexthopv4 	0

#else
#	define MaskBGPNexthopv4  	0xffffffff00000000LL
#	define ShiftBGPNexthopv4 	0
#endif

	union {
		struct {
			uint8_t	dst_tos;	// 0xff00'0000'0000'0000
			uint8_t	dir;		// 0x00ff'0000'0000'0000
			uint8_t	src_mask;	// 0x0000'ff00'0000'0000
			uint8_t	dst_mask;	// 0x0000'00ff'0000'0000
		};
		uint32_t	any;
	};

	// extension 13
	uint16_t	src_vlan;		// 0x0000'0000'ffff'0000
	uint16_t	dst_vlan;		// 0x0000'0000'0000'ffff

#	define OffsetDstTos			(offsetof(master_record_t, dst_tos) >> 3)
#	define OffsetDir			(offsetof(master_record_t, dir) >> 3)
#	define OffsetMask			(offsetof(master_record_t, src_mask) >> 3)
#	define OffsetVlan 			(offsetof(master_record_t, src_vlan) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskDstTos			0xff00000000000000LL
#	define ShiftDstTos  		56

#	define MaskDir				0x00ff000000000000LL
#	define ShiftDir  			48

#	define MaskSrcMask			0x0000ff0000000000LL
#	define ShiftSrcMask  		40

#	define MaskDstMask			0x000000ff00000000LL
#	define ShiftDstMask 		32

#	define MaskSrcVlan  		0x00000000ffff0000LL
#	define ShiftSrcVlan 		16

#	define MaskDstVlan  		0x000000000000ffffLL
#	define ShiftDstVlan 		0

#else
#	define MaskDstTos			0x00000000000000ffLL
#	define ShiftDstTos  		0

#	define MaskDir				0x000000000000ff00LL
#	define ShiftDir  			8

#	define MaskSrcMask			0x0000000000ff0000LL
#	define ShiftSrcMask  		16

#	define MaskDstMask			0x00000000ff000000LL
#	define ShiftDstMask 		24

#	define MaskSrcVlan  		0x0000ffff00000000LL
#	define ShiftSrcVlan 		32

#	define MaskDstVlan  		0xffff000000000000LL
#	define ShiftDstVlan 		48

#endif

	uint64_t	out_pkts;		// 0xffff'ffff'ffff'ffff
#	define OffsetOutPackets 	(offsetof(master_record_t, out_pkts) >> 3)

	uint64_t	out_bytes;		// 0xffff'ffff'ffff'ffff
#	define OffsetOutBytes 		(offsetof(master_record_t, out_bytes) >> 3)

	uint64_t	aggr_flows;		// 0xffff'ffff'ffff'ffff
#	define OffsetAggrFlows 		(offsetof(master_record_t, aggr_flows) >> 3)
#	define MaskFlows 	 		0xffffffffffffffffLL

	uint64_t	in_src_mac;		// 0xffff'ffff'ffff'ffff
#	define OffsetInSrcMAC 		(offsetof(master_record_t, in_src_mac) >> 3)
#	define MaskMac 	 			0xffffffffffffffffLL

	uint64_t	out_dst_mac;	// 0xffff'ffff'ffff'ffff
#	define OffsetOutDstMAC 		(offsetof(master_record_t, out_dst_mac) >> 3)

	uint64_t	in_dst_mac;		// 0xffff'ffff'ffff'ffff
#	define OffsetInDstMAC 		(offsetof(master_record_t, in_dst_mac) >> 3)

	uint64_t	out_src_mac;	// 0xffff'ffff'ffff'ffff
#	define OffsetOutSrcMAC 		(offsetof(master_record_t, out_src_mac) >> 3)

	uint32_t	mpls_label[10];
#	define OffsetMPLS12 		(offsetof(master_record_t, mpls_label[0]) >> 3)
#	define OffsetMPLS34 		(offsetof(master_record_t, mpls_label[2]) >> 3)
#	define OffsetMPLS56 		(offsetof(master_record_t, mpls_label[4]) >> 3)
#	define OffsetMPLS78 		(offsetof(master_record_t, mpls_label[6]) >> 3)
#	define OffsetMPLS910 		(offsetof(master_record_t, mpls_label[8]) >> 3)

#ifdef WORDS_BIGENDIAN
#	define MaskMPLSlabelOdd  	0x00fffff000000000LL
#	define ShiftMPLSlabelOdd 	36
#	define MaskMPLSexpOdd  		0x0000000e00000000LL
#	define ShiftMPLSexpOdd 		33

#	define MaskMPLSlabelEven  	0x0000000000fffff0LL
#	define ShiftMPLSlabelEven 	4
#	define MaskMPLSexpEven  	0x000000000000000eLL
#	define ShiftMPLSexpEven 	1
#else
#	define MaskMPLSlabelOdd 	0x000000000000fff0LL
#	define ShiftMPLSlabelOdd 	4
#	define MaskMPLSexpOdd  		0x000000000000000eLL
#	define ShiftMPLSexpOdd 		1

#	define MaskMPLSlabelEven 	0x00fffff000000000LL
#	define ShiftMPLSlabelEven 	36
#	define MaskMPLSexpEven 		0x0000000e00000000LL
#	define ShiftMPLSexpEven		33

#endif

	ip_addr_t	ip_router;		// ipv4 0x0000'0000'ffff'ffff
								// ipv6	0xffff'ffff'ffff'ffff
								// ipv6	0xffff'ffff'ffff'ffff

#	define OffsetRouterv4 		(offsetof(master_record_t, ip_router.ip_union._v4) >> 3)
#	define OffsetRouterv6a		(offsetof(master_record_t, ip_router.ip_union._v6[0]) >> 3)
#	define OffsetRouterv6b		(offsetof(master_record_t, ip_router.ip_union._v6[1]) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskRouterv4  		0x00000000ffffffffLL
#	define ShiftRouterv4 		0

#else
#	define MaskRouterv4  		0xffffffff00000000LL
#	define ShiftRouterv4 		0
#endif

	// BGP next/prev AS
	uint32_t	bgpNextAdjacentAS;	// 0xffff'ffff'0000'0000
	uint32_t	bgpPrevAdjacentAS;	// 0x0000'0000'ffff'ffff

#	define OffsetBGPadj			(offsetof(master_record_t, bgpNextAdjacentAS) >> 3)
#ifdef WORDS_BIGENDIAN
#	define MaskBGPadjNext		0xFFFFFFFF00000000LL
#	define ShiftBGPadjNext		32
#	define MaskBGPadjPrev		0x00000000FFFFFFFFLL
#	define ShiftBGPadjPrev		0

#else
#	define MaskBGPadjNext		0x00000000FFFFFFFFLL
#	define ShiftBGPadjNext		0
#	define MaskBGPadjPrev		0xFFFFFFFF00000000LL
#	define ShiftBGPadjPrev		32
#endif

	// latency extension
	uint64_t	client_nw_delay_usec;	// index LATENCY_BASE_OFFSET 0xffff'ffff'ffff'ffff
	uint64_t	server_nw_delay_usec;	// index LATENCY_BASE_OFFSET + 1 0xffff'ffff'ffff'ffff
	uint64_t	appl_latency_usec;		// index LATENCY_BASE_OFFSET + 2 0xffff'ffff'ffff'ffff

#define LATENCY_BASE_OFFSET     (offsetof(master_record_t, client_nw_delay_usec) >> 3)
#   define OffsetClientLatency  LATENCY_BASE_OFFSET
#   define OffsetServerLatency  LATENCY_BASE_OFFSET + 1
#   define OffsetAppLatency     LATENCY_BASE_OFFSET + 2
#   define MaskLatency          0xFFFFFFFFFFFFFFFFLL
#   define ShiftLatency         0

	// NSEL extensions
#ifdef NSEL 
#define NSEL_BASE_OFFSET     (offsetof(master_record_t, connID) >> 3)

	// common block
#   define OffsetConnID  NSEL_BASE_OFFSET
#   define OffsetNATevent  NSEL_BASE_OFFSET
	uint32_t	connID;			// index OffsetConnID    0xffff'ffff'0000'0000
	uint8_t		event;			// index OffsetConnID    0x0000'0000'ff00'0000
#define FW_EVENT 1
#define NAT_EVENT 2
	uint8_t		event_flag;		// index OffsetConnID    0x0000'0000'00ff'0000
	uint16_t	fwXevent;		// index OffsetConnID    0x0000'0000'0000'ffff
	uint64_t	msecEvent;		// index OffsetConnID +1 0x1111'1111'1111'1111
#ifdef WORDS_BIGENDIAN
#	define MaskConnID		0xFFFFFFFF00000000LL
#	define ShiftConnID		32
#	define MaskFWevent		0x00000000FF000000LL
#	define ShiftFWevent		24
#	define MasNATevent		0x00000000FF000000LL
#	define ShiftNATevent	24
#	define MaskFWXevent		0x000000000000FFFFLL
#	define ShiftFWXevent	0
#else
#	define MaskConnID		0x00000000FFFFFFFFLL
#	define ShiftConnID		0
#	define MaskFWevent		0x000000FF00000000LL
#	define ShiftFWevent		32
#	define MasNATevent		0x000000FF00000000LL
#	define ShiftNATevent	32
#	define MaskFWXevent		0xFFFF000000000000LL
#	define ShiftFWXevent	48

#endif

	// xlate ip/port
#   define OffsetXLATEPort NSEL_BASE_OFFSET+2
	uint16_t	xlate_src_port;		// index OffsetXLATEPort 0xffff'0000'0000'0000
	uint16_t	xlate_dst_port;		// index OffsetXLATEPort 0x0000'ffff'0000'0000
	uint32_t	xlate_flags;
#   define OffsetXLATESRCIP NSEL_BASE_OFFSET+3
	ip_addr_t	xlate_src_ip;		// ipv4  OffsetXLATESRCIP +1 0x0000'0000'ffff'ffff
									// ipv6	 OffsetXLATESRCIP 	 0xffff'ffff'ffff'ffff
									// ipv6	 OffsetXLATESRCIP	 0xffff'ffff'ffff'ffff

	ip_addr_t	xlate_dst_ip;		// ipv4  OffsetXLATEDSTIP +1 0x0000'0000'ffff'ffff
									// ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff
									// ipv6	 OffsetXLATEDSTIP 	 0xffff'ffff'ffff'ffff
#	define OffsetXLATESRCv6a OffsetXLATESRCIP
#	define OffsetXLATESRCv6b OffsetXLATESRCIP+1
#	define OffsetXLATEDSTv6a OffsetXLATESRCIP+2
#	define OffsetXLATEDSTv6b OffsetXLATESRCIP+3

#ifdef WORDS_BIGENDIAN
#	define MaskXLATESRCPORT	 0xFFFF000000000000LL
#	define ShiftXLATESRCPORT 48
#	define MaskXLATEDSTPORT	 0x0000FFFF00000000LL
#	define ShiftXLATEDSTPORT 32

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0x00000000fFFFFFFFLL
#	define ShiftXLATEIPv4 	 0

#else
#	define MaskXLATESRCPORT	 0x000000000000FFFFLL
#	define ShiftXLATESRCPORT 0
#	define MaskXLATEDSTPORT	 0x00000000FFFF0000LL
#	define ShiftXLATEDSTPORT 16

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0xFFFFFFFF00000000LL
#	define ShiftXLATEIPv4 	 32

#endif


	// ingress/egress ACL id
#   define OffsetIngressAclId NSEL_BASE_OFFSET+7
#	define OffsetIngressAceId NSEL_BASE_OFFSET+7
#	define OffsetIngressGrpId NSEL_BASE_OFFSET+8
#	define OffsetEgressAclId  NSEL_BASE_OFFSET+8
#	define OffsetEgressAceId  NSEL_BASE_OFFSET+9
#	define OffsetEgressGrpId  NSEL_BASE_OFFSET+9
	uint32_t ingressAcl[3];	// index OffsetIngressAclId   0xffff'ffff'0000'0000
								// index OffsetIngressAceId   0x0000'0000'ffff'ffff
								// index OffsetIngressGrpId   0xffff'ffff'0000'0000
	uint32_t egressAcl[3];	// index OffsetEgressAclId	  0x0000'0000'ffff'ffff
								// index OffsetEgressAceId	  0xffff'ffff'0000'0000
								// index OffsetEgressGrpId	  0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#define MaskIngressAclId	0xffffffff00000000LL
#define ShiftIngressAclId	32
#define MaskIngressAceId	0x00000000ffffffffLL
#define ShiftIngressAceId	0
#define MaskIngressGrpId	0xffffffff00000000LL
#define ShiftIngressGrpId	32
#define MaskEgressAclId		0x00000000ffffffffLL
#define ShiftEgressAclId	0
#define MaskEgressAceId		0xffffffff00000000LL
#define ShiftEgressAceId	32
#define MaskEgressGrpId		0x00000000ffffffffLL
#define ShiftEgressGrpId	0
#else
#define MaskIngressAclId	0x00000000ffffffffLL
#define ShiftIngressAclId	0
#define MaskIngressAceId	0xffffffff00000000LL
#define ShiftIngressAceId	32
#define MaskIngressGrpId	0x00000000ffffffffLL
#define ShiftIngressGrpId	0
#define MaskEgressAclId		0xffffffff00000000LL
#define ShiftEgressAclId	32
#define MaskEgressAceId		0x00000000ffffffffLL
#define ShiftEgressAceId	0
#define MaskEgressGrpId		0xffffffff00000000LL
#define ShiftEgressGrpId	32
#endif

	// username
#	define OffsetUsername  NSEL_BASE_OFFSET+10
	char username[72];

	// NAT extensions
	// NAT event is mapped into ASA event
#define NAT_BASE_OFFSET     (offsetof(master_record_t, ingressVrf) >> 3)
	// common block
#   define OffsetNELcommon  NEL_BASE_OFFSET
#   define OffsetIVRFID  	NAT_BASE_OFFSET
#   define OffsetEVRFID  	NAT_BASE_OFFSET
#   define OffsetPortBlock	NAT_BASE_OFFSET+1
	uint32_t	ingressVrf;	// OffsetIVRFID	   0xffff'ffff'0000'0000
	uint32_t	egressVrf;	// OffsetEVRFID	   0x0000'0000'ffff'ffff

	// Port block allocation
	uint16_t	block_start;	// OffsetPortBlock 0xffff'0000'0000'0000
	uint16_t	block_end;		// OffsetPortBlock 0x0000'ffff'0000'0000
	uint16_t	block_step;		// OffsetPortBlock 0x0000'0000'ffff'0000
	uint16_t	block_size;		// OffsetPortBlock 0x0000'0000'0000'ffff

#ifdef WORDS_BIGENDIAN
#	define MaskIVRFID			0xFFFFFFFF00000000LL
#	define ShiftIVRFID			32
#	define MaskEVRFID			0x00000000FFFFFFFFLL
#	define ShiftEVRFID			0
#	define MaskPortBlockStart	0xFFFF000000000000LL
#	define ShiftPortBlockStart	48
#	define MaskPortBlockEnd		0x0000FFFF00000000LL
#	define ShiftPortBlockEnd	32
#	define MaskPortBlockStep	0x00000000FFFF0000LL
#	define ShiftPortBlockStep	16
#	define MaskPortBlockSize	0x000000000000FFFFLL
#	define ShiftPortBlockSize	0
#else
#	define MaskIVRFID			0x00000000FFFFFFFFLL
#	define ShiftIVRFID			0
#	define MaskEVRFID			0xFFFFFFFF00000000LL
#	define ShiftEVRFID			32
#	define MaskPortBlockStart	0x000000000000FFFFLL
#	define ShiftPortBlockStart	0
#	define MaskPortBlockEnd		0x00000000FFFF0000LL
#	define ShiftPortBlockEnd	16
#	define MaskPortBlockStep	0x0000FFFF00000000LL
#	define ShiftPortBlockStep	32
#	define MaskPortBlockSize	0xFFFF000000000000LL
#	define ShiftPortBlockSize	48
#endif

#endif

	// nbar AppID - actect array
	uint8_t	nbarAppID[8];		// 0xffff'ffff'ffff'ffff
#	define OffsetNbarAppID 		(offsetof(master_record_t, nbarAppID) >> 3)


	// last entry in master record 
	uint16_t	exElementList[64];	// XXX fix number of elements

	// reference to exporter
	exporter_info_record_t	*exp_ref;

	char	*payload;
	char	*label;
#	define Offset_MR_LAST	offsetof(master_record_t, label)
} master_record_t;


typedef struct stat_record_s {
    // overall stat
    uint64_t    numflows;
    uint64_t    numbytes;
    uint64_t    numpackets;
    // flow stat
    uint64_t    numflows_tcp;
    uint64_t    numflows_udp;
    uint64_t    numflows_icmp;
    uint64_t    numflows_other;
    // bytes stat
    uint64_t    numbytes_tcp;
    uint64_t    numbytes_udp;
    uint64_t    numbytes_icmp;
    uint64_t    numbytes_other;
    // packet stat
    uint64_t    numpackets_tcp;
    uint64_t    numpackets_udp;
    uint64_t    numpackets_icmp;
    uint64_t    numpackets_other;
    // time window
    uint32_t    first_seen;
    uint32_t    last_seen;
    uint16_t    msec_first;
    uint16_t    msec_last;
    // other
    uint32_t    sequence_failure;
} stat_record_t;

#endif //_NFDUMP_H

