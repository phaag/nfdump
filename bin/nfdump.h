/*
 *  Copyright (c) 2009-2021, Peter Haag
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
	// 							#ifdef WORDS_BIGENDIAN

	uint16_t	type;			// index 0  0xffff 0000 0000 0000
	uint16_t	size;			// index 0	0x0000'ffff'0000 0000
	uint8_t		flags;			// index 0  0x0000'0000'ff00'0000
	uint8_t		nfversion;		// index 0  0x0000'0000'00ff'0000
	uint16_t	ext_map;		// index 0	0x0000'0000'0000'ffff
#	define OffsetRecordFlags 	0
#	define OffsetRecordVersion 	0
#ifdef WORDS_BIGENDIAN
#	define MaskRecordFlags  	0x00000000ff000000LL
#	define ShiftRecordFlags 	24
#	define MaskRecordVersion  	0x0000000000ff0000LL
#	define ShiftRecordVersion 	16
#else
#	define MaskRecordFlags  	0x000000ff00000000LL
#	define ShiftRecordFlags 	32
#	define MaskRecordVersion  	0x0000ff0000000000LL
#	define ShiftRecordVersion 	40
#endif

	//
	uint16_t	msec_first;		// index 1	0xffff'0000'0000'0000
	uint16_t	msec_last;		// index 1	0x0000'ffff'0000'0000

	// 12 bytes offset in master record to first
#define BYTE_OFFSET_first	12

	uint32_t	first;			// index 1	0x0000'0000'ffff'ffff

	//
	uint32_t	last;			// index 2	0xffff'ffff'0000'0000
	uint8_t		fwd_status;		// index 2	0x0000'0000'ff00'0000
	uint8_t		tcp_flags;		// index 2  0x0000'0000'00ff'0000
	uint8_t		prot;			// index 2  0x0000'0000'0000'ff00
	uint8_t		tos;			// index 2  0x0000'0000'0000'00ff
#ifdef WORDS_BIGENDIAN
#	define OffsetStatus 		2
#	define MaskStatus  			0x00000000ff000000LL
#	define ShiftStatus  		24

#	define OffsetFlags 			2
#	define MaskFlags   			0x0000000000ff0000LL
	#define ShiftFlags  		16

#	define OffsetProto 			2
#	define MaskProto   			0x000000000000ff00LL
#	define ShiftProto  			8

#	define OffsetTos			2
#	define MaskTos	   			0x00000000000000ffLL
#	define ShiftTos  			0

#else
#	define OffsetStatus 		2
#	define MaskStatus  			0x000000ff00000000LL
#	define ShiftStatus  		32

#	define OffsetFlags 			2
#	define MaskFlags   			0x0000ff0000000000LL
#	define ShiftFlags  			40

#	define OffsetProto 			2
#	define MaskProto   			0x00ff000000000000LL
#	define ShiftProto  			48

#	define OffsetTos			2
#	define MaskTos	   			0xff00000000000000LL
#	define ShiftTos  			56
#endif

	uint16_t	srcport;		// index 3	0xffff'0000'0000'0000
	uint16_t	dstport;		// index 3  0x0000'ffff'0000'0000
	uint16_t	exporter_sysid; // index 3	0x0000'0000'ffff'0000

	uint8_t		biFlowDir;
	uint8_t		flowEndReason;

#	define OffsetPort 			3
#	define OffsetExporterSysID	3
#ifdef WORDS_BIGENDIAN
#	define MaskSrcPort			0xffff000000000000LL
#	define ShiftSrcPort			48

#	define MaskDstPort			0x0000ffff00000000LL
#	define ShiftDstPort 		32	

#	define MaskExporterSysID  	0x00000000ffff0000LL
#	define ShiftExporterSysID 	16


#else
#	define MaskSrcPort			0x000000000000ffffLL
#	define ShiftSrcPort			0

#	define MaskDstPort			0x00000000ffff0000LL
#	define ShiftDstPort 		16

#	define MaskExporterSysID  	0x0000ffff00000000LL
#	define ShiftExporterSysID 	32

#endif

	// extension 4 / 5
	uint32_t	input;			// index 4	0xffff'ffff'0000'0000
	uint32_t	output;			// index 4	0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#	define OffsetInOut     		4
#	define MaskInput       		0xffffffff00000000LL
#	define ShiftInput      		32
#	define MaskOutput      		0x00000000ffffffffLL
#	define ShiftOutput     		0

#else
#	define OffsetInOut     		4
#	define MaskInput      		0x00000000ffffffffLL
#	define ShiftInput      		0
#	define MaskOutput       	0xffffffff00000000LL
#	define ShiftOutput     		32
#endif

	// extension 6 / 7
	uint32_t	srcas;			// index 5	0xffff'ffff'0000'0000
	uint32_t	dstas;			// index 5	0x0000'0000'ffff'ffff
#ifdef WORDS_BIGENDIAN
#	define OffsetAS 			5
#	define MaskSrcAS 			0xffffffff00000000LL
#	define ShiftSrcAS 			32
#	define MaskDstAS 			0x00000000ffffffffLL
#	define ShiftDstAS 			0

#else
#	define OffsetAS 			5
#	define MaskSrcAS 			0x00000000ffffffffLL
#	define ShiftSrcAS 			0
#	define MaskDstAS 			0xffffffff00000000LL
#	define ShiftDstAS 			32
#endif


	// IP address block 
	union {						
		struct _ipv4_s {
#ifdef WORDS_BIGENDIAN
			uint32_t	fill1[3];	// <empty>		index 6	0xffff'ffff'ffff'ffff
									// <empty>		index 7 0xffff'ffff'0000'0000
			uint32_t	srcaddr;	// srcaddr      index 7 0x0000'0000'ffff'ffff
			uint32_t	fill2[3];	// <empty>		index 8	0xffff'ffff'ffff'ffff
									// <empty>		index 9	0xffff'ffff'0000'0000
			uint32_t	dstaddr;	// dstaddr      index 9 0x0000'0000'ffff'ffff
#else
			uint32_t	fill1[2];	// <empty>		index 6	0xffff'ffff'ffff'ffff
			uint32_t	srcaddr;	// srcaddr      index 7 0xffff'ffff'0000'0000
			uint32_t	fill2;		// <empty>		index 7 0x0000'0000'ffff'ffff
			uint32_t	fill3[2];	// <empty>		index 8 0xffff'ffff'ffff'ffff
			uint32_t	dstaddr;	// dstaddr      index 9 0xffff'ffff'0000'0000
			uint32_t	fill4;		// <empty>		index 9 0xffff'ffff'0000'0000
#endif
		} _v4;	
		struct _ipv6_s {
			uint64_t	srcaddr[2];	// srcaddr[0-1] index 6 0xffff'ffff'ffff'ffff
									// srcaddr[2-3] index 7 0xffff'ffff'ffff'ffff
			uint64_t	dstaddr[2];	// dstaddr[0-1] index 8 0xffff'ffff'ffff'ffff
									// dstaddr[2-3] index 9 0xffff'ffff'ffff'ffff
		} _v6;
		struct _ip64_s {
			uint64_t	addr[4];
		} _ip_64;
	} ip_union;

#ifdef WORDS_BIGENDIAN
#	define OffsetSrcIPv4 		7
#	define MaskSrcIPv4  		0x00000000ffffffffLL
#	define ShiftSrcIPv4 		0

#	define OffsetDstIPv4 		9
#	define MaskDstIPv4  		0x00000000ffffffffLL
#	define ShiftDstIPv4  		0	

#	define OffsetSrcIPv6a 		6
#	define OffsetSrcIPv6b 		7
#	define OffsetDstIPv6a 		8
#	define OffsetDstIPv6b 		9
#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0

#else
#	define OffsetSrcIPv4 		6
#	define MaskSrcIPv4  		0xffffffff00000000LL
#	define ShiftSrcIPv4 		32

#	define OffsetDstIPv4 		8
#	define MaskDstIPv4  		0xffffffff00000000LL
#	define ShiftDstIPv4  		32

#	define OffsetSrcIPv6a 		6
#	define OffsetSrcIPv6b 		7
#	define OffsetDstIPv6a 		8
#	define OffsetDstIPv6b 		9
#	define MaskIPv6  			0xffffffffffffffffLL
#	define ShiftIPv6 			0
#endif


	// counter block - expanded to 8 bytes
	uint64_t	dPkts;			// index 10	0xffff'ffff'ffff'ffff
#	define OffsetPackets 		10
#	define MaskPackets  		0xffffffffffffffffLL
#	define ShiftPackets 		0

	uint64_t	dOctets;		// index 11 0xffff'ffff'ffff'ffff
#	define OffsetBytes 			11
#	define MaskBytes  			0xffffffffffffffffLL
#	define ShiftBytes 			0

	// extension 9 / 10
	ip_addr_t	ip_nexthop;		// ipv4   index 13 0x0000'0000'ffff'ffff
								// ipv6	  index 12 0xffff'ffff'ffff'ffff
								// ipv6	  index 13 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetNexthopv4 		13	
#	define MaskNexthopv4  		0x00000000ffffffffLL
#	define ShiftNexthopv4 		0

#	define OffsetNexthopv6a		12
#	define OffsetNexthopv6b		13
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetNexthopv4 		13	
#	define MaskNexthopv4  		0xffffffff00000000LL
#	define ShiftNexthopv4 		0

#	define OffsetNexthopv6a		12
#	define OffsetNexthopv6b		13
#endif

	// extension 11 / 12
	ip_addr_t	bgp_nexthop;	// ipv4   index 15 0x0000'0000'ffff'ffff
								// ipv6	  index 14 0xffff'ffff'ffff'ffff
								// ipv6	  index 15 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetBGPNexthopv4 	15	
#	define MaskBGPNexthopv4  	0x00000000ffffffffLL
#	define ShiftBGPNexthopv4 	0

#	define OffsetBGPNexthopv6a	14
#	define OffsetBGPNexthopv6b	15
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetBGPNexthopv4 	15	
#	define MaskBGPNexthopv4  	0xffffffff00000000LL
#	define ShiftBGPNexthopv4 	0

#	define OffsetBGPNexthopv6a	14
#	define OffsetBGPNexthopv6b	15
#endif

	// extension 8
	union {
		struct {
			uint8_t	dst_tos;	// index 16 0xff00'0000'0000'0000
			uint8_t	dir;		// index 16 0x00ff'0000'0000'0000
			uint8_t	src_mask;	// index 16 0x0000'ff00'0000'0000
			uint8_t	dst_mask;	// index 16 0x0000'00ff'0000'0000
		};
		uint32_t	any;
	};

	// extension 13
	uint16_t	src_vlan;		// index 16 0x0000'0000'ffff'0000
	uint16_t	dst_vlan;		// index 16 0x0000'0000'0000'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetDstTos			16
#	define MaskDstTos			0xff00000000000000LL
#	define ShiftDstTos  		56

#	define OffsetDir			16
#	define MaskDir				0x00ff000000000000LL
#	define ShiftDir  			48

#	define OffsetMask			16
#	define MaskSrcMask			0x0000ff0000000000LL
#	define ShiftSrcMask  		40

#	define MaskDstMask			0x000000ff00000000LL
#	define ShiftDstMask 		32

#	define OffsetVlan 			16	
#	define MaskSrcVlan  		0x00000000ffff0000LL
#	define ShiftSrcVlan 		16

#	define MaskDstVlan  		0x000000000000ffffLL
#	define ShiftDstVlan 		0

#else
#	define OffsetDstTos			16
#	define MaskDstTos			0x00000000000000ffLL
#	define ShiftDstTos  		0

#	define OffsetDir			16
#	define MaskDir				0x000000000000ff00LL
#	define ShiftDir  			8

#	define OffsetMask			16
#	define MaskSrcMask			0x0000000000ff0000LL
#	define ShiftSrcMask  		16

#	define MaskDstMask			0x00000000ff000000LL
#	define ShiftDstMask 		24

#	define OffsetVlan 			16	
#	define MaskSrcVlan  		0x0000ffff00000000LL
#	define ShiftSrcVlan 		32

#	define MaskDstVlan  		0xffff000000000000LL
#	define ShiftDstVlan 		48

#endif

	// extension 14 / 15
	uint64_t	out_pkts;		// index 17	0xffff'ffff'ffff'ffff
#	define OffsetOutPackets 	17
// MaskPackets and ShiftPackets already defined

	// extension 16 / 17
	uint64_t	out_bytes;		// index 18 0xffff'ffff'ffff'ffff
#	define OffsetOutBytes 		18

	// extension 18 / 19
	uint64_t	aggr_flows;		// index 19 0xffff'ffff'ffff'ffff
#	define OffsetAggrFlows 		19
#	define MaskFlows 	 		0xffffffffffffffffLL

	// extension 20
	uint64_t	in_src_mac;		// index 20 0xffff'ffff'ffff'ffff
#	define OffsetInSrcMAC 		20
#	define MaskMac 	 			0xffffffffffffffffLL

	// extension 20
	uint64_t	out_dst_mac;	// index 21 0xffff'ffff'ffff'ffff
#	define OffsetOutDstMAC 		21

	// extension 21
	uint64_t	in_dst_mac;		// index 22 0xffff'ffff'ffff'ffff
#	define OffsetInDstMAC 		22

	// extension 21
	uint64_t	out_src_mac;	// index 23 0xffff'ffff'ffff'ffff
#	define OffsetOutSrcMAC 		23

	// extension 22
	uint32_t	mpls_label[10];
#	define OffsetMPLS12 		24
#	define OffsetMPLS34 		25
#	define OffsetMPLS56 		26
#	define OffsetMPLS78 		27
#	define OffsetMPLS910 		28

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

	// extension 23 / 24
	ip_addr_t	ip_router;		// ipv4   index 30 0x0000'0000'ffff'ffff
								// ipv6	  index 29 0xffff'ffff'ffff'ffff
								// ipv6	  index 30 0xffff'ffff'ffff'ffff

#ifdef WORDS_BIGENDIAN
#	define OffsetRouterv4 		30
#	define MaskRouterv4  		0x00000000ffffffffLL
#	define ShiftRouterv4 		0

#	define OffsetRouterv6a		29
#	define OffsetRouterv6b		30
// MaskIPv6 and ShiftIPv6 already defined

#else
#	define OffsetRouterv4 		30
#	define MaskRouterv4  		0xffffffff00000000LL
#	define ShiftRouterv4 		0

#	define OffsetRouterv6a		29
#	define OffsetRouterv6b		30
#endif

	uint16_t	sec_group_tag;	// sec group tag index 31 0xffff'0000'0000'0000
	uint8_t		engine_type;	// type index 31 0x0000'ff00'0000'0000
	uint8_t		engine_id;		// ID	index 31 0x0000'00ff'0000'0000

	uint16_t	reserved;

	union {
		struct {
#ifdef WORDS_BIGENDIAN
			uint8_t		icmp_type;	// index 31  0x0000'0000'0000'ff00
			uint8_t		icmp_code;	// index 31  0x0000'0000'0000'00ff
#else
			// little endian confusion ...
			uint8_t		icmp_code;	
			uint8_t		icmp_type;
#endif
		};
		uint16_t icmp;
	};


#	define OffsetRouterID	31
#	define OffsetICMP		31
#ifdef WORDS_BIGENDIAN
#	define MaskEngineType		0x0000FF0000000000LL
#	define ShiftEngineType		40
#	define MaskEngineID			0x000000FF00000000LL
#	define ShiftEngineID		32

#	define MaskICMPtype			0x000000000000FF00LL
#	define ShiftICMPtype 		8
#	define MaskICMPcode			0x00000000000000FFLL
#	define ShiftICMPcode 		0

#else
#	define MaskEngineType		0x0000000000FF0000LL
#	define ShiftEngineType		16
#	define MaskEngineID			0x00000000FF000000LL
#	define ShiftEngineID		24

#	define MaskICMPtype			0xFF00000000000000LL
#	define ShiftICMPtype 		56
#	define MaskICMPcode			0x00FF000000000000LL
#	define ShiftICMPcode 		48
#endif

	// IPFIX extensions in v9
	// BGP next/prev AS
	uint32_t	bgpNextAdjacentAS;	// index 32 0xffff'ffff'0000'0000
	uint32_t	bgpPrevAdjacentAS;	// index 32 0x0000'0000'ffff'ffff

// extension 18
#	define OffsetBGPadj	32
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

	// NSEL extensions
#ifdef NSEL 
#define NSEL_BASE_OFFSET     (offsetof(master_record_t, conn_id) >> 3)

	// common block
#   define OffsetConnID  NSEL_BASE_OFFSET
#   define OffsetNATevent  NSEL_BASE_OFFSET
	uint32_t	conn_id;			// index OffsetConnID    0xffff'ffff'0000'0000
	uint8_t		event;				// index OffsetConnID    0x0000'0000'ff00'0000
#define FW_EVENT 1
#define NAT_EVENT 2
	uint8_t		event_flag;			// index OffsetConnID    0x0000'0000'00ff'0000
	uint16_t	fw_xevent;			// index OffsetConnID    0x0000'0000'0000'ffff
	uint64_t	event_time;			// index OffsetConnID +1 0x1111'1111'1111'1111
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
#ifdef WORDS_BIGENDIAN
#	define MaskXLATESRCPORT	 0xFFFF000000000000LL
#	define ShiftXLATESRCPORT 48
#	define MaskXLATEDSTPORT	 0x0000FFFF00000000LL
#	define ShiftXLATEDSTPORT 32

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0x00000000fFFFFFFFLL
#	define ShiftXLATEIPv4 	 0

#	define OffsetXLATESRCv6a OffsetXLATESRCIP
#	define OffsetXLATESRCv6b OffsetXLATESRCIP+1

#	define OffsetXLATEDSTv6a OffsetXLATESRCIP+2
#	define OffsetXLATEDSTv6b OffsetXLATESRCIP+3

#else
#	define MaskXLATESRCPORT	 0x000000000000FFFFLL
#	define ShiftXLATESRCPORT 0
#	define MaskXLATEDSTPORT	 0x00000000FFFF0000LL
#	define ShiftXLATEDSTPORT 16

#	define OffsetXLATESRCv4	 OffsetXLATESRCIP+1
#	define MaskXLATEIPv4  	 0xFFFFFFFF00000000LL
#	define ShiftXLATEIPv4 	 32

#	define OffsetXLATESRCv6a OffsetXLATESRCIP
#	define OffsetXLATESRCv6b OffsetXLATESRCIP+1

#	define OffsetXLATEDSTv6a OffsetXLATESRCIP+2
#	define OffsetXLATEDSTv6b OffsetXLATESRCIP+3

#endif


	// ingress/egress ACL id
#   define OffsetIngressAclId NSEL_BASE_OFFSET+7
#	define OffsetIngressAceId NSEL_BASE_OFFSET+7
#	define OffsetIngressGrpId NSEL_BASE_OFFSET+8
#	define OffsetEgressAclId  NSEL_BASE_OFFSET+8
#	define OffsetEgressAceId  NSEL_BASE_OFFSET+9
#	define OffsetEgressGrpId  NSEL_BASE_OFFSET+9
	uint32_t ingress_acl_id[3];	// index OffsetIngressAclId   0xffff'ffff'0000'0000
								// index OffsetIngressAceId   0x0000'0000'ffff'ffff
								// index OffsetIngressGrpId   0xffff'ffff'0000'0000
	uint32_t egress_acl_id[3];	// index OffsetEgressAclId	  0x0000'0000'ffff'ffff
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
#define NAT_BASE_OFFSET     (offsetof(master_record_t, ingress_vrfid) >> 3)
	// common block
#   define OffsetNELcommon  NEL_BASE_OFFSET
#   define OffsetIVRFID  	NAT_BASE_OFFSET
#   define OffsetEVRFID  	NAT_BASE_OFFSET
#   define OffsetPortBlock	NAT_BASE_OFFSET+1
	uint32_t	ingress_vrfid;	// OffsetIVRFID	   0xffff'ffff'0000'0000
	uint32_t	egress_vrfid;	// OffsetEVRFID	   0x0000'0000'ffff'ffff

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

	// flow received time in ms
	uint64_t	received;

/* possible user extensions may fit here
 * - Put each extension into its own #ifdef
 * - Define the base offset for the user extension as reference to the first object
 * - Refer to this base offset for each of the values in the master record for the extension
 * - make sure the extension is 64bit aligned
 * - The user extension must be independant of the number of user extensions already defined
 * - the extension map must be updated accordingly
 */

#ifdef USER_EXTENSION_1
	uint64_t	u64_1;
#	define Offset_BASE_U1	offsetof(master_record_t, u64_1)
#	define OffsetUser1_u64	Offset_BASE_U1
	
	uint32_t	u32_1;
	uint32_t	u32_2;
#	define OffsetUser1_u32_1	Offset_BASE_U1 + 8
#	define MaskUser1_u32_1 		0xffffffff00000000LL
#	define MaskUser1_u32_2 		0x00000000ffffffffLL

#endif

	// reference to exporter
	exporter_info_record_t	*exp_ref;

	// last entry in master record 
#	define Offset_MR_LAST	offsetof(master_record_t, map_ref)
	extension_map_t	*map_ref;

	// optional flowlabel
	char	*label;
} master_record_t;

// convenience type conversion record 
typedef struct type_mask_s {
	union {
		uint8_t		val8[8];
		uint16_t	val16[4];
		uint32_t	val32[2];
		uint64_t	val64;
	} val;
} type_mask_t;


#endif //_NFDUMP_H

