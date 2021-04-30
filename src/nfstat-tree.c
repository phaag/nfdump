/*  
 *  Copyright (c) 2009-2020, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "rbtree.h"
#include "nfxV3.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "nfnet.h"
#include "output_util.h"
#include "nflowcache.h"
#include "nfstat.h"
#include "blocksort.h"
#include "memhandle.h"

extern int hash_hit;
extern int hash_miss;
extern int hash_skip;

typedef struct statNode {
	RB_ENTRY(statNode) entry;
	uint64_t value[3];

	// node stats
	uint64_t	counter[5];
	uint64_t	msecFirst;
	uint64_t	msecLast;
	uint8_t		record_flags;
	uint8_t		tcp_flags;
	uint8_t		tos;
} StatRecord_t;

static int statNodeCMP(struct statNode *s1, struct statNode *s2);

typedef RB_HEAD(StatTree, statNode) StatTree_t;

RB_PROTOTYPE(StatTree, statNode, entry, statNodeCMP);

RB_GENERATE(StatTree, statNode, entry, statNodeCMP);

static int statNodeCMP(struct statNode *s1, struct statNode *s2) {
	if ( s1->value[0] < s2->value[0] )
		return -1;
	if ( s1->value[0] > s2->value[0] )
		return 1;

	if ( s1->value[1] < s2->value[1] )
		return -1;
	if ( s1->value[1] > s2->value[1] )
		return 1;
	return 0;
	// return memcmp((void *)&s1->value, (void *)&s2->value, 3 * sizeof(uint64_t));
}

/*
 * Stat Table
 * In order to generate any flow element statistics, the flows passed the filter
 * are stored into an internal hash table.
 */

#define MaxMemBlocks	256
typedef struct StatTable_s {
	// rb tree
	StatTree_t	*StatTree;		// rb tree
	struct statNode *node;		// 
	uint32_t	NumElements;	/// number of elements in tree
} StatTable_t;

struct flow_element_s {
	uint32_t	offset0;
	uint32_t	offset1;	// set in the netflow record block
	uint64_t	mask;		// mask for value in 64bit word
	uint32_t	shift;		// number of bits to shift right to get final value
};

enum { IS_NUMBER = 1, IS_IPADDR, IS_MACADDR, IS_MPLS_LBL, IS_LATENCY, IS_EVENT, IS_HEX};

struct StatParameter_s {
	char					*statname;		// name of -s option
	char					*HeaderInfo;	// How to name the field in the output header line
	struct flow_element_s	element[2];		// what element(s) in flow record is used for statistics.
											// need 2 elements to be able to get src/dst stats in one stat record
	uint8_t					num_elem;		// number of elements used. 1 or 2
	uint8_t					type;			// Type of element: Number, IP address, MAC address etc. 
} StatParameters[] ={
	// flow record stat
	{ "record",	 "", 			
		{ {0,0, 0,0},										{0,0,0,0} },
			1, 0},

	// 9 possible flow element stats 
	{ "srcip",	 "Src IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "dstip",	 "Dst IP Addr", 
		{ {OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "ip",	 	"IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6} },
			2, IS_IPADDR },

	{ "nhip",	 "Nexthop IP", 
		{ {OffsetNexthopv6a, OffsetNexthopv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "nhbip",	 "Nexthop BGP IP", 
		{ {OffsetBGPNexthopv6a, OffsetBGPNexthopv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "router",	 "Router IP", 
		{ {OffsetRouterv6a, OffsetRouterv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR },

	{ "srcport", "Src Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstport", "Dst Port", 
		{ {0, OffsetPort, MaskDstPort, ShiftDstPort}, 		{0,0,0,0} },
			1, IS_NUMBER },

	{ "port", 	 "Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0, OffsetPort, MaskDstPort, ShiftDstPort}},
			2, IS_NUMBER },

	{ "proto", 	 "Protocol", 
		{ {0, OffsetProto, MaskProto, ShiftProto}, 			{0,0,0,0} },
			1, IS_NUMBER },

	{ "tos", 	 "Tos", 
		{ {0, OffsetTos, MaskTos, ShiftTos}, 				{0,0,0,0} },
			1, IS_NUMBER },

	{ "srctos",  "Tos", 
		{ {0, OffsetTos, MaskTos, ShiftTos}, 				{0,0,0,0} },
			1, IS_NUMBER },

	{ "dsttos",	 "Dst Tos", 
		{ {0, OffsetDstTos, MaskDstTos, ShiftDstTos},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dir",	 "Dir", 
		{ {0, OffsetDir, MaskDir, ShiftDir},		  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "srcas",	 "Src AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},		  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstas",	 "Dst AS", 
		{ {0, OffsetAS, MaskDstAS, ShiftDstAS},  	  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "prevas",	 "Prev AS", 
		{ {0, OffsetBGPadj, MaskBGPadjPrev, ShiftBGPadjPrev},		  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "nextas",	 "Next AS", 
		{ {0, OffsetBGPadj, MaskBGPadjNext, ShiftBGPadjNext},  	  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "as",	 	 "AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},  	  		{0, OffsetAS, MaskDstAS, ShiftDstAS} },
			2, IS_NUMBER },

	{ "inif", 	 "Input If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput}, 			{0,0,0,0} },
			1, IS_NUMBER },

	{ "outif", 	 "Output If", 
		{ {0, OffsetInOut, MaskOutput, ShiftOutput},		{0,0,0,0} },
			1, IS_NUMBER },

	{ "if", 	 "In/Out If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput},			{0, OffsetInOut, MaskOutput, ShiftOutput} },
			2, IS_NUMBER },

	{ "srcmask",	 "Src Mask", 
		{ {0, OffsetMask, MaskSrcMask, ShiftSrcMask},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstmask",	 "Dst Mask", 
		{ {0, OffsetMask, MaskDstMask, ShiftDstMask},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "mask",	 "Mask", 
		{ {0, OffsetMask, MaskSrcMask, ShiftSrcMask},  		{0, OffsetMask, MaskDstMask, ShiftDstMask} },
			2, IS_NUMBER },

	{ "srcvlan",	 "Src Vlan", 
		{ {0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "dstvlan",	 "Dst Vlan", 
		{ {0, OffsetVlan, MaskDstVlan, ShiftDstVlan},  		{0,0,0,0} },
			1, IS_NUMBER },

	{ "vlan",	 "Vlan", 
		{ {0, OffsetVlan, MaskSrcVlan, ShiftSrcVlan},  		{0, OffsetVlan, MaskDstVlan, ShiftDstVlan} },
			2, IS_NUMBER },

	{ "insrcmac",	 "In Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "outdstmac",	 "Out Dst Mac", 
		{ {0, OffsetOutDstMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "indstmac",	 "In Dst Mac", 
		{ {0, OffsetInDstMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "outsrcmac",	 "Out Src Mac", 
		{ {0, OffsetOutSrcMAC, MaskMac, 0},  		{0,0,0,0} },
			1, IS_MACADDR },

	{ "srcmac",	 "Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0, OffsetOutSrcMAC, MaskMac, 0}},
			2, IS_MACADDR },

	{ "dstmac",	 "Dst Mac", 
		{ {0, OffsetOutDstMAC, MaskMac, 0},  		{0, OffsetInDstMAC, MaskMac, 0} },
			2, IS_MACADDR },

	{ "inmac",	 "In Src Mac", 
		{ {0, OffsetInSrcMAC, MaskMac, 0},  		{0, OffsetInDstMAC, MaskMac, 0} },
			1, IS_MACADDR },

	{ "outmac",	 "Out Src Mac", 
		{ {0, OffsetOutSrcMAC, MaskMac, 0},  		{0, OffsetOutDstMAC, MaskMac, 0} },
			2, IS_MACADDR },

	{ "mpls1",	 " MPLS lab 1", 
		{ {0, OffsetMPLS12, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls2",	 " MPLS lab 2", 
		{ {0, OffsetMPLS12, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls3",	 " MPLS lab 3", 
		{ {0, OffsetMPLS34, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls4",	 " MPLS lab 4", 
		{ {0, OffsetMPLS34, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls5",	 " MPLS lab 5", 
		{ {0, OffsetMPLS56, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls6",	 " MPLS lab 6", 
		{ {0, OffsetMPLS56, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls7",	 " MPLS lab 7", 
		{ {0, OffsetMPLS78, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls8",	 " MPLS lab 8", 
		{ {0, OffsetMPLS78, MaskMPLSlabelEven, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls9",	 " MPLS lab 9", 
		{ {0, OffsetMPLS910, MaskMPLSlabelOdd, 0}, 	{0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "mpls10",	 "MPLS lab 10", 
		{ {0, OffsetMPLS910, MaskMPLSlabelEven, 0}, {0,0,0,0} },
			1, IS_MPLS_LBL },

	{ "cl",	 "Client Latency", 
		{ {0, OffsetClientLatency, MaskLatency, 0}, {0,0,0,0} },
			1, IS_LATENCY },

	{ "sl",	 "Server Latency", 
		{ {0, OffsetServerLatency, MaskLatency, 0}, {0,0,0,0} },
			1, IS_LATENCY },

	{ "al",	 "  Appl Latency", 
		{ {0, OffsetAppLatency, MaskLatency, 0}, {0,0,0,0} },
			1, IS_LATENCY },

#ifdef NSEL
	{ "event", " Event", 
		{ {0, OffsetConnID, MaskFWevent, ShiftFWevent}, 		{0,0,0,0} },
			1, IS_EVENT},

	{ "nevent", " Event", 
		{ {0, OffsetConnID, MaskFWevent, ShiftFWevent}, 		{0,0,0,0} },
			1, IS_EVENT},

	{ "xevent", "X-Event", 
		{ {0, OffsetConnID, MaskFWXevent, ShiftFWXevent}, 		{0,0,0,0} },
			1, IS_NUMBER},

	{ "xsrcip",	 "X-Src IP Addr", 
		{ {OffsetXLATESRCv6a, OffsetXLATESRCv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR},

	{ "xdstip",	 "X-Dst IP Addr", 
		{ {OffsetXLATEDSTv6a, OffsetXLATEDSTv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR},

	{ "xsrcport", " X-Src Port", 
		{ {0, OffsetXLATEPort, MaskXLATESRCPORT, ShiftXLATESRCPORT}, 		{0,0,0,0} },
			1, IS_NUMBER},

	{ "xdstport", " X-Dst Port", 
		{ {0, OffsetXLATEPort, MaskXLATEDSTPORT, ShiftXLATEDSTPORT}, 		{0,0,0,0} },
			1, IS_NUMBER},

	{ "iacl", "Ingress ACL", 
		{ {0, OffsetIngressAclId, MaskIngressAclId, ShiftIngressAclId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "iace", "Ingress ACE", 
		{ {0, OffsetIngressAceId, MaskIngressAceId, ShiftIngressAceId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "ixace", "Ingress xACE", 
		{ {0, OffsetIngressGrpId, MaskIngressGrpId, ShiftIngressGrpId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "eacl", "Egress ACL", 
		{ {0, OffsetEgressAclId, MaskEgressAclId, ShiftEgressAclId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "eace", "Egress ACE", 
		{ {0, OffsetEgressAceId, MaskEgressAceId, ShiftEgressAceId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "exace", "Egress xACE", 
		{ {0, OffsetEgressGrpId, MaskEgressGrpId, ShiftEgressGrpId}, 		{0,0,0,0} },
			1, IS_HEX},

	{ "ivrf", " I-vrf-ID", 
		{ {0, OffsetIVRFID, MaskIVRFID, ShiftIVRFID}, 		{0,0,0,0} },
			1, IS_NUMBER},

	{ "evrf", " E-vrf-ID", 
		{ {0, OffsetEVRFID, MaskEVRFID, ShiftEVRFID}, 		{0,0,0,0} },
			1, IS_NUMBER},

// keep the following stats strings for compate v1.6.10 -> merged NSEL
	{ "nsrcip",	 "X-Src IP Addr", 
		{ {OffsetXLATESRCv6a, OffsetXLATESRCv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR},

	{ "ndstip",	 "X-Dst IP Addr", 
		{ {OffsetXLATEDSTv6a, OffsetXLATEDSTv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, IS_IPADDR},

	{ "nsrcport", " X-Src Port", 
		{ {0, OffsetXLATEPort, MaskXLATESRCPORT, ShiftXLATESRCPORT}, 		{0,0,0,0} },
			1, IS_NUMBER},

	{ "ndstport", " X-Dst Port", 
		{ {0, OffsetXLATEPort, MaskXLATEDSTPORT, ShiftXLATEDSTPORT}, 		{0,0,0,0} },
			1, IS_NUMBER},

#endif

	{ NULL, 	 NULL, 			
		{ {0,0,0,0},	{0,0,0,0} },
			1, 0 }
};

enum CntIndices { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };
enum FlowDir 	{ IN = 0, OUT, INOUT };

#define MaxStats 16
struct StatRequest_s {
	uint32_t	order_bits;		// bits 0: flows 1: packets 2: bytes 3: pps 4: bps, 5 bpp
	int16_t		StatType;		// index into StatParameters
	uint8_t		order_proto;	// protocol separated statistics
} StatRequest[MaxStats];		// This number should do it for a single run


/* 
 * pps, bps and bpp are not directly available in the flow/stat record
 * therefore we need a function to calculate these values
 */
typedef uint64_t (*order_proc_record_t)(FlowTableRecord_t *, int);
typedef uint64_t (*order_proc_element_t)(StatRecord_t *, int);

/* order functions */
static inline uint64_t	null_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	flows_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	packets_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	bytes_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	pps_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	bps_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	bpp_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	tstart_record(FlowTableRecord_t *record, int inout);
static inline uint64_t	tend_record(FlowTableRecord_t *record, int inout);
// static inline uint64_t	clat_record(FlowTableRecord_t *record, int inout);

static inline uint64_t	null_element(StatRecord_t *record, int inout);
static inline uint64_t	flows_element(StatRecord_t *record, int inout);
static inline uint64_t	packets_element(StatRecord_t *record, int inout);
static inline uint64_t	bytes_element(StatRecord_t *record, int inout);
static inline uint64_t	pps_element(StatRecord_t *record, int inout);
static inline uint64_t	bps_element(StatRecord_t *record, int inout);
static inline uint64_t	bpp_element(StatRecord_t *record, int inout);

#define ASCENDING 1
#define DESCENDING 0
struct order_mode_s {
	char *string;	// Stat name 
	int	 inout;		// use IN or OUT or INOUT packets/bytes
	int	 direction;	// ascending or descending
	order_proc_record_t  record_function;	// Function to call for record stats
	order_proc_element_t element_function;	// Function to call for element stats
} order_mode[] = {
	{ "-",			0,	0, null_record, null_element},	// empty entry 0
	{ "flows",		IN,	DESCENDING, flows_record, flows_element},
	{ "packets",		INOUT,	DESCENDING, packets_record, packets_element},
	{ "ipkg",		IN,	DESCENDING, packets_record, packets_element},
	{ "opkg",		OUT,	DESCENDING, packets_record, packets_element},
	{ "bytes",		INOUT,	DESCENDING, bytes_record, bytes_element},
	{ "ibyte",		IN,	DESCENDING, bytes_record, bytes_element},
	{ "obyte",		OUT,	DESCENDING, bytes_record, bytes_element},
	{ "pps",		INOUT,	DESCENDING, pps_record, pps_element},
	{ "ipps",		IN,	DESCENDING, pps_record, pps_element},
	{ "opps",		OUT,	DESCENDING, pps_record, pps_element},
	{ "bps",		INOUT,	DESCENDING, bps_record, bps_element},
	{ "ibps",		IN,	DESCENDING, bps_record, bps_element},
	{ "obps",		OUT,	DESCENDING, bps_record, bps_element},
	{ "bpp",		INOUT,	DESCENDING, bpp_record, bpp_element},
	{ "ibpp",		IN,	DESCENDING, bpp_record, bpp_element},
	{ "obpp",		OUT,	DESCENDING, bpp_record, bpp_element},
	{ "tstart",		0,	ASCENDING,  tstart_record, null_element},
	{ "tend",		0,	ASCENDING,  tend_record, null_element},
//	{ "clat",		0,	DESCENDING,  clat_record, null_element},
	{ NULL,			0,		0,	 NULL, NULL}
};
#define Default_PrintOrder 1
static uint32_t	print_order_bits = 0;
static uint32_t	PrintOrder 		 = 0;
static uint32_t	GuessDirection 	 = 0;
static uint32_t	NumStats 		 = 0;

static uint64_t	byte_limit, packet_limit;
static int byte_mode, packet_mode;
enum { NONE = 0, LESS, MORE };

/* function prototypes */
static int ParseStatString(char *str, int16_t	*StatType, int *flow_record_stat, uint16_t *order_proto);

static inline void PrintSortedFlowcache(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, 
		int GuessFlowDirection, printer_t print_record, int ascending);

static void PrintStatLine(stat_record_t	*stat, uint32_t printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static void PrintCvsStatLine(stat_record_t	*stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout);

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order );

/* locals */
static StatTable_t *StatTable   = NULL;
static MemHandler_t *MemHandler = NULL;

/* Functions */

#include "nffile_inline.c"
#include "memhandle.c"
#include "applybits_inline.c"


static uint64_t	null_record(FlowTableRecord_t *record, int inout) {
	return 0;
}

static uint64_t	flows_record(FlowTableRecord_t *record, int inout) {
	return record->counter[FLOWS];
}

static uint64_t	packets_record(FlowTableRecord_t *record, int inout) {
	if (NeedSwap(GuessDirection, record)) {
		if (inout == IN)
			inout = OUT;
		else if (inout == OUT)
			inout = IN;
	}
	if (inout == IN)
		return record->counter[INPACKETS];
	else if (inout == OUT)
		return record->counter[OUTPACKETS];
	else
		return record->counter[INPACKETS] + record->counter[OUTPACKETS];
}

static uint64_t	bytes_record(FlowTableRecord_t *record, int inout) {
	if (NeedSwap(GuessDirection, record)) {
		if (inout == IN)
			inout = OUT;
		else if (inout == OUT)
			inout = IN;
	}
	if (inout == IN)
		return record->counter[INBYTES];
	else if (inout == OUT)
		return record->counter[OUTBYTES];
	else
		return record->counter[INBYTES] + record->counter[OUTBYTES];
}

static uint64_t	pps_record(FlowTableRecord_t *record, int inout) {
uint64_t		duration;
uint64_t		packets;

	/* duration in msec */
	duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		return 0;
	else {
	        packets = packets_record(record, inout);
		return ( 1000LL * packets ) / duration;
	}
} // End of pps_record

static uint64_t	bps_record(FlowTableRecord_t *record, int inout) {
uint64_t		duration;
uint64_t		bytes;

	duration = record->msecLast - record->msecLast;
	if ( duration == 0 )
		return 0;
	else {
		bytes = bytes_record(record, inout);
		return ( 8000LL * bytes ) / duration;	/* 8 bits per Octet - x 1000 for msec */
	}
} // End of bps_record

static uint64_t	bpp_record(FlowTableRecord_t *record, int inout) {
uint64_t packets = packets_record(record, inout);
uint64_t bytes = bytes_record(record, inout);

	return packets ? bytes / packets : 0;
} // End of bpp_record

static uint64_t	tstart_record(FlowTableRecord_t *record, int inout) {
	return record->msecFirst;
} // End of tstart_record

static uint64_t	tend_record(FlowTableRecord_t *record, int inout) {
	return record->msecLast;
} // End of tend_record

static uint64_t	null_element(StatRecord_t *record, int inout) {
	return 0;
}

static uint64_t	flows_element(StatRecord_t *record, int inout) {
	return record->counter[FLOWS];
}

static uint64_t	packets_element(StatRecord_t *record, int inout) {
	if (inout == IN)
		return record->counter[INPACKETS];
	else if (inout == OUT)
		return record->counter[OUTPACKETS];
	else
		return record->counter[INPACKETS] + record->counter[OUTPACKETS];
}

static uint64_t	bytes_element(StatRecord_t *record, int inout) {
	if (inout == IN)
		return record->counter[INBYTES];
	else if (inout == OUT)
		return record->counter[OUTBYTES];
	else
		return record->counter[INBYTES] + record->counter[OUTBYTES];
}

static uint64_t	pps_element(StatRecord_t *record, int inout) {
uint64_t		duration;
uint64_t		packets;

	/* duration in msec */
	duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		return 0;
	else {
		packets = packets_element(record, inout);
		return ( 1000LL * packets ) / duration;
	}

} // End of pps_element

static uint64_t	bps_element(StatRecord_t *record, int inout) {
uint64_t		duration;
uint64_t		bytes;

	duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		return 0;
	else {
        bytes = bytes_element(record, inout);
		return ( 8000LL * bytes ) / duration;	/* 8 bits per Octet - x 1000 for msec */
	}

} // End of bps_element

static uint64_t	bpp_element(StatRecord_t *record, int inout) {
uint64_t packets = packets_element(record, inout);
uint64_t bytes = bytes_element(record, inout);

	return packets ? bytes / packets : 0;

} // End of bpp_element

void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string ) {
char 		*s, c;
uint32_t	len,scale;

	if ( ( stat == 0 ) && ( packet_limit_string || byte_limit_string )) {
		fprintf(stderr,"Options -l and -L do not make sense for plain packet dumps.\n");
		fprintf(stderr,"Use -l and -L together with -s -S or -a.\n");
		fprintf(stderr,"Use netflow filter syntax to limit the number of packets and bytes in netflow records.\n");
		exit(250);
	}
	packet_limit = byte_limit = 0;
	if ( packet_limit_string ) {
		switch ( packet_limit_string[0] ) {
			case '-':
				packet_mode = LESS;
				s = &packet_limit_string[1];
				break;
			case '+':
				packet_mode = MORE;
				s = &packet_limit_string[1];
				break;
			default:
				if ( !isdigit((int)packet_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", packet_limit_string);
					exit(250);
				}
				packet_mode = MORE;
				s = packet_limit_string;
		}
		len = strlen(packet_limit_string);
		c = packet_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1000;
				break;
			case 'M':
			case 'm':
				scale = 1000 * 1000;
				break;
			case 'G':
			case 'g':
				scale = 1000 * 1000 * 1000;
				break;
			default:
				scale = 1;
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, packet_limit_string);
					exit(250);
				}
		}
		packet_limit = (uint64_t)atol(s) * (uint64_t)scale;
	}

	if ( byte_limit_string ) {
		switch ( byte_limit_string[0] ) {
			case '-':
				byte_mode = LESS;
				s = &byte_limit_string[1];
				break;
			case '+':
				byte_mode = MORE;
				s = &byte_limit_string[1];
				break;
			default:
				if ( !isdigit((int)byte_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", byte_limit_string);
					exit(250);
				}
				byte_mode = MORE;
				s = byte_limit_string;
		}
		len = strlen(byte_limit_string);
		c = byte_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1000;
				break;
			case 'M':
			case 'm':
				scale = 1000 * 1000;
				break;
			case 'G':
			case 'g':
				scale = 1000 * 1000 * 1000;
				break;
			default:
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, byte_limit_string);
					exit(250);
				}
				scale = 1;
		}
		byte_limit = (uint64_t)atol(s) * (uint64_t)scale;
	}

	if ( byte_limit )
		printf("Byte limit: %c %llu bytes\n", byte_mode == LESS ? '<' : '>', (long long unsigned)byte_limit);

	if ( packet_limit )
		printf("Packet limit: %c %llu packets\n", packet_mode == LESS ? '<' : '>', (long long unsigned)packet_limit);


} // End of SetLimits

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc) {
int hash_num;

	StatTable = (StatTable_t *)calloc(NumStats, sizeof(StatTable_t));
	if ( !StatTable ) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	MemHandler = MemHandler_Init(NumStats * Prealloc * sizeof(StatRecord_t));
	if ( !MemHandler ) 
		return 0;

	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		StatTable[hash_num].NumElements  = 0;

		StatTable[hash_num].StatTree = calloc(1, sizeof(StatTree_t));
		if ( !StatTable[hash_num].StatTree ) {
        	LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}
		RB_INIT(StatTable[hash_num].StatTree);
	}

	return 1;

} // End of Init_StatTable

void Dispose_StatTable() {

	if ( StatTable ) {
		for ( int hash_num=0; hash_num<NumStats; hash_num++ ) {
			// 
		}
	}
	if ( MemHandler ) 
		MemHandler_free(MemHandler);

} // End of Dispose_Tables

int SetStat(char *str, int *element_stat, int *flow_stat) {
int			flow_record_stat = 0;
int16_t 	StatType    = 0;
uint16_t	order_proto = 0;

	if ( NumStats == MaxStats ) {
		fprintf(stderr, "Too many stat options! Stats are limited to %i stats per single run!\n", MaxStats);
		return 0;
	}

	print_order_bits = 0;
	if ( ParseStatString(str, &StatType, &flow_record_stat, &order_proto) ) {
		if ( flow_record_stat ) {
			if ( !print_order_bits ) {
				int bit = 1 << PrintOrder;
				print_order_bits = PrintOrder ? bit : Default_PrintOrder;
			}
			*flow_stat = 1;
		} else {
			StatRequest[NumStats].StatType 	  = StatType;
			StatRequest[NumStats].order_bits  = print_order_bits;
			StatRequest[NumStats].order_proto = order_proto;
			NumStats++;
			*element_stat = 1;
		}
		return 1;
	} else {
		fprintf(stderr, "Unknown stat: '%s'!\n", str);
		return 0;
	}

} // End of SetStat

static int ParseStatString(char *str, int16_t	*StatType, int *flow_record_stat, uint16_t *order_proto) {
char	*s, *p, *q, *r;
int i=0;

	print_order_bits = 0;
	if ( NumStats >= MaxStats )
		return 0;

	s = strdup(str);
	q = strchr(s, '/');
	if ( q ) 
		*q = 0;

	*order_proto = 0;
	p = strchr(s, ':');
	if ( p ) {
		*p = 0;
		*order_proto = 1;
	}

	i = 0;
	// check for a valid stat name
	while ( StatParameters[i].statname ) {
		if ( strncasecmp(s, StatParameters[i].statname ,16) == 0 ) {
			// set flag if it's the flow record stat request
			*flow_record_stat = strncasecmp(s, "record", 16) == 0;
			break;
		}
		i++;
	}

	// if so - initialize type and order_bits
 	if ( StatParameters[i].statname ) {
		*StatType = i;
		if ( strncasecmp(StatParameters[i].statname, "proto", 16) == 0 ) 
			*order_proto = 1;
	} else {
		free(s);
		return 0;
	}

	// no order is given - default order applies;
	if ( !q ) {
		q = "/flows";  // default to flows
	}

	// check if one or more orders are given
	r = ++q;
	if ( ParseListOrder(r, MULTIPLE_LIST_ORDERS ) == 1 ) {
		free(s);
		return 1;
	} else {
		free(s);
		return 0;
	}

} // End of ParseStatString

int ParseListOrder(char *s, int multiple_orders ) {
char *q;
uint32_t order_bits;

	order_bits = 0;
	while ( s ) {
		int i;
		q = strchr(s, '/');
		if ( q && !multiple_orders ) {
			return -1;
		}
		if ( q ) 
			*q = 0;
		i = 0;
		while ( order_mode[i].string ) {
			if (  strcasecmp(order_mode[i].string, s ) == 0 )
				break;
			i++;
		}
		if ( order_mode[i].string ) {
			order_bits |= (1<<i);
		} else {
			return 0;
		}

		if ( !q ) {
			print_order_bits = order_bits;
			return 1;
		}

		s = ++q;
	}
	
	// not reached
	return 1;

} // End of ParseListOrder

int Parse_PrintOrder(char *order) {

	PrintOrder = 0;
	while ( order_mode[PrintOrder].string ) {
		if (  strcasecmp(order_mode[PrintOrder].string, order ) == 0 )
			break;
		PrintOrder++;
	}
	if ( !order_mode[PrintOrder].string ) {
		PrintOrder = 0;
		return -1;
	}

	return PrintOrder;

} // End of Parse_PrintOrder

void AddStat(master_record_t *flow_record ) {
uint64_t			value[2][2];
int	j, i;

	// for every requested -s stat do
	for ( j=0; j<NumStats; j++ ) {
		int stat   = StatRequest[j].StatType;
		// for the number of elements in this stat type
		for ( i=0; i<StatParameters[stat].num_elem; i++ ) {
			uint32_t offset = StatParameters[stat].element[i].offset1;
			uint64_t mask	= StatParameters[stat].element[i].mask;
			uint32_t shift	= StatParameters[stat].element[i].shift;

			value[i][1] = (((uint64_t *)flow_record)[offset] & mask) >> shift;
			offset = StatParameters[stat].element[i].offset0;
			value[i][0] = offset ? ((uint64_t *)flow_record)[offset] : 0;

			/* 
			 * make sure each flow is counted once only
			 * if src and dst have the same values, count it once only
			 */
			if ( i == 1 && value[0][0] == value[1][0] && value[0][1] == value[1][1] ) {
				break;
			}

			struct statNode *node;
			if ( StatTable[j].node )
				node = StatTable[j].node;
			else
				node = MemHandler_get(MemHandler, sizeof(struct statNode));

			node->value[0] = value[i][0];
			node->value[1] = value[i][1];
			node->value[2] = flow_record->proto;

			struct statNode *n = RB_INSERT(StatTree, StatTable[j].StatTree, node);
			if ( n == NULL ) {
				// inserted new node - set values
				node->counter[INBYTES]   = flow_record->dOctets;
				node->counter[INPACKETS] = flow_record->dPkts;
				node->counter[OUTBYTES]  = flow_record->out_bytes;
				node->counter[OUTPACKETS]= flow_record->out_pkts;
				node->msecFirst			 = flow_record->msecFirst; 
				node->msecLast			 = flow_record->msecLast;
				node->record_flags		 = flow_record->flags & 0x1;
				node->counter[FLOWS]	 = flow_record->aggr_flows ? flow_record->aggr_flows : 1;
				StatTable[j].NumElements++;
				StatTable[j].node = NULL;
			} else {
				// node exist in tree - update values
				n->counter[INBYTES] 	  += flow_record->dOctets;
				n->counter[INPACKETS]  += flow_record->dPkts;
				n->counter[OUTBYTES]   += flow_record->out_bytes;
				n->counter[OUTPACKETS] += flow_record->out_pkts;
		
				if (flow_record->msecFirst < n->msecFirst )  {
					n->msecFirst	= flow_record->msecFirst;
				}
				if (flow_record->msecLast > n->msecLast) {
					n->msecLast	= flow_record->msecLast;
				}
				node->counter[FLOWS] += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
				StatTable[j].node = node;
			}

		} // for the number of elements in this stat type
	} // for every requested -s stat

} // End of AddStat

static void PrintStatLine(stat_record_t	*stat, uint32_t printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
char		valstr[40], datestr[64];
char		flows_str[NUMBER_STRING_SIZE], byte_str[NUMBER_STRING_SIZE], packets_str[NUMBER_STRING_SIZE];
char		pps_str[NUMBER_STRING_SIZE], bps_str[NUMBER_STRING_SIZE];
char tag_string[2];
uint64_t	count_flows, count_packets, count_bytes;
double		duration, flows_percent, packets_percent, bytes_percent;
uint32_t	bpp;
uint64_t	pps, bps;
time_t		first;
struct tm	*tbuff;

	tag_string[0] = '\0';
	tag_string[1] = '\0';
	switch (type) {
		case NONE:
			break;
		case IS_NUMBER:
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->value[1]);
			break;
		case IS_IPADDR:
			tag_string[0] = tag ? TAG_CHAR : '\0';
			if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
				uint64_t	_key[2];
				_key[0] = htonll(StatData->value[0]);
				_key[1] = htonll(StatData->value[1]);
				inet_ntop(AF_INET6, _key, valstr, sizeof(valstr));
				if ( ! Getv6Mode() )
					CondenseV6(valstr);
	
			} else {	// IPv4
				uint32_t	ipv4;
				ipv4 = htonl(StatData->value[1]);
				inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
			}
			break;
		case IS_MACADDR: {
			int i;
			uint8_t mac[6];
			for ( i=0; i<6; i++ ) {
				mac[i] = ((unsigned long long)StatData->value[1] >> ( i*8 )) & 0xFF;
			}
			snprintf(valstr, 40, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
			} break;
		case IS_MPLS_LBL: {
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->value[1]);
			snprintf(valstr, 40,"%8llu-%1llu-%1llu", 
				(unsigned long long)StatData->value[1] >> 4 , 
				((unsigned long long)StatData->value[1] & 0xF ) >> 1, 
				(unsigned long long)StatData->value[1] & 1);
			} break;
		case IS_LATENCY: {
			snprintf(valstr, 40, "      %9.3f", (double)((double)StatData->value[1]/1000.0));
			} break;
#ifdef NSEL
		case IS_EVENT: {
			long long unsigned event = StatData->value[1];
			char *s;
			switch(event) {
				case 0:
					s = "ignore";
					break;
				case 1:
					s = "CREATE";
					break;
				case 2:
					s = "DELETE";
					break;
				case 3:
					s = "DENIED";
					break;
				default:
					s = "UNKNOWN";
			}			
			snprintf(valstr, 40, "      %6s", s);
			} break;
#endif
		case IS_HEX: {
			snprintf(valstr, 40, "0x%llx", (unsigned long long)StatData->value[1]);
		} break;
	}

	valstr[39] = 0;
	count_flows = StatData->counter[FLOWS];
	count_packets = packets_element(StatData, inout);
	count_bytes = bytes_element(StatData, inout);
	format_number(count_flows, flows_str, printPlain, FIXED_WIDTH);
	format_number(count_packets, packets_str, printPlain, FIXED_WIDTH);
	format_number(count_bytes, byte_str, printPlain, FIXED_WIDTH);

	flows_percent   = stat->numflows   ? (double)(count_flows * 100 ) / (double)stat->numflows : 0;
	if ( stat->numpackets ) {
		packets_percent  = (double)(count_packets * 100 ) / (double)stat->numpackets;
	} else {
		packets_percent  = 0;
	}

	if ( stat->numbytes ) {
		bytes_percent  = (double)(count_bytes * 100 ) / (double)stat->numbytes;
	} else {
		bytes_percent  = 0;
	}

	duration = (StatData->msecLast - StatData->msecFirst);
	if ( duration != 0 ) {
		pps  = (uint64_t)((double)count_packets / duration);
		bps  = (uint64_t)((double)(8 * count_bytes) / duration);
	} else {
		pps  = bps  = 0;
	}

	if (count_packets) {
		bpp = count_bytes / count_packets;
	} else {
		bpp = 0;
	}

	format_number(pps, pps_str, printPlain, FIXED_WIDTH);
	format_number(bps, bps_str, printPlain, FIXED_WIDTH);

	first = StatData->msecFirst / 1000LL;
	tbuff = localtime(&first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	if ( Getv6Mode() && ( type == IS_IPADDR ) )
		printf("%s.%03u %9.3f %-5s %s%39s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n", 
			datestr, (unsigned)(StatData->msecFirst % 1000), duration / 1000.0,
			order_proto ? ProtoString(StatData->value[2], printPlain) : "any", tag_string, valstr, 
			flows_str, flows_percent, packets_str, packets_percent, byte_str,
			bytes_percent, pps_str, bps_str, bpp );
	else {
		printf("%s.%03u %9.3f %-5s %s%17s %8s(%4.1f) %8s(%4.1f) %8s(%4.1f) %8s %8s %5u\n",
		datestr, (unsigned)(StatData->msecFirst % 1000), duration / 1000.0,
		order_proto ? ProtoString(StatData->value[2], printPlain) : "any", tag_string, valstr,
		flows_str, flows_percent, packets_str, packets_percent, byte_str,
		bytes_percent, pps_str, bps_str, bpp );
	}

} // End of PrintStatLine

static void PrintPipeStatLine(StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
double		duration;
uint64_t	count_flows, count_packets, count_bytes, _key[2];
uint32_t	pps, bps, bpp;
uint32_t	sa[4];
int			af;

	sa[0] = sa[1] = sa[2] = sa[3] = 0;
	af = AF_UNSPEC;
	_key[0] = StatData->value[0];
	_key[1] = StatData->value[1];
	if ( type == IS_IPADDR ) {
		if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
			_key[0] = htonll(StatData->value[0]);
			_key[1] = htonll(StatData->value[1]);
			af = PF_INET6;

		} else {	// IPv4
			af = PF_INET;
		}
		// Make sure Endian does not screw us up
    	sa[0] = ( _key[0] >> 32 ) & 0xffffffffLL;
    	sa[1] = _key[0] & 0xffffffffLL;
    	sa[2] = ( _key[1] >> 32 ) & 0xffffffffLL;
    	sa[3] = _key[1] & 0xffffffffLL;
	} 
	duration = (StatData->msecLast - StatData->msecFirst);
	
	count_flows = flows_element(StatData, inout);
	count_packets = packets_element(StatData, inout);
	count_bytes = bytes_element(StatData, inout);
	if ( duration != 0 ) {
		pps = (uint32_t)((double)count_packets / duration);
		bps = (uint32_t)((double)(8 * count_bytes) / duration);
	} else {
		pps = bps = 0;
	}

	if ( count_packets )
		bpp = count_bytes / count_packets;
	else
		bpp = 0;

	if ( !order_proto ) {
		StatData->value[2] = 0;
	}

	if ( type == IS_IPADDR )
		printf("%i|%llu|%llu|%llu|%u|%u|%u|%u|%llu|%llu|%llu|%u|%u|%u\n",
			af, StatData->msecFirst, StatData->msecLast, StatData->value[2],
			sa[0], sa[1], sa[2], sa[3], (long long unsigned)count_flows,
			(long long unsigned)count_packets, (long long unsigned)count_bytes,
			pps, bps, bpp);
	else
		printf("%i|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%u|%u|%u\n",
			af, StatData->msecFirst, StatData->msecLast, StatData->value[2],
			(long long unsigned)_key[1], (long long unsigned)count_flows,
			(long long unsigned)count_packets, (long long unsigned)count_bytes,
			pps, bps, bpp);

} // End of PrintPipeStatLine

static void PrintCvsStatLine(stat_record_t	*stat, int printPlain, StatRecord_t *StatData, int type, int order_proto, int tag, int inout) {
char		valstr[40], datestr1[64], datestr2[64];
uint64_t	count_flows, count_packets, count_bytes;
double		duration, flows_percent, packets_percent, bytes_percent;
uint32_t	bpp;
uint64_t	pps, bps;
time_t		when;
struct tm	*tbuff;

	switch (type) {
		case NONE:
			break;
		case IS_NUMBER:
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->value[1]);
			break;
		case IS_IPADDR:
			if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
				uint64_t	_key[2];
				_key[0] = htonll(StatData->value[0]);
				_key[1] = htonll(StatData->value[1]);
				inet_ntop(AF_INET6, _key, valstr, sizeof(valstr));
	
			} else {	// IPv4
				uint32_t	ipv4;
				ipv4 = htonl(StatData->value[1]);
				inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
			}
			break;
		case IS_MACADDR: {
			int i;
			uint8_t mac[6];
			for ( i=0; i<6; i++ ) {
				mac[i] = ((unsigned long long)StatData->value[1] >> ( i*8 )) & 0xFF;
			}
			snprintf(valstr, 40, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
			} break;
		case IS_MPLS_LBL: {
			snprintf(valstr, 40, "%llu", (unsigned long long)StatData->value[1]);
			snprintf(valstr, 40,"%8llu-%1llu-%1llu", 
				(unsigned long long)StatData->value[1] >> 4 , 
				((unsigned long long)StatData->value[1] & 0xF ) >> 1, 
				(unsigned long long)StatData->value[1] & 1);
			} break;
	}

	valstr[39] = 0;

	count_flows   = StatData->counter[FLOWS];
	count_packets = packets_element(StatData, inout);
	count_bytes   = bytes_element(StatData, inout);

	flows_percent   = stat->numflows ? (double)(count_flows * 100 ) / (double)stat->numflows : 0;
	packets_percent = stat->numpackets ? (double)(count_packets * 100 ) / (double)stat->numpackets : 0;
	bytes_percent   = stat->numbytes ? (double)(count_bytes * 100 ) / (double)stat->numbytes : 0;

	duration = (StatData->msecLast - StatData->msecFirst);
	
	if ( duration != 0 ) {
		pps  = (uint64_t)((double)count_packets / duration);
		bps  = (uint64_t)((double)(8 * count_bytes) / duration);
	} else {
		pps  = bps  = 0;
	}

	if (count_packets) {
		bpp = count_bytes / count_packets;
	} else {
		bpp = 0;
	}

	when = StatData->msecFirst / 1000;
	tbuff = localtime(&when);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	when = StatData->msecLast / 1000;
	tbuff = localtime(&when);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	printf("%s,%s,%.3f,%s,%s,%llu,%.1f,%llu,%.1f,%llu,%.1f,%llu,%llu,%u\n",
		datestr1, datestr2, duration/1000.0,
		order_proto ? ProtoString(StatData->value[2], printPlain) : "any", valstr,
		(long long unsigned)count_flows, flows_percent,
		(long long unsigned)count_packets, packets_percent,
		(long long unsigned)count_bytes, bytes_percent,
		(long long unsigned)pps,(long long unsigned)bps,bpp);

} // End of PrintCvsStatLine


void PrintFlowTable(printer_t print_record, outputParams_t *outputParams, int GuessDir) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
master_record_t		*aggr_record_mask;
SortElement_t 		*SortList;
uint64_t			value;
uint32_t 			i;
uint32_t			maxindex, c;
char				*string;

	GuessDirection = GuessDir;
	FlowTable = GetFlowTable();
	aggr_record_mask = GetMasterAggregateMask();
	c = 0;
	maxindex = FlowTable->NumRecords;
	if ( PrintOrder ) {
		// Sort according the requested order
		SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

		if ( !SortList ) {
        	LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return;
		}

		// preset SortList table - still unsorted
		for ( i=0; i<=FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			if ( !r ) 
				continue;

			// foreach elem in this bucket
			while ( r ) {
				// we want to sort only those flows which pass the packet or byte limits
				if ( byte_limit ) {
				        value = bytes_record(r, order_mode[PrintOrder].inout);
					if (( byte_mode == LESS && value >= byte_limit ) ||
						( byte_mode == MORE && value <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
				        value = packets_record(r, order_mode[PrintOrder].inout);
					if (( packet_mode == LESS && value >= packet_limit ) ||
						( packet_mode == MORE && value <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}
				
				SortList[c].count  = order_mode[PrintOrder].record_function(r, order_mode[PrintOrder].inout);
				SortList[c].record = (void *)r;
				c++;
				r = r->next;
			}
		}

		maxindex = c;

		if ( c >= 2 ) {
 			blocksort((SortRecord_t *)SortList, c);
		}

		PrintSortedFlowcache(SortList, maxindex, outputParams, GuessDir, 
			print_record, order_mode[PrintOrder].direction);

	} else {
		// print them as they came
		c = 0;
		for ( i=0; i<=FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			while ( r ) {
				master_record_t	flow_record;
				recordHeaderV3_t *raw_record;

				if ( outputParams->topN && c >= outputParams->topN )
					return;

				// we want to print only those flows which pass the packet or byte limits
				if ( byte_limit ) {
				        value = bytes_record(r, order_mode[PrintOrder].inout);
					if (( byte_mode == LESS && value >= byte_limit ) ||
						( byte_mode == MORE && value <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
				        value = packets_record(r, order_mode[PrintOrder].inout);
					if (( packet_mode == LESS && value >= packet_limit ) ||
						( packet_mode == MORE && value <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}

				raw_record = &(r->flowrecord);
				memset((void *)&flow_record, 0, sizeof(master_record_t));
				ExpandRecord_v3(raw_record, &flow_record);
				flow_record.dPkts 		= r->counter[INPACKETS];
				flow_record.dOctets 	= r->counter[INBYTES];
				flow_record.out_pkts 	= r->counter[OUTPACKETS];
				flow_record.out_bytes 	= r->counter[OUTBYTES];
				flow_record.aggr_flows	= r->counter[FLOWS];
				flow_record.msecFirst	= r->msecFirst;
				flow_record.msecLast	= r->msecLast;

				// apply IP mask from aggregation, to provide a pretty output
				if ( FlowTable->has_masks ) {
					flow_record.V6.srcaddr[0] &= FlowTable->IPmask[0];
					flow_record.V6.srcaddr[1] &= FlowTable->IPmask[1];
					flow_record.V6.dstaddr[0] &= FlowTable->IPmask[2];
					flow_record.V6.dstaddr[1] &= FlowTable->IPmask[3];
				}

				if ( aggr_record_mask ) {
					ApplyAggrMask(&flow_record, aggr_record_mask);
				}

				if (NeedSwap(GuessDir, &flow_record))
					SwapFlow(&flow_record);

				print_record((void *)&flow_record, &string, outputParams->doTag);
				printf("%s\n", string);

				c++;
				r = r->next;
			}
		}
	}
} // End of PrintFlowTable

void PrintFlowStat(func_prolog_t record_header, printer_t print_record, outputParams_t *outputParams) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
unsigned int 		order_index, i;
uint64_t			value;
uint32_t			maxindex, c;

return;
	FlowTable = GetFlowTable();
	c = 0;
	maxindex = FlowTable->NumRecords;

	// Create the sort array
	SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

	if ( !SortList ) {
       	LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return;
	}

	// preset the first stat
	for ( order_index=0; order_mode[order_index].string != NULL; order_index++ ) {
		unsigned int order_bit = 1 << order_index;
		if ( print_order_bits & order_bit ) 
			break;
	}

	// preset SortList table - still unsorted
	for ( i=0; i<=FlowTable->IndexMask; i++ ) {
		r = FlowTable->bucket[i];
		if ( !r ) 
			continue;

		// foreach elem in this bucket
		while ( r ) {
			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
			        value = bytes_record(r, order_mode[order_index].inout);
				if (( byte_mode == LESS && value >= byte_limit ) ||
					( byte_mode == MORE && value <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
			        value = packets_record(r, order_mode[order_index].inout);
				if (( packet_mode == LESS && value >= packet_limit ) ||
					( packet_mode == MORE && value <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}
			
			// As we touch each flow in the list here, fill in the values for the first requested stat
			// often, no more than one stat is requested anyway. This saves time
			SortList[c].count  = order_mode[order_index].record_function(r, order_mode[order_index].inout);
			SortList[c].record = (void *)r;
			c++;
			r = r->next;
		}
	}

	maxindex = c;

	if ( !(outputParams->quiet || outputParams->modeCsv) ) 
		printf("Aggregated flows %u\n", maxindex);

	if ( c >= 2 ) {
 		blocksort((SortRecord_t *)SortList, c);
	}
	if ( !outputParams->quiet ) {
		if ( !outputParams->modeCsv ) {
			if ( outputParams->topN != 0 )
				printf("Top %i flows ordered by %s:\n", outputParams->topN, order_mode[order_index].string);
			else
				printf("Top flows ordered by %s:\n", order_mode[order_index].string);
		}
		if ( record_header ) 
			record_header();
	}

	PrintSortedFlowcache(SortList, maxindex, outputParams, 0, print_record, DESCENDING);

	// process all the remaining stats, if requested
	for ( order_index++ ; order_mode[order_index].string != NULL; order_index++ ) {
		unsigned int order_bit = 1 << order_index;
		if ( print_order_bits & order_bit ) {

			for ( i = 0; i < maxindex; i++ ) {
				r = (FlowTableRecord_t *)(SortList[i].record);
				/* if we have some different sort orders, which are not directly available in the FlowTableRecord_t
		 		 * we need to calculate this value first - such as bpp, bps etc.
		 		 */
				SortList[i].count  = order_mode[order_index].record_function(r, order_mode[order_index].inout);
			}

			if ( maxindex >= 2 ) {
 				blocksort((SortRecord_t *)SortList, maxindex);
			}
			if ( !outputParams->quiet ) {
				if ( !outputParams->modeCsv ) {
					if ( outputParams->topN != 0 ) 
						printf("Top %i flows ordered by %s:\n", outputParams->topN, order_mode[order_index].string);
					else
						printf("Top flows ordered by %s:\n", order_mode[order_index].string);
				}
				if ( record_header ) 
					record_header();
			}
			PrintSortedFlowcache(SortList, maxindex, outputParams, 0, print_record, DESCENDING);

		}
	}

} // End of PrintFlowStat

static inline void PrintSortedFlowcache(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, 
	int GuessFlowDirection, printer_t print_record, int ascending) {
hash_FlowTable *FlowTable;
master_record_t		*aggr_record_mask;
int	i, max;


	FlowTable = GetFlowTable();
	aggr_record_mask = GetMasterAggregateMask();

	max = maxindex;
	if ( outputParams->topN && outputParams->topN < maxindex )
		max = outputParams->topN;

	for ( i = 0; i < max; i++ ) {
		master_record_t	flow_record;
		recordHeaderV3_t *raw_record;
		FlowTableRecord_t	*r;
		char	*string;
		int j;

		if ( ascending )
			j = i;
		else
			j = maxindex - 1 - i;

		r = (FlowTableRecord_t *)(SortList[j].record);
		raw_record = &(r->flowrecord);

		memset((void *)&flow_record, 0, sizeof(master_record_t));
		ExpandRecord_v3(raw_record, &flow_record);

		flow_record.dPkts 		= r->counter[INPACKETS];
		flow_record.dOctets 	= r->counter[INBYTES];
		flow_record.out_pkts 	= r->counter[OUTPACKETS];
		flow_record.out_bytes 	= r->counter[OUTBYTES];
		flow_record.aggr_flows 	= r->counter[FLOWS];
		flow_record.msecFirst	= r->msecFirst;
		flow_record.msecLast	= r->msecLast;

		// apply IP mask from aggregation, to provide a pretty output
		if ( FlowTable->has_masks ) {
			flow_record.V6.srcaddr[0] &= FlowTable->IPmask[0];
			flow_record.V6.srcaddr[1] &= FlowTable->IPmask[1];
			flow_record.V6.dstaddr[0] &= FlowTable->IPmask[2];
			flow_record.V6.dstaddr[1] &= FlowTable->IPmask[3];
		}

		if ( FlowTable->apply_netbits ) {
			int src_mask = flow_record.src_mask;
			int dst_mask = flow_record.dst_mask;
			ApplyNetMaskBits(&flow_record, FlowTable->apply_netbits);
			if ( aggr_record_mask )
				ApplyAggrMask(&flow_record, aggr_record_mask);
			flow_record.src_mask = src_mask;
			flow_record.dst_mask = dst_mask;
		} else if ( aggr_record_mask )
			ApplyAggrMask(&flow_record, aggr_record_mask);

		if ( NeedSwap(GuessFlowDirection, &flow_record) )
			SwapFlow(&flow_record);

		print_record((void *)&flow_record, &string, outputParams->doTag);
		printf("%s\n", string);
	}

} // End of PrintSortedFlowcache

void PrintElementStat(stat_record_t	*sum_stat, outputParams_t *outputParams, printer_t print_record) {
SortElement_t	*topN_element_list;
uint32_t		numflows;
int32_t 		i, j, hash_num, order_index;

	numflows = 0;
	// for every requested -s stat do
	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		int stat   = StatRequest[hash_num].StatType;
		int order  = StatRequest[hash_num].order_bits;
		int	type = StatParameters[stat].type;
		for ( order_index=0; order_mode[order_index].string != NULL; order_index++ ) {
			unsigned int order_bit = (1<<order_index);
			if ( order & order_bit ) {
				// XXX
				topN_element_list = StatTopN(outputParams->topN, &numflows, hash_num, order_index);

				// this output formating is pretty ugly - and needs to be cleaned up - improved
				if ( !outputParams->modePipe && !outputParams->modeCsv && !outputParams->quiet  ) {
					if ( outputParams->topN != 0 ) 
						printf("Top %i %s ordered by %s:\n", 
							outputParams->topN, StatParameters[stat].HeaderInfo, order_mode[order_index].string);
					else
						printf("Top %s ordered by %s:\n", 
							StatParameters[stat].HeaderInfo, order_mode[order_index].string);
					//      2005-07-26 20:08:59.197 1553.730      ss    65255   203435   52.2 M      130   281636   268
					if ( Getv6Mode() && (type == IS_IPADDR )) 
						printf("Date first seen          Duration Proto %39s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   bpp\n",
							StatParameters[stat].HeaderInfo);
					else
						printf("Date first seen          Duration Proto %17s    Flows(%%)     Packets(%%)       Bytes(%%)         pps      bps   bpp\n",
							StatParameters[stat].HeaderInfo);
				}

				if ( outputParams->modeCsv ) {
					if ( order_mode[order_index].inout == IN )
						printf("ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp\n");
					else if ( order_mode[order_index].inout == OUT )
						printf("ts,te,td,pr,val,fl,flP,opkt,opktP,obyt,obytP,opps,obps,obpp\n");
					else
						printf("ts,te,td,pr,val,fl,flP,pkt,pktP,byt,bytP,pps,bps,bpp\n");
				}

				j = numflows - outputParams->topN;
				j = j < 0 ? 0 : j;
				if ( outputParams->topN == 0 )
					j = 0;
				for ( i=numflows-1; i>=j ; i--) {
					//if ( !topN_element_list[i].count )
						//break;

					// Again - ugly output formating - needs to be cleaned up
					if ( outputParams->modePipe ) 
						PrintPipeStatLine((StatRecord_t *)topN_element_list[i].record, type, 
							StatRequest[hash_num].order_proto, outputParams->doTag, order_mode[order_index].inout);
					else if ( outputParams->modeCsv ) 
						PrintCvsStatLine(sum_stat, outputParams->printPlain, (StatRecord_t *)topN_element_list[i].record, type, 
							StatRequest[hash_num].order_proto, outputParams->doTag, order_mode[order_index].inout);
					else
						PrintStatLine(sum_stat, outputParams->printPlain, (StatRecord_t *)topN_element_list[i].record, 
							type, StatRequest[hash_num].order_proto, outputParams->doTag, order_mode[order_index].inout);
				}
				free((void *)topN_element_list);
				printf("\n");
			}
		} // for every requested order
	} // for every requested -s stat do
} // End of PrintElementStat

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order ) {

	uint32_t maxindex  = StatTable[hash_num].NumElements;
	SortElement_t *topN_list = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

	if ( !topN_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	uint32_t c = 0;
	struct statNode *node;
	RB_FOREACH(node, StatTree, StatTable[hash_num].StatTree) {
		uint64_t v = order_mode[order].element_function(node, order_mode[order].inout);
		dbg_printf("Add count: %llu, record: %llp\n", v, node);
		topN_list[c].count  = v;
		topN_list[c].record = (void *)node;
		c++;
	}
	*count = c;

	dbg_printf ("Sort %u flows\n", c);
	
#ifdef DEVEL
	for ( int i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llp\n", i, topN_list[i].count, topN_list[i].record);
#endif

	// Sorting makes only sense, when 2 or more flows are left
	if ( c >= 2 ) {
 		blocksort((SortRecord_t *)topN_list, c);
	}

#ifdef DEVEL
	for ( int i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llp\n", i, topN_list[i].count, topN_list[i].record);
#endif

	return topN_list;
	
} // End of StatTopN

void SwapFlow(master_record_t *flow_record) {
uint64_t _tmp_ip[2];
uint64_t _tmp_l;
uint32_t _tmp;

	_tmp_ip[0] = flow_record->V6.srcaddr[0];
	_tmp_ip[1] = flow_record->V6.srcaddr[1];
	flow_record->V6.srcaddr[0] = flow_record->V6.dstaddr[0];
	flow_record->V6.srcaddr[1] = flow_record->V6.dstaddr[1];
	flow_record->V6.dstaddr[0] = _tmp_ip[0];
	flow_record->V6.dstaddr[1] = _tmp_ip[1];

	_tmp = flow_record->srcPort;
	flow_record->srcPort = flow_record->dstPort;
	flow_record->dstPort = _tmp;

	_tmp = flow_record->srcas;
	flow_record->srcas = flow_record->dstas;
	flow_record->dstas = _tmp;

	_tmp = flow_record->input;
	flow_record->input = flow_record->output;
	flow_record->output = _tmp;

	_tmp_l = flow_record->dPkts;
	flow_record->dPkts = flow_record->out_pkts;
	flow_record->out_pkts = _tmp_l;

	_tmp_l = flow_record->dOctets;
	flow_record->dOctets = flow_record->out_bytes;
	flow_record->out_bytes = _tmp_l;

} // End of SwapFlow

