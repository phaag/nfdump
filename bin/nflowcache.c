/*
 *  Copyright (c) 2009-2021, Peter Haag
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
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <assert.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "exporter.h"
#include "memhandle.h"
#include "khash.h"
#include "blocksort.h"
#include "klist.h"
#include "nflowcache.h"
#include "output_raw.h"

typedef struct aggregate_param_s {
	uint32_t	size;	// size of parameter in bytes
	uint32_t    offset;	// offset in master record
	uint64_t    mask;	// mask for this value in master record
	uint64_t    shift;	// bis shift for this value in master record
} aggregate_param_t;

static struct aggregate_table_s {
	char				*aggregate_token;	// name of aggregation parameter
	aggregate_param_t	param;				// the parameter array
	int					merge;				// apply bis mask? => -1 no, otherwise index of mask[] array
	int					active;				// is this parameter set?
	char				*fmt;				// for automatic output format generation
} aggregate_table [] = {
	{ "srcip4",		{ 8, OffsetSrcIPv6a, 	MaskIPv6, 	 ShiftIPv6 },     	 0, 0,	"%sa" },
	{ "srcip4",		{ 8, OffsetSrcIPv6b, 	MaskIPv6, 	 ShiftIPv6 },     	 1, 0,	NULL	},
	{ "srcip6",		{ 8, OffsetSrcIPv6a, 	MaskIPv6, 	 ShiftIPv6 },     	 0, 0,	"%sa" 	},
	{ "srcip6",		{ 8, OffsetSrcIPv6b, 	MaskIPv6, 	 ShiftIPv6 },     	 1, 0,	NULL 	},
	{ "srcnet",		{ 8, OffsetSrcIPv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%sn" 	},
	{ "srcnet",		{ 8, OffsetSrcIPv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "dstnet",		{ 8, OffsetDstIPv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%dn"	},
	{ "dstnet",		{ 8, OffsetDstIPv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "srcip",		{ 8, OffsetSrcIPv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%sa" 	},
	{ "srcip",		{ 8, OffsetSrcIPv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "dstip",		{ 8, OffsetDstIPv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%da"	},
	{ "dstip",		{ 8, OffsetDstIPv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
#ifdef NSEL
	{ "xsrcip",		{ 8, OffsetXLATESRCv6a,	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%xsa" 	},
	{ "xsrcip",		{ 8, OffsetXLATESRCv6b,	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "xdstip",		{ 8, OffsetXLATEDSTv6a,	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%xda"	},
	{ "xdstip",		{ 8, OffsetXLATESRCv6b,	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "xsrcport",	{ 2, OffsetXLATEPort,   MaskXLATESRCPORT,   ShiftXLATESRCPORT }, 	-1, 0, 	"%xsp"	},
	{ "xdstport",	{ 2, OffsetXLATEPort,   MaskXLATEDSTPORT,   ShiftXLATEDSTPORT }, 	-1, 0, 	"%xdp"	},
#endif
	{ "dstip4",		{ 8, OffsetDstIPv6a, 	MaskIPv6, 	 ShiftIPv6 },     	 0, 0,	"%da"	},
	{ "dstip4",		{ 8, OffsetDstIPv6b, 	MaskIPv6, 	 ShiftIPv6 },     	 1, 0,	NULL	},
	{ "dstip6",		{ 8, OffsetDstIPv6a, 	MaskIPv6, 	 ShiftIPv6 },     	 0, 0,	"%da"	},
	{ "dstip6",		{ 8, OffsetDstIPv6b, 	MaskIPv6, 	 ShiftIPv6 },     	 1, 0, 	NULL	},
	{ "next",		{ 8, OffsetNexthopv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%nh"	},
	{ "next",		{ 8, OffsetNexthopv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "bgpnext",	{ 8, OffsetBGPNexthopv6a, 	MaskIPv6, 	 ShiftIPv6 },	-1, 0, 	"%nhb"	},
	{ "bgpnext",	{ 8, OffsetBGPNexthopv6b, 	MaskIPv6, 	 ShiftIPv6 },	-1, 0, 	NULL	},
	{ "router",		{ 8, OffsetRouterv6a, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0,	"%ra"	},
	{ "router",		{ 8, OffsetRouterv6b, 	MaskIPv6, 	 ShiftIPv6 },    	-1, 0, 	NULL	},
	{ "insrcmac",	{ 8, OffsetInSrcMAC, 	MaskMac, 	 ShiftIPv6 },		-1, 0,	"%ismc"	},
	{ "outdstmac",	{ 8, OffsetOutDstMAC, 	MaskMac, 	 ShiftIPv6 },		-1, 0,	"%odmc"	},
	{ "indstmac",	{ 8, OffsetInDstMAC, 	MaskMac, 	 ShiftIPv6 },		-1, 0,	"%idmc"	},
	{ "outsrcmac",	{ 8, OffsetOutSrcMAC, 	MaskMac, 	 ShiftIPv6 },		-1, 0, 	"%osmc"	},
	{ "srcas",		{ 4, OffsetAS, 			MaskSrcAS, 	 ShiftSrcAS },	 	-1, 0, 	"%sas"	},
	{ "dstas",		{ 4, OffsetAS, 			MaskDstAS, 	 ShiftDstAS }, 	 	-1, 0, 	"%das"	},
	{ "nextas",		{ 4, OffsetBGPadj, 		MaskBGPadjNext, 	 ShiftBGPadjNext },	 	-1, 0, 	"%nas"	},
	{ "prevas",		{ 4, OffsetBGPadj, 		MaskBGPadjPrev, 	 ShiftBGPadjPrev },  	-1, 0, 	"%pas"	},
	{ "inif",		{ 4, OffsetInOut, 		MaskInput, 	 ShiftInput },	 	-1, 0, 	"%in"	},
	{ "outif",		{ 4, OffsetInOut, 		MaskOutput,  ShiftOutput },	 	-1, 0,	"%out"	},
	{ "mpls1",		{ 4, OffsetMPLS12, 		MaskMPLSlabelOdd,  ShiftMPLSlabelOdd },	 	-1, 0, 	"%mpls1"},
	{ "mpls2",		{ 4, OffsetMPLS12, 		MaskMPLSlabelEven,  ShiftMPLSlabelEven }, 	-1, 0, 	"%mpls2"},
	{ "mpls3",		{ 4, OffsetMPLS34, 		MaskMPLSlabelOdd,  ShiftMPLSlabelOdd },	 	-1, 0, 	"%mpls3"},
	{ "mpls4",		{ 4, OffsetMPLS34, 		MaskMPLSlabelEven,  ShiftMPLSlabelEven }, 	-1, 0, 	"%mpls4"},
	{ "mpls5",		{ 4, OffsetMPLS56, 		MaskMPLSlabelOdd,  ShiftMPLSlabelOdd },	 	-1, 0, 	"%mpls5"},
	{ "mpls6",		{ 4, OffsetMPLS56, 		MaskMPLSlabelEven,  ShiftMPLSlabelEven }, 	-1, 0, 	"%mpls6"},
	{ "mpls7",		{ 4, OffsetMPLS78, 		MaskMPLSlabelOdd,  ShiftMPLSlabelOdd },	 	-1, 0, 	"%mpls7"},
	{ "mpls8",		{ 4, OffsetMPLS78, 		MaskMPLSlabelEven,  ShiftMPLSlabelEven }, 	-1, 0, 	"%mpls8"},
	{ "mpls9",		{ 4, OffsetMPLS910,		MaskMPLSlabelOdd,  ShiftMPLSlabelOdd },	 	-1, 0, 	"%mpls9"},
	{ "mpls10",		{ 4, OffsetMPLS910,		MaskMPLSlabelEven,  ShiftMPLSlabelEven }, 	-1, 0, 	"%mpls10"},
	{ "srcport",	{ 2, OffsetPort, 		MaskSrcPort, ShiftSrcPort }, 	-1, 0, 	"%sp"	},
	{ "dstport",	{ 2, OffsetPort, 		MaskDstPort, ShiftDstPort }, 	-1, 0, 	"%dp"	},
	{ "srcvlan",	{ 2, OffsetVlan, 		MaskSrcVlan, ShiftSrcVlan }, 	-1, 0, 	"%svln"	},
	{ "dstvlan",	{ 2, OffsetVlan, 		MaskDstVlan, ShiftDstVlan }, 	-1, 0, 	"%dvln"	},
	{ "srcmask",	{ 1, OffsetMask, 		MaskSrcMask, ShiftSrcMask },   	-1, 0,	"%smk"	},
	{ "dstmask",	{ 1, OffsetMask, 		MaskDstMask, ShiftDstMask },   	-1, 0,	"%dmk"	},
	{ "proto",		{ 1, OffsetProto, 		MaskProto, 	 ShiftProto },   	-1, 0, 	"%pr"	},
	{ "tos",		{ 1, OffsetTos, 		MaskTos, 	 ShiftTos },   		-1, 0, 	"%tos"	},
	{ "srctos",		{ 1, OffsetTos, 		MaskTos, 	 ShiftTos },   		-1, 0,	"%stos"	},
	{ "dsttos",		{ 1, OffsetDstTos, 		MaskDstTos,  ShiftDstTos },   	-1, 0,	"%dtos"	},
	{ NULL,			{ 0, 0, 0, 0}, 0, 0, NULL}
};

/* Element of the flow hash ( cache ) */
typedef struct FlowHashRecord {
	// record chain - for FlowList
	union {
		struct FlowHashRecord *next;	
		uint8_t *hashkey;
	};
	uint32_t hash;	// the full 32bit hash value - cached for khash resize
	uint32_t fill;	// align

	// flow counter parameters for FLOWS, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES
	uint64_t counter[5];

	// time info in msec
	uint64_t msecFirst;
	uint64_t msecLast;

	recordHeaderV3_t	*flowrecord;
} FlowHashRecord_t;

// printing order definitions
enum CntIndices { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };
enum FlowDir 	{ IN = 0, OUT, INOUT };

typedef uint64_t (*order_proc_record_t)(FlowHashRecord_t *, int);

// prototypes for order functions
static inline uint64_t	null_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	flows_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	packets_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	bytes_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	pps_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	bps_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	bpp_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	tstart_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	tend_record(FlowHashRecord_t *record, int inout);
static inline uint64_t	duration_record(FlowHashRecord_t *record, int inout);

#define ASCENDING 1
#define DESCENDING 0
static struct order_mode_s {
	char *string;	// Stat name 
	int	 inout;		// use IN or OUT or INOUT packets/bytes
	int	 direction;	// ascending or descending
	order_proc_record_t  record_function;	// Function to call for record stats
} order_mode[] = {
	{ "-",			0,		0, 			null_record},	// empty entry 0
	{ "flows",		IN,		DESCENDING, flows_record},
	{ "packets",	INOUT,	DESCENDING, packets_record},
	{ "ipkg",		IN,		DESCENDING, packets_record},
	{ "opkg",		OUT,	DESCENDING, packets_record},
	{ "bytes",		INOUT,	DESCENDING, bytes_record},
	{ "ibyte",		IN,		DESCENDING, bytes_record},
	{ "obyte",		OUT,	DESCENDING, bytes_record},
	{ "pps",		INOUT,	DESCENDING, pps_record},
	{ "ipps",		IN,		DESCENDING, pps_record},
	{ "opps",		OUT,	DESCENDING, pps_record},
	{ "bps",		INOUT,	DESCENDING, bps_record},
	{ "ibps",		IN,		DESCENDING, bps_record},
	{ "obps",		OUT,	DESCENDING, bps_record},
	{ "bpp",		INOUT,	DESCENDING, bpp_record},
	{ "ibpp",		IN,		DESCENDING, bpp_record},
	{ "obpp",		OUT,	DESCENDING, bpp_record},
	{ "tstart",		0,		ASCENDING,  tstart_record},
	{ "tend",		0,		ASCENDING,  tend_record},
	{ "duration",	0,		DESCENDING, duration_record},
	{ NULL,			0,		0,			NULL}
};

static uint32_t	FlowStat_order = 0;	// bit field for multiple print orders
static uint32_t	PrintOrder 	   = 0; // -O selected print order - index into order_mode
static uint32_t PrintDirection = 0;
static uint32_t	GuessDirection = 0;

typedef struct FlowKey_s {
	struct _ipv6_s ipaddr;
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t proto;
} FlowKey_t;

// definitions for khash flow cache
typedef const uint8_t *hashkey_t;	// hash key - byte sequence
static size_t hashKeyLen = 0;			// length of hash_key

static inline uint32_t SuperFastHash (const char * data, int len);

/*
// hash func - reduce byte sequence to kh_int
static kh_inline khint_t __HashFunc(const FlowHashRecord_t record) {
	return SuperFastHash((char *)record.hashkey, hashKeyLen);
}
*/
#define __HashFunc(k)	(k).hash

// compare func - compare two hash keys
static kh_inline khint_t __HashEqual(FlowHashRecord_t r1, FlowHashRecord_t r2) {
	return r1.hash == r2.hash && memcmp((void *)r1.hashkey, (void *)r2.hashkey, hashKeyLen) == 0;
}
// insert FlowHash definitions/code
KHASH_INIT(FlowHash, FlowHashRecord_t, char, 0, __HashFunc, __HashEqual)
// FlowHash var
static khash_t(FlowHash) *FlowHash = NULL;
sig_atomic_t lock = 0;

// linear FlowList
static struct FlowList_s {
	FlowHashRecord_t *head;
	FlowHashRecord_t **tail;
	size_t	NumRecords;
} FlowList;

static struct aggregate_info_s {
	aggregate_param_t *stack;
	master_record_t	  *mask;

    uint64_t IPmask[4];      // 0-1 srcIP, 2-3 dstIP
    int		 has_masks;
    int		 apply_netbits;  // bit 0: src, bit 1: dst

} aggregate_info = {
	.stack = NULL
};

static uint32_t	bidir_flows		  = 0;

#include "nfdump_inline.c"
#include "applybits_inline.c"
#include "memhandle.c"
#define NEED_PACKRECORD 1
#include "nffile_inline.c"
#include "heapsort_inline.c"

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
					   +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif


static inline void New_HashKey(void *keymem, master_record_t *flow_record, int swap_flow);

static SortElement_t *GetSortList(size_t *size);

static master_record_t *SetAggregateMask(void);

static inline void PrintSortList(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, 
	int GuessFlowDirection, printer_t print_record, int ascending);

static inline uint32_t SuperFastHash (const char *data, int len) {
uint32_t hash = len;

	if (len <= 0 || data == NULL) return 0;

	int rem = len & 3;
	len >>= 2;

	/* Main loop */
	uint32_t tmp;
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp	= (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (uint16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
		case 3: hash += get16bits (data);
				hash ^= hash << 16;
				hash ^= data[sizeof (uint16_t)] << 18;
				hash += hash >> 11;
				break;
		case 2: hash += get16bits (data);
				hash ^= hash << 11;
				hash += hash >> 17;
				break;
		case 1: hash += *data;
				hash ^= hash << 10;
				hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

static inline void New_HashKey(void *keymem, master_record_t *flow_record, int swap_flow) {
uint64_t *record = (uint64_t *)flow_record;
FlowKey_t *keyptr;

	// apply src/dst mask bits if requested
	if ( aggregate_info.apply_netbits ) {
		ApplyNetMaskBits(flow_record, aggregate_info.apply_netbits);
	}

	if ( aggregate_info.stack ) {
		// custom user aggregation
		aggregate_param_t *aggr_param = aggregate_info.stack;
		while ( aggr_param->size ) {
			uint64_t val = (record[aggr_param->offset] & aggr_param->mask) >> aggr_param->shift;

			switch ( aggr_param->size ) {
				case 8: {
					uint64_t *_v = (uint64_t *)keymem;
					*_v = val;
					keymem += sizeof(uint64_t);
					} break;
				case 4: {
					uint32_t *_v = (uint32_t *)keymem;
					*_v = val;
					keymem += sizeof(uint32_t);
					} break;
				case 2: {
					uint16_t *_v = (uint16_t *)keymem;
					*_v = val;
					keymem += sizeof(uint16_t);
					} break;
				case 1: {
					uint8_t *_v = (uint8_t *)keymem;
					*_v = val;
					keymem += sizeof(uint8_t);
					} break;
				default:
					fprintf(stderr, "Panic: Software error in %s line %d\n", __FILE__, __LINE__);
					exit(255);
			} // switch
			aggr_param++;
		} // while 
	} else if ( swap_flow ) {
		// default 5-tuple aggregation for bidirectional flows
		keyptr = (FlowKey_t *)keymem;
		keyptr->ipaddr 	= flow_record->ip_addr._v6;
		keyptr->srcPort	= flow_record->dstPort;
		keyptr->dstPort	= flow_record->srcPort;
		keyptr->proto	= flow_record->proto;
	} else {
		// default 5-tuple aggregation
		keyptr = (FlowKey_t *)keymem;
		keyptr->ipaddr	= flow_record->ip_addr._v6;
		keyptr->srcPort	= flow_record->srcPort;
		keyptr->dstPort	= flow_record->dstPort;
		keyptr->proto	= flow_record->proto;
	}
	
} // End of New_HashKey

static uint64_t	null_record(FlowHashRecord_t *record, int inout) {
	return 0;
}

static uint64_t	flows_record(FlowHashRecord_t *record, int inout) {
	return record->counter[FLOWS];
}

static uint64_t	packets_record(FlowHashRecord_t *record, int inout) {
	if (NeedSwap(GuessDirection, (FlowKey_t *)record->hashkey)) {
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

static uint64_t	bytes_record(FlowHashRecord_t *record, int inout) {
	if (NeedSwap(GuessDirection, (FlowKey_t *)record->hashkey)) {
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

static uint64_t	pps_record(FlowHashRecord_t *record, int inout) {

	/* duration in msec */
	uint64_t duration = record->msecLast - record->msecFirst;
	if ( duration == 0 )
		return 0;
	else {
	    uint64_t packets = packets_record(record, inout);
		return ( 1000LL * packets ) / duration;
	}
} // End of pps_record

static uint64_t	bps_record(FlowHashRecord_t *record, int inout) {

	uint64_t duration = record->msecLast - record->msecLast;
	if ( duration == 0 )
		return 0;
	else {
		uint64_t bytes = bytes_record(record, inout);
		return ( 8000LL * bytes ) / duration;	/* 8 bits per Octet - x 1000 for msec */
	}
} // End of bps_record

static uint64_t	bpp_record(FlowHashRecord_t *record, int inout) {
uint64_t packets = packets_record(record, inout);
uint64_t bytes = bytes_record(record, inout);

	return packets ? bytes / packets : 0;
} // End of bpp_record

static uint64_t	tstart_record(FlowHashRecord_t *record, int inout) {
	return record->msecFirst;
} // End of tstart_record

static uint64_t	tend_record(FlowHashRecord_t *record, int inout) {
	return record->msecLast;
} // End of tend_record

static uint64_t	duration_record(FlowHashRecord_t *record, int inout) {
	return record->msecLast - record->msecFirst;
} // End of duration_record


static master_record_t *SetAggregateMask(void) {
master_record_t *aggr_record_mask;

	if ( aggregate_info.stack ) {
		uint64_t *r;
		aggregate_param_t *aggr_param = aggregate_info.stack;

		aggr_record_mask = (master_record_t *)calloc(1, sizeof(master_record_t));
		if ( !aggr_record_mask ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}

		r = (uint64_t *)aggr_record_mask;
		while ( aggr_param->size ) {
			int offset = aggr_param->offset;
			r[offset] |= aggr_param->mask;
			aggr_param++;
		}

		// not really needed, but preset it anyway
		r[0] = 0xffffffffffffffffLL;
		r[1] = 0xffffffffffffffffLL;
		aggr_record_mask->inPackets	 = 0xffffffffffffffffLL;
		aggr_record_mask->inBytes	 = 0xffffffffffffffffLL;
		aggr_record_mask->out_pkts	 = 0xffffffffffffffffLL;
		aggr_record_mask->out_bytes	 = 0xffffffffffffffffLL;
		aggr_record_mask->aggr_flows = 0xffffffffffffffffLL;
		aggr_record_mask->msecLast	 = 0xffffffffffffffffLL;

		return aggr_record_mask;
	} else {
		return NULL;
	}

} // End of SetAggregateMask

// return a linear list of aggregated/listed flows for later sorting
static SortElement_t *GetSortList(size_t *size) {
SortElement_t *list;

	size_t hashSize = kh_size(FlowHash);
	if ( hashSize ) { // aggregated flows in khash
    	list = (SortElement_t *)calloc(hashSize, sizeof(SortElement_t));
		if ( !list ) {
       		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			*size = 0;
			return NULL;
		}

		int c = 0;
		for (khiter_t k = kh_begin(FlowHash); k != kh_end(FlowHash); ++k) {  // traverse
			if (kh_exist(FlowHash,k)) {
				FlowHashRecord_t *r = &kh_key(FlowHash,k);
        		list[c++].record = (void *)r;
			}
    	}
		*size = hashSize;

	} else { // linear flow list 
    	size_t listSize = FlowList.NumRecords;
		if ( !listSize ) { 
			*size = 0;
			return NULL;
		}
    	list = (SortElement_t *)calloc(listSize, sizeof(SortElement_t));
		if ( !list ) {
       		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			*size = 0;
			return NULL;
		}

		FlowHashRecord_t *r = FlowList.head;
		for (int i=0; i<listSize; i++ ) {
       		list[i].record = (void *)r;
			r = r->next;
    	}
		*size = listSize;
	}

    return list;

} // End of GetSortList

int Init_FlowCache(void) {

	if ( !nfalloc_Init(0) )
		return 0;

	if ( !hashKeyLen ) 
		hashKeyLen = sizeof(FlowKey_t);

	FlowHash = kh_init(FlowHash);

	FlowList.head = NULL;
	FlowList.tail = &FlowList.head;
	FlowList.NumRecords = 0;

	return 1;

} // End of Init_FlowCache

void Dispose_FlowTable(void) {
	nfalloc_free();
} // End of Dispose_FlowTable

// Parse flow cache print order -O
int Parse_PrintOrder(char *order) {

	int direction = -1;
	char *r = strchr(order, ':');
	if ( r ) {
		*r++ = 0;
		switch (*r) {
			case 'a':
				direction = ASCENDING;
				break;
			case 'd':
				direction = DESCENDING;
				break;
			default:
				return -1;
		}
	} 

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

	PrintDirection = direction >= 0 ? direction : order_mode[PrintOrder].direction;

	return PrintOrder;

} // End of Parse_PrintOrder

// set sort order is given by -s record - parsed in nfstat.c
// multiple sort orders may be given - each order adds the
// corresoponding bit
void Add_FlowStatOrder(uint32_t order, uint32_t direction) {
	FlowStat_order |= order;
	PrintDirection = direction;
} // End of Add_FlowStatOrder

char *ParseAggregateMask(char *arg) {
struct aggregate_table_s *a;
uint64_t mask[2];
char *aggr_fmt;

	if ( bidir_flows ) {
		LogError("Can not set custom aggregation in bidir mode");
		return NULL;
	}

	uint32_t stack_count = 0;
	uint32_t subnet		 = 0;
	uint32_t has_mask    = 0;

	hashKeyLen = 0;
	memset((void *)&aggregate_info, 0, sizeof(aggregate_info));

	size_t fmt_len = 0;
	for (int i=0; aggregate_table[i].aggregate_token != NULL; i++ ) {
		if ( aggregate_table[i].fmt )
			fmt_len += ( strlen(aggregate_table[i].fmt) + 1 );
	}
	fmt_len++;	// trailing '\0'

	aggr_fmt = malloc(fmt_len);
	if ( !aggr_fmt ) {
		LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	aggr_fmt[0] = '\0';

	aggregate_info.apply_netbits  = 0;
	aggregate_info.has_masks = 0;
	aggregate_info.IPmask[0] = 0xffffffffffffffffLL;;
	aggregate_info.IPmask[1] = 0xffffffffffffffffLL;;
	aggregate_info.IPmask[2] = 0xffffffffffffffffLL;;
	aggregate_info.IPmask[3] = 0xffffffffffffffffLL;;

	// separate tokens
	char *p = strtok(arg, ",");
	while ( p ) {

		// check for subnet bits
		char *q = strchr(p, '/');
		if ( q ) {
			char *n;

			has_mask = 1;

			*q = 0;
			subnet = atoi(q+1);

			// get IP version
			n = &(p[strlen(p)-1]);
			if ( *n == '4' ) {
				// IPv4
				if ( subnet < 1 || subnet > 32 ) {
					LogError("Subnet mask length '%d' out of range for IPv4", subnet);
					return NULL;
				}
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 32 - subnet );

			} else if ( *n == '6' ) {
				// IPv6
				if ( subnet < 1 || subnet > 128 ) {
					LogError("Subnet mask length '%d' out of range for IPv4", subnet);
					return NULL;
				}

				if ( subnet > 64 ) {
					mask[0] = 0xffffffffffffffffLL;
					mask[1] = 0xffffffffffffffffLL << ( 64 - subnet );
				} else {
					mask[0] = 0xffffffffffffffffLL << ( 64 - subnet );
					mask[1] = 0;
				}
			} else {
				// rubbish
				*q = '/';
				LogError("Need src4/dst4 or src6/dst6 for IPv4 or IPv6 to aggregate with explicit netmask: '%s'", p);
				return NULL;
			}
		} else {
			has_mask = 0;
		}

		a = aggregate_table;
		while ( a->aggregate_token && (strcasecmp(p, a->aggregate_token ) != 0) )
			a++;

		if ( a->active ) {
			LogError("Duplicate aggregation mask: %s", p);
			return NULL;
		} else if ( a->aggregate_token != NULL ) {

			if ( a->fmt != NULL ) {
				strncat(aggr_fmt, a->fmt, fmt_len);
				fmt_len -= strlen(a->fmt);
				strncat(aggr_fmt, " ", fmt_len);
				fmt_len -= 1;
			}

			if ( strcasecmp(p, "srcnet" ) == 0 ) {
				aggregate_info.apply_netbits  |= 1;
			}
			if ( strcasecmp(p, "dstnet" ) == 0 ) {
				aggregate_info.apply_netbits  |= 2;
			}

			do {
				int i = a->merge;
				if ( i != -1 ) {
					if ( has_mask ) {
						a->param.mask = mask[i];
					} else {
						LogError("'%s' needs number of subnet bits to aggregate", p);
						return NULL;
					}
				} else {
					if ( has_mask ) { 
						LogError("'%s' No subnet bits allowed here", p);
						return NULL;
					}
				}
				a->active = 1;
				hashKeyLen += a->param.size;
				stack_count++;
				a++;
			} while (a->aggregate_token && (strcasecmp(p, a->aggregate_token ) == 0));

			if ( has_mask ) {
				aggregate_info.has_masks = 1;
				switch (p[0]) {
					case 's':
						aggregate_info.IPmask[0] = mask[0];
						aggregate_info.IPmask[1] = mask[1];
						break;
					case 'd':
						aggregate_info.IPmask[2] = mask[0];
						aggregate_info.IPmask[3] = mask[1];
						break;
				}
			} 
		} else {
			LogError("Unknown aggregation field '%s'", p);
			return NULL;
		}

		p = strtok(NULL, ",");
	}

	if ( stack_count == 0 ) {
		LogError("No aggregation specified!");
		return NULL;
	}

	aggregate_info.stack = (aggregate_param_t *)malloc((stack_count+1) * sizeof(aggregate_param_t));

	stack_count = 0;
	a = aggregate_table;
	while ( a->aggregate_token ) {
		if ( a->active ) {
			aggregate_info.stack[stack_count++] = a->param;
			dbg_printf("Set aggregate param: %s\n", a->aggregate_token);
		}
		a++;
	}
	// final '0' record
	aggregate_info.stack[stack_count] = a->param;

	dbg_printf("Aggregate key len: %zu bytes\n", hashKeyLen);
	dbg_printf("Aggregate format string: '%s'\n", aggr_fmt);

#ifdef DEVEL
	if ( aggregate_info.stack ) {
		aggregate_param_t *aggr_param = aggregate_info.stack;
		printf("Aggregate stack:\n");
		while ( aggr_param->size ) {
			printf("Offset: %u, Mask: %llx, Shift: %llu\n", aggr_param->offset, 
				(long long unsigned)aggr_param->mask,  (long long unsigned)aggr_param->shift);
			aggr_param++;
		} // while 
	} 
	printf("Has IP mask: %i %i\n", has_mask, aggregate_info.has_masks);
	printf("Mask 0: 0x%llx\n", (unsigned long long)aggregate_info.IPmask[0]);
	printf("Mask 1: 0x%llx\n", (unsigned long long)aggregate_info.IPmask[1]);
	printf("Mask 2: 0x%llx\n", (unsigned long long)aggregate_info.IPmask[2]);
	printf("Mask 3: 0x%llx\n", (unsigned long long)aggregate_info.IPmask[3]);

#endif

	aggregate_info.mask = SetAggregateMask();

	return aggr_fmt;
} // End of ParseAggregateMask

int SetBidirAggregation(void) {
	
	if ( aggregate_info.stack ) {
		LogError("Can not set bidir mode with custom aggregation mask");
		return 0;
	}
	bidir_flows = 1;

	return 1;

} // End of SetBidirAggregation

void InsertFlow(void *raw_record, master_record_t *flow_record) {
recordHeaderV3_t	*recordHeaderV3 = (recordHeaderV3_t *)raw_record;
FlowHashRecord_t	*record;

	record = nfmalloc(sizeof(FlowHashRecord_t));
	record->flowrecord = nfmalloc(recordHeaderV3->size);
	memcpy((void *)record->flowrecord, (void *)raw_record, recordHeaderV3->size);

	record->msecFirst = flow_record->msecFirst;
	record->msecLast  = flow_record->msecLast;

	record->counter[INBYTES]	 = flow_record->inBytes;
	record->counter[INPACKETS] 	 = flow_record->inPackets;
	record->counter[OUTBYTES]	 = flow_record->out_bytes;
	record->counter[OUTPACKETS]  = flow_record->out_pkts;
	record->counter[FLOWS]	 	 = flow_record->aggr_flows ? flow_record->aggr_flows : 1;
	FlowList.NumRecords++;

	record->next = NULL;
	*FlowList.tail = record;
	FlowList.tail = &(record->next);

} // End of InsertFlow

static void AddBidirFlow(void *raw_record, master_record_t *flow_record) {
recordHeaderV3_t *record = (recordHeaderV3_t *)raw_record;
static void	*keymem = NULL;
static void	*bidirkeymem = NULL;
FlowHashRecord_t r;

	if ( keymem == NULL ) {
		keymem = nfmalloc(hashKeyLen);
	}
	New_HashKey(keymem, flow_record, 0);
	r.hashkey = keymem;
	r.hash = SuperFastHash(keymem, hashKeyLen);

	int ret;
	khiter_t k = kh_get(FlowHash, FlowHash, r);
	if ( k != kh_end(FlowHash) ) {
		// flow record found - best case! update all fields
		kh_key(FlowHash,k).counter[INBYTES]    += flow_record->inBytes;
		kh_key(FlowHash,k).counter[INPACKETS]  += flow_record->inPackets;
		kh_key(FlowHash,k).counter[OUTBYTES]   += flow_record->out_bytes;
		kh_key(FlowHash,k).counter[OUTPACKETS] += flow_record->out_pkts;

		if ( flow_record->msecFirst < kh_key(FlowHash,k).msecFirst ) {
			kh_key(FlowHash,k).msecFirst = flow_record->msecFirst;
		}
		if ( flow_record->msecLast > kh_key(FlowHash,k).msecLast )  {
			kh_key(FlowHash,k).msecLast =	flow_record->msecLast;
		}

		kh_key(FlowHash,k).counter[FLOWS] += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
	} else if ( flow_record->proto != IPPROTO_TCP && flow_record->proto != IPPROTO_UDP) {
		// no flow record found and no TCP/UDP bidir flows. Insert flow record into hash
		k = kh_put(FlowHash, FlowHash, r, &ret);
		kh_key(FlowHash,k).counter[INBYTES]	   = flow_record->inBytes;
		kh_key(FlowHash,k).counter[INPACKETS]  = flow_record->inPackets;
		kh_key(FlowHash,k).counter[OUTBYTES]   = flow_record->out_bytes;
		kh_key(FlowHash,k).counter[OUTPACKETS] = flow_record->out_pkts;
		kh_key(FlowHash,k).counter[FLOWS]      = flow_record->aggr_flows ? flow_record->aggr_flows : 1;

		kh_key(FlowHash,k).msecFirst	  = flow_record->msecFirst;
		kh_key(FlowHash,k).msecLast	  = flow_record->msecLast;

		void *p = malloc(record->size);
		if ( !p ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
			exit(255);
		}
		memcpy((void *)p, raw_record, record->size);
		kh_key(FlowHash,k).flowrecord = p;

		// keymen got part of the cache
		keymem = NULL;
	} else {
		// for bidir flows do

		// generate reverse hash key to search for bidir flow
		// we need it only to lookup 
		if ( bidirkeymem == NULL ) {
			bidirkeymem = nfmalloc(hashKeyLen);
		}

		// generate the hash key for reverse record (bidir)
		New_HashKey(bidirkeymem, flow_record, 1);
		r.hashkey = bidirkeymem;
		r.hash = SuperFastHash(bidirkeymem, hashKeyLen);

		k = kh_get(FlowHash, FlowHash, r);
		if ( k != kh_end(FlowHash) ) {
			// we found a corresponding flow - so update all fields in reverse direction
			kh_key(FlowHash,k).counter[OUTBYTES]   += flow_record->inBytes;
			kh_key(FlowHash,k).counter[OUTPACKETS] += flow_record->inPackets;
			kh_key(FlowHash,k).counter[INBYTES]    += flow_record->out_bytes;
			kh_key(FlowHash,k).counter[INPACKETS]  += flow_record->out_pkts;

			if ( flow_record->msecFirst < kh_key(FlowHash,k).msecFirst ) {
				kh_key(FlowHash,k).msecFirst = flow_record->msecFirst;
			}
			if ( flow_record->msecLast > kh_key(FlowHash,k).msecLast ) {
				kh_key(FlowHash,k).msecLast = flow_record->msecLast;
			}

			kh_key(FlowHash,k).counter[FLOWS] += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
		} else {
			// no bidir flow found 
			// insert original flow into the cache
			r.hashkey = keymem;
			k = kh_put(FlowHash, FlowHash, r, &ret);
			kh_key(FlowHash,k).counter[INBYTES]	   = flow_record->inBytes;
			kh_key(FlowHash,k).counter[INPACKETS]  = flow_record->inPackets;
			kh_key(FlowHash,k).counter[OUTBYTES]   = flow_record->out_bytes;
			kh_key(FlowHash,k).counter[OUTPACKETS] = flow_record->out_pkts;
			kh_key(FlowHash,k).counter[FLOWS]	   = flow_record->aggr_flows ? flow_record->aggr_flows : 1;

			kh_key(FlowHash,k).msecFirst = flow_record->msecFirst;
			kh_key(FlowHash,k).msecLast	 = flow_record->msecLast;

			void *p = malloc(record->size);
			if ( !p ) {
				LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
				exit(255);
			}
			memcpy((void *)p, raw_record, record->size);
			kh_key(FlowHash,k).flowrecord = p;

			// keymen got part of the cache
			keymem = NULL;
		}
	} 

} // End of AddBidirFlow

void AddFlowCache(void *raw_record, master_record_t *flow_record) {
recordHeaderV3_t *record = (recordHeaderV3_t *)raw_record;
static void	*keymem = NULL;
FlowHashRecord_t r;

	if ( bidir_flows )
		return AddBidirFlow(raw_record, flow_record);

	if ( keymem == NULL ) {
		keymem = nfmalloc(hashKeyLen);
	}
	New_HashKey(keymem, flow_record, 0);
	r.hashkey = keymem;
	r.hash = SuperFastHash(keymem, hashKeyLen);
	// r.hash = (uint32_t)flow_record->dstPort << 16 | flow_record->srcPort;

	int ret;
	khiter_t k = kh_put(FlowHash, FlowHash, r, &ret);
	if ( ret == 0 ) {
		// flow record found - best case! update all fields
		kh_key(FlowHash,k).counter[INBYTES]    += flow_record->inBytes;
		kh_key(FlowHash,k).counter[INPACKETS]  += flow_record->inPackets;
		kh_key(FlowHash,k).counter[OUTBYTES]   += flow_record->out_bytes;
		kh_key(FlowHash,k).counter[OUTPACKETS] += flow_record->out_pkts;

		if ( flow_record->msecFirst < kh_key(FlowHash,k).msecFirst ) {
			kh_key(FlowHash,k).msecFirst = flow_record->msecFirst;
		}
		if ( flow_record->msecLast > kh_key(FlowHash,k).msecLast )  {
			kh_key(FlowHash,k).msecLast =	flow_record->msecLast;
		}

		kh_key(FlowHash,k).counter[FLOWS] += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
	} else {
		// no flow record found and no TCP/UDP bidir flows. Insert flow record into hash
		kh_key(FlowHash,k).counter[INBYTES]	   = flow_record->inBytes;
		kh_key(FlowHash,k).counter[INPACKETS]  = flow_record->inPackets;
		kh_key(FlowHash,k).counter[OUTBYTES]   = flow_record->out_bytes;
		kh_key(FlowHash,k).counter[OUTPACKETS] = flow_record->out_pkts;
		kh_key(FlowHash,k).counter[FLOWS]      = flow_record->aggr_flows ? flow_record->aggr_flows : 1;

		kh_key(FlowHash,k).msecFirst  = flow_record->msecFirst;
		kh_key(FlowHash,k).msecLast	  = flow_record->msecLast;

		void *p = nfmalloc(record->size);
		memcpy((void *)p, raw_record, record->size);
		kh_key(FlowHash,k).flowrecord = p;

		// keymen got part of the cache
		keymem = NULL;
	} 

} // End of AddFlow


// print SortList - apply possible aggregation mask to zero out aggregated fields
static inline void PrintSortList(SortElement_t *SortList, uint32_t maxindex, outputParams_t *outputParams, 
	int GuessFlowDirection, printer_t print_record, int ascending) {
master_record_t	*aggr_record_mask = aggregate_info.mask;

	int max = maxindex;
	if ( outputParams->topN && outputParams->topN < maxindex )
		max = outputParams->topN;

	for (int i = 0; i < max; i++ ) {
		int j;

		if ( ascending )
			j = i;
		else
			j = maxindex - 1 - i;

		FlowHashRecord_t *r = (FlowHashRecord_t *)(SortList[j].record);
		recordHeaderV3_t *raw_record = (r->flowrecord);

		master_record_t	flow_record;
		memset((void *)&flow_record, 0, sizeof(master_record_t));
		ExpandRecord_v3(raw_record, &flow_record);

		flow_record.inPackets 	= r->counter[INPACKETS];
		flow_record.inBytes 	= r->counter[INBYTES];
		flow_record.out_pkts 	= r->counter[OUTPACKETS];
		flow_record.out_bytes 	= r->counter[OUTBYTES];
		flow_record.aggr_flows 	= r->counter[FLOWS];
		flow_record.msecFirst	= r->msecFirst;
		flow_record.msecLast	= r->msecLast;

		// apply IP mask from aggregation, to provide a pretty output
		if ( aggregate_info.has_masks ) {
			flow_record.V6.srcaddr[0] &= aggregate_info.IPmask[0];
			flow_record.V6.srcaddr[1] &= aggregate_info.IPmask[1];
			flow_record.V6.dstaddr[0] &= aggregate_info.IPmask[2];
			flow_record.V6.dstaddr[1] &= aggregate_info.IPmask[3];
		}

		if ( aggregate_info.apply_netbits ) 
			ApplyNetMaskBits(&flow_record, aggregate_info.apply_netbits);

		if ( aggr_record_mask )
			ApplyAggrMask(&flow_record, aggr_record_mask);

		if ( NeedSwap(GuessFlowDirection, &flow_record) )
			SwapFlow(&flow_record);

		print_record(stdout, &flow_record, outputParams->doTag);
	}

} // End of PrintSortList

// export SortList - apply possible aggregation mask to zero out aggregated fields
static inline void ExportSortList(SortElement_t *SortList, uint32_t maxindex, 
	nffile_t *nffile, int GuessFlowDirection, int ascending) {
master_record_t	*aggr_record_mask = aggregate_info.mask;

	for ( int i = 0; i < maxindex; i++ ) {
		int j;

		if ( ascending )
			j = i;
		else
			j = maxindex -1 - i;

		FlowHashRecord_t *r = (FlowHashRecord_t *)(SortList[j].record);
		recordHeaderV3_t *raw_record = (r->flowrecord);

		master_record_t	flow_record;
		memset((void *)&flow_record, 0, sizeof(master_record_t));
		ExpandRecord_v3(raw_record, &flow_record);

		flow_record.inPackets	= r->counter[INPACKETS];
		flow_record.inBytes 	= r->counter[INBYTES];
		flow_record.out_pkts 	= r->counter[OUTPACKETS];
		flow_record.out_bytes 	= r->counter[OUTBYTES];
		flow_record.aggr_flows 	= r->counter[FLOWS];
		flow_record.msecFirst	= r->msecFirst;
		flow_record.msecLast	= r->msecLast;

		// apply IP mask from aggregation, to provide a pretty output
		if ( aggregate_info.has_masks ) {
			flow_record.V6.srcaddr[0] &= aggregate_info.IPmask[0];
			flow_record.V6.srcaddr[1] &= aggregate_info.IPmask[1];
			flow_record.V6.dstaddr[0] &= aggregate_info.IPmask[2];
			flow_record.V6.dstaddr[1] &= aggregate_info.IPmask[3];
		}

		if ( aggregate_info.apply_netbits )
			ApplyNetMaskBits(&flow_record, aggregate_info.apply_netbits);

		if ( aggr_record_mask ) {
			ApplyAggrMask(&flow_record, aggr_record_mask);
		}

		if ( NeedSwap(GuessFlowDirection, &flow_record) )
			SwapFlow(&flow_record);

		PackRecordV3(&flow_record, nffile);
#ifdef DEVEL
		char *string;
		flow_record_to_raw((void *)&flow_record, &string, 0);
		printf("%s\n", string);
#endif
		// Update statistics
		UpdateStat(nffile->stat_record, &flow_record);
	}

} // End of ExportSortList

// print -s record/xx statistics with as many print orders as required
void PrintFlowStat(func_prolog_t record_header, printer_t print_record, outputParams_t *outputParams) {
size_t	maxindex;

	// Get sort array
	SortElement_t *SortList = GetSortList(&maxindex);
	if ( !SortList ) {
		return;
	}

	// process all the remaining stats, if requested
	for ( int order_index=0 ; order_mode[order_index].string != NULL; order_index++ ) {
		unsigned int order_bit = 1 << order_index;
		if ( FlowStat_order & order_bit ) {

			for ( int i = 0; i < maxindex; i++ ) {
				FlowHashRecord_t *r = (FlowHashRecord_t *)(SortList[i].record);
				/* if we have some different sort orders, which are not directly available in the FlowHashRecord_t
		 		 * we need to calculate this value first - such as bpp, bps etc.
		 		 */
				SortList[i].count  = order_mode[order_index].record_function(r, order_mode[order_index].inout);
			}

			int direction = PrintDirection;
			if ( maxindex > 2 ) {
				if ( maxindex < 100 ) {
					heapSort(SortList, maxindex, outputParams->topN, PrintDirection);
					direction = 0;
				} else {
 					blocksort((SortRecord_t *)SortList, maxindex);
				}
			}
			if ( !outputParams->quiet ) {
				if ( outputParams->mode == MODE_PLAIN ) {
					if ( outputParams->topN != 0 ) 
						printf("Top %i flows ordered by %s:\n", outputParams->topN, order_mode[order_index].string);
					else
						printf("Top flows ordered by %s:\n", order_mode[order_index].string);
				}
				if ( record_header ) 
					record_header();
			}
			PrintSortList(SortList, maxindex, outputParams, 0, print_record, direction);
		}
	}

} // End of PrintFlowStat

// print Flow cache
void PrintFlowTable(printer_t print_record, outputParams_t *outputParams, int GuessDir) {

	GuessDirection = GuessDir;

	size_t	maxindex;
	SortElement_t *SortList = GetSortList(&maxindex);
	if ( !SortList ) 
		return;

	if ( PrintOrder ) {
		// for any -O print mode
		for (int i=0; i<maxindex; i++ ) {
			FlowHashRecord_t *r = (FlowHashRecord_t *)(SortList[i].record);
			SortList[i].count  = order_mode[PrintOrder].record_function(r, order_mode[PrintOrder].inout);
		}

		if ( maxindex >= 2 ) {
			if ( maxindex < 100 ) {
				heapSort(SortList, maxindex, 0, PrintDirection);
				PrintDirection = 0;
			} else {
 				blocksort((SortRecord_t *)SortList, maxindex);
			}
		}

		PrintSortList(SortList, maxindex, outputParams, GuessDir, 
			print_record, PrintDirection);
	} else {
		// for -a and no -O sorting required
		PrintSortList(SortList, maxindex, outputParams, GuessDir, 
			print_record, PrintDirection);
	}
} // End of PrintFlowTable

int ExportFlowTable(nffile_t *nffile, int aggregate, int bidir, int GuessDir) {

	GuessDirection = GuessDir;

	ExportExporterList(nffile);

	size_t maxindex;
	SortElement_t *SortList = GetSortList(&maxindex);
	if ( !SortList ) 
		return 0;

	if ( PrintOrder ) {
		// for any -O print mode
		for ( int i = 0; i < maxindex; i++ ) {
			FlowHashRecord_t *r = (FlowHashRecord_t *)(SortList[i].record);
			SortList[i].count  = order_mode[PrintOrder].record_function(r, order_mode[PrintOrder].inout);
		}

		if ( maxindex >= 2 ) {
			if ( maxindex < 100 ) {
				heapSort(SortList, maxindex, 0, PrintDirection);
				PrintDirection = 0;
			} else {
 				blocksort((SortRecord_t *)SortList, maxindex);
			}
		}

		ExportSortList(SortList, maxindex, nffile, GuessDir, PrintDirection);
	} else {
		ExportSortList(SortList, maxindex, nffile, GuessDir, PrintDirection);
	}

    if ( nffile->block_header->NumRecords ) {
        if ( WriteBlock(nffile) <= 0 ) {
            LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			return 0;
        } 
    }

	return 1;

} // End of ExportFlowTable
