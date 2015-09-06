/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2009, Peter Haag
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
 *  $Author: haag $
 *
 *  $Id: nflowcache.c 40 2009-12-16 10:41:44Z haag $
 *
 *  $LastChangedRevision: 40 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "nflowcache.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#define ALIGN_BYTES (offsetof (struct { char x; uint64_t y; }, y) - 1)

extern int hash_hit;
extern int hash_miss;
extern int hash_skip;

/* function prototypes */
static void MemoryHandle_free(MemoryHandle_t *handle);

static int MemoryHandle_init(MemoryHandle_t *handle);

static inline void *MemoryHandle_get(MemoryHandle_t *handle, uint32_t size);

static inline FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache, void *flowkey, common_record_t *flow_record);

static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 );

static inline uint32_t SuperFastHash (const char * data, int len);

static inline void New_Hash_Key(void *keymem, master_record_t *flow_record, int swap_flow);

/* locals */
static hash_FlowTable FlowTable;
static int	initialised = 0;
uint32_t loopcnt = 0;

typedef struct aggregate_param_s {
	uint32_t	size;	// size of parameter in bytes
	uint32_t    offset;	// offset in master record
	uint64_t    mask;	// mask for this value in master record
	uint64_t    shift;	// bis shift for this value in master record
} aggregate_param_t;

static struct aggregate_info_s {
	char				*aggregate_token;	// name of aggregation parameter
	aggregate_param_t	param;				// the parameter array
	int					merge;				// apply bis mask? => -1 no, otherwise index of mask[] array
	int					active;				// is this parameter set?
	char				*fmt;				// for automatic output format generation
} aggregate_info [] = {
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

typedef struct Default_key_s {
	uint16_t srcport;
	uint16_t dstport;
	uint64_t srcaddr[2];
	uint64_t dstaddr[2];
	uint32_t proto;
} Default_key_t;


static aggregate_param_t *aggregate_stack = NULL;
static uint32_t	aggregate_key_len 		  = sizeof(Default_key_t);
static uint32_t	bidir_flows				  = 0;

// counter indices
// The array size of FlowTableRecord_t array counter must match.
enum CNT_IND { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };

#include "applybits_inline.c"

/* Functions */

static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 ) {
	if ( t1 > t2 )
		return 1;
	if ( t2 > t1 ) 
		return 2;
	// else t1 == t2 - offset is now relevant
	if ( offset1 > offset2 )
		return 1;
	if ( offset2 > offset1 )
		return 2;
	else
		// both times are the same
		return 0;
} // End of TimeMsec_CMP

static int MemoryHandle_init(MemoryHandle_t *handle) {

	handle->memblock = (void **)calloc(MaxMemBlocks, sizeof(void *));
	if ( !handle->memblock ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	handle->BlockSize	  = MemBlockSize;

	handle->memblock[0]  = malloc(MemBlockSize);
	handle->MaxBlocks	= MaxMemBlocks;
	handle->NumBlocks	= 1;
	handle->CurrentBlock = 0;
	handle->Allocted 	 = 0;
	
	return 1;

} // End of  MemoryHandle_init

static void MemoryHandle_free(MemoryHandle_t *handle) {
int i;

	dbg_printf("MEM: NumBlocks: %u\n", handle->NumBlocks);
	for ( i=0; i < handle->NumBlocks; i++ ) {
		free(handle->memblock[i]);
	}
	handle->NumBlocks	= 0;
	handle->CurrentBlock = 0;
	handle->Allocted 	 = 0;

	free((void *)handle->memblock);
	handle->memblock	= NULL;
	handle->MaxBlocks	= 0;

} // End of MemoryHandle_free

static inline void *MemoryHandle_get(MemoryHandle_t *handle, uint32_t size) {
void 		*p;
uint32_t	aligned_size;

	// make sure size of memory is aligned
	aligned_size = (((u_int)(size) + ALIGN_BYTES) &~ ALIGN_BYTES);

	if ( (handle->Allocted+aligned_size) > MemBlockSize ) {
		// not enough space - allocate a new memblock

		handle->CurrentBlock++;
		if ( handle->CurrentBlock >= handle->MaxBlocks ) {
			// we run out in memblock array - re-allocate memblock array
			handle->MaxBlocks += MaxMemBlocks;
			handle->memblock   = (void **)realloc(handle->memblock, handle->MaxBlocks * sizeof(void *));
			if ( !handle->memblock ) {
				fprintf(stderr, "realloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
				exit(255);
			}
		} 

		// allocate new memblock
		p = malloc(MemBlockSize);
		if ( !p ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			exit(255);
		}
		handle->memblock[handle->CurrentBlock] = p;
		// reset counter for new memblock
		handle->Allocted = 0;
		handle->NumBlocks++;
	} 

	// enough space available in current memblock
	p = handle->memblock[handle->CurrentBlock] + handle->Allocted;
	handle->Allocted += aligned_size;
	dbg_printf("Mem Handle: Requested: %u, aligned: %u, ptr: %lu\n", size, aligned_size, (long unsigned)p);
	return p;

} // End of MemoryHandle_get

hash_FlowTable *GetFlowTable(void) {
	return &FlowTable;
} // End of GetFlowTable

int Init_FlowTable(void) {
uint32_t maxindex;

	maxindex = (1 << HashBits);
	FlowTable.IndexMask   = maxindex -1;
	FlowTable.NumBits	  = HashBits;
	FlowTable.NumRecords  = 0;
	FlowTable.bucket	  = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	FlowTable.bucketcache = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.bucket || !FlowTable.bucketcache ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	FlowTable.keysize = aggregate_key_len;

	// keylen = number of uint64_t 
 	FlowTable.keylen  = aggregate_key_len >> 3;	// aggregate_key_len / 8
	if ( (aggregate_key_len & 0x7 ) != 0 )
		FlowTable.keylen++;

	dbg_printf("FlowTable.keysize %i bytes\n", FlowTable.keysize);
	dbg_printf("FlowTable.keylen %i uint64_t\n", FlowTable.keylen);

	if ( !MemoryHandle_init(&FlowTable.mem) ) 
		return 0;

	initialised = 1;
	return 1;

} // End of Init_FlowTable


void Dispose_FlowTable(void) {

	if ( !initialised )
		return;
	free((void *)FlowTable.bucket);
	free((void *)FlowTable.bucketcache);
	MemoryHandle_free(&FlowTable.mem);
	FlowTable.NumRecords  	= 0;
	FlowTable.bucket 		= NULL;
	FlowTable.bucketcache 	= NULL;

} // End of Dispose_FlowTable


static inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, void *flowkey, master_record_t *flow_record) {
uint32_t			index;
int bsize;
FlowTableRecord_t	*record;

	*index_cache = SuperFastHash((char *)flowkey, FlowTable.keysize);
	index = *index_cache & FlowTable.IndexMask;

	if ( FlowTable.bucket[index] == NULL ) {
		hash_hit++;
		return NULL;
	}

	record = FlowTable.bucket[index];

	// skip records with different hash value ( full 32bit )
	while ( record )
		if ( record->hash != *index_cache ) {
			hash_skip++;
			record = record->next;
		} else
			break;

	bsize = 0;
	while ( record ) {
		uint64_t	*k1 = (uint64_t *)flowkey;
		uint64_t	*k2 = (uint64_t *)record->hash_key;
		int i;
		
		// compare key and break as soon as keys do not match
		i = 0;
		while ( i < FlowTable.keylen ) {
			if ( k1[i] == k2[i] )
				i++;
			else
				break;
		}
		loopcnt += i;

		if ( i == FlowTable.keylen ) {
			// hit - record found
		
			// some stats for debugging
			if ( bsize == 0 )
				hash_hit++;
			else
				hash_miss++;
			return record;
		}

		record = record->next;
		bsize++;
	}
	return NULL;

} // End of hash_lookup_FlowTable


inline static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache, void *flowkey, common_record_t *raw_record) {
FlowTableRecord_t	*record;
uint32_t index = index_cache & FlowTable.IndexMask;

	// allocate enough memory for the new flow including all additional information in FlowTableRecord_t
	// MemoryHandle_get always succeeds. If no memory, MemoryHandle_get already exists cleanly
	record = MemoryHandle_get(&FlowTable.mem, sizeof(FlowTableRecord_t) - sizeof(common_record_t) + raw_record->size);

	record->next 	 = NULL;
	record->hash 	 = index_cache;
	record->hash_key = flowkey;

	memcpy((void *)&record->flowrecord, (void *)raw_record, raw_record->size);
	if ( FlowTable.bucket[index] == NULL ) 
		FlowTable.bucket[index] = record;
	else 
		FlowTable.bucketcache[index]->next = record;

	FlowTable.bucketcache[index] = record;
  	FlowTable.NumRecords++;

	return record;

} // End of hash_insert_FlowTable

void InsertFlow(common_record_t *raw_record, master_record_t *flow_record, extension_info_t *extension_info) {
FlowTableRecord_t	*record;

	// allocate enough memory for the new flow including all additional information in FlowTableRecord_t
	// MemoryHandle_get always succeeds. If no memory, MemoryHandle_get already exits cleanly
	record = MemoryHandle_get(&FlowTable.mem, sizeof(FlowTableRecord_t) - sizeof(common_record_t) + raw_record->size);

	record->next 	 = NULL;
	record->hash 	 = 0;
	record->hash_key = NULL;

	memcpy((void *)&record->flowrecord, (void *)raw_record, raw_record->size);
	if ( FlowTable.bucket[0] == NULL ) 
		FlowTable.bucket[0] = record;
	else 
		FlowTable.bucketcache[0]->next = record;

	FlowTable.bucketcache[0] = record;
	
	// safe the extension map and exporter reference
	record->map_info_ref = extension_info;
	record->exp_ref = flow_record->exp_ref;

	record->counter[INBYTES]	 = flow_record->dOctets;
	record->counter[INPACKETS] 	 = flow_record->dPkts;
	record->counter[OUTBYTES]	 = flow_record->out_bytes;
	record->counter[OUTPACKETS]  = flow_record->out_pkts;
	record->counter[FLOWS]	 	 = flow_record->aggr_flows ? flow_record->aggr_flows : 1;
	FlowTable.NumRecords++;

} // End of InsertFlow



void AddFlow(common_record_t *raw_record, master_record_t *flow_record, extension_info_t *extension_info ) {
static void			*keymem = NULL, *bidirkeymem = NULL;
FlowTableRecord_t	*FlowTableRecord;
uint32_t			index_cache; 

	if ( keymem == NULL ) {
		keymem = MemoryHandle_get(&FlowTable.mem ,FlowTable.keysize );
		// the last aligned word may not be fully used. set it to 0 to guarantee
		// a proper comarison

		// for 64 bit arch int == 8 bytes otherwise 4
		((int *)keymem)[FlowTable.keylen-1] = 0;

	}

	New_Hash_Key(keymem, flow_record, 0);

	// Update netflow statistics
	FlowTableRecord = hash_lookup_FlowTable(&index_cache, keymem, flow_record);
	if ( FlowTableRecord ) {
		// flow record found - best case! update all fields
		FlowTableRecord->counter[INBYTES]    += flow_record->dOctets;
		FlowTableRecord->counter[INPACKETS]  += flow_record->dPkts;
		FlowTableRecord->counter[OUTBYTES]   += flow_record->out_bytes;
		FlowTableRecord->counter[OUTPACKETS] += flow_record->out_pkts;

		if ( TimeMsec_CMP(flow_record->first, flow_record->msec_first, 
				FlowTableRecord->flowrecord.first, FlowTableRecord->flowrecord.msec_first) == 2) {
			FlowTableRecord->flowrecord.first = flow_record->first;
			FlowTableRecord->flowrecord.msec_first = flow_record->msec_first;
		}
		if ( TimeMsec_CMP(flow_record->last, flow_record->msec_last, 
				FlowTableRecord->flowrecord.last, FlowTableRecord->flowrecord.msec_last) == 1) {
			FlowTableRecord->flowrecord.last = flow_record->last;
			FlowTableRecord->flowrecord.msec_last = flow_record->msec_last;
		}

		FlowTableRecord->counter[FLOWS]        += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
		FlowTableRecord->flowrecord.tcp_flags  |= flow_record->tcp_flags;

	} else if ( !bidir_flows || ( flow_record->prot != IPPROTO_TCP && flow_record->prot != IPPROTO_UDP) ) {
		// no flow record found and no TCP/UDP bidir flows. Insert flow record into hash
		FlowTableRecord = hash_insert_FlowTable(index_cache, keymem, raw_record);

		FlowTableRecord->counter[INBYTES]	 = flow_record->dOctets;
		FlowTableRecord->counter[INPACKETS]  = flow_record->dPkts;
		FlowTableRecord->counter[OUTBYTES]   = flow_record->out_bytes;
		FlowTableRecord->counter[OUTPACKETS] = flow_record->out_pkts;
		FlowTableRecord->counter[FLOWS]   	 = flow_record->aggr_flows ? flow_record->aggr_flows : 1;

		FlowTableRecord->map_info_ref  	 	 = extension_info;
		FlowTableRecord->exp_ref  	 		 = flow_record->exp_ref;

		// keymen got part of the cache
		keymem = NULL;
	} else {
		// for bidir flows do
		uint32_t	bidir_index_cache; 

		// use tmp memory for bidir hash key to search for bidir flow
		// we need it only to lookup 
		if ( bidirkeymem == NULL ) {
			bidirkeymem = MemoryHandle_get(&FlowTable.mem ,FlowTable.keysize );
			// the last aligned word may not be fully used. set it to 0 to guarantee
			// a proper comarison

			// for 64 bit arch int == 8 bytes otherwise 4
			((int *)bidirkeymem)[FlowTable.keylen-1] = 0;
		}

		// generate the hash key for reverse record (bidir)
		New_Hash_Key(bidirkeymem, flow_record, 1);
		FlowTableRecord = hash_lookup_FlowTable(&bidir_index_cache, bidirkeymem, flow_record);
		if ( FlowTableRecord ) {
			// we found a corresponding flow - so update all fields in reverse direction
			FlowTableRecord->counter[OUTBYTES]   += flow_record->dOctets;
			FlowTableRecord->counter[OUTPACKETS] += flow_record->dPkts;
			FlowTableRecord->counter[INBYTES]    += flow_record->out_bytes;
			FlowTableRecord->counter[INPACKETS]  += flow_record->out_pkts;

			if ( TimeMsec_CMP(flow_record->first, flow_record->msec_first, 
					FlowTableRecord->flowrecord.first, FlowTableRecord->flowrecord.msec_first) == 2) {
				FlowTableRecord->flowrecord.first = flow_record->first;
				FlowTableRecord->flowrecord.msec_first = flow_record->msec_first;
			}
			if ( TimeMsec_CMP(flow_record->last, flow_record->msec_last, 
				FlowTableRecord->flowrecord.last, FlowTableRecord->flowrecord.msec_last) == 1) {
				FlowTableRecord->flowrecord.last = flow_record->last;
				FlowTableRecord->flowrecord.msec_last = flow_record->msec_last;
			}
	
			FlowTableRecord->counter[FLOWS]        += flow_record->aggr_flows ? flow_record->aggr_flows : 1;
			FlowTableRecord->flowrecord.tcp_flags  |= flow_record->tcp_flags;
		} else {
			// no bidir flow found 
			// insert original flow into the cache
			FlowTableRecord = hash_insert_FlowTable(index_cache, keymem, raw_record);
	
			FlowTableRecord->counter[INBYTES]	 = flow_record->dOctets;
			FlowTableRecord->counter[INPACKETS]  = flow_record->dPkts;
			FlowTableRecord->counter[OUTBYTES]   = flow_record->out_bytes;
			FlowTableRecord->counter[OUTPACKETS] = flow_record->out_pkts;
			FlowTableRecord->counter[FLOWS]   	 = flow_record->aggr_flows ? flow_record->aggr_flows : 1;
			FlowTableRecord->map_info_ref  	 	 = extension_info;
			FlowTableRecord->exp_ref  	 		 = flow_record->exp_ref;

			keymem = NULL;
		}

	} 

} // End of AddFlow


#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
					   +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

static inline uint32_t SuperFastHash (const char * data, int len) {
uint32_t hash = len, tmp;
int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
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

int SetBidirAggregation(void) {
	
	if ( aggregate_stack ) {
		fprintf(stderr, "Can not set bidir mode while custom aggregation is set.\n");
		return 0;
	}

	bidir_flows = 1;

	return 1;

} // End of SetBidirAggregation

int ParseAggregateMask( char *arg, char **aggr_fmt ) {
char 		*p, *q;
uint64_t mask[2];
uint32_t subnet, stack_count;
int		 i, fmt_len, has_mask;
struct aggregate_info_s *a;


	if ( bidir_flows ) {
		fprintf(stderr, "Can not set custom aggregation while bidir mode is set.\n");
		return 0;
	}

	stack_count = 0;
	subnet 		= 0;
	has_mask    = 0;

	aggregate_key_len = 0;

	fmt_len = 0;
	i = 0;
	while ( aggregate_info[i].aggregate_token != NULL ) {
		if ( aggregate_info[i].active )
			stack_count++;
		if ( aggregate_info[i].fmt )
			fmt_len += ( strlen(aggregate_info[i].fmt) + 1 );
		i++;
	}
	fmt_len++;	// trailing '\0'

	if ( !*aggr_fmt ) {
		*aggr_fmt = malloc(fmt_len);
		(*aggr_fmt)[0] = '\0';
	}
	if ( !*aggr_fmt ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}


	FlowTable.apply_netbits  = 0;
	FlowTable.has_masks = 0;
	FlowTable.IPmask[0] = 0xffffffffffffffffLL;;
	FlowTable.IPmask[1] = 0xffffffffffffffffLL;;
	FlowTable.IPmask[2] = 0xffffffffffffffffLL;;
	FlowTable.IPmask[3] = 0xffffffffffffffffLL;;

	// separate tokens
	p = strtok(arg, ",");
	while ( p ) {

		// check for subnet bits
		q = strchr(p, '/');
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
					fprintf(stderr, "Subnet specifier '%s' out of range for IPv4\n", q+1);
					return 0;
				}

				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 32 - subnet );

			} else if ( *n == '6' ) {
				// IPv6
				if ( subnet < 1 || subnet > 128 ) {
					fprintf(stderr, "Subnet specifier '%s' out of range for IPv6\n", q+1);
					return 0;
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
				fprintf(stderr, "Need src4/dst4 src6/dst6 for IPv4 or IPv6 to aggregate with explicit netmask: '%s'\n", p);
				return 0;
			}
		} else {
			has_mask = 0;
		}

		a = aggregate_info;
		while ( a->aggregate_token && (strcasecmp(p, a->aggregate_token ) != 0) )
			a++;

		if ( a->active ) {
			fprintf(stderr, "Skip already given aggregation mask: %s\n", p);
		} else if ( a->aggregate_token != NULL ) {

			if ( a->fmt != NULL ) {
				strncat(*aggr_fmt, a->fmt, fmt_len);
				fmt_len -= strlen(a->fmt);
				strncat(*aggr_fmt, " ", fmt_len);
				fmt_len -= 1;
			}

			if ( strcasecmp(p, "srcnet" ) == 0 ) {
				FlowTable.apply_netbits  |= 1;
			}
			if ( strcasecmp(p, "dstnet" ) == 0 ) {
				FlowTable.apply_netbits  |= 2;
			}

			do {
				int i = a->merge;
				if ( i != -1 ) {
					if ( has_mask ) {
						a->param.mask = mask[i];
					} else {
						fprintf(stderr, "'%s' needs subnet bits too aggregate\n", p);
						return 0;
					}
				} else {
					if ( has_mask ) { 
						fprintf(stderr, "'%s' No subnet bits allowed here!\n", p);
						return 0;
					}
				}
				a->active = 1;
				aggregate_key_len += a->param.size;
				stack_count++;
				a++;
			} while (a->aggregate_token && (strcasecmp(p, a->aggregate_token ) == 0));

			if ( has_mask ) {
				FlowTable.has_masks = 1;
				switch (p[0]) {
					case 's':
						FlowTable.IPmask[0] = mask[0];
						FlowTable.IPmask[1] = mask[1];
						break;
					case 'd':
						FlowTable.IPmask[2] = mask[0];
						FlowTable.IPmask[3] = mask[1];
						break;
				}
			} 
		} else {
			fprintf(stderr, "Unknown aggregation specifier '%s'\n", p);
			return 0;
		}

		p = strtok(NULL, ",");
	}

	if ( stack_count == 0 ) {
		fprintf(stderr, "No aggregation specified!\n");
		return 0;
	}

	aggregate_stack = (aggregate_param_t *)malloc((stack_count+1) * sizeof(aggregate_param_t));

	stack_count = 0;
	a = aggregate_info;
	while ( a->aggregate_token ) {
		if ( a->active ) {
			aggregate_stack[stack_count++] = a->param;
			dbg_printf("Set aggregate param: %s\n", a->aggregate_token);
		}
		a++;
	}
	// final '0' record
	aggregate_stack[stack_count] = a->param;

	dbg_printf("Aggregate key len: %i bytes\n", aggregate_key_len);
	dbg_printf("Aggregate format string: '%s'\n", *aggr_fmt);

#ifdef DEVEL
	if ( aggregate_stack ) {
		aggregate_param_t *aggr_param = aggregate_stack;
		printf("Aggregate stack:\n");
		while ( aggr_param->size ) {
			printf("Offset: %u, Mask: %llx, Shift: %llu\n", aggr_param->offset, 
				(long long unsigned)aggr_param->mask,  (long long unsigned)aggr_param->shift);
			aggr_param++;
		} // while 
	} 
	printf("Has IP mask: %i %i\n", has_mask, FlowTable.has_masks);
	printf("Mask 0: 0x%llx\n", (unsigned long long)FlowTable.IPmask[0]);
	printf("Mask 1: 0x%llx\n", (unsigned long long)FlowTable.IPmask[1]);
	printf("Mask 2: 0x%llx\n", (unsigned long long)FlowTable.IPmask[2]);
	printf("Mask 3: 0x%llx\n", (unsigned long long)FlowTable.IPmask[3]);

#endif

	return 1;
} // End of ParseAggregateMask

master_record_t *GetMasterAggregateMask(void) {
master_record_t *aggr_record_mask;

	if ( aggregate_stack ) {
		uint64_t *r;
		aggregate_param_t *aggr_param = aggregate_stack;

		aggr_record_mask = (master_record_t *)malloc(sizeof(master_record_t));
		if ( !aggr_record_mask ) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}

		r = (uint64_t *)aggr_record_mask;
		memset((void *)aggr_record_mask, 0, sizeof(master_record_t));
		while ( aggr_param->size ) {
			int offset = aggr_param->offset;
			r[offset] |= aggr_param->mask;
			aggr_param++;
		}

		// not really needed, but preset it anyway
		r[0] = 0xffffffffffffffffLL;
		r[1] = 0xffffffffffffffffLL;
		aggr_record_mask->dPkts   	= 0xffffffffffffffffLL;
		aggr_record_mask->dOctets 	= 0xffffffffffffffffLL;
		aggr_record_mask->out_pkts   = 0xffffffffffffffffLL;
		aggr_record_mask->out_bytes  = 0xffffffffffffffffLL;
		aggr_record_mask->aggr_flows = 0xffffffffffffffffLL;
		aggr_record_mask->last    	= 0xffffffff;
		
		return aggr_record_mask;
	} else {
		return NULL;
	}

} // End of GetMasterAggregateMask

static inline void New_Hash_Key(void *keymem, master_record_t *flow_record, int swap_flow) {
uint64_t *record = (uint64_t *)flow_record;
Default_key_t *keyptr;

	// apply src/dst mask bits if requested
	if ( FlowTable.apply_netbits ) {
		ApplyNetMaskBits(flow_record, FlowTable.apply_netbits);
	}

	if ( aggregate_stack ) {
		// custom user aggregation
		aggregate_param_t *aggr_param = aggregate_stack;
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
		keyptr = (Default_key_t *)keymem;
		keyptr->srcaddr[0]	= flow_record->v6.dstaddr[0];
		keyptr->srcaddr[1]	= flow_record->v6.dstaddr[1];
		keyptr->dstaddr[0]	= flow_record->v6.srcaddr[0];
		keyptr->dstaddr[1]	= flow_record->v6.srcaddr[1];
		keyptr->srcport		= flow_record->dstport;
		keyptr->dstport		= flow_record->srcport;
		keyptr->proto		= flow_record->prot;
	} else {
		// default 5-tuple aggregation
		keyptr = (Default_key_t *)keymem;
		keyptr->srcaddr[0]	= flow_record->v6.srcaddr[0];
		keyptr->srcaddr[1]	= flow_record->v6.srcaddr[1];
		keyptr->dstaddr[0]	= flow_record->v6.dstaddr[0];
		keyptr->dstaddr[1]	= flow_record->v6.dstaddr[1];
		keyptr->srcport		= flow_record->srcport;
		keyptr->dstport		= flow_record->dstport;
		keyptr->proto		= flow_record->prot;
	}
	
} // End of New_Hash_Key

