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

#ifndef _NFSTAT_H
#define _NFSTAT_H 1

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "output_util.h"
#include "output_fmt.h"
#include "nfx.h"
#include "nffile.h"

/* Definitions */


/*
 * Stat Table
 * In order to generate any flow element statistics, the flows passed the filter
 * are stored into an internal hash table.
 */

typedef struct SumRecord_s {
	uint64_t	flows;
	uint64_t	ipkg;
	uint64_t	opkg;
	uint64_t	ibyte;
	uint64_t	obyte;
} SumRecord_t;

typedef struct StatRecord {
	// record chain
	struct StatRecord *next;
	// flow parameters
	uint64_t	counter[5];	// flows ipkg ibyte opkg obyte
	uint32_t	first;
	uint32_t	last;
	uint16_t	msec_first;
	uint16_t	msec_last;
	// key 
	uint8_t		prot;
	uint64_t	stat_key[2];
} StatRecord_t;

typedef struct hash_StatTable {
	/* hash table data */
	uint16_t 			NumBits;		/* width of the hash table */
	uint32_t			IndexMask;		/* Mask which corresponds to NumBits */
	StatRecord_t 		**bucket;		/* Hash entry point: points to elements in the stat block */
	StatRecord_t 		**bucketcache;	/* in case of index collisions, this array points to the last element with that index */

	/* memory management */
	/* memory blocks - containing the stat records */
	StatRecord_t		**memblock;		/* array holding all NumBlocks allocated stat blocks */
	uint32_t 			MaxBlocks;		/* Size of memblock array */
	/* stat blocks - containing the stat records */
	uint32_t 			NumBlocks;		/* number of allocated stat blocks in memblock array */
	uint32_t 			Prealloc;		/* Number of stat records in each stat block */
	uint32_t			NextBlock;		/* This stat block contains the next free slot for a stat recorrd */
	uint32_t			NextElem;		/* This element in the current stat block is the next free slot */
} hash_StatTable;

typedef struct SortElement {
	void 		*record;
    uint64_t	count;
} SortElement_t;

#define ASCENDING 1
#define DESCENDING 0

#define MULTIPLE_LIST_ORDERS 1
#define SINGLE_LIST_ORDER    0

#define NeedSwap(GuessDir, r) ( GuessDir && \
	((r)->prot == IPPROTO_TCP || (r)->prot == IPPROTO_UDP) && \
	 ((((r)->srcport < 1024) && ((r)->dstport >= 1024)) || \
	  (((r)->srcport < 32768) && ((r)->dstport >= 32768)) || \
	  (((r)->srcport < 49152) && ((r)->dstport >= 49152)) \
	 ) \
	)

/* Function prototypes */
void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string );

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc);

void Dispose_StatTable(void);

int SetStat(char *str, int *element_stat, int *flow_stat);

int Parse_PrintOrder(char *order);

void AddStat(common_record_t *raw_record, master_record_t *flow_record );

void PrintFlowTable(printer_t print_record, outputParams_t *outputParams, int GuessDir, extension_map_list_t *extension_map_list);

void PrintFlowStat(func_prolog_t record_header, printer_t print_record, outputParams_t *outputParams, extension_map_list_t *extension_map_list);
void PrintElementStat(stat_record_t	*sum_stat, outputParams_t *outputParams, printer_t print_record);

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int tag);

void SwapFlow(master_record_t *flow_record);
#endif //_NFSTAT_H
