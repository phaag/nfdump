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

#define MULTIPLE_LIST_ORDERS 1
#define SINGLE_LIST_ORDER    0

#define NeedSwap(GuessDir, r) ( GuessDir && \
	((r)->proto == IPPROTO_TCP || (r)->proto == IPPROTO_UDP) && \
	 ((((r)->srcPort < 1024) && ((r)->dstPort >= 1024)) || \
	  (((r)->srcPort < 32768) && ((r)->dstPort >= 32768)) || \
	  (((r)->srcPort < 49152) && ((r)->dstPort >= 49152)) \
	 ) \
	)

typedef struct SortElement {
	void 		*record;
    uint64_t	count;
} SortElement_t;

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

int ParseListOrder(char *s, int multiple_orders );

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int tag);

void SwapFlow(master_record_t *flow_record);
#endif //_NFSTAT_H
