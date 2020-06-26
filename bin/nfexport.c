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

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "nfxV3.h"
#include "nfstat.h"
#include "nflowcache.h"
#include "exporter.h"
#include "output_util.h"
#include "nfexport.h"

#include "nfdump_inline.c"

#define NEED_PACKRECORD 1
#include "nffile_inline.c"
#undef NEED_PACKRECORD

#include "heapsort_inline.c"
#include "applybits_inline.c"

/* global vars */
extern extension_descriptor_t extension_descriptor[];

/* local vars */
enum CntIndices { FLOWS = 0, INPACKETS, INBYTES, OUTPACKETS, OUTBYTES };

int ExportFlowTable(nffile_t *nffile, int aggregate, int bidir, int GuessDir, int date_sorted) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
master_record_t		*aggr_record_mask;
uint32_t 			i;
uint32_t			maxindex, c;
#ifdef DEVEL
char				*string;
#endif

	ExportExporterList(nffile);

	aggr_record_mask = GetMasterAggregateMask();

	FlowTable = GetFlowTable();
	c = 0;
	maxindex = FlowTable->NumRecords;
	if ( date_sorted ) {
		// Sort records according the date
		SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

		if ( !SortList ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}

		// preset SortList table - still unsorted
		for ( i=0; i<=FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			if ( !r ) 
				continue;

			// foreach elem in this bucket
			while ( r ) {
				SortList[c].count  = r->msecFirst;	// sort according the date
				SortList[c].record = (void *)r;
				c++;
				r = r->next;
			}
		}

		if ( c != maxindex ) {
			LogError("Abort: Mismatch %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}

		if ( c >= 2 )
 			heapSort(SortList, c, 0);

		for ( i = 0; i < c; i++ ) {
			master_record_t	flow_record;
			recordHeaderV3_t *raw_record;

			r = (FlowTableRecord_t *)(SortList[i].record);
			raw_record = &(r->flowrecord);

			memset((void *)&flow_record, 0, sizeof(master_record_t));
			ExpandRecord_v3(raw_record, &flow_record);
			flow_record.dPkts 		= r->counter[INPACKETS];
			flow_record.dOctets 	= r->counter[INBYTES];
			flow_record.out_pkts 	= r->counter[OUTPACKETS];
			flow_record.out_bytes 	= r->counter[OUTBYTES];
			flow_record.aggr_flows 	= r->counter[FLOWS];

			// apply IP mask from aggregation, to provide a pretty output
			if ( FlowTable->has_masks ) {
				flow_record.V6.srcaddr[0] &= FlowTable->IPmask[0];
				flow_record.V6.srcaddr[1] &= FlowTable->IPmask[1];
				flow_record.V6.dstaddr[0] &= FlowTable->IPmask[2];
				flow_record.V6.dstaddr[1] &= FlowTable->IPmask[3];
			}

			if ( FlowTable->apply_netbits )
				ApplyNetMaskBits(&flow_record, FlowTable->apply_netbits);

			if ( aggr_record_mask ) {
				ApplyAggrMask(&flow_record, aggr_record_mask);
			}

			if ( NeedSwap(GuessDir, &flow_record) )
				SwapFlow(&flow_record);

			PackRecordV3(&flow_record, nffile);
#ifdef DEVEL
			flow_record_to_raw((void *)&flow_record, &string, 0);
			printf("%s\n", string);
#endif
			// Update statistics
			UpdateStat(nffile->stat_record, &flow_record);
		}

	} else {
		// print them as they came
		for ( i=0; i<=FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			while ( r ) {
				master_record_t	flow_record;
				recordHeaderV3_t *raw_record;

				raw_record = &(r->flowrecord);
				memset((void *)&flow_record, 0, sizeof(master_record_t));
				ExpandRecord_v3(raw_record, &flow_record);
				flow_record.dPkts 		= r->counter[INPACKETS];
				flow_record.dOctets 	= r->counter[INBYTES];
				flow_record.out_pkts 	= r->counter[OUTPACKETS];
				flow_record.out_bytes 	= r->counter[OUTBYTES];
				flow_record.aggr_flows	= r->counter[FLOWS];

				// apply IP mask from aggregation, to provide a pretty output
				if ( FlowTable->has_masks ) {
					flow_record.V6.srcaddr[0] &= FlowTable->IPmask[0];
					flow_record.V6.srcaddr[1] &= FlowTable->IPmask[1];
					flow_record.V6.dstaddr[0] &= FlowTable->IPmask[2];
					flow_record.V6.dstaddr[1] &= FlowTable->IPmask[3];
				}

				if ( FlowTable->apply_netbits )
					ApplyNetMaskBits(&flow_record, FlowTable->apply_netbits);

				if ( aggr_record_mask ) {
					ApplyAggrMask(&flow_record, aggr_record_mask);
				}

				if ( NeedSwap(GuessDir, &flow_record) )
					SwapFlow(&flow_record);

				// switch to output extension map
				PackRecordV3(&flow_record, nffile);
#ifdef DEVEL
				flow_record_to_raw((void *)&flow_record, &string, 0);
				printf("%s\n", string);
#endif
				// Update statistics
				UpdateStat(nffile->stat_record, &flow_record);

				r = r->next;
			}
		}

	}

    if ( nffile->block_header->NumRecords ) {
        if ( WriteBlock(nffile) <= 0 ) {
            LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			return 0;
        } 
    }

	return 1;

} // End of ExportFlowTable


