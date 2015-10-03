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
 *  $Id: nfexport.c 54 2010-01-29 11:30:22Z haag $
 *
 *  $LastChangedRevision: 54 $
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
#include "nf_common.h"
#include "nffile.h"
#include "nfx.h"
#include "nfstat.h"
#include "nfxstat.h"
#include "nflowcache.h"
#include "exporter.h"

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

static void ExportExtensionMaps( int aggregate, int bidir, nffile_t *nffile, extension_map_list_t *extension_map_list );

static void ExportExtensionMaps( int aggregate, int bidir, nffile_t *nffile, extension_map_list_t *extension_map_list ) {
int map_id, opt_extensions, num_extensions, new_map_size, opt_align;
extension_map_t	*new_map;

	// no extension maps to export - nothing to do
	if ( extension_map_list->max_used == 0 )
		return;

	new_map = NULL;

	for ( map_id = 0; map_id <= extension_map_list->max_used; map_id++ ) {
		extension_map_t *SourceMap = extension_map_list->slot[map_id]->map;
		int i, has_aggr_flows, has_out_bytes, has_out_packets, has_nat;
		// skip maps, never referenced

#ifdef DEVEL
		printf("Process map id: %i\n", map_id);
		printf("Ref count: %i\n", extension_map_list->slot[map_id]->ref_count);
#endif

		if ( extension_map_list->slot[map_id]->ref_count == 0 ) {
#ifdef DEVEL
			printf("Ref count = 0 => Skip map\n");
#endif
			continue;
		}

		// parse Source map if it contains all required fields:
		// for aggregation EX_AGGR_FLOWS_4 or _8 is required
		// for bidir flows EX_OUT_PKG_4 or _8 and EX_OUT_BYTES_4 or_8 are required
		has_aggr_flows  = 0;
		has_out_bytes	= 0;
		has_out_packets	= 0;
		// parse map for older NEL nat extension
		has_nat			= 0;

		num_extensions = 0;
		i = 0;
		while ( SourceMap->ex_id[i] ) {
			switch (SourceMap->ex_id[i]) {
				case EX_AGGR_FLOWS_4:
				case EX_AGGR_FLOWS_8:
					has_aggr_flows  = 1;
					break;
				case EX_OUT_BYTES_4:
				case EX_OUT_BYTES_8:
					has_out_bytes	= 1;
					break;
				case EX_OUT_PKG_4:
				case EX_OUT_PKG_8:
					has_out_packets	= 1;
					break;
				case EX_NEL_GLOBAL_IP_v4:
					// Map old nat extension to common NSEL extension
					SourceMap->ex_id[i] = EX_NSEL_XLATE_IP_v4;
					has_nat	= 1;
				// default: nothing to do
			}
			i++;
			num_extensions++;
		}
#ifdef DEVEL
		printf("map: num_extensions: %i, has_aggr_flows: %i, has_out_bytes: %i, has_out_packets: %i, has_nat: %i\n", 
			num_extensions, has_aggr_flows, has_out_bytes, has_out_packets, has_nat);
#endif

		// count missing extensions
		opt_extensions = 0;
		if ( aggregate && !has_aggr_flows )
			opt_extensions++;

		if ( bidir && !has_out_bytes ) 
			opt_extensions++;

		if ( bidir && !has_out_packets ) 
			opt_extensions++;

		opt_extensions += has_nat;
		// calculate new map size
		new_map_size = sizeof(extension_map_t) + ( num_extensions + opt_extensions) * sizeof(uint16_t);

#ifdef DEVEL
		printf("opt_extensions: %i, new_map_size: %i\n", opt_extensions,new_map_size );
		PrintExtensionMap(SourceMap);
#endif
		if ( opt_extensions ) {
    		// align 32bits
    		if (( new_map_size & 0x3 ) != 0 ) {
        		new_map_size += 4 - ( new_map_size & 0x3 );
				opt_align = 1;
    		} else {
				opt_align = 0;
			}
		} else {
			// no missing elements in extension map - we can used the original one
			// and we are done

#ifdef DEVEL
			printf("New map identical => use this map:\n");
			PrintExtensionMap(SourceMap);
#endif
			// Flush the map to disk
			AppendToBuffer(nffile, (void *)SourceMap, SourceMap->size);
			continue;
		}

#ifdef DEVEL
		printf("Create new map:\n");
#endif
		// new map is different - create the new map
		new_map = (extension_map_t *)malloc((ssize_t)new_map_size);
		if ( !new_map ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}

		// Panic check - should never happen, but we are going to copy memory
		if ( new_map_size < SourceMap->size ) {
			LogError("PANIC! new_map_size(%i) < SourceMap->size(%i) in %s line %d\n", 
				new_map_size, SourceMap->size,  __FILE__, __LINE__);
			exit(255);
		}
		// copy existing map
		memcpy((void *)new_map, (void *)SourceMap, SourceMap->size);
		
		new_map->size   = new_map_size;

		// add the missing extensions to the output map
		// skip to end of current map
		while ( new_map->ex_id[i] )
			i++;

		if ( has_nat ) {
			new_map->ex_id[i++] 	 = EX_NSEL_XLATE_PORTS;
			new_map->extension_size += extension_descriptor[EX_NSEL_XLATE_PORTS].size;
		}
		// add missing map elements
		if ( aggregate && !has_aggr_flows ) {
			new_map->ex_id[i++] 	 = EX_AGGR_FLOWS_4;
			new_map->extension_size += extension_descriptor[EX_AGGR_FLOWS_4].size;
		}
		if ( bidir && !has_out_bytes )  {
			new_map->ex_id[i++] 	 = EX_OUT_BYTES_8;
			new_map->extension_size += extension_descriptor[EX_OUT_BYTES_8].size;
		}
		if ( bidir && !has_out_packets )  {
			new_map->ex_id[i++] 	 = EX_OUT_PKG_8;
			new_map->extension_size += extension_descriptor[EX_OUT_PKG_8].size;
		}
		// end of map tag
		new_map->ex_id[i++]    = 0;
		if ( opt_align )
			new_map->ex_id[i]  = 0;

#ifdef DEVEL
		PrintExtensionMap(new_map);
#endif

		free(extension_map_list->slot[map_id]->map);
		extension_map_list->slot[map_id]->map = new_map; 

		// Flush the map to disk
		AppendToBuffer(nffile, (void *)new_map, new_map->size);

	}

} // End of ExportExtensionMaps

int ExportFlowTable(nffile_t *nffile, int aggregate, int bidir, int date_sorted, extension_map_list_t *extension_map_list) {
hash_FlowTable *FlowTable;
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
master_record_t		*aggr_record_mask;
uint32_t 			i;
uint32_t			maxindex, c;
#ifdef DEVEL
char				*string;
#endif

	ExportExtensionMaps(aggregate, bidir, nffile, extension_map_list);
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
				SortList[c].count  = 1000LL * r->flowrecord.first + r->flowrecord.msec_first;	// sort according the date
				SortList[c].record = (void *)r;
				c++;
				r = r->next;
			}
		}

		if ( c != maxindex ) {
			LogError("Abort: Missmatch %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}

		if ( c >= 2 )
 			heapSort(SortList, c, 0);

		for ( i = 0; i < c; i++ ) {
			master_record_t	*flow_record;
			common_record_t *raw_record;
			extension_info_t *extension_info;

			r = (FlowTableRecord_t *)(SortList[i].record);
			raw_record = &(r->flowrecord);
			extension_info = r->map_info_ref;

			flow_record = &(extension_info->master_record);
			ExpandRecord_v2( raw_record, extension_info, r->exp_ref, flow_record);
			flow_record->dPkts 		= r->counter[INPACKETS];
			flow_record->dOctets 	= r->counter[INBYTES];
			flow_record->out_pkts 	= r->counter[OUTPACKETS];
			flow_record->out_bytes 	= r->counter[OUTBYTES];
			flow_record->aggr_flows 	= r->counter[FLOWS];

			// apply IP mask from aggregation, to provide a pretty output
			if ( FlowTable->has_masks ) {
				flow_record->v6.srcaddr[0] &= FlowTable->IPmask[0];
				flow_record->v6.srcaddr[1] &= FlowTable->IPmask[1];
				flow_record->v6.dstaddr[0] &= FlowTable->IPmask[2];
				flow_record->v6.dstaddr[1] &= FlowTable->IPmask[3];
			}

			if ( FlowTable->apply_netbits )
				ApplyNetMaskBits(flow_record, FlowTable->apply_netbits);

			if ( aggr_record_mask ) {
				ApplyAggrMask(flow_record, aggr_record_mask);
			}

			// switch to output extension map
			flow_record->map_ref = extension_info->map;
			flow_record->ext_map = extension_info->map->map_id;
			PackRecord(flow_record, nffile);
#ifdef DEVEL
			format_file_block_record((void *)flow_record, &string, 0);
			printf("%s\n", string);
#endif
			// Update statistics
			UpdateStat(nffile->stat_record, flow_record);
		}

	} else {
		// print them as they came
		for ( i=0; i<=FlowTable->IndexMask; i++ ) {
			r = FlowTable->bucket[i];
			while ( r ) {
				master_record_t	*flow_record;
				common_record_t *raw_record;
				extension_info_t *extension_info;

				raw_record = &(r->flowrecord);
				extension_info = r->map_info_ref;

				flow_record = &(extension_info->master_record);
				ExpandRecord_v2( raw_record, extension_info, r->exp_ref, flow_record);
				flow_record->dPkts 		= r->counter[INPACKETS];
				flow_record->dOctets 	= r->counter[INBYTES];
				flow_record->out_pkts 	= r->counter[OUTPACKETS];
				flow_record->out_bytes 	= r->counter[OUTBYTES];
				flow_record->aggr_flows	= r->counter[FLOWS];

				// apply IP mask from aggregation, to provide a pretty output
				if ( FlowTable->has_masks ) {
					flow_record->v6.srcaddr[0] &= FlowTable->IPmask[0];
					flow_record->v6.srcaddr[1] &= FlowTable->IPmask[1];
					flow_record->v6.dstaddr[0] &= FlowTable->IPmask[2];
					flow_record->v6.dstaddr[1] &= FlowTable->IPmask[3];
				}

				if ( FlowTable->apply_netbits )
					ApplyNetMaskBits(flow_record, FlowTable->apply_netbits);

				if ( aggr_record_mask ) {
					ApplyAggrMask(flow_record, aggr_record_mask);
				}

				// switch to output extension map
				flow_record->map_ref = extension_info->map;
				flow_record->ext_map = extension_info->map->map_id;
				PackRecord(flow_record, nffile);
#ifdef DEVEL
				format_file_block_record((void *)flow_record, &string, 0);
				printf("%s\n", string);
#endif
				// Update statistics
				UpdateStat(nffile->stat_record, flow_record);

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


