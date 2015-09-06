/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2012, Peter Haag
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
 *  $Author: peter $
 *
 *  $Id: exporter.c 224 2014-02-16 12:59:29Z peter $
 *
 *  $LastChangedRevision: 224 $
 *	
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "util.h"
#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"
#include "nf_common.h"
#include "netflow_v1.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "ipfix.h"

/* global */
generic_exporter_t **exporter_list;

/* local variables */
#define MAX_EXPORTERS 65535
static generic_exporter_t *exporter_root;

#include "nffile_inline.c"

/* local prototypes */

/* functions */
int InitExporterList(void) {

	exporter_list = calloc(MAX_EXPORTERS, sizeof(generic_exporter_t *));
	if ( !exporter_list ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	exporter_root = NULL;
	return 1;

} // End of InitExporterList

int AddExporterInfo(exporter_info_record_t *exporter_record) {
uint32_t id = exporter_record->sysid;
int i;
char *p1, *p2;

	// sanity check
	if ( id >= MAX_EXPORTERS ) {
		LogError("Exporter id: %u out of range. Skip exporter", id);
		return 0;
	}
	if ( exporter_list[id] != NULL ) {
		// slot already taken - check if exporters are identical
		exporter_record->sysid = exporter_list[id]->info.sysid;
		if ( memcmp((void *)exporter_record, (void *)&(exporter_list[id]->info), sizeof(exporter_info_record_t)) == 0 ) {
			dbg_printf("Found identical exporter record at SysID: %i, Slot: %u\n", exporter_record->sysid, id);
			// we are done
			return 2;
		} else {
			// exporters not identical - move current slot
			int i;
			// search first emty slot at the top of the list
			for ( i = id+1; i < MAX_EXPORTERS  && exporter_list[i] != NULL; i++ ) {;}
			if ( i >= MAX_EXPORTERS ) {
				// all slots taken
				LogError("Too many exporters (>256)\n");
				return 0;
			} 
			dbg_printf("Move existing exporter from slot %u, to %i\n", id, i);
			// else - move slot
			exporter_list[i] = exporter_list[id];
			exporter_list[id] = NULL;
			exporter_record->sysid = i;
		}
	}

	// slot[id] is now available
	exporter_list[id] = (generic_exporter_t *)calloc(1, sizeof(generic_exporter_t));
	if ( !exporter_list[id] ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	// SPARC gcc fails here, if we use directly a pointer to the struct.
	// SPARC barfs and core dumps otherwise
	// memcpy((void *)&(exporter_list[id]->info), (void *)exporter_record, sizeof(exporter_info_record_t));
	p1 = (char *)&(exporter_list[id]->info);
	p2 = (char *)exporter_record;
	for ( i=0; i<sizeof(exporter_info_record_t); i++ ) 
		*p1++ = *p2++;

	dbg_printf("Insert exporter record in Slot: %i, Sysid: %u\n", id, exporter_record->sysid);

#ifdef DEVEL
	{
		#define IP_STRING_LEN   40
		char ipstr[IP_STRING_LEN];
		if ( exporter_record->sa_family == AF_INET ) {
			uint32_t _ip = htonl(exporter_record->ip.v4);
			inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
			printf("SysID: %u, IP: %16s, version: %u, ID: %2u, Slot: %u\n", exporter_record->sysid,
				ipstr, exporter_record->version, exporter_record->id, id);
		} else if ( exporter_record->sa_family == AF_INET6 ) {
			uint64_t _ip[2];
			_ip[0] = htonll(exporter_record->ip.v6[0]);
			_ip[1] = htonll(exporter_record->ip.v6[1]);
			inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
			printf("SysID: %u, IP: %40s, version: %u, ID: %2u, Slot: %u\n", exporter_record->sysid,
				ipstr, exporter_record->version, exporter_record->id, id);
		} else {
			strncpy(ipstr, "<unknown>", IP_STRING_LEN);
			printf("**** Exporter IP version unknown ****\n");
		}
	}
	printf("\n");
#endif

	if ( !exporter_root ) {
		exporter_root = exporter_list[id];
	}

	return 1;
} // End of AddExporterInfo

int AddSamplerInfo(sampler_info_record_t *sampler_record) {
uint32_t id = sampler_record->exporter_sysid;
generic_sampler_t	**sampler;

	if ( !exporter_list[id] ) {
		LogError("Exporter SysID: %u not found! - Skip sampler record", id);
		return 0;
	}
	sampler = &exporter_list[id]->sampler;
	while ( *sampler ) {
		if ( memcmp((void *)&(*sampler)->info, (void *)sampler_record, sizeof(sampler_info_record_t)) == 0 ) {
			// Found identical sampler already registered
			dbg_printf("Identical sampler already registered: Exporter SysID: %u, Sampler: id: %i, mode: %u, interval: %u\n",
				sampler_record->exporter_sysid, sampler_record->id, sampler_record->mode, sampler_record->interval);
			return 2;
		}
		sampler = &((*sampler)->next);
	}

	*sampler = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
	if ( !*sampler ) {
		LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}
	(*sampler)->next = NULL;
	sampler_record->exporter_sysid = exporter_list[id]->info.sysid;

	memcpy((void *)&(*sampler)->info, (void *)sampler_record, sizeof(sampler_info_record_t));
	dbg_printf("Insert sampler record for exporter at slot %i:\n", id);

#ifdef DEVEL
	{
		if ( sampler_record->id < 0 ) {
			printf("Exporter SysID: %u,	Generic Sampler: mode: %u, interval: %u\n",
				sampler_record->exporter_sysid, sampler_record->mode, sampler_record->interval);
		} else {
			printf("Exporter SysID: %u, Sampler: id: %i, mode: %u, interval: %u\n",
				sampler_record->exporter_sysid, sampler_record->id, sampler_record->mode, sampler_record->interval);
		}
	}
#endif

	return 1;
} // End of AddSamplerInfo

int AddExporterStat(exporter_stats_record_t *stat_record) {
int i, use_copy;
exporter_stats_record_t *rec;

	// 64bit counters can be potentially unaligned
	if ( ((ptrdiff_t)stat_record & 0x7) != 0 ) {
		rec = malloc(stat_record->header.size);
		if ( !rec ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
		memcpy(rec, stat_record, stat_record->header.size);
		use_copy = 1;
	} else {
		rec = stat_record;
		use_copy = 0;
	}

	for (i=0; i<rec->stat_count; i++ ) {
		uint32_t id = rec->stat[i].sysid;
		if ( !exporter_list[id] ) {
			LogError("Exporter SysID: %u not found! - Skip stat record record.\n");
			continue;
		}
		exporter_list[id]->sequence_failure += rec->stat[i].sequence_failure;
		exporter_list[id]->packets 			+= rec->stat[i].packets;
		exporter_list[id]->flows 			+= rec->stat[i].flows;
		dbg_printf("Update exporter stat for SysID: %i: Sequence failures: %u, packets: %llu, flows: %llu\n", 
			id, exporter_list[id]->sequence_failure, exporter_list[id]->packets, exporter_list[id]->flows);
	}

	if ( use_copy )
		free(rec);

	return 1;

} // End of AddExporterStat

void ExportExporterList( nffile_t *nffile ) {
int i;

	// sysid 0 unused -> no exporter available
	i = 1;
	while ( i < MAX_EXPORTERS  && exporter_list[i] != NULL ) {
		exporter_info_record_t *exporter;
       	generic_sampler_t *sampler;

		exporter = &exporter_list[i]->info;
		AppendToBuffer(nffile, (void *)exporter, exporter->header.size);

		sampler  = exporter_list[i]->sampler;
        while ( sampler ) {
            AppendToBuffer(nffile, (void *)&(sampler->info), sampler->info.header.size);
            sampler = sampler->next;
        }

		i++;
	}

	
} // End of ExportExporterList

void PrintExporters(char *filename) {
int i, done, found = 0;
nffile_t	*nffile;
record_header_t *record;
uint32_t skipped_blocks;
uint64_t total_bytes;

	printf("Exporters:\n");

	nffile = OpenFile(filename, NULL);
	if ( !nffile ) {
		return;
	}

	total_bytes	   = 0;
	skipped_blocks = 0;
	done = 0;
	while ( !done ) {
	int i, ret;

		// get next data block from file
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					LogError("Corrupt data file '%s': '%s'\n",filename);
				else 
					LogError("Read error in file '%s': %s\n",filename, strerror(errno) );
				done = 1;
				continue;
				break;
				// fall through - get next file in chain
			case NF_EOF:
				done = 1;
				continue;
				break;
	
			default:
				// successfully read block
				total_bytes += ret;
		}

		if ( nffile->block_header->id != DATA_BLOCK_TYPE_2 ) {
			skipped_blocks++;
			continue;
		}

		// block type = 2

		record = (record_header_t *)nffile->buff_ptr;

		for ( i=0; i < nffile->block_header->NumRecords; i++ ) {
			switch ( record->type ) {
				// ExporterRecordType and SamplerRecordype tc versions only
				case ExporterRecordType: {
					#define IP_STRING_LEN   40
					char ipstr[IP_STRING_LEN];
					exporter_record_t *exporter_record = (exporter_record_t *)record ;
					found = 1;
					printf("\n");
					if ( exporter_record->sa_family == AF_INET ) {
						uint32_t _ip = htonl(exporter_record->ip.v4);
						inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
						printf("SysID: %u, IP: %16s, version: %u, ID: %2u, Sequence Failures: %u\n", exporter_record->sysid,
							ipstr, exporter_record->version, exporter_record->exporter_id, exporter_record->sequence_failure);
					} else if ( exporter_record->sa_family == AF_INET6 ) {
						uint64_t _ip[2];
						_ip[0] = htonll(exporter_record->ip.v6[0]);
						_ip[1] = htonll(exporter_record->ip.v6[1]);
						inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
						printf("SysID: %u, IP: %40s, version: %u, ID: %2u, Sequence Failures: %u\n", exporter_record->sysid,
							ipstr, exporter_record->version, exporter_record->exporter_id, exporter_record->sequence_failure);
					} else {
						strncpy(ipstr, "<unknown>", IP_STRING_LEN);
						printf("**** Exporter IP version unknown ****\n");
					}
				} break;
				case SamplerRecordype: {
					sampler_record_t  *sampler_record = (sampler_record_t *)record;;
					if ( sampler_record->id < 0 ) {
						printf("	Generic Sampler: mode: %u, interval: %u\n",
							sampler_record->mode, sampler_record->interval);
					} else {
						printf("	Sampler: id: %i, mode: %u, interval: %u\n",
							sampler_record->id, sampler_record->mode, sampler_record->interval);
					}
				} break;
				case ExporterInfoRecordType:
					found = 1;
					if ( !AddExporterInfo((exporter_info_record_t *)record) ) {
						LogError("Failed to add Exporter Record\n");
					}
					break;
				case ExporterStatRecordType:
					AddExporterStat((exporter_stats_record_t *)record);
					break;
				case SamplerInfoRecordype:
					if ( !AddSamplerInfo((sampler_info_record_t *)record) ) {
						LogError("Failed to add Sampler Record\n");
					}
					break;
			}
			// Advance pointer by number of bytes for netflow record
			record = (record_header_t *)((pointer_addr_t)record + record->size);	
		}
	}

	CloseFile(nffile);
	DisposeFile(nffile);
	if ( !found ) {
		printf("No Exporter records found\n");
	}

	i = 1;
	while ( i < MAX_EXPORTERS  && exporter_list[i] != NULL ) {
		#define IP_STRING_LEN   40
		char ipstr[IP_STRING_LEN];

		exporter_info_record_t *exporter;
       	generic_sampler_t *sampler;

		printf("\n");
		exporter = &exporter_list[i]->info;
		if ( exporter->sa_family == AF_INET ) {
			uint32_t _ip = htonl(exporter->ip.v4);
			inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
			if ( exporter_list[i]->flows ) 
				printf("SysID: %u, IP: %16s, version: %u, ID: %2u, Sequence failures: %u, packets: %llu, flows: %llu\n", 
					exporter->sysid, ipstr, exporter->version, exporter->id, 
					exporter_list[i]->sequence_failure, 
					(long long unsigned)exporter_list[i]->packets, 
					(long long unsigned)exporter_list[i]->flows);
			else 
				printf("SysID: %u, IP: %16s, version: %u, ID: %2u\n", 
					exporter->sysid, ipstr, exporter->version, exporter->id);
					
		} else if ( exporter->sa_family == AF_INET6 ) {
			uint64_t _ip[2];
			_ip[0] = htonll(exporter->ip.v6[0]);
			_ip[1] = htonll(exporter->ip.v6[1]);
			inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
			if ( exporter_list[i]->flows ) 
				printf("SysID: %u, IP: %40s, version: %u, ID: %2u, Sequence failures: %u, packets: %llu, flows: %llu\n ", 
					exporter->sysid, ipstr, exporter->version, exporter->id, 
					exporter_list[i]->sequence_failure, 
					(long long unsigned)exporter_list[i]->packets, 
					(long long unsigned)exporter_list[i]->flows);
			else
				printf("SysID: %u, IP: %40s, version: %u, ID: %2u\n ", 
					exporter->sysid, ipstr, exporter->version, exporter->id);
		} else {
			strncpy(ipstr, "<unknown>", IP_STRING_LEN);
			printf("**** Exporter IP version unknown ****\n");
		}

		sampler  = exporter_list[i]->sampler;
        while ( sampler ) {
			if ( sampler->info.id < 0 ) {
				printf("	Sampler for Exporter SysID: %u,	Generic Sampler: mode: %u, interval: %u\n",
					sampler->info.exporter_sysid, sampler->info.mode, sampler->info.interval);
			} else {
				printf("	Sampler for Exporter SysID: %u, Sampler: id: %i, mode: %u, interval: %u\n",
					sampler->info.exporter_sysid, sampler->info.id, sampler->info.mode, sampler->info.interval);
			}
           	sampler = sampler->next;
       	}

		i++;
	}


} // End of PrintExporters

