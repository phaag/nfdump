/*
 *  Copyright (c) 2014, Peter Haag
 *  Copyright (c) 2013, Peter Haag
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
 *  $Author:$
 *
 *  $Id:$
 *
 *  $LastChangedRevision:$
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nffile.h"
#include "nfx.h"
#include "nfnet.h"
#include "nf_common.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "exporter.h"

#include "flowtree.h"
#include "netflow_pcap.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

extern int verbose;
extern extension_descriptor_t extension_descriptor[];

/* module limited globals */
static extension_info_t pcap_extension_info;		// common for all pcap records
static extension_map_t	*pcap_extension_map;

static uint32_t pcap_output_record_size_v4;
static uint32_t pcap_output_record_size_v6;

typedef struct pcap_v4_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint32_t	data[1];	// link to next record
} __attribute__((__packed__ )) pcap_v4_block_t;
#define PCAP_V4_BLOCK_DATA_SIZE (sizeof(pcap_v4_block_t) - sizeof(uint32_t))

typedef struct pcap_v6_block_s {
	uint64_t	srcaddr[2];
	uint64_t	dstaddr[2];
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint32_t	data[1];	// link to next record
} __attribute__((__packed__ )) pcap_v6_block_t;
#define PCAP_V6_BLOCK_DATA_SIZE (sizeof(pcap_v6_block_t) - sizeof(uint32_t))

// All required extension to save full pcap records
static uint16_t pcap_full_map[] = { 0 };

#include "nffile_inline.c"

int Init_pcap2nf(void) {
int i, id, map_index;
int extension_size;
uint16_t	map_size;

	// prepare pcap extension map
	pcap_extension_info.map = NULL;
	extension_size	 = 0;
	map_size 		 = 0;

	i=0;
	while ( (id = pcap_full_map[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			extension_size += extension_descriptor[id].size;
			map_size += sizeof(uint16_t);
		}
		i++;
	}
	// extension_size contains the sum of all optional extensions
	// caculate the record size 
	pcap_output_record_size_v4 = COMMON_RECORD_DATA_SIZE + PCAP_V4_BLOCK_DATA_SIZE + extension_size;	
	pcap_output_record_size_v6 = COMMON_RECORD_DATA_SIZE + PCAP_V6_BLOCK_DATA_SIZE + extension_size;	

	// now the full extension map size
	map_size 	+= sizeof(extension_map_t);

	// align 32 bits
	if ( ( map_size & 0x3 ) != 0 )
		map_size += 2;

	// Create a generic pcap extension map
	pcap_extension_info.map = (extension_map_t *)malloc((size_t)map_size);
	if ( !pcap_extension_info.map ) {
		syslog(LOG_ERR, "Process_pcap: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	pcap_extension_info.map->type 	  	  	= ExtensionMapType;
	pcap_extension_info.map->size 	  	  	= map_size;
	pcap_extension_info.map->map_id 	  	= INIT_ID;		
	pcap_extension_info.map->extension_size = extension_size;		

	// see netflow_pcap.h for extension map description
	map_index = 0;
	i=0;
	while ( (id = pcap_full_map[i]) != 0 ) {
		if ( extension_descriptor[id].enabled )
			pcap_extension_info.map->ex_id[map_index++] = id;
		i++;
	}
	pcap_extension_info.map->ex_id[map_index] = 0;

	pcap_extension_map = NULL;

	return 1;

} // End of Init_pcap2nf

int StorePcapFlow(FlowSource_t *fs, struct FlowNode *Node) {
common_record_t		*common_record;
uint32_t			packets, bytes, pcap_output_record_size;
uint64_t	start_time, end_time;
int			j, id;
char		*string;
void		*data_ptr;

	if ( !pcap_extension_map ) {
		pcap_extension_map	= (extension_map_t *)malloc(pcap_extension_info.map->size);
		if ( !pcap_extension_map ) {
			LogError("Process_pcap: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return 0;
		}
		memcpy((void *)pcap_extension_map, (void *)pcap_extension_info.map, pcap_extension_info.map->size);
		if ( !AddExtensionMap(fs, pcap_extension_map) ) {
			LogError("Process_pcap: Fatal: AddExtensionMap() failed in %s line %d\n", __FILE__, __LINE__);
			return 0;
		}

	}

	if ( Node->version == AF_INET6 ) {
		pcap_output_record_size = pcap_output_record_size_v6;
		dbg_printf("Store Flow v6 node: size: %u\n", pcap_output_record_size);
	} else if ( Node->version == AF_INET ) {
		pcap_output_record_size = pcap_output_record_size_v4;
		dbg_printf("Store Flow v4 node: size: %u\n", pcap_output_record_size);
	} else {
		LogError("Process_pcap: Unexpected version in %s line %d: %u\n", __FILE__, __LINE__, Node->version);
		return 0;
	}

	// output buffer size check for all expected records
	if ( !CheckBufferSpace(fs->nffile, pcap_output_record_size) ) {
		// fishy! - should never happen. maybe disk full?
		LogError("Process_pcap: output buffer size error. Abort pcap record processing");
		return 0;
	}

	// map output record to memory buffer
	common_record	= (common_record_t *)fs->nffile->buff_ptr;

	// header data
	common_record->flags		= 0;
  	common_record->type			= CommonRecordType;
	common_record->exporter_sysid = 0;
	common_record->ext_map		= pcap_extension_map->map_id;
	common_record->size			= pcap_output_record_size;

	// pcap common fields
	common_record->srcport		= Node->src_port;
	common_record->dstport		= Node->dst_port;
	common_record->tcp_flags	= Node->flags;
	common_record->prot			= Node->proto;
	common_record->tos			= 0;
	common_record->fwd_status 	= 0;

	if ( Node->version == AF_INET6 ) {
		SetFlag(common_record->flags, FLAG_IPV6_ADDR);
		pcap_v6_block_t *pcap_v6_block = (pcap_v6_block_t *)common_record->data;
		pcap_v6_block->srcaddr[0] = Node->src_addr.v6[0];
		pcap_v6_block->srcaddr[1] = Node->src_addr.v6[1];
		pcap_v6_block->dstaddr[0] = Node->dst_addr.v6[0];
		pcap_v6_block->dstaddr[1] = Node->dst_addr.v6[1];
		pcap_v6_block->dPkts	  = packets = Node->packets;
		pcap_v6_block->dOctets	  = bytes   = Node->bytes;

		data_ptr = (void *)pcap_v6_block->data;
	} else {
		pcap_v4_block_t *pcap_v4_block = (pcap_v4_block_t *)common_record->data;
		pcap_v4_block->srcaddr = Node->src_addr.v4;
		pcap_v4_block->dstaddr = Node->dst_addr.v4;
		pcap_v4_block->dPkts   = packets = Node->packets;
		pcap_v4_block->dOctets = bytes   = Node->bytes;

		data_ptr = (void *)pcap_v4_block->data;
	}

	// process optional extensions
	j = 0;
	while ( (id = pcap_extension_map->ex_id[j]) != 0 ) {
		switch (id) {
			case EX_IO_SNMP_2:	{	// 2 byte input/output interface index
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)data_ptr;
 					tpl->input  = 0;
 					tpl->output = 0;
				data_ptr = (void *)tpl->data;
				} break;
			default:
				// this should never happen, as pcap has no other extensions
				LogError("Process_pcap: Unexpected extension %i for pcap record. Skip extension", id);
		}
		j++;
	}

	common_record->first 		= Node->t_first.tv_sec;
	common_record->msec_first	= Node->t_first.tv_usec / 1000;

	common_record->last 		= Node->t_last.tv_sec;
	common_record->msec_last	= Node->t_last.tv_usec / 1000;

	start_time = (1000LL * (uint64_t)common_record->first) + (uint64_t)common_record->msec_first;
	end_time   = (1000LL * (uint64_t)common_record->last) + (uint64_t)common_record->msec_last;

	// update first_seen, last_seen
	if ( start_time < fs->first_seen )
		fs->first_seen = start_time;
	if ( end_time > fs->last_seen )
		fs->last_seen = end_time;


	// Update stats
	switch (common_record->prot) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			fs->nffile->stat_record->numflows_icmp++;
			fs->nffile->stat_record->numpackets_icmp += packets;
			fs->nffile->stat_record->numbytes_icmp   += bytes;
			// fix odd CISCO behaviour for ICMP port/type in src port
			if ( common_record->srcport != 0 ) {
				uint8_t *s1, *s2;
				s1 = (uint8_t *)&(common_record->srcport);
				s2 = (uint8_t *)&(common_record->dstport);
				s2[0] = s1[1];
				s2[1] = s1[0];
				common_record->srcport = 0;
			}
			break;
		case IPPROTO_TCP:
			fs->nffile->stat_record->numflows_tcp++;
			fs->nffile->stat_record->numpackets_tcp += packets;
			fs->nffile->stat_record->numbytes_tcp   += bytes;
			break;
		case IPPROTO_UDP:
			fs->nffile->stat_record->numflows_udp++;
			fs->nffile->stat_record->numpackets_udp += packets;
			fs->nffile->stat_record->numbytes_udp   += bytes;
			break;
		default:
			fs->nffile->stat_record->numflows_other++;
			fs->nffile->stat_record->numpackets_other += packets;
			fs->nffile->stat_record->numbytes_other   += bytes;
	}

	fs->nffile->stat_record->numflows++;
	fs->nffile->stat_record->numpackets	+= packets;
	fs->nffile->stat_record->numbytes	+= bytes;

	if ( fs->xstat ) {
		uint32_t bpp = packets ? bytes/packets : 0;
		if ( bpp > MAX_BPP ) 
			bpp = MAX_BPP;
		if ( common_record->prot == IPPROTO_TCP ) {
			fs->xstat->bpp_histogram->tcp.bpp[bpp]++;
			fs->xstat->bpp_histogram->tcp.count++;

			fs->xstat->port_histogram->src_tcp.port[common_record->srcport]++;
			fs->xstat->port_histogram->dst_tcp.port[common_record->dstport]++;
			fs->xstat->port_histogram->src_tcp.count++;
			fs->xstat->port_histogram->dst_tcp.count++;
		} else if ( common_record->prot == IPPROTO_UDP ) {
			fs->xstat->bpp_histogram->udp.bpp[bpp]++;
			fs->xstat->bpp_histogram->udp.count++;

			fs->xstat->port_histogram->src_udp.port[common_record->srcport]++;
			fs->xstat->port_histogram->dst_udp.port[common_record->dstport]++;
			fs->xstat->port_histogram->src_udp.count++;
			fs->xstat->port_histogram->dst_udp.count++;
		}
	}

	if ( verbose ) {
		master_record_t master_record;
		ExpandRecord_v2((common_record_t *)common_record, &pcap_extension_info, NULL, &master_record);
	 	format_file_block_record(&master_record, &string, 0);
		printf("%s\n", string);
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->NumRecords += 1;
	fs->nffile->block_header->size 		 += pcap_output_record_size;
	fs->nffile->buff_ptr 				 = data_ptr;

	return 1;

} /* End of StorePcapFlow */

