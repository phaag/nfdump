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
 *  $Author: peter $
 *
 *  $Id: netflow_v1.c 30 2011-07-18 11:19:46Z peter $
 *
 *  $LastChangedRevision: 30 $
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
#include "netflow_v1.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

extern int verbose;
extern extension_descriptor_t extension_descriptor[];

/* module limited globals */
static extension_info_t v1_extension_info;		// common for all v1 records
static uint16_t v1_output_record_size;

// All required extension to save full v1 records
static uint16_t v1_full_map[] = { EX_IO_SNMP_2, EX_NEXT_HOP_v4, EX_ROUTER_IP_v4, EX_RECEIVED, 0 };

typedef struct v1_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint32_t	data[1];	// link to next record
} v1_block_t;
#define V1_BLOCK_DATA_SIZE (sizeof(v1_block_t) - sizeof(uint32_t))

typedef struct exporter_v1_s {
	// identical to generic_exporter_t
	struct exporter_v1_s *next;

	// generic exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	generic_sampler_t		*sampler;
	// End of generic_exporter_t

	// extension map
	extension_map_t 	 *extension_map;

} exporter_v1_t;

static inline exporter_v1_t *GetExporter(FlowSource_t *fs, netflow_v1_header_t *header);

/* functions */

#include "nffile_inline.c"

int Init_v1(void) {
int i, id, map_index;
int extension_size;
uint16_t	map_size;

	// prepare v1 extension map
	v1_extension_info.map		   = NULL;
	v1_extension_info.next		   = NULL;
	v1_extension_info.offset_cache = NULL;
	v1_extension_info.ref_count	= 0;

	extension_size  = 0;
	// default map - 0 extensions
	map_size 		 = sizeof(extension_map_t);
	i=0;
	dbg_printf("v1 map: map size start: %u\n", map_size);
	while ( (id = v1_full_map[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			extension_size += extension_descriptor[id].size;
			map_size += sizeof(uint16_t);
			dbg_printf("v1 map: enabled extension %u\n", id);
		}
		i++;
	}
	dbg_printf("v1 map: map size so far: %u\n", map_size);

	// extension_size contains the sum of all optional extensions
	// caculate the record size 
	v1_output_record_size = COMMON_RECORD_DATA_SIZE + V1_BLOCK_DATA_SIZE + extension_size;  
 
	// align 32 bits
	if ( ( map_size & 0x3 ) != 0 )
		map_size += 2;

	// Create a generic netflow v1 extension map
	v1_extension_info.map = (extension_map_t *)malloc((size_t)map_size);
	if ( !v1_extension_info.map ) {
		syslog(LOG_ERR, "Process_v1: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}

	v1_extension_info.map->type 	  	  = ExtensionMapType;
	v1_extension_info.map->size 	  	  = map_size;
	v1_extension_info.map->map_id 	  	  = INIT_ID;		
	v1_extension_info.map->extension_size = extension_size;  

	// see netflow_v1.h for extension map description
	map_index = 0;
	i=0;
	while ( (id = v1_full_map[i]) != 0 ) {
		if ( extension_descriptor[id].enabled )
			v1_extension_info.map->ex_id[map_index++] = id;
		i++;
	}
	v1_extension_info.map->ex_id[map_index] = 0;

	return 1;
} // End of Init_v1

/*
 * functions used for receiving netflow v1 records
 */


static inline exporter_v1_t *GetExporter(FlowSource_t *fs, netflow_v1_header_t *header) {
exporter_v1_t **e = (exporter_v1_t **)&(fs->exporter_data);
uint16_t	version    = ntohs(header->version);
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];

	// search the appropriate exporter engine
	while ( *e ) {
		if ( (*e)->info.version == version && 
			 (*e)->info.ip.v6[0] == fs->ip.v6[0] && (*e)->info.ip.v6[1] == fs->ip.v6[1]) 
			return *e;
		e = &((*e)->next);
	}

	// nothing found
	*e = (exporter_v1_t *)malloc(sizeof(exporter_v1_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v1: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_v1_t));
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version 		= version;
	(*e)->info.id			= 0;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->next	 			= NULL;
	(*e)->packets			= 0;
	(*e)->flows				= 0;
	(*e)->sequence_failure	= 0;
	(*e)->sampler			= NULL;

	// copy the v1 generic extension map
	(*e)->extension_map		= (extension_map_t *)malloc(v1_extension_info.map->size);
	if ( !(*e)->extension_map ) {
		syslog(LOG_ERR, "Process_v1: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		free(*e);
		*e = NULL;
		return NULL;
	}
	memcpy((void *)(*e)->extension_map, (void *)v1_extension_info.map, v1_extension_info.map->size);

	if ( !AddExtensionMap(fs, (*e)->extension_map) ) {
		// bad - we must free this map and fail - otherwise data can not be read any more
		free((*e)->extension_map);
		free(*e);
		*e = NULL;
		return NULL;
	}

	(*e)->info.sysid = 0;
	FlushInfoExporter(fs, &((*e)->info));

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.v4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.v6[0]);
		_ip[1] = htonll(fs->ip.v6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	dbg_printf("New Exporter: v1 SysID: %u, Extension ID: %i, IP: %s, \n", 
		(*e)->info.sysid, (*e)->extension_map->map_id, ipstr);
	syslog(LOG_INFO, "Process_v1: SysID: %u, New exporter: IP: %s\n", (*e)->info.sysid, ipstr);

	return (*e);

} // End of GetExporter

void Process_v1(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
netflow_v1_header_t	*v1_header;
netflow_v1_record_t *v1_record;
exporter_v1_t 		*exporter;
extension_map_t		*extension_map;
common_record_t		*common_record;
uint64_t	start_time, end_time, boot_time;
uint32_t   	First, Last;
uint16_t	count;
uint8_t		flags;
int			i, done, flow_record_length;
ssize_t		size_left;
char		*string;

		// map v1 data structure to input buffer
		v1_header 	= (netflow_v1_header_t *)in_buff;

		exporter = GetExporter(fs, v1_header);
		if ( !exporter ) {
			syslog(LOG_ERR,"Process_v1: Exporter NULL: Abort v1 record processing");
			return;
		}
		flags = 0;

		exporter->packets++;

		extension_map = exporter->extension_map;
		flow_record_length = NETFLOW_V1_RECORD_LENGTH;

		// this many data to process
		size_left	= in_buff_cnt;

		common_record = fs->nffile->buff_ptr;
		done = 0;
		while ( !done ) {
			v1_block_t			*v1_block;

			/* Process header */
	
			// count check
	  		count	= ntohs(v1_header->count);
			if ( count > NETFLOW_V1_MAX_RECORDS ) {
				syslog(LOG_ERR,"Process_v1: Unexpected record count in header: %i. Abort v1 record processing", count);
				fs->nffile->buff_ptr = (void *)common_record;
				return;
			}

			// input buffer size check for all expected records
			if ( size_left < ( NETFLOW_V1_HEADER_LENGTH + count * flow_record_length) ) {
				syslog(LOG_ERR,"Process_v1: Not enough data to process v1 record. Abort v1 record processing");
				fs->nffile->buff_ptr = (void *)common_record;
				return;
			}
	
			// output buffer size check for all expected records
			if ( !CheckBufferSpace(fs->nffile, count * v1_output_record_size) ) {
				// fishy! - should never happen. maybe disk full?
				syslog(LOG_ERR,"Process_v1: output buffer size error. Abort v1 record processing");
				return;
			}

			// map output record to memory buffer
			common_record	= (common_record_t *)fs->nffile->buff_ptr;
			v1_block		= (v1_block_t *)common_record->data;

	  		v1_header->SysUptime	 = ntohl(v1_header->SysUptime);
	  		v1_header->unix_secs	 = ntohl(v1_header->unix_secs);
	  		v1_header->unix_nsecs	 = ntohl(v1_header->unix_nsecs);
	
			/* calculate boot time in msec */
			boot_time  = ((uint64_t)(v1_header->unix_secs)*1000 + 
					((uint64_t)(v1_header->unix_nsecs) / 1000000) ) - (uint64_t)(v1_header->SysUptime);
	
			// process all records
			v1_record	= (netflow_v1_record_t *)((pointer_addr_t)v1_header + NETFLOW_V1_HEADER_LENGTH);

			/* loop over each records associated with this header */
			for (i = 0; i < count; i++) {
				pointer_addr_t	bsize;
				void	*data_ptr;
				uint8_t *s1, *s2;
				int j, id;
				// header data
	  			common_record->flags		= flags;
	  			common_record->type			= CommonRecordType;
	  			common_record->exporter_sysid = exporter->info.sysid;
	  			common_record->ext_map		= extension_map->map_id;
	  			common_record->size			= v1_output_record_size;

				// v1 common fields
	  			common_record->srcport		= ntohs(v1_record->srcport);
	  			common_record->dstport		= ntohs(v1_record->dstport);
	  			common_record->tcp_flags	= v1_record->tcp_flags;
	  			common_record->prot			= v1_record->prot;
	  			common_record->tos			= v1_record->tos;
	  			common_record->fwd_status 	= 0;
	  			common_record->reserved 	= 0;

				// v1 typed data as fixed struct v1_block
	  			v1_block->srcaddr	= ntohl(v1_record->srcaddr);
	  			v1_block->dstaddr	= ntohl(v1_record->dstaddr);
	  			v1_block->dPkts  	= ntohl(v1_record->dPkts);
	  			v1_block->dOctets	= ntohl(v1_record->dOctets);

				// process optional extensions
				data_ptr = (void *)v1_block->data;
				j = 0;
				while ( (id = extension_map->ex_id[j]) != 0 ) {
					switch (id) {
						case EX_IO_SNMP_2:	{	// 2 byte input/output interface index
							tpl_ext_4_t *tpl = (tpl_ext_4_t *)data_ptr;
	  						tpl->input  = ntohs(v1_record->input);
	  						tpl->output = ntohs(v1_record->output);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_NEXT_HOP_v4:	 {	// IPv4 next hop
							tpl_ext_9_t *tpl = (tpl_ext_9_t *)data_ptr;
							tpl->nexthop = ntohl(v1_record->nexthop);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_ROUTER_IP_v4:	 {	// IPv4 router address
							tpl_ext_23_t *tpl = (tpl_ext_23_t *)data_ptr;
							tpl->router_ip = fs->ip.v4;
							data_ptr = (void *)tpl->data;
							ClearFlag(common_record->flags, FLAG_IPV6_EXP);
							} break;
						case EX_RECEIVED: {
							tpl_ext_27_t *tpl = (tpl_ext_27_t *)data_ptr;
							tpl->received  = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
							data_ptr = (void *)tpl->data;
							} break;

						default:
							// this should never happen, as v1 has no other extensions
							syslog(LOG_ERR,"Process_v1: Unexpected extension %i for v1 record. Skip extension", id);
					}
					j++;
				}
	
				// Time issues
	  			First	 				= ntohl(v1_record->First);
	  			Last		 			= ntohl(v1_record->Last);

				if ( First > Last ) {
					/* First in msec, in case of msec overflow, between start and end */
					start_time = boot_time - 0x100000000LL + (uint64_t)First;
				} else {
					start_time = boot_time + (uint64_t)First;
				}

				/* end time in msecs */
				end_time = (uint64_t)Last + boot_time;

				// if overflow happened after flow ended but before got exported
				if ( Last > v1_header->SysUptime ) {
					start_time  -= 0x100000000LL;
					end_time    -= 0x100000000LL;
				}

				common_record->first 		= start_time/1000;
				common_record->msec_first	= start_time - common_record->first*1000;
	
				common_record->last 		= end_time/1000;
				common_record->msec_last	= end_time - common_record->last*1000;
	
				// update first_seen, last_seen
				if ( start_time < fs->first_seen )
					fs->first_seen = start_time;
				if ( end_time > fs->last_seen )
					fs->last_seen = end_time;
	
	
				// Update stats
				switch (common_record->prot) {
					case IPPROTO_ICMP:
						fs->nffile->stat_record->numflows_icmp++;
						fs->nffile->stat_record->numpackets_icmp += v1_block->dPkts;
						fs->nffile->stat_record->numbytes_icmp   += v1_block->dOctets;
						// fix odd CISCO behaviour for ICMP port/type in src port
						if ( common_record->srcport != 0 ) {
							s1 = (uint8_t *)&(common_record->srcport);
							s2 = (uint8_t *)&(common_record->dstport);
							s2[0] = s1[1];
							s2[1] = s1[0];
							common_record->srcport = 0;
						}
						break;
					case IPPROTO_TCP:
						fs->nffile->stat_record->numflows_tcp++;
						fs->nffile->stat_record->numpackets_tcp += v1_block->dPkts;
						fs->nffile->stat_record->numbytes_tcp   += v1_block->dOctets;
						break;
					case IPPROTO_UDP:
						fs->nffile->stat_record->numflows_udp++;
						fs->nffile->stat_record->numpackets_udp += v1_block->dPkts;
						fs->nffile->stat_record->numbytes_udp   += v1_block->dOctets;
						break;
					default:
						fs->nffile->stat_record->numflows_other++;
						fs->nffile->stat_record->numpackets_other += v1_block->dPkts;
						fs->nffile->stat_record->numbytes_other   += v1_block->dOctets;
				}
				exporter->flows++;
				fs->nffile->stat_record->numflows++;
				fs->nffile->stat_record->numpackets	+= v1_block->dPkts;
				fs->nffile->stat_record->numbytes	+= v1_block->dOctets;

				if ( fs->xstat ) {
					uint32_t bpp = v1_block->dPkts ? v1_block->dOctets/v1_block->dPkts : 0;
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
					ExpandRecord_v2((common_record_t *)common_record, &v1_extension_info, &(exporter->info), &master_record);
				 	format_file_block_record(&master_record, &string, 0);
					printf("%s\n", string);
				}

				// advance to next input flow record
				v1_record		= (netflow_v1_record_t *)((pointer_addr_t)v1_record + flow_record_length);

				if ( ((pointer_addr_t)data_ptr - (pointer_addr_t)common_record) != v1_output_record_size ) {
					printf("Panic size check: ptr diff: %llu, record size: %u\n", (unsigned long long)((pointer_addr_t)data_ptr - (pointer_addr_t)common_record), v1_output_record_size ); 
					abort();
				}
				// advance to next output record
				common_record	= (common_record_t *)data_ptr;
				v1_block		= (v1_block_t *)common_record->data;
				
				// buffer size sanity check - should never happen, but check it anyway
				bsize = (pointer_addr_t)common_record - (pointer_addr_t)fs->nffile->block_header - sizeof(data_block_header_t);
				if ( bsize > BUFFSIZE ) {
					syslog(LOG_ERR,"### Software error ###: %s line %d", __FILE__, __LINE__);
					syslog(LOG_ERR,"Process_v1: Output buffer overflow! Flush buffer and skip records.");
					syslog(LOG_ERR,"Buffer size: size: %u, bsize: %llu > %u", fs->nffile->block_header->size, (unsigned long long)bsize, BUFFSIZE);
					// reset buffer
					fs->nffile->block_header->size 		= 0;
					fs->nffile->block_header->NumRecords = 0;
					fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
					return;
				}

			} // End of foreach v1 record

		// update file record size ( -> output buffer size )
		fs->nffile->block_header->NumRecords += count;
		fs->nffile->block_header->size 		 += count * v1_output_record_size;
		fs->nffile->buff_ptr 				  = (void *)common_record;

		// still to go for this many input bytes
		size_left 	-= NETFLOW_V1_HEADER_LENGTH + count * flow_record_length;

		// next header
		v1_header	= (netflow_v1_header_t *)v1_record;

		// should never be < 0
		done = size_left <= 0;

	} // End of while !done

	return;

} /* End of Process_v1 */

