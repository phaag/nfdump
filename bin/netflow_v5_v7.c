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
 *  $Id: netflow_v5_v7.c 69 2010-09-09 07:17:43Z haag $
 *
 *  $LastChangedRevision: 69 $
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
#include "netflow_v5_v7.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

extern int verbose;
extern extension_descriptor_t extension_descriptor[];
extern uint32_t default_sampling;
extern uint32_t overwrite_sampling;

/* module limited globals */
static extension_info_t v5_extension_info;		// common for all v5 records
static uint16_t v5_output_record_size, v5_output_record_base_size;

// All required extension to save full v5 records
static uint16_t v5_full_mapp[] = { EX_IO_SNMP_2, EX_AS_2, EX_MULIPLE, EX_NEXT_HOP_v4, EX_ROUTER_IP_v4, EX_ROUTER_ID, EX_RECEIVED, 0 };

// to simplify, assume blocks with 64 bit counters to check for enough buffer space
// regardless if 32 or 64 bit packet/byte counters
#define V5_BLOCK_DATA_SIZE (sizeof(ipv4_block_t) - sizeof(uint32_t) + 2 * sizeof(uint64_t))

typedef struct exporter_v5_s {
	// identical to generic_exporter_t
	struct exporter_v5_s *next;

	// generic exporter information
	exporter_info_record_t info;

	uint64_t	packets;			// number of packets sent by this exporter
	uint64_t	flows;				// number of flow records sent by this exporter
	uint32_t	sequence_failure;	// number of sequence failues

	// generic sampler
	generic_sampler_t		*sampler;
	// end of generic_exporter_t

	// sequence vars
	int64_t	 last_sequence;
	int64_t  sequence, distance;
	int64_t  last_count;

	int		first;

	// extension map
	extension_map_t 	 *extension_map;

} exporter_v5_t;

// for sending netflow v5
static netflow_v5_header_t	*v5_output_header;
static netflow_v5_record_t	*v5_output_record;
static exporter_v5_t 		output_engine;

static inline exporter_v5_t *GetExporter(FlowSource_t *fs, netflow_v5_header_t *header);

static inline int CheckBufferSpace(nffile_t *nffile, size_t required);

/* functions */

#include "nffile_inline.c"

int Init_v5_v7_input(void) {
int i, id, map_index;
int extension_size;
uint16_t	map_size;

	extension_size   = 0;
	// prepare v5 extension map
	v5_extension_info.map		   = NULL;
	v5_extension_info.next		   = NULL;
	v5_extension_info.offset_cache = NULL;
	v5_extension_info.ref_count	   = 0;

	// default map - 0 extensions
	map_size 		 = sizeof(extension_map_t);
	i=0;
	while ( (id = v5_full_mapp[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			extension_size += extension_descriptor[id].size;
			map_size += sizeof(uint16_t);
		}
		i++;
	}
	// extension_size contains the sum of all optional extensions
	// caculate the record size without counters!
	v5_output_record_base_size = COMMON_RECORD_DATA_SIZE + 8 + extension_size;  // + 8 for 2 x IPv4 addr
 
	// align 32 bits
	if ( ( map_size & 0x3 ) != 0 )
		map_size += 2;

	// Create a generic v5 extension map
	v5_extension_info.map = (extension_map_t *)malloc((size_t)map_size);
	if ( !v5_extension_info.map ) {
		syslog(LOG_ERR, "Process_v5: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return 0;
	}
	v5_extension_info.map->type 	  	  = ExtensionMapType;
	v5_extension_info.map->size 	  	  = map_size;
	v5_extension_info.map->map_id 	  	  = INIT_ID;		
	v5_extension_info.map->extension_size = extension_size;

	// see netflow_v5_v7.h for extension map description
	map_index = 0;
	i=0;
	while ( (id = v5_full_mapp[i]) != 0 ) {
		if ( extension_descriptor[id].enabled )
			v5_extension_info.map->ex_id[map_index++] = id;
		i++;
	}
	v5_extension_info.map->ex_id[map_index] = 0;

	return 1;
} // End of Init_v5_input

/*
 * functions used for receiving netflow v5 records
 */


static inline exporter_v5_t *GetExporter(FlowSource_t *fs, netflow_v5_header_t *header) {
exporter_v5_t **e = (exporter_v5_t **)&(fs->exporter_data);
generic_sampler_t *sampler;
uint16_t	engine_tag = ntohs(header->engine_tag);
uint16_t	version    = ntohs(header->version);
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];

	// search the appropriate exporter engine
	while ( *e ) {
		if ( (*e)->info.version == version && (*e)->info.id == engine_tag &&
			 (*e)->info.ip.v6[0] == fs->ip.v6[0] && (*e)->info.ip.v6[1] == fs->ip.v6[1]) 
			return *e;
		e = &((*e)->next);
	}

	// nothing found
	*e = (exporter_v5_t *)malloc(sizeof(exporter_v5_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v5: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_v5_t));
	(*e)->next	 			= NULL;
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version 		= version;
	(*e)->info.id			= engine_tag;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->sequence_failure	= 0;
	(*e)->packets			= 0;
	(*e)->flows				= 0;
	(*e)->first	 			= 1;

	sampler = (generic_sampler_t *)malloc(sizeof(generic_sampler_t));
	if ( !sampler ) {
		syslog(LOG_ERR, "Process_v5: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	(*e)->sampler = sampler;

	sampler->info.header.type 	= SamplerInfoRecordype;
	sampler->info.header.size	= sizeof(sampler_info_record_t);
	sampler->info.id			= -1;
	sampler->info.mode			= (0xC000 & ntohs(header->sampling_interval)) >> 14;
	sampler->info.interval		= 0x3fff & ntohs(header->sampling_interval);
	sampler->next				= NULL;

	// default is global default_sampling ( user defined or unsampled => 1 )
	if ( sampler->info.interval == 0 )
		sampler->info.interval = default_sampling;

	// copy the v5 generic extension map
	(*e)->extension_map		= (extension_map_t *)malloc(v5_extension_info.map->size);
	if ( !(*e)->extension_map ) {
		syslog(LOG_ERR, "Process_v5: malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		free(*e);
		*e = NULL;
		return NULL;
	}
	memcpy((void *)(*e)->extension_map, (void *)v5_extension_info.map, v5_extension_info.map->size);

	if ( !AddExtensionMap(fs, (*e)->extension_map) ) {
		// bad - we must free this map and fail - otherwise data can not be read any more
		free((*e)->extension_map);
		free(*e);
		*e = NULL;
		return NULL;
	}

	(*e)->info.sysid = 0;
	FlushInfoExporter(fs, &((*e)->info));
	sampler->info.exporter_sysid		= (*e)->info.sysid;
	FlushInfoSampler(fs, &(sampler->info));

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



	dbg_printf("New Exporter: v5 SysID: %u, Extension ID: %i, IP: %s, Sampling Mode: %i, Sampling Interval: %u\n", 
		(*e)->info.sysid, (*e)->extension_map->map_id, ipstr, sampler->info.mode	,sampler->info.interval);
	syslog(LOG_INFO, "Process_v5: New exporter: SysID: %u, engine id %u, type %u, IP: %s, Sampling Mode: %i, Sampling Interval: %u\n", 
		(*e)->info.sysid, ( engine_tag & 0xFF ),( (engine_tag >> 8) & 0xFF ), ipstr, sampler->info.mode	,sampler->info.interval );

	if ( overwrite_sampling > 0 )  {
		sampler->info.interval = overwrite_sampling;
		syslog(LOG_INFO, "Process_v5: Hard overwrite sampling rate: %u\n", sampler->info.interval);
	}

	return (*e);

} // End of GetExporter

void Process_v5_v7(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
netflow_v5_header_t	*v5_header;
netflow_v5_record_t *v5_record;
exporter_v5_t 		*exporter;
extension_map_t		*extension_map;
common_record_t		*common_record;
uint64_t	start_time, end_time, boot_time;
uint32_t   	First, Last;
uint16_t	count;
uint8_t		flags;
int			i, done, version, flow_record_length;
ssize_t		size_left;
char		*string;

		/*
		 * v7 is treated as v5. It differes only in the record length, for what we process.
		 */

		// map v5 data structure to input buffer
		v5_header 	= (netflow_v5_header_t *)in_buff;

		exporter = GetExporter(fs, v5_header);
		if ( !exporter ) {
			syslog(LOG_ERR,"Process_v5: Exporter NULL: Abort v5/v7 record processing");
			return;
		}
		exporter->packets++;

		// calculate record size depending on counter size
		// sigh .. one day I should fix switch to 64bits
		if ( exporter->sampler->info.interval == 1 ) {
			flags = 0;
			v5_output_record_size = v5_output_record_base_size + 8; // 2 x  4 byte counters
		} else {
			flags = 0;
			SetFlag(flags, FLAG_SAMPLED);
			SetFlag(flags, FLAG_PKG_64);
			SetFlag(flags, FLAG_BYTES_64);
			v5_output_record_size = v5_output_record_base_size + 16; // 2 x  8 byte counters
		}

		extension_map = exporter->extension_map;

		version = ntohs(v5_header->version);
		flow_record_length = version == 5 ? NETFLOW_V5_RECORD_LENGTH : NETFLOW_V7_RECORD_LENGTH;

		// this many data to process
		size_left	= in_buff_cnt;

		common_record = fs->nffile->buff_ptr;
		done = 0;
		while ( !done ) {
			ipv4_block_t	*ipv4_block;

			/* Process header */
	
			// count check
	  		count	= ntohs(v5_header->count);
			if ( count > NETFLOW_V5_MAX_RECORDS ) {
				syslog(LOG_ERR,"Process_v5: Unexpected record count in header: %i. Abort v5/v7 record processing", count);
				fs->nffile->buff_ptr = (void *)common_record;
				return;
			}

			// input buffer size check for all expected records
			if ( size_left < ( NETFLOW_V5_HEADER_LENGTH + count * flow_record_length) ) {
				syslog(LOG_ERR,"Process_v5: Not enough data to process v5 record. Abort v5/v7 record processing");
				fs->nffile->buff_ptr = (void *)common_record;
				return;
			}
	
			// output buffer size check for all expected records
			if ( !CheckBufferSpace(fs->nffile, count * v5_output_record_size) ) {
				// fishy! - should never happen. maybe disk full?
				syslog(LOG_ERR,"Process_v5: output buffer size error. Abort v5/v7 record processing");
				return;
			}

			// map output record to memory buffer
			common_record	= (common_record_t *)fs->nffile->buff_ptr;
			ipv4_block		= (ipv4_block_t *)common_record->data;

			// sequence check
			if ( exporter->first ) {
				exporter->last_sequence = ntohl(v5_header->flow_sequence);
				exporter->sequence 	  	= exporter->last_sequence;
				exporter->first 	  	= 0;
			} else {
				exporter->last_sequence = exporter->sequence;
				exporter->sequence 	  = ntohl(v5_header->flow_sequence);
				exporter->distance 	  = exporter->sequence - exporter->last_sequence;
				// handle overflow
				if (exporter->distance < 0) {
					exporter->distance = 0xffffffff + exporter->distance  +1;
				}
				if (exporter->distance != exporter->last_count) {
#define delta(a,b) ( (a)>(b) ? (a)-(b) : (b)-(a) )
					fs->nffile->stat_record->sequence_failure++;
					exporter->sequence_failure++;
					/*
					syslog(LOG_ERR,"Flow v%d sequence last:%llu now:%llu mismatch. Missing: dist:%lu flows",
						version, exporter->last_sequence, exporter->sequence, exporter->distance);
					*/

				}
			}
			exporter->last_count  = count;
	
	  		v5_header->SysUptime	 = ntohl(v5_header->SysUptime);
	  		v5_header->unix_secs	 = ntohl(v5_header->unix_secs);
	  		v5_header->unix_nsecs	 = ntohl(v5_header->unix_nsecs);
	
			/* calculate boot time in msec */
			boot_time  = ((uint64_t)(v5_header->unix_secs)*1000 + 
					((uint64_t)(v5_header->unix_nsecs) / 1000000) ) - (uint64_t)(v5_header->SysUptime);
	
			// process all records
			v5_record	= (netflow_v5_record_t *)((pointer_addr_t)v5_header + NETFLOW_V5_HEADER_LENGTH);

			/* loop over each records associated with this header */
			for (i = 0; i < count; i++) {
				pointer_addr_t	bsize;
				uint64_t	packets, bytes;
				void	*data_ptr;
				uint8_t *s1, *s2;
				int j, id;
				// header data
	  			common_record->flags		  = flags;
	  			common_record->type			  = CommonRecordType;
	  			common_record->exporter_sysid = exporter->info.sysid;;
	  			common_record->ext_map		  = extension_map->map_id;
	  			common_record->size			  = v5_output_record_size;

				// v5 common fields
	  			common_record->srcport		  = ntohs(v5_record->srcport);
	  			common_record->dstport		  = ntohs(v5_record->dstport);
	  			common_record->tcp_flags	  = v5_record->tcp_flags;
	  			common_record->prot			  = v5_record->prot;
	  			common_record->tos			  = v5_record->tos;
	  			common_record->fwd_status 	  = 0;
	  			common_record->reserved 	  = 0;

				// v5 typed data as fixed struct v5_block
	  			ipv4_block->srcaddr	= ntohl(v5_record->srcaddr);
	  			ipv4_block->dstaddr	= ntohl(v5_record->dstaddr);

				if ( exporter->sampler->info.interval == 1 ) {
					value32_t   *v = (value32_t *)ipv4_block->data;

	  				packets  	= (uint64_t)ntohl(v5_record->dPkts);
	  				bytes		= (uint64_t)ntohl(v5_record->dOctets);

					v->val		= packets;
					v 			= (value32_t *)v->data;
					v->val		= bytes;

					data_ptr = (void *)v->data;
				} else {
					value64_t   *v = (value64_t *)ipv4_block->data;
					uint32_t    *ptr = (uint32_t *)&packets;

	  				packets  	= (uint64_t)ntohl(v5_record->dPkts)   * (uint64_t)exporter->sampler->info.interval;
	  				bytes		= (uint64_t)ntohl(v5_record->dOctets) * (uint64_t)exporter->sampler->info.interval;

					// pack packets in 32bit chunks
					v->val.val32[0] = ptr[0];
					v->val.val32[1] = ptr[1];

					// pack bytes in 32bit chunks
					v   = (value64_t *)v->data;
					ptr = (uint32_t *)&bytes;
					v->val.val32[0] = ptr[0];
					v->val.val32[1] = ptr[1];

					data_ptr = (void *)v->data;
				}

				// process optional extensions
				j = 0;
				while ( (id = extension_map->ex_id[j]) != 0 ) {
					switch (id) {
						case EX_IO_SNMP_2:	{	// 2 byte input/output interface index
							tpl_ext_4_t *tpl = (tpl_ext_4_t *)data_ptr;
	  						tpl->input  = ntohs(v5_record->input);
	  						tpl->output = ntohs(v5_record->output);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_AS_2:	 {	// 2 byte src/dst AS number
							tpl_ext_6_t *tpl = (tpl_ext_6_t *)data_ptr;
	  						tpl->src_as	= ntohs(v5_record->src_as);
	  						tpl->dst_as	= ntohs(v5_record->dst_as);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_MULIPLE:	 {	// dst tos, direction, src/dst mask
							tpl_ext_8_t *tpl = (tpl_ext_8_t *)data_ptr;
							tpl->dst_tos	= 0;
							tpl->dir		= 0;
							tpl->src_mask	= v5_record->src_mask;
							tpl->dst_mask	= v5_record->dst_mask;
							data_ptr = (void *)tpl->data;
							} break;
						case EX_NEXT_HOP_v4:	 {	// IPv4 next hop
							tpl_ext_9_t *tpl = (tpl_ext_9_t *)data_ptr;
							tpl->nexthop = ntohl(v5_record->nexthop);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_ROUTER_IP_v4:	 {	// IPv4 router address
							tpl_ext_23_t *tpl = (tpl_ext_23_t *)data_ptr;
							tpl->router_ip = fs->ip.v4;
							data_ptr = (void *)tpl->data;
							ClearFlag(common_record->flags, FLAG_IPV6_EXP);
							} break;
						case EX_ROUTER_ID:	 {	// engine type, engine ID
							tpl_ext_25_t *tpl = (tpl_ext_25_t *)data_ptr;
							uint16_t	engine_tag = ntohs(v5_header->engine_tag);
							tpl->engine_type  = (engine_tag >> 8) & 0xFF;
							tpl->engine_id    = (engine_tag & 0xFF);
							data_ptr = (void *)tpl->data;
							} break;
						case EX_RECEIVED: {
							tpl_ext_27_t *tpl = (tpl_ext_27_t *)data_ptr;
							tpl->received  = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
							data_ptr = (void *)tpl->data;
							} break;

						default:
							// this should never happen, as v5 has no other extensions
							syslog(LOG_ERR,"Process_v5: Unexpected extension %i for v5 record. Skip extension", id);
					}
					j++;
				}
	
				// Time issues
	  			First	 				= ntohl(v5_record->First);
	  			Last		 			= ntohl(v5_record->Last);

#ifdef FIXTIMEBUG
				/* 
				 * Some users report, that they see flows, which have duration time of about 40days
				 * which is almost the overflow value. Investigating this, it cannot be an overflow
				 * and the difference is always 15160 or 15176 msec too little for a classical 
				 * overflow. Therefore assume this must be an exporter bug
				 */
				if ( First > Last && ( (First - Last)  < 20000) ) {
					uint32_t _t;
					syslog(LOG_ERR,"Process_v5: Unexpected time swap: First 0x%llx smaller than boot time: 0x%llx", start_time, boot_time);
					_t= First;
					First = Last;
					Last = _t;
				}
#endif
				if ( First > Last ) {
					/* First in msec, in case of msec overflow, between start and end */
					start_time = boot_time - 0x100000000LL + (uint64_t)First;
				} else {
					start_time = boot_time + (uint64_t)First;
				}

				/* end time in msecs */
				end_time = (uint64_t)Last + boot_time;

				// if overflow happened after flow ended but before got exported
				// the additional check > 100000 is required due to a CISCO IOS bug
				// CSCei12353 - thanks to Bojan
				if ( Last > v5_header->SysUptime && (( Last - v5_header->SysUptime) > 100000)) {
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
						fs->nffile->stat_record->numpackets_icmp += packets;
						fs->nffile->stat_record->numbytes_icmp   += bytes;
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
				exporter->flows++;
				fs->nffile->stat_record->numflows++;
				fs->nffile->stat_record->numpackets	+= packets;
				fs->nffile->stat_record->numbytes	+= bytes;

				if ( fs->xstat ) {
					uint32_t bpp = packets ? (bytes/packets) : 0;
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
					ExpandRecord_v2((common_record_t *)common_record, &v5_extension_info, &(exporter->info), &master_record);
				 	format_file_block_record(&master_record, &string, 0);
					printf("%s\n", string);
				}

				// advance to next input flow record
				v5_record		= (netflow_v5_record_t *)((pointer_addr_t)v5_record + flow_record_length);

				if ( ((pointer_addr_t)data_ptr - (pointer_addr_t)common_record) != v5_output_record_size ) {
					printf("Panic size check: ptr diff: %llu, record size: %u\n", 
						(unsigned long long)((pointer_addr_t)data_ptr - (pointer_addr_t)common_record), v5_output_record_size ); 
					abort();
				}
				// advance to next output record
				common_record	= (common_record_t *)data_ptr;
				ipv4_block		= (ipv4_block_t *)common_record->data;
				
				// buffer size sanity check - should never happen, but check it anyway
				bsize = (pointer_addr_t)common_record - (pointer_addr_t)fs->nffile->block_header - sizeof(data_block_header_t);
				if ( bsize >= BUFFSIZE ) {
					syslog(LOG_ERR,"### Software error ###: %s line %d", __FILE__, __LINE__);
					syslog(LOG_ERR,"Process_v5: Output buffer overflow! Flush buffer and skip records.");
					syslog(LOG_ERR,"Buffer size: size: %u, bsize: %llu > %u", fs->nffile->block_header->size, (unsigned long long)bsize, BUFFSIZE);
					// reset buffer
					fs->nffile->block_header->size 		= 0;
					fs->nffile->block_header->NumRecords = 0;
					fs->nffile->buff_ptr = (void *)((pointer_addr_t)fs->nffile->block_header + sizeof(data_block_header_t) );
					return;
				}

			} // End of foreach v5 record

		// update file record size ( -> output buffer size )
		fs->nffile->block_header->NumRecords	+= count;
		fs->nffile->block_header->size 		+= count * v5_output_record_size;
		fs->nffile->buff_ptr 					= (void *)common_record;

		// still to go for this many input bytes
		size_left 	-= NETFLOW_V5_HEADER_LENGTH + count * flow_record_length;

		// next header
		v5_header	= (netflow_v5_header_t *)v5_record;

		// should never be < 0
		done = size_left <= 0;

	} // End of while !done

	return;

} /* End of Process_v5 */

/*
 * functions used for sending netflow v5 records
 */
void Init_v5_v7_output(send_peer_t *peer) {

	v5_output_header = (netflow_v5_header_t *)peer->send_buffer;
	v5_output_header->version 		= htons(5);
	v5_output_header->SysUptime		= 0;
	v5_output_header->unix_secs		= 0;
	v5_output_header->unix_nsecs	= 0;
	v5_output_header->count 		= 0;
	output_engine.first				= 1;

	output_engine.sequence		   = 0;
	output_engine.last_sequence	   = 0;
	output_engine.last_count 	   = 0;
	output_engine.sequence_failure = 0;
	v5_output_record = (netflow_v5_record_t *)((pointer_addr_t)v5_output_header + (pointer_addr_t)sizeof(netflow_v5_header_t));	

} // End of Init_v5_v7_output

int Add_v5_output_record(master_record_t *master_record, send_peer_t *peer) {
static uint64_t	boot_time;	// in msec
static int	cnt;
extension_map_t *extension_map = master_record->map_ref;
uint32_t	i, id, t1, t2;

	// Skip IPv6 records
	if ( (master_record->flags & FLAG_IPV6_ADDR ) != 0 )
		return 0;

	if ( output_engine.first ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time  			 		= (uint64_t)(master_record->first - 86400)*1000;
		v5_output_header->unix_secs = htonl(master_record->first - 86400);
		cnt   	 = 0;
		output_engine.first 	 = 0;
	}
	if ( cnt == 0 ) {
		peer->buff_ptr  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V5_HEADER_LENGTH);
		v5_output_record = (netflow_v5_record_t *)((pointer_addr_t)v5_output_header + (pointer_addr_t)sizeof(netflow_v5_header_t));	
		output_engine.sequence = output_engine.last_sequence + output_engine.last_count;
		v5_output_header->flow_sequence	= htonl(output_engine.sequence);
		output_engine.last_sequence = output_engine.sequence;
	}

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + (uint64_t)master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + (uint64_t)master_record->msec_last - boot_time);
  	v5_output_record->First		= htonl(t1);
  	v5_output_record->Last		= htonl(t2);

	v5_output_record->srcaddr	= htonl(master_record->v4.srcaddr);
  	v5_output_record->dstaddr	= htonl(master_record->v4.dstaddr);

  	v5_output_record->srcport	= htons(master_record->srcport);
  	v5_output_record->dstport	= htons(master_record->dstport);
  	v5_output_record->tcp_flags = master_record->tcp_flags;
  	v5_output_record->prot		= master_record->prot;
  	v5_output_record->tos		= master_record->tos;

	// the 64bit counters are cut down to 32 bits for v5
  	v5_output_record->dPkts		= htonl((uint32_t)master_record->dPkts);
  	v5_output_record->dOctets	= htonl((uint32_t)master_record->dOctets);

  	v5_output_record->input		= 0;
  	v5_output_record->output	= 0;
  	v5_output_record->src_as	= 0;
  	v5_output_record->dst_as	= 0;
	v5_output_record->src_mask 	= 0;
	v5_output_record->dst_mask 	= 0;
	v5_output_record->pad1 		= 0;
	v5_output_record->pad2 		= 0;
  	v5_output_record->nexthop	= 0;

	i = 0;
	while ( (id = extension_map->ex_id[i]) != 0 ) {
		switch (id) {
			case EX_IO_SNMP_2:
  				v5_output_record->input		= htons(master_record->input);
  				v5_output_record->output	= htons(master_record->output);
				break;
			case EX_AS_2:
  				v5_output_record->src_as	= htons(master_record->srcas);
  				v5_output_record->dst_as	= htons(master_record->dstas);
				break;
			case EX_MULIPLE:
				v5_output_record->src_mask 	= master_record->src_mask;
				v5_output_record->dst_mask 	= master_record->dst_mask;
				break;
			case EX_NEXT_HOP_v4:
				v5_output_record->nexthop	= htonl(master_record->ip_nexthop.v4);
				break;
			// default: Other extensions can not be sent with v5
		}
		i++;
	}
	cnt++;

	v5_output_header->count 	= htons(cnt);
	peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + NETFLOW_V5_RECORD_LENGTH);
	v5_output_record++;
	if ( cnt == NETFLOW_V5_MAX_RECORDS ) {
		peer->flush = 1;
		output_engine.last_count 	  = cnt;
		cnt = 0; 
	}

	return 0;

} // End of Add_v5_output_record
