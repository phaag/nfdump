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

/* 
 * sfcapd makes use of code originated from sflowtool by InMon Corp. 
 * Those parts of the code are distributed under the InMon Public License below.
 * All other/additional code is pubblished under BSD license.
 */

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <setjmp.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfx.h"
#include "output_raw.h"
#include "bookkeeper.h"
#include "collector.h"

#include "sflow.h" /* sFlow v5 */
#include "sflow_v2v4.h" /* sFlow v2/4 */
#include "sflow_process.h"
#include "sflow_nfdump.h"

#define MAX_SFLOW_EXTENSIONS 8

typedef struct exporter_sflow_s {
	// link chain
	struct exporter_sflow_s *next;

	// exporter information
	exporter_info_record_t info;

    uint64_t    packets;            // number of packets sent by this exporter
    uint64_t    flows;              // number of flow records sent by this exporter
    uint32_t    sequence_failure;   // number of sequence failues

    sampler_t       *sampler;

	// extension map
	// extension maps are common for all exporters
	extension_info_t sflow_extension_info[MAX_SFLOW_EXTENSIONS];

} exporter_sflow_t;

extern extension_descriptor_t extension_descriptor[];

/* module limited globals */

/*
 * As sflow has no templates, we need to have an extension map for each possible
 * combination of IPv4/IPv6 addresses in all ip fields
 *
 * index id:
 * 0 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 1 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 2 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 3 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 4 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 5 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 6 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 * 7 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 */
static uint16_t sflow_output_record_size[MAX_SFLOW_EXTENSIONS];

// All available extensions for sflow
static uint16_t sflow_extensions[] = { 
	EX_IO_SNMP_4, 
	EX_AS_4, 
	EX_MULIPLE, 
	EX_VLAN, 
	EX_MAC_1, 
	EX_RECEIVED,
	0 			// final token
};
static int Num_enabled_extensions;

static struct sflow_ip_extensions_s {
	int next_hop;
	int next_hop_bgp;
	int router_ip;
} sflow_ip_extensions[] = {
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6 },
	{ EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6 },
};

#define SFLOW_NEXT_HOP 	   1
#define SFLOW_NEXT_HOP_BGP 2
#define SFLOW_ROUTER_IP    4

extern int verbose;

static int IP_extension_mask = 0;

static int Setup_Extension_Info(FlowSource_t *fs, exporter_sflow_t	*exporter, int num);

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount);

#include "inline.c"
#include "nffile_inline.c"

void Init_sflow(void) {
int i, id;

	i=0;
	Num_enabled_extensions = 0;
	while ( (id = sflow_extensions[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			dbg_printf("Enabled extension: %i\n", id);
			Num_enabled_extensions++;
		}
		i++;
	}

	IP_extension_mask = 0;
	i=0;
	while ( extension_descriptor[i].description != NULL  ) {
		switch (extension_descriptor[i].id) {
			case EX_NEXT_HOP_v4:
			// case EX_NEXT_HOP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_NEXT_HOP);
					Num_enabled_extensions++;
				} break;
			case EX_NEXT_HOP_BGP_v4:
			// case EX_NEXT_HOP_BGP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_NEXT_HOP_BGP);
					Num_enabled_extensions++;
				} break;
			case EX_ROUTER_IP_v4:
			// case EX_ROUTER_IP_v6: - not really needed
				if ( extension_descriptor[i].enabled ) {
					SetFlag(IP_extension_mask, SFLOW_ROUTER_IP);
					Num_enabled_extensions++;
				} break;
		}
		i++;
	}

	dbg_printf("Num enabled Extensions: %i\n", Num_enabled_extensions);

} // End of Init_sflow

// called by sfcapd for each packet
void Process_sflow(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
SFSample 	sample;
int 		exceptionVal;

	memset(&sample, 0, sizeof(sample));
	sample.rawSample = in_buff;
	sample.rawSampleLen = in_buff_cnt;
	sample.sourceIP.s_addr = fs->sa_family == PF_INET ? htonl(fs->ip.V4) : 0;;

	dbg_printf("startDatagram =================================\n");
	// catch SFABORT in sflow code
	if((exceptionVal = setjmp(sample.env)) == 0)	{
		// TRY
		sample.datap = (uint32_t *)sample.rawSample;
		sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;
		readSFlowDatagram(&sample, fs, verbose);
	} else {
		// CATCH
		dbg_printf("SFLOW: caught exception: %d\n", exceptionVal);
		LogError("SFLOW: caught exception: %d", exceptionVal);
	}
	dbg_printf("endDatagram	 =================================\n");

} // End of Process_sflow

static int Setup_Extension_Info(FlowSource_t *fs, exporter_sflow_t	*exporter, int num) {
int i, id, extension_size, map_size, map_index;

	dbg_printf("Setup Extension ID 0x%x\n", num);
	LogInfo("SFLOW: setup extension map %u", num);

	// prepare sflow extension map <num>
	exporter->sflow_extension_info[num].map   = NULL;
	extension_size	 = 0;

	// calculate the full extension map size
	map_size 	= Num_enabled_extensions * sizeof(uint16_t) + sizeof(extension_map_t);

	// align 32 bits
	if ( ( map_size & 0x3 ) != 0 )
		map_size += 2;


	// Create a sflow extension map
	exporter->sflow_extension_info[num].map = (extension_map_t *)malloc((size_t)map_size);
	if ( !exporter->sflow_extension_info[num].map ) {
		LogError("SFLOW: malloc() allocation error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
		return 0;
	}

	// calclate the extension size
	i=0;
	map_index = 0;
	while ( (id = sflow_extensions[i]) != 0  ) {
		if ( extension_descriptor[id].enabled ) {
			extension_size += extension_descriptor[id].size;
			exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
		}
		i++;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_NEXT_HOP)) {
		id = sflow_ip_extensions[num].next_hop;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_NEXT_HOP_BGP)) {
		id = sflow_ip_extensions[num].next_hop_bgp;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	if ( TestFlag(IP_extension_mask, SFLOW_ROUTER_IP)) {
		id = sflow_ip_extensions[num].router_ip;
		extension_size += extension_descriptor[id].size;
		exporter->sflow_extension_info[num].map->ex_id[map_index++] = id;
	}

	// terminating null record
	exporter->sflow_extension_info[num].map->ex_id[map_index] = 0;

	dbg_printf("Extension size: %i\n", extension_size);

	// caculate the basic record size: without IP addr space ( v4/v6 dependant )
	// byte/packet counters are 32bit -> 2 x uint32_t
	// extension_size contains the sum of all optional extensions
	sflow_output_record_size[num] = COMMON_RECORD_DATA_SIZE + 2*sizeof(uint32_t) + extension_size;	

	dbg_printf("Record size: %i\n", sflow_output_record_size[num]);

	exporter->sflow_extension_info[num].map->type 	   	  = ExtensionMapType;
	exporter->sflow_extension_info[num].map->size 	   	  = map_size;
	exporter->sflow_extension_info[num].map->map_id   	  = INIT_ID;		
	exporter->sflow_extension_info[num].map->extension_size = extension_size;		

	LogInfo("Extension size: %i", extension_size);
	LogInfo("Extension map size: %i", map_size);

	if ( !AddExtensionMap(fs, exporter->sflow_extension_info[num].map) ) {
		// bad - we must free this map and fail - otherwise data can not be read any more
		free(exporter->sflow_extension_info[num].map);
		exporter->sflow_extension_info[num].map = NULL;
		return 0;
	}
	dbg_printf("New Extension map ID %i\n", exporter->sflow_extension_info[num].map->map_id);
	LogInfo("New extension map id: %i", exporter->sflow_extension_info[num].map->map_id);

	return 1;

} // End of Setup_Extension_Info

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount) {
exporter_sflow_t **e = (exporter_sflow_t **)&(fs->exporter_data);
sampler_t *sampler;
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];
int i;

	// search the appropriate exporter engine
	while ( *e ) {
		if ( (*e)->info.id == agentSubId && (*e)->info.version == SFLOW_VERSION &&
			 (*e)->info.ip.V6[0] == fs->ip.V6[0] && (*e)->info.ip.V6[1] == fs->ip.V6[1]) 
			return *e;
		e = &((*e)->next);
	}

	if ( fs->sa_family == AF_INET ) {
		uint32_t _ip = htonl(fs->ip.V4);
		inet_ntop(AF_INET, &_ip, ipstr, sizeof(ipstr));
	} else if ( fs->sa_family == AF_INET6 ) {
		uint64_t _ip[2];
		_ip[0] = htonll(fs->ip.V6[0]);
		_ip[1] = htonll(fs->ip.V6[1]);
		inet_ntop(AF_INET6, &_ip, ipstr, sizeof(ipstr));
	} else {
		strncpy(ipstr, "<unknown>", IP_STRING_LEN);
	}

	// nothing found
	LogInfo("SFLOW: New exporter" );

	*e = (exporter_sflow_t *)malloc(sizeof(exporter_sflow_t));
	if ( !(*e)) {
		LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_sflow_t));
	(*e)->next	 			= NULL;
	(*e)->info.header.type  = ExporterInfoRecordType;
	(*e)->info.header.size  = sizeof(exporter_info_record_t);
	(*e)->info.version		= SFLOW_VERSION;
	(*e)->info.id 			= agentSubId;
	(*e)->info.ip			= fs->ip;
	(*e)->info.sa_family	= fs->sa_family;
	(*e)->sequence_failure	= 0;
	(*e)->packets			= 0;
	(*e)->flows				= 0;
	for (i=0; i<MAX_SFLOW_EXTENSIONS; i++ ) {
		(*e)->sflow_extension_info[i].map = NULL;
	}

	sampler = (sampler_t *)malloc(sizeof(sampler_t));
	if ( !sampler ) {
		LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	(*e)->sampler = sampler;

	sampler->info.header.type 	= SamplerInfoRecordype;
	sampler->info.header.size	= sizeof(sampler_info_record_t);
	sampler->info.id			= -1;
	sampler->info.mode			= 0;
	sampler->info.interval		= meanSkipCount;
	sampler->next				= NULL;

	FlushInfoExporter(fs, &((*e)->info));
	sampler->info.exporter_sysid		= (*e)->info.sysid;
	FlushInfoSampler(fs, &(sampler->info));

	dbg_printf("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s\n", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);
	LogInfo("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);

	return (*e);

} // End of GetExporter

// store sflow in nfdump format
void StoreSflowRecord(SFSample *sample, FlowSource_t *fs) {
common_record_t	*common_record;
stat_record_t *stat_record = fs->nffile->stat_record;
exporter_sflow_t 	*exporter;
extension_map_t		*extension_map;
struct timeval now;
void	 *next_data;
value32_t	*val;
uint32_t bytes, j, id, ipsize, ip_flags;
uint64_t _bytes, _packets, _t;	// tmp buffers

	dbg_printf("StoreSflowRecord\n");

	gettimeofday(&now, NULL);

	if( sample->ip_fragmentOffset > 0 ) {
		sample->dcd_sport = 0;
		sample->dcd_dport = 0;
	}

	bytes = sample->sampledPacketSize;
	
	ip_flags = 0;
	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 )
		SetFlag(ip_flags, SFLOW_NEXT_HOP);
		
	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 )
		SetFlag(ip_flags, SFLOW_NEXT_HOP_BGP);
		
	if ( fs->sa_family == AF_INET6 ) 
		SetFlag(ip_flags, SFLOW_ROUTER_IP);

	ip_flags &= IP_extension_mask;

	if ( ip_flags >= MAX_SFLOW_EXTENSIONS ) {
		LogError("SFLOW: Corrupt ip_flags: %u", ip_flags);
	}
	exporter = GetExporter(fs, sample->agentSubId, sample->meanSkipCount);
	if ( !exporter ) {
		LogError("SFLOW: Exporter NULL: Abort sflow record processing");
		return;
	}
	exporter->packets++;

	// get appropriate extension map
	extension_map = exporter->sflow_extension_info[ip_flags].map;
	if ( !extension_map ) {
		LogInfo("SFLOW: setup extension map: %u", ip_flags);
		if ( !Setup_Extension_Info(fs, exporter, ip_flags ) ) {
			LogError("SFLOW: Extension map: NULL: Abort sflow record processing");
			return;
		}
		extension_map = exporter->sflow_extension_info[ip_flags].map;
		LogInfo("SFLOW: setup extension map: %u done", ip_flags);
	}

	// output buffer size check
	// IPv6 needs 2 x 16 bytes, IPv4 2 x 4 bytes
	ipsize = sample->gotIPV6 ? 32 : 8;
	if ( !CheckBufferSpace(fs->nffile, sflow_output_record_size[ip_flags] + ipsize )) {
		// fishy! - should never happen. maybe disk full?
		LogError("SFLOW: output buffer size error. Abort sflow record processing");
		return;
	}

	dbg_printf("Fill Record\n");
	common_record = (common_record_t *)fs->nffile->buff_ptr;

	common_record->size			  = sflow_output_record_size[ip_flags] + ipsize;
	common_record->type			  = CommonRecordType;
	common_record->flags		  = 0;
	SetFlag(common_record->flags, FLAG_SAMPLED);

	common_record->exporter_sysid = exporter->info.sysid;
	common_record->ext_map		  = extension_map->map_id;

	common_record->first		  = now.tv_sec;
	common_record->last			  = common_record->first;
	common_record->msec_first	  = now.tv_usec / 1000;
	common_record->msec_last	  = common_record->msec_first;
	_t							  = 1000LL * now.tv_sec + common_record->msec_first;	// tmp buff for first_seen

	common_record->fwd_status	  = 0;
	common_record->reserved	  	  = 0;
	common_record->tcp_flags	  = sample->dcd_tcpFlags;
	common_record->prot			  = sample->dcd_ipProtocol;
	common_record->tos			  = sample->dcd_ipTos;
	common_record->srcport		  = (uint16_t)sample->dcd_sport;
	common_record->dstport		  = (uint16_t)sample->dcd_dport;

	if(sample->gotIPV6) {
		u_char 		*b;
		uint64_t	*u;
		ipv6_block_t	*ipv6 	= (ipv6_block_t *)common_record->data;
		SetFlag(common_record->flags, FLAG_IPV6_ADDR);

		b = sample->ipsrc.address.ip_v6.addr;
		u = (uint64_t *)b;
		ipv6->srcaddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6->srcaddr[1] = ntohll(*u);

		b = sample->ipdst.address.ip_v6.addr;
		u = (uint64_t *)b;
		ipv6->dstaddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6->dstaddr[1] = ntohll(*u);

		next_data = (void *)ipv6->data;
	} else {
		ipv4_block_t *ipv4 = (ipv4_block_t *)common_record->data;
		ipv4->srcaddr = ntohl(sample->dcd_srcIP.s_addr);
		ipv4->dstaddr = ntohl(sample->dcd_dstIP.s_addr);
	
		next_data = (void *)ipv4->data;
	}

	// 4 byte Packet value
	val = (value32_t *)next_data;
	val->val = sample->meanSkipCount;
	_packets = val->val;

	// 4 byte Bytes value
	val = (value32_t *)val->data;
	val->val = sample->meanSkipCount * bytes;
	_bytes = val->val;

	next_data = (void *)val->data;

	j = 0;
	while ( (id = extension_map->ex_id[j]) != 0 ) {
		switch (id) {
			case EX_IO_SNMP_4:	{	// 4 byte input/output interface index
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)next_data;
				tpl->input  = sample->inputPort;
				tpl->output = sample->outputPort;
				next_data = (void *)tpl->data;
				} break;
			case EX_AS_4:	 {	// 4 byte src/dst AS number
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)next_data;
				tpl->src_as	= sample->src_as;
				tpl->dst_as	= sample->dst_as;
				next_data = (void *)tpl->data;
				} break;
			case EX_VLAN: { // 2 byte valn label
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)next_data;
				tpl->src_vlan = sample->in_vlan;
				tpl->dst_vlan = sample->out_vlan;
				next_data = (void *)tpl->data;
				} break;
			case EX_MULIPLE:	 {	// dst tos, direction, src/dst mask
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)next_data;
				tpl->dst_tos	= sample->dcd_ipTos;
				tpl->dir		= 0;
				tpl->src_mask	= sample->srcMask;
				tpl->dst_mask	= sample->dstMask;
				next_data = (void *)tpl->data;
				} break;
			case EX_MAC_1: 	{ // MAC addreses
				tpl_ext_20_t *tpl = (tpl_ext_20_t *)next_data;
				tpl->in_src_mac  = Get_val48((void *)&sample->eth_src);
				tpl->out_dst_mac = Get_val48((void *)&sample->eth_dst);
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_v4:	 {	// next hop IPv4 router address
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)next_data;
				if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
					tpl->nexthop = ntohl(sample->nextHop.address.ip_v4.addr);
				} else {
					tpl->nexthop = 0;
				}
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_v6:	 {	// next hop IPv6 router address
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)next_data;
				void *ptr = (void *)sample->nextHop.address.ip_v6.addr;
				if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
					tpl->nexthop[0] = ntohll(((uint64_t *)ptr)[0]);
					tpl->nexthop[1] = ntohll(((uint64_t *)ptr)[1]);
				} else {
					tpl->nexthop[0] = 0;
					tpl->nexthop[1] = 0;
				}
				SetFlag(common_record->flags, FLAG_IPV6_NH);
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_BGP_v4:	 {	// next hop bgp IPv4 router address
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)next_data;
				if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
					tpl->bgp_nexthop = ntohl(sample->bgp_nextHop.address.ip_v4.addr);
				} else {
					tpl->bgp_nexthop = 0;
				}
				next_data = (void *)tpl->data;
			} break;
			case EX_NEXT_HOP_BGP_v6:	 {	// next hop IPv4 router address
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)next_data;
				void *ptr = (void *)sample->bgp_nextHop.address.ip_v6.addr;
				if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
					tpl->bgp_nexthop[0] = ntohll(((uint64_t *)ptr)[0]);
					tpl->bgp_nexthop[1] = ntohll(((uint64_t *)ptr)[1]);
				} else {
					tpl->bgp_nexthop[0] = 0;
					tpl->bgp_nexthop[1] = 0;
				}
				SetFlag(common_record->flags, FLAG_IPV6_NHB);
				next_data = (void *)tpl->data;
			} break;
			case EX_ROUTER_IP_v4:
			case EX_ROUTER_IP_v6: 	// IPv4/IPv6 router address
			if(sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)next_data;
				tpl->router_ip = ntohl(sample->agent_addr.address.ip_v4.addr);
				next_data = (void *)tpl->data;
				ClearFlag(common_record->flags, FLAG_IPV6_EXP);
			} else {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)next_data;
				void *ptr = (void *)sample->agent_addr.address.ip_v6.addr;
				tpl->router_ip[0] = ntohll(((uint64_t *)ptr)[0]);
				tpl->router_ip[1] = ntohll(((uint64_t *)ptr)[1]);
				next_data = (void *)tpl->data;
				SetFlag(common_record->flags, FLAG_IPV6_EXP);
			}
			break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)next_data;
				tpl->received  = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
				next_data = (void *)tpl->data;
			} break;
			default: 
				// this should never happen
				LogError("SFLOW: Unexpected extension %i for sflow record. Skip extension", id);
				dbg_printf("SFLOW: Unexpected extension %i for sflow record. Skip extension", id);
		}
		j++;
	}

	// update first_seen, last_seen
	if ( _t < fs->first_seen )	// the very first time stamp need to be set
		fs->first_seen = _t;
	fs->last_seen = _t;

	// Update stats
	switch (common_record->prot) {
		case 1:
			stat_record->numflows_icmp++;
			stat_record->numpackets_icmp += _packets;
			stat_record->numbytes_icmp   += _bytes;
			break;
		case 6:
			stat_record->numflows_tcp++;
			stat_record->numpackets_tcp += _packets;
			stat_record->numbytes_tcp   += _bytes;
			break;
		case 17:
			stat_record->numflows_udp++;
			stat_record->numpackets_udp += _packets;
			stat_record->numbytes_udp   += _bytes;
			break;
		default:
			stat_record->numflows_other++;
			stat_record->numpackets_other += _packets;
			stat_record->numbytes_other   += _bytes;
	}
	exporter->flows++;
	stat_record->numflows++;
	stat_record->numpackets	+= _packets;
	stat_record->numbytes	+= _bytes;

	if ( verbose ) {
		master_record_t master_record;
		char	*string;
		ExpandRecord_v2((common_record_t *)common_record, &exporter->sflow_extension_info[ip_flags], &(exporter->info), &master_record);
	 	flow_record_to_raw(&master_record, &string, 0);
		printf("%s\n", string);
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->NumRecords++;
	fs->nffile->block_header->size 		+= (sflow_output_record_size[ip_flags] + ipsize);
#ifdef DEVEL
	if ( (next_data - fs->nffile->buff_ptr) != (sflow_output_record_size[ip_flags] + ipsize) ) {
		printf("PANIC: Size error. Buffer diff: %llu, Size: %u\n", 
			(unsigned long long)(next_data - fs->nffile->buff_ptr), 
			(sflow_output_record_size[ip_flags] + ipsize));
		exit(255);
	}
#endif
	fs->nffile->buff_ptr 					= next_data;

} // End of StoreSflowRecord

