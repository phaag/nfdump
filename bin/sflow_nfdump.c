/*
 *  Copyright (c) 2009-2021, Peter Haag
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
#include "nfxV3.h"
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

} exporter_sflow_t;

static int printRecord = 0;
static uint32_t recordBaseSize;
static uint32_t numBaseElements;

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount);

#include "inline.c"
#include "nffile_inline.c"

void Init_sflow(int verbose) {

	printRecord = verbose;
	recordBaseSize = EXgenericFlowSize + EXflowMiscSize + 
					 EXasRoutingSize + EXvLanSize + EXmacAddrSize;
	numBaseElements = 5;

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
		readSFlowDatagram(&sample, fs, printRecord);
	} else {
		// CATCH
		dbg_printf("SFLOW: caught exception: %d\n", exceptionVal);
		LogError("SFLOW: caught exception: %d", exceptionVal);
	}
	dbg_printf("endDatagram	 =================================\n");

} // End of Process_sflow

static exporter_sflow_t *GetExporter(FlowSource_t *fs, uint32_t agentSubId, uint32_t meanSkipCount) {
exporter_sflow_t **e = (exporter_sflow_t **)&(fs->exporter_data);
sampler_t *sampler;
#define IP_STRING_LEN   40
char ipstr[IP_STRING_LEN];

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

	sampler = (sampler_t *)malloc(sizeof(sampler_t));
	if ( !sampler ) {
		LogError("SFLOW: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	(*e)->sampler = sampler;

	sampler->info.header.type 	= SamplerInfoRecordType;
	sampler->info.header.size	= sizeof(sampler_info_record_t);
	sampler->info.id			= -1;
	sampler->info.mode			= 0;
	sampler->info.interval		= meanSkipCount;
	sampler->next				= NULL;

	FlushInfoExporter(fs, &((*e)->info));
	sampler->info.exporter_sysid		= (*e)->info.sysid;
	AppendToBuffer(fs->nffile, &(sampler->info.header), sampler->info.header.size);

	dbg_printf("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s\n", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);
	LogInfo("SFLOW: New exporter: SysID: %u, agentSubId: %u, MeanSkipCount: %u, IP: %s", 
		(*e)->info.sysid, agentSubId, meanSkipCount, ipstr);

	return (*e);

} // End of GetExporter

// store sflow in nfdump format
void StoreSflowRecord(SFSample *sample, FlowSource_t *fs) {
exporter_sflow_t 	*exporter;
struct timeval now;

	dbg_printf("StoreSflowRecord\n");

	gettimeofday(&now, NULL);

	exporter = GetExporter(fs, sample->agentSubId, sample->meanSkipCount);
	if ( !exporter ) {
		LogError("SFLOW: Exporter NULL: Abort sflow record processing");
		return;
	}
	exporter->packets++;

	if( sample->ip_fragmentOffset > 0 ) {
		sample->dcd_sport = 0;
		sample->dcd_dport = 0;
	}

	uint32_t recordSize = recordBaseSize;
	uint32_t numElements = numBaseElements;
	if(sample->gotIPV6) {
		recordSize += EXipv6FlowSize;
	} else {
		recordSize += EXipv4FlowSize;
	}
	numElements++;

	if (sample->mpls_num_labels > 0) {
		recordSize += EXmplsLabelSize;
		numElements++;
	} 

	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
		recordSize += EXipNextHopV4Size;
		numElements++;
	} 
	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
		recordSize += EXipNextHopV6Size;
		numElements++;
	}

	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
		recordSize += EXbgpNextHopV4Size;
		numElements++;
	}
	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
		recordSize += EXbgpNextHopV6Size;
		numElements++;
	}

	if ( fs->sa_family == AF_INET6 ) {
		recordSize += EXipReceivedV6Size;
		numElements++;
	} else {
		recordSize += EXipReceivedV4Size;
		numElements++;
	}


	recordSize += sizeof(recordHeaderV3_t);
	if ( !CheckBufferSpace(fs->nffile, recordSize)) {
		// fishy! - should never happen. maybe disk full?
		LogError("SFLOW: output buffer size error. Abort sflow record processing");
		return;
	}

	dbg_printf("Fill Record\n");
	AddV3Header(fs->nffile->buff_ptr, recordHeader);

    recordHeader->exporterID = exporter->info.sysid;
	recordHeader->flags		 = V3_FLAG_SAMPLED;
	recordHeader->nfversion  = 0x80 | sample->datagramVersion;

    // pack V3 record
    PushExtension(recordHeader, EXgenericFlow, genericFlow);
    genericFlow->msecFirst = now.tv_sec * 1000L + now.tv_usec / 1000;
    genericFlow->msecLast  = genericFlow->msecFirst;
    genericFlow->proto     = sample->dcd_ipProtocol;
    genericFlow->tcpFlags  = sample->dcd_tcpFlags;
    genericFlow->srcPort   = (uint16_t)sample->dcd_sport;
    genericFlow->dstPort   = (uint16_t)sample->dcd_dport;
	genericFlow->msecReceived = (uint64_t)((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);
	genericFlow->inPackets	= sample->meanSkipCount;
	genericFlow->inBytes	= sample->meanSkipCount *  sample->sampledPacketSize;
    genericFlow->srcTos     = sample->dcd_ipTos;

	if(sample->gotIPV6) {
		PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
		SetFlag(recordHeader->flags, V3_FLAG_IPV6_ADDR);

		u_char   *b = sample->ipsrc.address.ip_v6.addr;
		uint64_t *u = (uint64_t *)b;
		ipv6Flow->srcAddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6Flow->srcAddr[1] = ntohll(*u);

		b = sample->ipdst.address.ip_v6.addr;
		u = (uint64_t *)b;
		ipv6Flow->dstAddr[0] = ntohll(*u);
		u = (uint64_t *)&(b[8]);
		ipv6Flow->dstAddr[1] = ntohll(*u);

	} else {
		PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
		ipv4Flow->srcAddr = ntohl(sample->dcd_srcIP.s_addr);
		ipv4Flow->dstAddr = ntohl(sample->dcd_dstIP.s_addr);
	}

    PushExtension(recordHeader, EXflowMisc, flowMisc);
	flowMisc->input   = sample->inputPort;
	flowMisc->output  = sample->outputPort;
    flowMisc->srcMask = sample->srcMask;
    flowMisc->dstMask = sample->dstMask;

	PushExtension(recordHeader, EXvLan, vLan);
	vLan->srcVlan = sample->in_vlan;
	vLan->dstVlan = sample->out_vlan;

	PushExtension(recordHeader, EXasRouting, asRouting);
	asRouting->srcAS = sample->src_as;
	asRouting->dstAS = sample->dst_as;

	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
		PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
		ipNextHopV4->ip = ntohl(sample->nextHop.address.ip_v4.addr);
	} 
	if ( sample->nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
		uint64_t *addr = (uint64_t *)sample->nextHop.address.ip_v6.addr;
		PushExtension(recordHeader, EXipNextHopV6, ipNextHopV6);
		ipNextHopV6->ip[0] = ntohll(addr[0]);
		ipNextHopV6->ip[1] = ntohll(addr[1]);
	}

	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V4 ) {
		PushExtension(recordHeader, EXbgpNextHopV4, bgpNextHopV4);
		bgpNextHopV4->ip = ntohl(sample->bgp_nextHop.address.ip_v4.addr);
	}
	if ( sample->bgp_nextHop.type == SFLADDRESSTYPE_IP_V6 ) {
		uint64_t *addr = (void *)sample->bgp_nextHop.address.ip_v6.addr;
		PushExtension(recordHeader, EXipReceivedV6, ipNextHopV6);
		ipNextHopV6->ip[0] = ntohll(addr[0]);
		ipNextHopV6->ip[1] = ntohll(addr[1]);
	}

	PushExtension(recordHeader, EXmacAddr, macAddr);
	macAddr->inSrcMac   = Get_val48((void *)&sample->eth_src);
	macAddr->outDstMac  = Get_val48((void *)&sample->eth_dst);
	macAddr->inDstMac   = 0;
	macAddr->outSrcMac  = 0;

	if (sample->mpls_num_labels > 0) {
		PushExtension(recordHeader, EXmplsLabel, mplsLabel);
		for (int i=0; i<sample->mpls_num_labels; i++ ) {
			mplsLabel->mplsLabel[i] = sample->mpls_label[i];
		}
	}

	if(sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
		PushExtension(recordHeader, EXipReceivedV4, received);
		received->ip = ntohl(sample->agent_addr.address.ip_v4.addr);
	} else {
		uint64_t *addr = (void *)sample->agent_addr.address.ip_v6.addr;
		PushExtension(recordHeader, EXipReceivedV6, receivedIP);
		receivedIP->ip[0] = ntohll(addr[0]);
		receivedIP->ip[1] = ntohll(addr[1]);
	}

	// update first_seen, last_seen
	if ( genericFlow->msecFirst < fs->msecFirst )	// the very first time stamp need to be set
		fs->msecFirst = genericFlow->msecFirst;
	fs->msecLast = genericFlow->msecFirst;

	// Update stats
	stat_record_t *stat_record = fs->nffile->stat_record;
	switch (genericFlow->proto) {
		case IPPROTO_ICMP:
			stat_record->numflows_icmp++;
			stat_record->numpackets_icmp += genericFlow->inPackets;
			stat_record->numbytes_icmp   += genericFlow->inBytes;
			break;
		case IPPROTO_TCP:
			stat_record->numflows_tcp++;
			stat_record->numpackets_tcp += genericFlow->inPackets;
			stat_record->numbytes_tcp   += genericFlow->inBytes;
			break;
		case IPPROTO_UDP:
			stat_record->numflows_udp++;
			stat_record->numpackets_udp += genericFlow->inPackets;
			stat_record->numbytes_udp   += genericFlow->inBytes;
			break;
		default:
			stat_record->numflows_other++;
			stat_record->numpackets_other += genericFlow->inPackets;
			stat_record->numbytes_other   += genericFlow->inBytes;
	}
	exporter->flows++;
	stat_record->numflows++;
	stat_record->numpackets	+= genericFlow->inPackets;
	stat_record->numbytes	+= genericFlow->inBytes;

	if ( printRecord ) {
		master_record_t master_record;
		memset((void *)&master_record, 0, sizeof(master_record_t));
		ExpandRecord_v3(recordHeader, &master_record);
	 	flow_record_to_raw(stdout, &master_record, 0);
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->NumRecords++;
	fs->nffile->block_header->size += recordSize;

	dbg_assert(recordHeader->size == recordSize);

	fs->nffile->buff_ptr += recordSize;

} // End of StoreSflowRecord

