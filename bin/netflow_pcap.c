/*
 *  Copyright (c) 2013-2020, Peter Haag
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nfnet.h"
#include "output_raw.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"

#include "flowtree.h"
#include "netflow_pcap.h"

static int printRecord;
static uint32_t recordSizev6;
static uint32_t recordSizev4;

#include "nffile_inline.c"

int Init_pcap2nf(int verbose) {

	printRecord = verbose;
	recordSizev6 = EXgenericFlowSize + EXipv6FlowSize + EXlatencySize;
	recordSizev4 = EXgenericFlowSize + EXipv4FlowSize + EXlatencySize;
	return 1;

} // End of Init_pcap2nf

int StorePcapFlow(FlowSource_t *fs, struct FlowNode *Node) {
uint32_t	recordSize;

	if ( Node->version == AF_INET6 ) {
		recordSize = recordSizev6;
		dbg_printf("Store Flow v6 node: size: %u\n", recordSize);
	} else if ( Node->version == AF_INET ) {
		recordSize = recordSizev4;
		dbg_printf("Store Flow v4 node: size: %u\n", recordSize);
	} else {
		LogError("Process_pcap: Unexpected version in %s line %d: %u\n", __FILE__, __LINE__, Node->version);
		return 0;
	}

	// output buffer size check for all expected records
	recordSize += sizeof(recordHeaderV3_t);
	if ( !CheckBufferSpace(fs->nffile, recordSize) ) {
		// fishy! - should never happen. maybe disk full?
		LogError("Process_pcap: output buffer size error. Abort pcap record processing");
		return 0;
	}

	// map output record to memory buffer
	AddV3Header(fs->nffile->buff_ptr, recordHeader);

	// header data
    recordHeader->nfversion  = 0x41;
    recordHeader->engineType = 0x11;
    recordHeader->engineID   = 1;
	recordHeader->exporterID = 0;

    // pack V3 record
    PushExtension(recordHeader, EXgenericFlow, genericFlow);
    genericFlow->msecFirst = (1000 * Node->t_first.tv_sec) + Node->t_first.tv_usec / 1000;
    genericFlow->msecLast  = (1000 * Node->t_last.tv_sec) + Node->t_last.tv_usec / 1000;

	struct timeval now;
	gettimeofday(&now, NULL);
	genericFlow->msecReceived = now.tv_sec * 1000L + now.tv_usec / 1000;

	genericFlow->inPackets = Node->packets;
	genericFlow->inBytes   = Node->bytes;

    genericFlow->proto     = Node->proto;
    genericFlow->tcpFlags  = Node->flags;
    genericFlow->srcPort   = Node->src_port;
    genericFlow->dstPort   = Node->dst_port;

	if ( Node->version == AF_INET6 ) {
		PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
		ipv6Flow->srcAddr[0] = Node->src_addr.v6[0];
		ipv6Flow->srcAddr[1] = Node->src_addr.v6[1];
		ipv6Flow->dstAddr[0] = Node->dst_addr.v6[0];
		ipv6Flow->dstAddr[1] = Node->dst_addr.v6[1];
	} else {
		PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
		ipv4Flow->srcAddr = Node->src_addr.v4;
		ipv4Flow->dstAddr = Node->dst_addr.v4;
	}


/* future extension XXX
	PushExtension(p, EXmacAddr, macAddr);
	macAddr->inSrcMac   = Get_val48((void *)&sample->eth_src);
	macAddr->outDstMac  = Get_val48((void *)&sample->eth_dst);
	macAddr->inDstMac   = 0;
	macAddr->outSrcMac  = 0;
*/

	PushExtension(recordHeader, EXlatency, latency);
	latency->usecClientNwDelay = Node->latency.client;
	latency->usecServerNwDelay = Node->latency.server;
	latency->usecApplLatency   = Node->latency.application;


	// update first_seen, last_seen
	if ( genericFlow->msecFirst  < fs->msecFirst )
		fs->msecFirst = genericFlow->msecFirst ;
	if ( genericFlow->msecLast > fs->msecLast )
		fs->msecLast = genericFlow->msecLast;


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
	stat_record->numflows++;
	stat_record->numpackets	+= genericFlow->inPackets;
	stat_record->numbytes	+= genericFlow->inBytes;

	if ( printRecord ) {
		char *string;
		master_record_t master_record;
		memset((void *)&master_record, 0, sizeof(master_record_t));
		ExpandRecord_v3(recordHeader, &master_record);
	 	flow_record_to_raw(&master_record, &string, 0);
		printf("%s\n", string);
	}

	// update file record size ( -> output buffer size )
	fs->nffile->block_header->NumRecords += 1;
	fs->nffile->block_header->size 		 += recordHeader->size;

	assert(recordHeader->size == recordSize);
	fs->nffile->buff_ptr += recordHeader->size;

	return 1;

} /* End of StorePcapFlow */

// Server latency = t(SYN Server) - t(SYN CLient)
void SetServer_latency(struct FlowNode *node) {
struct FlowNode *Client_node;
uint64_t	latency;

	Client_node = node->rev_node;
	if ( !Client_node ) 
		return;

	latency = ((uint64_t)node->t_first.tv_sec * (uint64_t)1000000 + (uint64_t)node->t_first.tv_usec) -
			  ((uint64_t)Client_node->t_first.tv_sec * (uint64_t)1000000 + (uint64_t)Client_node->t_first.tv_usec);
	
	node->latency.server 		= latency;
	Client_node->latency.server = latency;
	// set flag, to calc client latency with nex packet from client
	Client_node->latency.flag 	= 1;
	dbg_printf("Server latency: %llu\n", (long long unsigned)latency);

} // End of SetServerClient_latency

// Client latency = t(ACK CLient) - t(SYN Server)
void SetClient_latency(struct FlowNode *node, struct timeval *t_packet) {
struct FlowNode *Server_node;
uint64_t	latency;

	Server_node = node->rev_node;
	if ( !Server_node ) 
		return;

	latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
			  ((uint64_t)Server_node->t_first.tv_sec * (uint64_t)1000000 + (uint64_t)Server_node->t_first.tv_usec);
	
	node->latency.client 		= latency;
	Server_node->latency.client = latency;
	// reset flag
	node->latency.flag			= 0;
	// set flag, to calc application latency with nex packet from server
	Server_node->latency.flag	= 2;
	Server_node->latency.t_request = *t_packet;
	dbg_printf("Client latency: %llu\n", (long long unsigned)latency);

} // End of SetClient_latency

// Application latency = t(ACK Server) - t(ACK CLient)
void SetApplication_latency(struct FlowNode *node, struct timeval *t_packet) {
struct FlowNode *Client_node;
uint64_t	latency;

	Client_node = node->rev_node;
	if ( !Client_node ) 
		return;

	latency = ((uint64_t)t_packet->tv_sec * (uint64_t)1000000 + (uint64_t)t_packet->tv_usec) -
			  ((uint64_t)node->latency.t_request.tv_sec * (uint64_t)1000000 + (uint64_t)node->latency.t_request.tv_usec);
	
	node->latency.application 		 = latency;
	Client_node->latency.application = latency;
	// reset flag
	node->latency.flag			= 0;
	dbg_printf("Application latency: %llu\n", (long long unsigned)latency);

} // End of SetApplication_latency


