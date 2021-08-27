/*
 *  Copyright (c) 2021, Peter Haag
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
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "nfnet.h"
#include "output_short.h"
#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"

#include "queue.h"
#include "netflow_pcapd.h"
#include "flowdump.h"
#include "flowsend.h"

static int printRecord = 0;
#include "nffile_inline.c"

#define UpdateRecordSize(s) recordSize += (s); \
	if (recordSize > availableSize) continue;

static void *sendBuffer  = NULL;
static uint32_t sequence = 0;

static int ProcessFlow(flowParam_t *flowParam, struct FlowNode *Node);

static int SendFlow(repeater_t *sendHost, pcapd_header_t *pcapd_header) {

	dbg_printf("Sending %u records\n", pcapd_header->numRecord); 
	uint32_t length = pcapd_header->length;
	pcapd_header->length = htons(pcapd_header->length);
	pcapd_header->lastSequence = htonl(sequence++);
	pcapd_header->numRecord = htonl(pcapd_header->numRecord);
	// send buffer
	ssize_t len = sendto(sendHost->sockfd, pcapd_header, length, 0, 
			(struct sockaddr *)&(sendHost->addr), sendHost->addrlen);
	if ( len < 0 ) {
		LogError("ERROR: sendto() failed: %s", strerror(errno));
		return len;
	}
	
	// init new header
	pcapd_header->length = sizeof(pcapd_header_t);
	pcapd_header->numRecord = 0;
	
	return 0;

} // End of SendFlow

static int ProcessFlow(flowParam_t *flowParam, struct FlowNode *Node) {
repeater_t *sendHost = flowParam->sendHost;

	dbg_printf("Send Flow node\n");
	
	pcapd_header_t *pcapd_header = (pcapd_header_t *)sendBuffer;
	void *buffPtr = sendBuffer + pcapd_header->length;
	uint32_t recordSize = 0;
	do {
		size_t availableSize = 65535 - pcapd_header->length;
		if (recordSize > availableSize || availableSize < 150) {
			if (SendFlow(sendHost, pcapd_header) < 0)
				return 0;
			continue;
		}
		recordSize = 0;

		// map output record to memory buffer
		UpdateRecordSize(V3HeaderRecordSize);
		AddV3Header(buffPtr, recordHeader);

		// header data
    	recordHeader->nfversion  = 0x41;
    	recordHeader->engineType = 0x11;
    	recordHeader->engineID   = 1;
		recordHeader->exporterID = 0;

    	// pack V3 record
		UpdateRecordSize(EXgenericFlowSize);
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
			UpdateRecordSize(EXipv6FlowSize);
			PushExtension(recordHeader, EXipv6Flow, ipv6Flow);
			ipv6Flow->srcAddr[0] = Node->src_addr.v6[0];
			ipv6Flow->srcAddr[1] = Node->src_addr.v6[1];
			ipv6Flow->dstAddr[0] = Node->dst_addr.v6[0];
			ipv6Flow->dstAddr[1] = Node->dst_addr.v6[1];
		} else {
			UpdateRecordSize(EXipv4FlowSize);
			PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
			ipv4Flow->srcAddr = Node->src_addr.v4;
			ipv4Flow->dstAddr = Node->dst_addr.v4;
		}

		if ( flowParam->extendedFlow ) {
			if ( Node->vlanID ) {
				UpdateRecordSize(EXvLanSize);
				PushExtension(recordHeader, EXvLan, vlan);
				vlan->dstVlan = Node->vlanID;
			}

			UpdateRecordSize(EXmacAddrSize);
			PushExtension(recordHeader, EXmacAddr, macAddr);
			macAddr->inSrcMac   = ntohll(Node->srcMac) >> 16;
			macAddr->outDstMac  = ntohll(Node->dstMac) >> 16;
			macAddr->inDstMac   = 0;
			macAddr->outSrcMac  = 0;

			if ( Node->mpls[0] ) {
				UpdateRecordSize(EXmplsLabelSize);
				PushExtension(recordHeader, EXmplsLabel, mplsLabel);
				for (int i=0; Node->mpls[i] != 0; i++) {
					mplsLabel->mplsLabel[i] = ntohl(Node->mpls[i]) >> 8;
				}
			}

			if ( Node->proto == IPPROTO_TCP) {
				UpdateRecordSize(EXlatencySize);
				PushExtension(recordHeader, EXlatency, latency);
				latency->usecClientNwDelay = Node->latency.client;
				latency->usecServerNwDelay = Node->latency.server;
				latency->usecApplLatency   = Node->latency.application;
			}
		}

		if ( flowParam->addPayload ) {
			if ( Node->payloadSize ) {
				UpdateRecordSize(EXinPayloadSize+Node->payloadSize);
				PushVarLengthPointer(recordHeader, EXinPayload, inPayload, Node->payloadSize);
				memcpy(inPayload, Node->payload, Node->payloadSize);
			}
		}

		if ( printRecord ) {
			master_record_t master_record;
			memset((void *)&master_record, 0, sizeof(master_record_t));
			ExpandRecord_v3(recordHeader, &master_record);
	 		flow_record_short(stdout, &master_record, 0);
		}

		// update file record size ( -> output buffer size )
		pcapd_header->numRecord++;
		pcapd_header->length += recordHeader->size;

		dbg_printf("Record size: %u, header size: %u\n",
			recordSize, recordHeader->size);

		assert(recordHeader->size == recordSize);
		break;

	} while(1);

	if (pcapd_header->length > 1200) {
		// send buffer - prevent fragmentation for next packet
		if (SendFlow(sendHost, pcapd_header) < 0)
			return 0;
	}

	return 1;

} /* End of StorePcapFlow */

static inline int CloseSender(flowParam_t *flowParam, time_t timestamp) {
repeater_t *sendHost = flowParam->sendHost;

	return close(sendHost->sockfd);

} // end of CloseFlowFile

__attribute__((noreturn)) void *sendflow_thread(void *thread_data) {
// argument dispatching
flowParam_t *flowParam = (flowParam_t *)thread_data;

	sendBuffer	   = malloc(65535);
	pcapd_header_t *pcapd_header = (pcapd_header_t *)sendBuffer;
	memset((void *)pcapd_header, 0, sizeof(pcapd_header_t));
	pcapd_header->version	   = htons(240);
	pcapd_header->length	   = sizeof(pcapd_header_t);
	pcapd_header->lastSequence = 1;
	
	printRecord = flowParam->printRecord;
	while (1) {
		struct FlowNode	*Node = Pop_Node(flowParam->NodeList);
		if (Node->fin == SIGNAL_SYNC) {
			// skip
		} else if (Node->fin == SIGNAL_DONE) {
			CloseSender(flowParam, Node->timestamp);
			break;
		} else {
			ProcessFlow(flowParam, Node);
		}
		Free_Node(Node);
	}

	LogInfo("Terminating flow sending");
	dbg_printf("End flow sendthread[%lu]\n", (long unsigned)flowParam->tid);

	pthread_exit((void *)flowParam);
	/* NOTREACHED */

} // End of p_flow_thread


