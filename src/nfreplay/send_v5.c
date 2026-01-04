/*
 *  Copyright (c) 2022-2025, Peter Haag
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

#include "send_v5.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "exporter.h"
#include "nfxV3.h"

/* v5 structures */
typedef struct netflow_v5_header {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint16_t engine_tag;
    uint16_t sampling_interval;
} netflow_v5_header_t;

typedef struct netflow_v5_record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
} netflow_v5_record_t;

#define NETFLOW_V5_HEADER_LENGTH 24
#define NETFLOW_V5_RECORD_LENGTH 48
#define NETFLOW_V5_MAX_RECORDS 30

// for sending netflow v5
static netflow_v5_header_t *v5_output_header;
static netflow_v5_record_t *v5_output_record;
static exporter_entry_t output_engine = {0};

/*
 * functions used for sending netflow v5 records
 */
void Init_v5_v7_output(send_peer_t *peer) {
    assert(sizeof(netflow_v5_header_t) == NETFLOW_V5_HEADER_LENGTH);
    assert(sizeof(netflow_v5_record_t) == NETFLOW_V5_RECORD_LENGTH);

    v5_output_header = (netflow_v5_header_t *)peer->send_buffer;
    v5_output_header->version = htons(5);
    v5_output_header->SysUptime = 0;
    v5_output_header->unix_secs = 0;
    v5_output_header->unix_nsecs = 0;
    v5_output_header->count = 0;

    output_engine = (exporter_entry_t){.sequence = UINT32_MAX};
    output_engine.version.v5 = (exporter_v5_t){0};

    v5_output_record = (netflow_v5_record_t *)((void *)v5_output_header + NETFLOW_V5_HEADER_LENGTH);

}  // End of Init_v5_v7_output

int Add_v5_output_record(recordHandle_t *recordHandle, send_peer_t *peer) {
    static uint64_t msecBoot = 0;  // in msec
    static int cnt = 0;
    uint32_t t1, t2;

    // Skip IPv6 records
    if (recordHandle->extensionList[EXipv6FlowID]) return 0;

    // skip empty records and records without enough information for v5
    if (recordHandle->extensionList[EXgenericFlowID] == NULL || recordHandle->extensionList[EXipv4FlowID] == NULL) {
        printf("Skip record\n");
        return 0;
    }

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];

    // set device boot time to 1 day back of tstart of first flow
    if (output_engine.sequence == UINT32_MAX) {  // first time a record is added
        // boot time is set one day back - assuming that the start time of every flow does not start
        // earlier
        msecBoot = ((genericFlow->msecFirst / 1000LL) - 86400LL) * 1000LL;
        cnt = 0;
        output_engine.sequence = 0;
    }

    if (cnt == 0) {
        v5_output_record = (netflow_v5_record_t *)(peer->send_buffer + NETFLOW_V5_HEADER_LENGTH);
        peer->buff_ptr = (void *)v5_output_record;
        memset(peer->buff_ptr, 0, NETFLOW_V5_MAX_RECORDS * NETFLOW_V5_RECORD_LENGTH);

        output_engine.sequence += output_engine.version.v5.last_count;
        v5_output_header->flow_sequence = htonl(output_engine.sequence);

        uint32_t unix_secs = (genericFlow->msecLast / 1000LL) + 3600;
        v5_output_header->unix_secs = htonl(unix_secs);
        v5_output_header->SysUptime = htonl((uint32_t)(unix_secs * 1000 - msecBoot));
    }

    // EXgenericFlowID
    t1 = (uint32_t)(genericFlow->msecFirst - msecBoot);
    t2 = (uint32_t)(genericFlow->msecLast - msecBoot);
    v5_output_record->First = htonl(t1);
    v5_output_record->Last = htonl(t2);

    v5_output_record->srcPort = htons(genericFlow->srcPort);
    v5_output_record->dstPort = htons(genericFlow->dstPort);
    v5_output_record->tcp_flags = genericFlow->tcpFlags;
    v5_output_record->prot = genericFlow->proto;
    v5_output_record->tos = genericFlow->srcTos;

    // the 64bit counters are cut down to 32 bits for v5
    v5_output_record->dPkts = htonl((uint32_t)genericFlow->inPackets);
    v5_output_record->dOctets = htonl((uint32_t)genericFlow->inBytes);

    // EXipv4FlowID
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    v5_output_record->srcaddr = htonl(ipv4Flow->srcAddr);
    v5_output_record->dstaddr = htonl(ipv4Flow->dstAddr);

    // EXflowMiscID
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)recordHandle->extensionList[EXflowMiscID];
    if (flowMisc) {
        v5_output_record->input = htons(flowMisc->input);
        v5_output_record->output = htons(flowMisc->output);
        v5_output_record->src_mask = flowMisc->srcMask;
        v5_output_record->dst_mask = flowMisc->dstMask;
    }

    // EXasRoutingID
    EXasRouting_t *asRouting = (EXasRouting_t *)recordHandle->extensionList[EXasRoutingID];
    if (asRouting) {
        v5_output_record->src_as = htons(asRouting->srcAS);
        v5_output_record->dst_as = htons(asRouting->dstAS);
    }

    // EXipNextHopV4ID
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)recordHandle->extensionList[EXipNextHopV4ID];
    if (ipNextHopV4) {
        v5_output_record->nexthop = htonl(ipNextHopV4->ip);
    }

    cnt++;

    v5_output_header->count = htons(cnt);
    peer->buff_ptr = (void *)(peer->buff_ptr + NETFLOW_V5_RECORD_LENGTH);
    v5_output_record++;
    if (cnt == NETFLOW_V5_MAX_RECORDS) {
        peer->flush = 1;
        output_engine.version.v5.last_count = cnt;
        cnt = 0;
    }

    return 0;

}  // End of Add_v5_output_record
