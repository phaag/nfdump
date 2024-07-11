/*
 *  Copyright (c) 2022-2024, Peter Haag
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

#include "send_v9.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// #include "exporter.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "send_net.h"
#include "util.h"

#define NF9_TEMPLATE_FLOWSET_ID 0
#define NF9_MIN_RECORD_FLOWSET_ID 256

typedef struct v9Header_s {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t sequence;
    uint32_t source_id;
} v9Header_t;

typedef struct template_flowset_s {
    uint16_t flowset_id;
    uint16_t length;
    uint16_t template_id;
    uint16_t count;
    struct {
        uint16_t type;
        uint16_t length;
    } field[1];
} template_flowset_t;

typedef struct data_flowset_s {
    uint16_t flowset_id;
    uint16_t length;
    uint8_t data[4];
} data_flowset_t;

typedef struct outTemplates_s {
    struct outTemplates_s *next;
    time_t time_sent;         // time, last sent
    uint16_t template_id;     // id assigned to this template
    uint16_t needs_refresh;   // tagged for refreshing
    uint16_t numExtensions;   // number of extension in record
    uint16_t align;           // not used - memory alignment
    uint64_t elementBits;     // active element in record
    uint64_t record_count;    // number of data records sent with this template
    uint32_t data_length;     // length of the data record resulting from this template
    uint32_t flowset_length;  // length of the flowset record

    template_flowset_t *template_flowset;  // full template in network byte order for sending
} outTemplate_t;

typedef struct sender_data_s {
    struct header_s {
        v9Header_t *v9_header;    // start of v9 packet
        uint32_t record_count;    // number of records in send buffer
        uint32_t template_count;  // number of templates in send buffer
        uint32_t sequence;
    } header;

    data_flowset_t *data_flowset;  // full data template in network byte order for sending
    uint32_t data_flowset_id;      // id of current data flowset

} sender_data_t;

#define MAX_LIFETIME 60

static outTemplate_t *outTemplates = NULL;
static sender_data_t *sender_data = NULL;

// Get_valxx, a  macros
#include "inline.c"

/*
 * functions for sending netflow v9 records
 */

static outTemplate_t *GetOutputTemplate(recordHandle_t *recordHandle);

static void Append_Record(send_peer_t *peer, recordHandle_t *recordHandle);

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer);

static void CloseDataFlowset(send_peer_t *peer);

static int CheckSendBufferSpace(size_t size, send_peer_t *peer);

int Init_v9_output(send_peer_t *peer) {
    sender_data = calloc(1, sizeof(sender_data_t));
    if (!sender_data) {
        LogError("calloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }
    sender_data->header.v9_header = (v9Header_t *)peer->send_buffer;
    peer->buff_ptr = (void *)((void *)sender_data->header.v9_header + sizeof(v9Header_t));

    sender_data->header.v9_header->version = htons(9);
    sender_data->header.v9_header->SysUptime = 0;
    sender_data->header.v9_header->unix_secs = 0;
    sender_data->header.v9_header->count = 0;
    sender_data->header.v9_header->source_id = htonl(1);
    sender_data->header.record_count = 0;
    sender_data->header.template_count = 0;
    sender_data->header.sequence = 0;

    sender_data->data_flowset = NULL;
    sender_data->data_flowset_id = 0;

    return 1;

}  // End of Init_v9_output

int Close_v9_output(send_peer_t *peer) {
    if ((sender_data->header.record_count + sender_data->header.template_count) > 0) {
        dbg_printf("Close v9 output\n");
        peer->flush = 1;
        sender_data->header.sequence++;
        sender_data->header.v9_header->sequence = htonl(sender_data->header.sequence);
        sender_data->header.v9_header->count = htons(sender_data->header.record_count + sender_data->header.template_count);
        CloseDataFlowset(peer);
        dbg_printf("Prepare buffer: sequence: %u, records: %u, templates: %u\n", sender_data->header.sequence, sender_data->header.record_count,
                   sender_data->header.template_count);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 1;
    }

    return 0;

}  // End of Close_v9_output

static outTemplate_t *GetOutputTemplate(recordHandle_t *recordHandle) {
    uint32_t template_id = 0;

    uint64_t elementBits = 0;
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        if (recordHandle->extensionList[i]) elementBits |= 1 << i;
    }

    outTemplate_t **t = &outTemplates;
    // search for the template, which corresponds to our flags and extension map
    while (*t) {
        if (((*t)->elementBits == elementBits) && ((*t)->numExtensions == recordHandle->numElements)) {
            return *t;
        }
        template_id = (*t)->template_id;
        t = &((*t)->next);
    }

    dbg_printf("No output template found. Create new template\n");
    // nothing found, otherwise we would not get here
    *t = (outTemplate_t *)calloc(1, sizeof(outTemplate_t));
    if (!(*t)) {
        LogError("malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    (*t)->next = NULL;

    (*t)->elementBits = elementBits;
    (*t)->numExtensions = recordHandle->numElements;

    if (template_id == 0)
        (*t)->template_id = NF9_MIN_RECORD_FLOWSET_ID;
    else
        (*t)->template_id = template_id + 1;

    (*t)->time_sent = 0;
    (*t)->record_count = 0;

    // add flowset array - includes one potential padding
    int32_t numV9Elements = 40;  // assume, this may be enough, otherwise expand table
    (*t)->template_flowset = calloc(1, sizeof(template_flowset_t) + (numV9Elements * 4));
    if (!(*t)->template_flowset) {
        LogError("malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    template_flowset_t *flowset = (*t)->template_flowset;

    // add two default elements
    int32_t count = 0;
    flowset->field[count].type = htons(NF9_ENGINE_TYPE);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_ENGINE_ID);
    flowset->field[count].length = htons(1);
    count++;
    uint32_t data_length = 2;

    dbg_printf("Generate template for %u extensions\n", recordHandle->numElements);
    // iterate over all extensions
    uint16_t srcMaskType = 0;
    uint16_t dstMaskType = 0;
    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        if (recordHandle->extensionList[ext] == 0) continue;

        // dynmaically increase flowset table, if too little slots are left
        if ((numV9Elements - count) < 15) {
            dbg_printf("Expand flowset table\n");
            numV9Elements += 20;
            size_t newSize = sizeof(template_flowset_t) + (numV9Elements * 4);
            (*t)->template_flowset = realloc((*t)->template_flowset, newSize);
            if (!(*t)->template_flowset) {
                LogError("malloc() %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                exit(255);
            }
            // remap flowset
            flowset = (*t)->template_flowset;
        }
        added++;
        dbg_printf("Add extension: %d\n", ext);
        switch (ext) {
            case EXnull:
                LogError("Unexpected NULL extension");
                break;
            case EXgenericFlowID:
                flowset->field[count].type = htons(NF_F_FLOW_CREATE_TIME_MSEC);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF_F_FLOW_END_TIME_MSEC);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_IN_PACKETS);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_IN_BYTES);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_L4_SRC_PORT);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF9_L4_DST_PORT);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF9_ICMP);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF9_IN_PROTOCOL);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(NF9_TCP_FLAGS);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(NF9_FORWARDING_STATUS);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(NF9_SRC_TOS);
                flowset->field[count].length = htons(1);
                count++;
                data_length += 42;
                break;
            case EXipv4FlowID:
                flowset->field[count].type = htons(NF9_IPV4_SRC_ADDR);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_IPV4_DST_ADDR);
                flowset->field[count].length = htons(4);
                count++;
                data_length += 8;
                srcMaskType = NF9_SRC_MASK;
                dstMaskType = NF9_DST_MASK;
                break;
            case EXipv6FlowID:
                flowset->field[count].type = htons(NF9_IPV6_SRC_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                flowset->field[count].type = htons(NF9_IPV6_DST_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                data_length += 32;
                srcMaskType = NF9_IPV6_SRC_MASK;
                dstMaskType = NF9_IPV6_DST_MASK;
                break;
            case EXflowMiscID:
                flowset->field[count].type = htons(NF9_INPUT_SNMP);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_OUTPUT_SNMP);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(srcMaskType);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(dstMaskType);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(NF9_DIRECTION);
                flowset->field[count].length = htons(1);
                count++;
                flowset->field[count].type = htons(NF9_DST_TOS);
                flowset->field[count].length = htons(1);
                count++;
                data_length += 12;
                break;
            case EXcntFlowID:
                flowset->field[count].type = htons(NF9_FLOWS_AGGR);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_OUT_PKTS);
                flowset->field[count].length = htons(8);
                count++;
                flowset->field[count].type = htons(NF9_OUT_BYTES);
                flowset->field[count].length = htons(8);
                count++;
                data_length += 24;
                break;
            case EXvLanID:
                flowset->field[count].type = htons(NF9_SRC_VLAN);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF9_DST_VLAN);
                flowset->field[count].length = htons(2);
                count++;
                data_length += 4;
                break;
            case EXasRoutingID:
                flowset->field[count].type = htons(NF9_SRC_AS);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF9_DST_AS);
                flowset->field[count].length = htons(4);
                count++;
                data_length += 8;
                break;
            case EXbgpNextHopV4ID:
                flowset->field[count].type = htons(NF9_BGP_V4_NEXT_HOP);
                flowset->field[count].length = htons(4);
                count++;
                data_length += 4;
                break;
            case EXbgpNextHopV6ID:
                flowset->field[count].type = htons(NF9_BPG_V6_NEXT_HOP);
                flowset->field[count].length = htons(16);
                count++;
                data_length += 16;
                break;
            case EXipNextHopV4ID:
                flowset->field[count].type = htons(NF9_V4_NEXT_HOP);
                flowset->field[count].length = htons(4);
                count++;
                data_length += 4;
                break;
            case EXipNextHopV6ID:
                flowset->field[count].type = htons(NF9_V6_NEXT_HOP);
                flowset->field[count].length = htons(16);
                count++;
                data_length += 16;
                break;
            case EXmplsLabelID:
                flowset->field[count].type = htons(NF9_MPLS_LABEL_1);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_2);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_3);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_4);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_5);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_6);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_7);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_8);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_9);
                flowset->field[count].length = htons(3);
                count++;
                flowset->field[count].type = htons(NF9_MPLS_LABEL_10);
                flowset->field[count].length = htons(3);
                count++;
                data_length += 30;
                break;
            case EXmacAddrID:
                flowset->field[count].type = htons(NF9_IN_SRC_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_OUT_DST_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_IN_DST_MAC);
                flowset->field[count].length = htons(6);
                count++;
                flowset->field[count].type = htons(NF9_OUT_SRC_MAC);
                flowset->field[count].length = htons(6);
                count++;
                data_length += 24;
                break;
            case EXasAdjacentID:
                flowset->field[count].type = htons(NF_F_BGP_ADJ_NEXT_AS);
                flowset->field[count].length = htons(4);
                count++;
                flowset->field[count].type = htons(NF_F_BGP_ADJ_PREV_AS);
                flowset->field[count].length = htons(4);
                count++;
                data_length += 8;
                break;
            case EXlayer2ID:
                flowset->field[count].type = htons(NF_F_dot1qVlanId);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF_F_postDot1qVlanId);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF_F_dot1qCustomerVlanId);
                flowset->field[count].length = htons(2);
                count++;
                flowset->field[count].type = htons(NF_F_postDot1qCustomerVlanId);
                flowset->field[count].length = htons(2);
                count++;
                data_length += 8;
                break;
        }
    }

    // one potential padding field
    flowset->field[count].type = 0;
    flowset->field[count].length = 0;

    (*t)->template_flowset->flowset_id = htons(NF9_TEMPLATE_FLOWSET_ID);
    (*t)->flowset_length = 4 * (2 + count);  // + 2 for the header

    // add proper padding for 32bit boundary
    if (((*t)->flowset_length & 0x3) != 0) (*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3));
    (*t)->template_flowset->length = htons((*t)->flowset_length);

    (*t)->data_length = data_length;

    dbg_printf("Created new template with id: %u, count: %u, record length: %u\n", (*t)->template_id, count, data_length);
    flowset->template_id = htons((*t)->template_id);
    flowset->count = htons(count);

    // canity check
    if ((*t)->flowset_length > UDP_PACKET_SIZE) {
        LogError("Error: flowset length: %u > UDP packet size: %u", (*t)->flowset_length, UDP_PACKET_SIZE);
        LogError("Panic in %s line %d", __FILE__, __LINE__);
        exit(255);
    }
    return *t;

}  // End of GetOutputTemplate

static void Append_Record(send_peer_t *peer, recordHandle_t *recordHandle) {
    uint8_t *p = (uint8_t *)peer->buff_ptr;
    *p++ = recordHandle->recordHeaderV3->engineType;
    *p++ = recordHandle->recordHeaderV3->engineID;
    peer->buff_ptr = (void *)p;

    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        void *elementPtr = recordHandle->extensionList[ext];
        if (elementPtr == NULL) continue;
        added++;
        switch (ext) {
            case EXgenericFlowID: {
                EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)elementPtr;
                Put_val64(htonll(genericFlow->msecFirst), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(genericFlow->msecLast), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(genericFlow->inPackets), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(genericFlow->inBytes), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val16(htons(genericFlow->srcPort), peer->buff_ptr);
                peer->buff_ptr += 2;
                if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {
                    Put_val16(0, peer->buff_ptr);
                    peer->buff_ptr += 2;
                    Put_val16(htons(genericFlow->dstPort), peer->buff_ptr);
                    peer->buff_ptr += 2;
                } else {
                    Put_val16(htons(genericFlow->dstPort), peer->buff_ptr);
                    peer->buff_ptr += 2;
                    Put_val16(0, peer->buff_ptr);
                    peer->buff_ptr += 2;
                }
                Put_val8(genericFlow->proto, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(genericFlow->tcpFlags, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(genericFlow->fwdStatus, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(genericFlow->srcTos, peer->buff_ptr);
                peer->buff_ptr += 1;
            } break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)elementPtr;
                Put_val32(htonl(ipv4Flow->srcAddr), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(ipv4Flow->dstAddr), peer->buff_ptr);
                peer->buff_ptr += 4;
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)elementPtr;
                Put_val64(htonll(ipv6Flow->srcAddr[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->srcAddr[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->dstAddr[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->dstAddr[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
            } break;
            case EXflowMiscID: {
                EXflowMisc_t *flowMisc = (EXflowMisc_t *)elementPtr;
                Put_val32(htonl(flowMisc->input), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(flowMisc->output), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val8(flowMisc->srcMask, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(flowMisc->dstMask, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(flowMisc->dir, peer->buff_ptr);
                peer->buff_ptr += 1;
                Put_val8(flowMisc->dstTos, peer->buff_ptr);
                peer->buff_ptr += 1;
            } break;
            case EXcntFlowID: {
                EXcntFlow_t *cntFlow = (EXcntFlow_t *)elementPtr;
                Put_val64(htonll(cntFlow->flows), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(cntFlow->outPackets), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(cntFlow->outBytes), peer->buff_ptr);
                peer->buff_ptr += 8;
            } break;
            case EXvLanID: {
                EXvLan_t *vLan = (EXvLan_t *)elementPtr;
                Put_val16(htons(vLan->srcVlan), peer->buff_ptr);
                peer->buff_ptr += 2;
                Put_val16(htons(vLan->dstVlan), peer->buff_ptr);
                peer->buff_ptr += 2;
            } break;
            case EXlayer2ID: {
                EXlayer2_t *dot1q = (EXlayer2_t *)elementPtr;
                Put_val16(htons(dot1q->vlanID), peer->buff_ptr);
                peer->buff_ptr += 2;
                Put_val16(htons(dot1q->postVlanID), peer->buff_ptr);
                peer->buff_ptr += 2;
                Put_val16(htons(dot1q->customerVlanId), peer->buff_ptr);
                peer->buff_ptr += 2;
                Put_val16(htons(dot1q->postCustomerVlanId), peer->buff_ptr);
                peer->buff_ptr += 2;
            } break;
            case EXasRoutingID: {
                EXasRouting_t *asRouting = (EXasRouting_t *)elementPtr;
                Put_val32(htonl(asRouting->srcAS), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(asRouting->dstAS), peer->buff_ptr);
                peer->buff_ptr += 4;
            } break;
            case EXbgpNextHopV4ID: {
                EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)elementPtr;
                Put_val32(htonl(bgpNextHopV4->ip), peer->buff_ptr);
                peer->buff_ptr += 4;
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)elementPtr;
                Put_val64(htonll(bgpNextHopV6->ip[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(bgpNextHopV6->ip[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)elementPtr;
                Put_val32(htonl(ipNextHopV4->ip), peer->buff_ptr);
                peer->buff_ptr += 4;
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)elementPtr;
                Put_val64(htonll(ipNextHopV6->ip[0]), peer->buff_ptr);
                peer->buff_ptr += 8;
                Put_val64(htonll(ipNextHopV6->ip[1]), peer->buff_ptr);
                peer->buff_ptr += 8;
            } break;
            case EXmplsLabelID: {
                EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)elementPtr;
                for (int i = 0; i < 10; i++) {
                    uint32_t val32 = htonl(mplsLabel->mplsLabel[i]);
                    Put_val24(val32, peer->buff_ptr);
                    peer->buff_ptr += 3;
                }
            } break;
            case EXmacAddrID: {
                EXmacAddr_t *macAddr = (EXmacAddr_t *)elementPtr;
                uint64_t val64 = htonll(macAddr->inSrcMac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(macAddr->outDstMac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(macAddr->inDstMac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;

                val64 = htonll(macAddr->outSrcMac);
                Put_val48(val64, peer->buff_ptr);
                peer->buff_ptr += 6;
            } break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)elementPtr;
                Put_val32(htonl(asAdjacent->nextAdjacentAS), peer->buff_ptr);
                peer->buff_ptr += 4;
                Put_val32(htonl(asAdjacent->prevAdjacentAS), peer->buff_ptr);
                peer->buff_ptr += 4;
            } break;
        }
    }

    sender_data->header.record_count++;

}  // End of Append_Record

static int Add_template_flowset(outTemplate_t *outTemplate, send_peer_t *peer) {
    dbg_printf("Add template %u, bytes: %u\n", outTemplate->template_id, outTemplate->flowset_length);
    memcpy(peer->buff_ptr, (void *)outTemplate->template_flowset, outTemplate->flowset_length);
    peer->buff_ptr = (void *)((pointer_addr_t)peer->buff_ptr + outTemplate->flowset_length);

    sender_data->header.template_count++;

    return 1;
}  // End of Add_template_flowset

static void CloseDataFlowset(send_peer_t *peer) {
    if (sender_data->data_flowset) {
        uint32_t length = (void *)peer->buff_ptr - (void *)sender_data->data_flowset;
        uint32_t align = length & 0x3;
        if (align != 0) {
            length += (4 - align);
            // fill padding with 0
            for (int i = 0; i < align; i++) {
                *((char *)peer->buff_ptr) = '\0';
                peer->buff_ptr++;
            }
        }
        sender_data->data_flowset->length = htons(length);
        sender_data->data_flowset = NULL;
        sender_data->data_flowset_id = 0;
        dbg_printf("Close flowset: Length: %u, align: %u\n", length, align);
    }
}  // End of CloseDataFlowset

static int CheckSendBufferSpace(size_t size, send_peer_t *peer) {
    dbg_printf("CheckSendBufferSpace for %lu bytes: ", size);
    if ((peer->buff_ptr + size) > peer->endp) {
        // request buffer flush
        dbg_printf("Check for %zu bytes in send buffer. Flush first.\n", size);
        peer->flush = 1;
        sender_data->header.sequence++;
        sender_data->header.v9_header->sequence = htonl(sender_data->header.sequence);
        sender_data->header.v9_header->count = htons(sender_data->header.record_count + sender_data->header.template_count);
        CloseDataFlowset(peer);
        dbg_printf("Prepare buffer: sequence: %u, records: %u, templates: %u\n", sender_data->header.sequence, sender_data->header.record_count,
                   sender_data->header.template_count);
        sender_data->header.record_count = 0;
        sender_data->header.template_count = 0;
        return 0;
    }
    dbg_printf("ok.\n");

    return 1;

}  // End of CheckBufferSpace

int Add_v9_output_record(recordHandle_t *recordHandle, send_peer_t *peer) {
    dbg_printf("\nNext packet\n");
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    if (recordHandle->numElements == 0 || !genericFlow) {
        dbg_printf("Skip record with 0 extensions\n");
        return 0;
    }

    if (!sender_data->header.v9_header->unix_secs) {  // first time a record is added
        dbg_printf("First time setup\n");
        // boot time is set one day back - assuming that the start time of every flow does not start
        // earlier
        uint64_t boot_time = genericFlow->msecFirst - 86400LL * 1000LL;
        uint32_t unix_secs = boot_time / 1000LL;
        sender_data->header.v9_header->unix_secs = htonl(unix_secs);
    }

    // check, if Buffer was flushed
    if (peer->buff_ptr == peer->send_buffer) {
        peer->buff_ptr = (void *)((void *)sender_data->header.v9_header + sizeof(v9Header_t));
    }

    time_t now = time(NULL);
    outTemplate_t *template = GetOutputTemplate(recordHandle);
    if ((sender_data->data_flowset_id != template->template_id) || template->needs_refresh) {
        // Different flowset ID - End data flowset and open new data flowset
        CloseDataFlowset(peer);

        if (!CheckSendBufferSpace(template->data_length + sizeof(data_flowset_t) + template->flowset_length, peer)) {
            // request buffer flush first
            dbg_printf("Flush Buffer #1\n");
            return 1;
        }

        // if never sent or needs refresh
        if (template->record_count == 0 || template->needs_refresh) {
            Add_template_flowset(template, peer);
            template->time_sent = now;
        }

        // Add data flowset
        dbg_printf("Add new data flowset\n");
        sender_data->data_flowset = peer->buff_ptr;
        sender_data->data_flowset->flowset_id = template->template_flowset->template_id;
        sender_data->data_flowset_id = template->template_id;
        peer->buff_ptr = (void *)sender_data->data_flowset->data;
    }

    // same data flowset ID - add Record
    if (!CheckSendBufferSpace(template->data_length, peer)) {
        // request buffer flush first
        dbg_printf("Flush Buffer #2\n");
        return 1;
    }

    dbg_printf("Add record %u, bytes: %u\n", template->template_id, template->data_length);
    Append_Record(peer, recordHandle);

    // template record counter
    template->record_count++;

    // need refresh?
    if (((template->record_count & 0xFFF) == 0) || (now - template->time_sent > MAX_LIFETIME)) {
        template->needs_refresh = 1;
        dbg_printf("Schedule template refresh\n");
    }

    dbg_printf("Done Add_v9_output_record\n\n");

    return 0;
}  // End of Add_v9_output_record
