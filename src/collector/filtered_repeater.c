/*
 *  Copyright (c) 2026, Peter Haag, Murilo Chianfa
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

#include "filtered_repeater.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "filter/filter.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "privsep.h"
#include "repeater.h"
#include "util.h"

// Include inline helper functions for Put_val* macros
#include "inline.c"

/* ============================================================================
 * NetFlow v5 structures and constants
 * ============================================================================ */
typedef struct netflow_v5_header_s {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint16_t engine_tag;
    uint16_t sampling_interval;
} netflow_v5_header_t;

typedef struct netflow_v5_record_s {
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

/* ============================================================================
 * NetFlow v9 structures and constants
 * ============================================================================ */

typedef struct netflow_v9_header_s {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t sequence;
    uint32_t source_id;
} netflow_v9_header_t;

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

#define NETFLOW_V9_HEADER_LENGTH sizeof(netflow_v9_header_t)
#define NF9_TEMPLATE_FLOWSET_ID 0
#define NF9_MIN_RECORD_FLOWSET_ID 256
#define MAX_TEMPLATE_LIFETIME 60    // Resend templates every 60 seconds
#define MAX_TEMPLATE_RECORDS 4096   // Resend templates every 4096 records

/* V9/IPFIX field type definitions */
#define NF_F_FLOW_CREATE_TIME_MSEC 152
#define NF_F_FLOW_END_TIME_MSEC 153
#define NF9_IN_BYTES 1
#define NF9_IN_PACKETS 2
#define NF9_FLOWS_AGGR 3
#define NF9_IN_PROTOCOL 4
#define NF9_SRC_TOS 5
#define NF9_TCP_FLAGS 6
#define NF9_L4_SRC_PORT 7
#define NF9_IPV4_SRC_ADDR 8
#define NF9_SRC_MASK 9
#define NF9_INPUT_SNMP 10
#define NF9_L4_DST_PORT 11
#define NF9_IPV4_DST_ADDR 12
#define NF9_DST_MASK 13
#define NF9_OUTPUT_SNMP 14
#define NF9_V4_NEXT_HOP 15
#define NF9_SRC_AS 16
#define NF9_DST_AS 17
#define NF9_BGP_V4_NEXT_HOP 18
#define NF9_LAST_SWITCHED 21
#define NF9_FIRST_SWITCHED 22
#define NF9_OUT_BYTES 23
#define NF9_OUT_PKTS 24
#define NF9_IPV6_SRC_ADDR 27
#define NF9_IPV6_DST_ADDR 28
#define NF9_IPV6_SRC_MASK 29
#define NF9_IPV6_DST_MASK 30
#define NF9_ICMP 32
#define NF9_ENGINE_TYPE 38
#define NF9_ENGINE_ID 39
#define NF9_DST_TOS 55
#define NF9_IN_SRC_MAC 56
#define NF9_OUT_DST_MAC 57
#define NF9_SRC_VLAN 58
#define NF9_DST_VLAN 59
#define NF_9_IP_PROTOCOL_VERSION 60
#define NF9_DIRECTION 61
#define NF9_V6_NEXT_HOP 62
#define NF9_BPG_V6_NEXT_HOP 63
#define NF9_MPLS_LABEL_1 70
#define NF9_MPLS_LABEL_2 71
#define NF9_MPLS_LABEL_3 72
#define NF9_MPLS_LABEL_4 73
#define NF9_MPLS_LABEL_5 74
#define NF9_MPLS_LABEL_6 75
#define NF9_MPLS_LABEL_7 76
#define NF9_MPLS_LABEL_8 77
#define NF9_MPLS_LABEL_9 78
#define NF9_MPLS_LABEL_10 79
#define NF9_IN_DST_MAC 80
#define NF9_OUT_SRC_MAC 81
#define NF9_FORWARDING_STATUS 89
#define NF_F_BGP_ADJ_NEXT_AS 128
#define NF_F_BGP_ADJ_PREV_AS 129
#define NF_F_dot1qVlanId 243
#define NF_F_postDot1qVlanId 254
#define NF_F_dot1qCustomerVlanId 245
#define NF_F_postDot1qCustomerVlanId 255

/* ============================================================================
 * IPFIX structures and constants
 * ============================================================================ */

typedef struct ipfix_header_s {
    uint16_t version;           // Set to 10 for IPFIX
    uint16_t length;            // Total length including header
    uint32_t export_time;       // UNIX epoch export time
    uint32_t sequence;          // Sequence counter (data records only)
    uint32_t observation_domain;
} ipfix_header_t;

#define IPFIX_HEADER_LENGTH sizeof(ipfix_header_t)
#define IPFIX_TEMPLATE_FLOWSET_ID 2
#define IPFIX_MIN_RECORD_FLOWSET_ID 256

/* ============================================================================
 * Output template structure for V9/IPFIX
 * ============================================================================ */

typedef struct outTemplate_s {
    struct outTemplate_s *next;
    time_t time_sent;           // Time last sent
    uint16_t template_id;       // ID assigned to this template
    uint16_t needs_refresh;     // Tagged for refreshing
    uint16_t numExtensions;     // Number of extensions in record
    uint16_t align;             // Memory alignment padding
    uint64_t elementBits;       // Active elements in record
    uint64_t record_count;      // Number of data records sent with this template
    uint32_t data_length;       // Length of data record from this template
    uint32_t flowset_length;    // Length of flowset record
    template_flowset_t *template_flowset;  // Template in network byte order
} outTemplate_t;

/* ============================================================================
 * Unified encoder state structure (supports V5, V9, and IPFIX)
 * ============================================================================ */

typedef struct encoder_state_s {
    uint64_t msecBoot;          // Device boot time in msec
    uint32_t sequence;          // Flow/packet sequence number
    int record_count;           // Current record count in buffer
    int initialized;            // Whether msecBoot has been set
    // V9/IPFIX specific fields
    outTemplate_t *templates;   // Linked list of templates
    data_flowset_t *data_flowset;  // Current data flowset pointer
    uint32_t data_flowset_id;   // Current data flowset template ID
    uint32_t template_count;    // Number of templates in current buffer
    time_t last_template_time;  // When templates were last sent
} encoder_state_t;

/* Static array of encoder states (one per repeater) */
static encoder_state_t encoder_state[MAX_REPEATERS];

// Forward declarations
static int EncodeRecordV5(repeater_t *rep, recordHandle_t *handle);
static int EncodeRecordV9(repeater_t *rep, recordHandle_t *handle);
static int EncodeRecordIPFIX(repeater_t *rep, recordHandle_t *handle);
static void FlushRepeaterBufferV5(repeater_t *rep, int rfd);
static void FlushRepeaterBufferV9(repeater_t *rep, int rfd);
static void FlushRepeaterBufferIPFIX(repeater_t *rep, int rfd);
static int SendFilteredMessage(int rfd, int repeater_index, void *buffer, size_t len);

// V9/IPFIX helper functions
static outTemplate_t *GetOutputTemplate(encoder_state_t *state, recordHandle_t *recordHandle);
static void AppendRecordV9(repeater_t *rep, encoder_state_t *state, recordHandle_t *recordHandle);
static int AddTemplateFlowset(repeater_t *rep, encoder_state_t *state, outTemplate_t *outTemplate);
static void CloseDataFlowset(repeater_t *rep, encoder_state_t *state);
static int CheckBufferSpace(repeater_t *rep, size_t size);
static void FreeTemplates(outTemplate_t *templates);

// Map record handle (inline version for this module)
static int MapRecordHandleLocal(recordHandle_t *handle, recordHeaderV3_t *recordHeaderV3) {
    memset((void *)handle, 0, sizeof(recordHandle_t));
    handle->recordHeaderV3 = recordHeaderV3;

    void *eor = (void *)recordHeaderV3 + recordHeaderV3->size;
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeaderV3 + sizeof(recordHeaderV3_t));

    int num = 0;
    while (num < recordHeaderV3->numElements) {
        if ((void *)elementHeader > eor) {
            return 0;
        }
        if (elementHeader->length == 0) {
            return 0;
        }
        if (elementHeader->type == 0) {
            elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
            continue;
        }
        if (elementHeader->type < MAXEXTENSIONS) {
            handle->extensionList[elementHeader->type] = (void *)elementHeader + sizeof(elementHeader_t);
        }
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);
        num++;
    }
    handle->extensionList[EXheader] = (void *)recordHeaderV3;
    handle->extensionList[EXlocal] = (void *)handle;
    handle->numElements = recordHeaderV3->numElements;

    return 1;
}

int HasFilteredRepeaters(repeater_t *repeater) {
    if (!repeater) return 0;

    for (int i = 0; i < MAX_REPEATERS && repeater[i].hostname; i++) {
        if (repeater[i].filter != NULL) {
            return 1;
        }
    }
    return 0;
}

int InitFilteredRepeaters(repeater_t *repeater, int rfd) {
    if (!repeater) return -1;

    memset(encoder_state, 0, sizeof(encoder_state));

    for (int i = 0; i < MAX_REPEATERS && repeater[i].hostname; i++) {
        if (repeater[i].filter != NULL) {
            // Compile the filter
            repeater[i].filterEngine = CompileFilter(repeater[i].filter);
            if (!repeater[i].filterEngine) {
                LogError("Failed to compile filter for repeater %s: '%s'",
                         repeater[i].hostname, repeater[i].filter);
                return -1;
            }
            LogInfo("Compiled filter for repeater %s: '%s'",
                    repeater[i].hostname, repeater[i].filter);

            // Allocate send buffer
            repeater[i].send_buffer = calloc(1, FILTERED_SEND_BUFFER_SIZE);
            if (!repeater[i].send_buffer) {
                LogError("Failed to allocate send buffer for repeater %s: %s",
                         repeater[i].hostname, strerror(errno));
                DisposeFilter(repeater[i].filterEngine);
                repeater[i].filterEngine = NULL;
                return -1;
            }

            // Set default netflow version if not specified
            if (repeater[i].netflow_version == 0) {
                repeater[i].netflow_version = 5;  // Default to v5
            }

            // Initialize header based on netflow version
            switch (repeater[i].netflow_version) {
                case 5: {
                    netflow_v5_header_t *header = (netflow_v5_header_t *)repeater[i].send_buffer;
                    header->version = htons(5);
                    header->count = 0;
                    header->SysUptime = 0;
                    header->unix_secs = 0;
                    header->unix_nsecs = 0;
                    header->flow_sequence = 0;
                    header->engine_tag = 0;
                    header->sampling_interval = 0;
                    repeater[i].buff_ptr = repeater[i].send_buffer + NETFLOW_V5_HEADER_LENGTH;
                    LogInfo("Initialized V5 encoder for repeater %s", repeater[i].hostname);
                } break;

                case 9: {
                    netflow_v9_header_t *header = (netflow_v9_header_t *)repeater[i].send_buffer;
                    header->version = htons(9);
                    header->count = 0;
                    header->SysUptime = 0;
                    header->unix_secs = 0;
                    header->sequence = 0;
                    header->source_id = htonl(1);
                    repeater[i].buff_ptr = repeater[i].send_buffer + NETFLOW_V9_HEADER_LENGTH;
                    LogInfo("Initialized V9 encoder for repeater %s", repeater[i].hostname);
                } break;

                case 10: {  // IPFIX
                    ipfix_header_t *header = (ipfix_header_t *)repeater[i].send_buffer;
                    header->version = htons(10);
                    header->length = 0;
                    header->export_time = 0;
                    header->sequence = 0;
                    header->observation_domain = htonl(1);
                    repeater[i].buff_ptr = repeater[i].send_buffer + IPFIX_HEADER_LENGTH;
                    LogInfo("Initialized IPFIX encoder for repeater %s", repeater[i].hostname);
                } break;

                default:
                    LogError("Unsupported netflow version %d for repeater %s",
                             repeater[i].netflow_version, repeater[i].hostname);
                    free(repeater[i].send_buffer);
                    repeater[i].send_buffer = NULL;
                    DisposeFilter(repeater[i].filterEngine);
                    repeater[i].filterEngine = NULL;
                    return -1;
            }

            repeater[i].flush = 0;

            dbg_printf("Initialized filtered repeater %d: %s:%s filter='%s' version=%d\n",
                       i, repeater[i].hostname, repeater[i].port, repeater[i].filter,
                       repeater[i].netflow_version);
        }
    }

    return 0;
}

void CleanupFilteredRepeaters(repeater_t *repeater) {
    if (!repeater) return;

    for (int i = 0; i < MAX_REPEATERS && repeater[i].hostname; i++) {
        if (repeater[i].filterEngine) {
            DisposeFilter(repeater[i].filterEngine);
            repeater[i].filterEngine = NULL;
        }
        if (repeater[i].send_buffer) {
            free(repeater[i].send_buffer);
            repeater[i].send_buffer = NULL;
        }
        if (repeater[i].filter) {
            free(repeater[i].filter);
            repeater[i].filter = NULL;
        }
        // Free V9/IPFIX templates
        if (encoder_state[i].templates) {
            FreeTemplates(encoder_state[i].templates);
            encoder_state[i].templates = NULL;
        }
    }
    // Clear all encoder states
    memset(encoder_state, 0, sizeof(encoder_state));
}

int ProcessFilteredRecord(repeater_t *repeater, int rfd, recordHeaderV3_t *recordHeaderV3) {
    if (!repeater || !recordHeaderV3) return 0;

    int sent_count = 0;
    recordHandle_t handle;

    // Map the record once
    if (!MapRecordHandleLocal(&handle, recordHeaderV3)) {
        dbg_printf("Failed to map record handle\n");
        return 0;
    }

    // Process each filtered repeater
    for (int i = 0; i < MAX_REPEATERS && repeater[i].hostname; i++) {
        if (!repeater[i].filterEngine) continue;

        // Apply filter
        if (FilterRecord(repeater[i].filterEngine, &handle)) {
            // Record matches filter - encode and add to buffer
            dbg_printf("Record matches filter for repeater %d (version %d)\n",
                       i, repeater[i].netflow_version);

            int result = 0;
            switch (repeater[i].netflow_version) {
                case 5:
                    result = EncodeRecordV5(&repeater[i], &handle);
                    break;
                case 9:
                    result = EncodeRecordV9(&repeater[i], &handle);
                    break;
                case 10:  // IPFIX
                    result = EncodeRecordIPFIX(&repeater[i], &handle);
                    break;
                default:
                    dbg_printf("Unsupported netflow version %d\n", repeater[i].netflow_version);
                    result = 0;
                    break;
            }

            if (result > 0) {
                sent_count++;
            }

            // Check if buffer needs flushing
            if (repeater[i].flush) {
                switch (repeater[i].netflow_version) {
                    case 5:
                        FlushRepeaterBufferV5(&repeater[i], rfd);
                        break;
                    case 9:
                        FlushRepeaterBufferV9(&repeater[i], rfd);
                        break;
                    case 10:  // IPFIX
                        FlushRepeaterBufferIPFIX(&repeater[i], rfd);
                        break;
                }
                repeater[i].flush = 0;
            }
        }
    }

    return sent_count;
}

void FlushFilteredRepeaters(repeater_t *repeater, int rfd) {
    if (!repeater) return;

    for (int i = 0; i < MAX_REPEATERS && repeater[i].hostname; i++) {
        if (repeater[i].filterEngine && encoder_state[i].record_count > 0) {
            // Flush any buffered records immediately
            switch (repeater[i].netflow_version) {
                case 5:
                    FlushRepeaterBufferV5(&repeater[i], rfd);
                    break;
                case 9:
                    FlushRepeaterBufferV9(&repeater[i], rfd);
                    break;
                case 10:  // IPFIX
                    FlushRepeaterBufferIPFIX(&repeater[i], rfd);
                    break;
            }
        }
    }
}

static int EncodeRecordV5(repeater_t *rep, recordHandle_t *handle) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    // Skip IPv6 records, v5 doesn't support IPv6 :(
    if (handle->extensionList[EXipv6FlowID]) {
        dbg_printf("Skipping IPv6 record for v5 encoding\n");
        return 0;
    }

    // Check for required extensions
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)handle->extensionList[EXipv4FlowID];

    if (!genericFlow || !ipv4Flow) {
        dbg_printf("Missing required extensions for v5 encoding\n");
        return 0;
    }

    // Initialize boot time on first record
    if (!state->initialized) {
        state->msecBoot = ((genericFlow->msecFirst / 1000LL) - 86400LL) * 1000LL;
        state->sequence = 0;
        state->record_count = 0;
        state->initialized = 1;
    }

    // Start new packet if count is 0
    if (state->record_count == 0) {
        netflow_v5_header_t *header = (netflow_v5_header_t *)rep->send_buffer;

        // Set sequence to current count (will be updated when packet is flushed)
        header->flow_sequence = htonl(state->sequence);

        uint32_t unix_secs = (uint32_t)(genericFlow->msecLast / 1000LL);
        header->unix_secs = htonl(unix_secs);
        header->SysUptime = htonl((uint32_t)(unix_secs * 1000 - state->msecBoot));

        rep->buff_ptr = rep->send_buffer + NETFLOW_V5_HEADER_LENGTH;
        memset(rep->buff_ptr, 0, NETFLOW_V5_MAX_RECORDS * NETFLOW_V5_RECORD_LENGTH);
    }

    // Encode the record
    netflow_v5_record_t *v5_record = (netflow_v5_record_t *)rep->buff_ptr;

    // Timestamps
    uint32_t t1 = (uint32_t)(genericFlow->msecFirst - state->msecBoot);
    uint32_t t2 = (uint32_t)(genericFlow->msecLast - state->msecBoot);
    v5_record->First = htonl(t1);
    v5_record->Last = htonl(t2);

    // Ports and protocol
    v5_record->srcPort = htons(genericFlow->srcPort);
    v5_record->dstPort = htons(genericFlow->dstPort);
    v5_record->tcp_flags = genericFlow->tcpFlags;
    v5_record->prot = genericFlow->proto;
    v5_record->tos = genericFlow->srcTos;

    // Counters (truncate 64-bit to 32-bit for v5, obs.: that's bad)
    v5_record->dPkts = htonl((uint32_t)genericFlow->inPackets);
    v5_record->dOctets = htonl((uint32_t)genericFlow->inBytes);

    // IP addresses
    v5_record->srcaddr = htonl(ipv4Flow->srcAddr);
    v5_record->dstaddr = htonl(ipv4Flow->dstAddr);

    // Interface info
    EXflowMisc_t *flowMisc = (EXflowMisc_t *)handle->extensionList[EXflowMiscID];
    if (flowMisc) {
        v5_record->input = htons(flowMisc->input);
        v5_record->output = htons(flowMisc->output);
        v5_record->src_mask = flowMisc->srcMask;
        v5_record->dst_mask = flowMisc->dstMask;
    }

    // AS routing info
    EXasRouting_t *asRouting = (EXasRouting_t *)handle->extensionList[EXasRoutingID];
    if (asRouting) {
        v5_record->src_as = htons((uint16_t)asRouting->srcAS);
        v5_record->dst_as = htons((uint16_t)asRouting->dstAS);
    }

    // Next hop
    EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)handle->extensionList[EXipNextHopV4ID];
    if (ipNextHopV4) {
        v5_record->nexthop = htonl(ipNextHopV4->ip);
    }

    // Update state
    state->record_count++;
    rep->buff_ptr = (void *)rep->buff_ptr + NETFLOW_V5_RECORD_LENGTH;

    // Update header count
    netflow_v5_header_t *header = (netflow_v5_header_t *)rep->send_buffer;
    header->count = htons(state->record_count);

    // Check if buffer is full
    if (state->record_count >= NETFLOW_V5_MAX_RECORDS) {
        rep->flush = 1;
    }

    return 1;
}

static void FlushRepeaterBufferV5(repeater_t *rep, int rfd) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    if (state->record_count == 0) return;

    // Calculate packet size
    size_t packet_size = NETFLOW_V5_HEADER_LENGTH + (state->record_count * NETFLOW_V5_RECORD_LENGTH);

    dbg_printf("Flushing V5 repeater %d: %d records, %zu bytes, sequence %u\n",
               idx, state->record_count, packet_size, state->sequence);

    // Send via privsep
    if (SendFilteredMessage(rfd, idx, rep->send_buffer, packet_size) < 0) {
        LogError("Failed to send filtered V5 packet to repeater %s", rep->hostname);
    }

    // Update sequence number for next packet (increment by actual record count)
    state->sequence += state->record_count;

    // Reset state for next packet
    state->record_count = 0;
    rep->buff_ptr = rep->send_buffer + NETFLOW_V5_HEADER_LENGTH;
}

static void FlushRepeaterBufferV9(repeater_t *rep, int rfd) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    if ((state->record_count + state->template_count) == 0) return;

    // Close any open data flowset
    CloseDataFlowset(rep, state);

    // Update V9 header
    netflow_v9_header_t *header = (netflow_v9_header_t *)rep->send_buffer;
    state->sequence++;
    header->sequence = htonl(state->sequence);
    header->count = htons(state->record_count + state->template_count);

    // Update timestamps
    time_t now = time(NULL);
    header->unix_secs = htonl((uint32_t)now);
    header->SysUptime = htonl((uint32_t)((now * 1000) - state->msecBoot));

    // Calculate packet size
    size_t packet_size = (void *)rep->buff_ptr - rep->send_buffer;

    dbg_printf("Flushing V9 repeater %d: %d records, %u templates, %zu bytes, sequence %u\n",
               idx, state->record_count, state->template_count, packet_size, state->sequence);

    // Send via privsep
    if (SendFilteredMessage(rfd, idx, rep->send_buffer, packet_size) < 0) {
        LogError("Failed to send filtered V9 packet to repeater %s", rep->hostname);
    }

    // Reset state for next packet
    state->record_count = 0;
    state->template_count = 0;
    state->data_flowset = NULL;
    state->data_flowset_id = 0;
    rep->buff_ptr = rep->send_buffer + NETFLOW_V9_HEADER_LENGTH;
}

static void FlushRepeaterBufferIPFIX(repeater_t *rep, int rfd) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    if ((state->record_count + state->template_count) == 0) return;

    // Close any open data flowset
    CloseDataFlowset(rep, state);

    // Update IPFIX header
    ipfix_header_t *header = (ipfix_header_t *)rep->send_buffer;
    
    // IPFIX sequence counts data records only (not template records)
    state->sequence += state->record_count;
    header->sequence = htonl(state->sequence);

    // Update export time
    time_t now = time(NULL);
    header->export_time = htonl((uint32_t)now);

    // Calculate and set total length
    size_t packet_size = (void *)rep->buff_ptr - rep->send_buffer;
    header->length = htons((uint16_t)packet_size);

    dbg_printf("Flushing IPFIX repeater %d: %d records, %u templates, %zu bytes, sequence %u\n",
               idx, state->record_count, state->template_count, packet_size, state->sequence);

    // Send via privsep
    if (SendFilteredMessage(rfd, idx, rep->send_buffer, packet_size) < 0) {
        LogError("Failed to send filtered IPFIX packet to repeater %s", rep->hostname);
    }

    // Reset state for next packet
    state->record_count = 0;
    state->template_count = 0;
    state->data_flowset = NULL;
    state->data_flowset_id = 0;
    rep->buff_ptr = rep->send_buffer + IPFIX_HEADER_LENGTH;
}

static int SendFilteredMessage(int rfd, int repeater_index, void *buffer, size_t len) {
    if (rfd <= 0) return -1;

    // Build message for privsep
    message_t msg_header;
    msg_header.type = PRIVMSG_FILTERED_REPEAT;
    msg_header.length = sizeof(message_t) + sizeof(filtered_repeater_message_t) + len;

    filtered_repeater_message_t frm;
    frm.packet_size = len;
    frm.repeater_index = repeater_index;

    struct iovec iov[3];
    iov[0].iov_base = &msg_header;
    iov[0].iov_len = sizeof(message_t);
    iov[1].iov_base = &frm;
    iov[1].iov_len = sizeof(filtered_repeater_message_t);
    iov[2].iov_base = buffer;
    iov[2].iov_len = len;

    ssize_t ret = writev(rfd, iov, 3);
    if (ret < 0) {
        LogError("writev() error sending filtered packet: %s", strerror(errno));
        return -1;
    }

    dbg_printf("Sent filtered message: type=%d, len=%d, repeater=%d, packet_size=%zu\n",
               msg_header.type, msg_header.length, repeater_index, len);

    return 0;
}

/* ============================================================================
 * V9/IPFIX Helper Functions
 * ============================================================================ */

static void FreeTemplates(outTemplate_t *templates) {
    while (templates) {
        outTemplate_t *next = templates->next;
        if (templates->template_flowset) {
            free(templates->template_flowset);
        }
        free(templates);
        templates = next;
    }
}

static int CheckBufferSpace(repeater_t *rep, size_t size) {
    void *endp = rep->send_buffer + FILTERED_SEND_BUFFER_SIZE;
    if ((rep->buff_ptr + size) > endp) {
        return 0;  // Not enough space
    }
    return 1;  // Enough space
}

static void CloseDataFlowset(repeater_t *rep, encoder_state_t *state) {
    if (state->data_flowset) {
        uint32_t length = (void *)rep->buff_ptr - (void *)state->data_flowset;
        uint32_t bits = length & 0x3;
        if (bits != 0) {
            uint32_t align = 4 - bits;
            length += align;
            // Fill padding with 0
            for (uint32_t i = 0; i < align; i++) {
                *((char *)rep->buff_ptr) = '\0';
                rep->buff_ptr++;
            }
        }
        dbg_printf("Close flowset: Length: %u, align: %u\n", length, bits ? (4 - bits) : 0);
        state->data_flowset->length = htons(length);
        state->data_flowset = NULL;
        state->data_flowset_id = 0;
    }
}

static outTemplate_t *GetOutputTemplate(encoder_state_t *state, recordHandle_t *recordHandle) {
    uint32_t template_id = 0;

    // Build element bits from extension list
    uint64_t elementBits = 0;
    for (int i = 0; i < MAXEXTENSIONS; i++) {
        if (recordHandle->extensionList[i]) elementBits |= (uint64_t)1 << i;
    }

    // Search for existing template
    outTemplate_t **t = &state->templates;
    while (*t) {
        if (((*t)->elementBits == elementBits) && ((*t)->numExtensions == recordHandle->numElements)) {
            return *t;
        }
        template_id = (*t)->template_id;
        t = &((*t)->next);
    }

    // Create new template
    *t = (outTemplate_t *)calloc(1, sizeof(outTemplate_t));
    if (!(*t)) {
        LogError("calloc() error: %s", strerror(errno));
        return NULL;
    }
    (*t)->next = NULL;
    (*t)->elementBits = elementBits;
    (*t)->numExtensions = recordHandle->numElements;

    if (template_id == 0)
        (*t)->template_id = NF9_MIN_RECORD_FLOWSET_ID;
    else
        (*t)->template_id = template_id + 1;

    dbg_printf("Create new template: %d\n", (*t)->template_id);

    (*t)->time_sent = 0;
    (*t)->record_count = 0;

    // Allocate flowset array
    int32_t numV9Elements = 40;
    (*t)->template_flowset = calloc(1, sizeof(template_flowset_t) + (size_t)(numV9Elements * 4));
    if (!(*t)->template_flowset) {
        LogError("calloc() error: %s", strerror(errno));
        free(*t);
        *t = NULL;
        return NULL;
    }
    template_flowset_t *flowset = (*t)->template_flowset;

    // Add two default elements (engine type and id)
    int32_t count = 0;
    flowset->field[count].type = htons(NF9_ENGINE_TYPE);
    flowset->field[count].length = htons(1);
    count++;
    flowset->field[count].type = htons(NF9_ENGINE_ID);
    flowset->field[count].length = htons(1);
    count++;
    uint32_t data_length = 2;

    dbg_printf("Generate template for %u extensions\n", recordHandle->numElements);

    // Determine mask types based on IP version
    uint16_t srcMaskType = NF9_SRC_MASK;
    uint16_t dstMaskType = NF9_DST_MASK;
    if (recordHandle->extensionList[EXipv6FlowID]) {
        srcMaskType = NF9_IPV6_SRC_MASK;
        dstMaskType = NF9_IPV6_DST_MASK;
    }

    // Iterate over all extensions
    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        if (recordHandle->extensionList[ext] == NULL) continue;

        // Dynamically increase flowset table if needed
        if ((numV9Elements - count) < 15) {
            dbg_printf("Expand flowset table\n");
            numV9Elements += 20;
            size_t newSize = sizeof(template_flowset_t) + (numV9Elements * 4);
            (*t)->template_flowset = realloc((*t)->template_flowset, newSize);
            if (!(*t)->template_flowset) {
                LogError("realloc() error: %s", strerror(errno));
                return NULL;
            }
            flowset = (*t)->template_flowset;
        }
        added++;
        dbg_printf("Add extension: %d\n", ext);

        switch (ext) {
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
                break;
            case EXipv6FlowID:
                flowset->field[count].type = htons(NF9_IPV6_SRC_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                flowset->field[count].type = htons(NF9_IPV6_DST_ADDR);
                flowset->field[count].length = htons(16);
                count++;
                data_length += 32;
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
                flowset->field[count].type = htons(NF_9_IP_PROTOCOL_VERSION);
                flowset->field[count].length = htons(1);
                count++;
                data_length += 9;
                break;
        }
    }

    // Terminate field list
    flowset->field[count].type = 0;
    flowset->field[count].length = 0;

    (*t)->template_flowset->flowset_id = htons(NF9_TEMPLATE_FLOWSET_ID);
    (*t)->flowset_length = 4 * (2 + count);  // +2 for header

    // Add padding for 32-bit boundary
    if (((*t)->flowset_length & 0x3) != 0)
        (*t)->flowset_length += (4 - ((*t)->flowset_length & 0x3));
    (*t)->template_flowset->length = htons((*t)->flowset_length);

    (*t)->data_length = data_length;

    dbg_printf("Created template id: %u, count: %u, data_length: %u, flowset_length: %u\n",
               (*t)->template_id, count, data_length, (*t)->flowset_length);

    flowset->template_id = htons((*t)->template_id);
    flowset->count = htons(count);

    return *t;
}

static int AddTemplateFlowset(repeater_t *rep, encoder_state_t *state, outTemplate_t *outTemplate) {
    if (!CheckBufferSpace(rep, outTemplate->flowset_length)) {
        return 0;
    }

    dbg_printf("Add template %u, bytes: %u\n", outTemplate->template_id, outTemplate->flowset_length);
    memcpy(rep->buff_ptr, (void *)outTemplate->template_flowset, outTemplate->flowset_length);
    rep->buff_ptr = (void *)((uintptr_t)rep->buff_ptr + outTemplate->flowset_length);

    state->template_count++;
    outTemplate->time_sent = time(NULL);
    outTemplate->needs_refresh = 0;

    return 1;
}

static void AppendRecordV9(repeater_t *rep, encoder_state_t *state, recordHandle_t *recordHandle) {
    uint8_t *p = (uint8_t *)rep->buff_ptr;

    // Engine type and ID
    *p++ = recordHandle->recordHeaderV3->engineType;
    *p++ = recordHandle->recordHeaderV3->engineID;
    rep->buff_ptr = (void *)p;

    int added = 0;
    for (int ext = 1; ext < MAXEXTENSIONS; ext++) {
        if (added == recordHandle->numElements) break;
        void *elementPtr = recordHandle->extensionList[ext];
        if (elementPtr == NULL) continue;
        added++;

        switch (ext) {
            case EXgenericFlowID: {
                EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)elementPtr;
                Put_val64(htonll(genericFlow->msecFirst), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(genericFlow->msecLast), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(genericFlow->inPackets), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(genericFlow->inBytes), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val16(htons(genericFlow->srcPort), rep->buff_ptr);
                rep->buff_ptr += 2;
                if (genericFlow->proto == IPPROTO_ICMP || genericFlow->proto == IPPROTO_ICMPV6) {
                    Put_val16(0, rep->buff_ptr);
                    rep->buff_ptr += 2;
                    Put_val16(htons(genericFlow->dstPort), rep->buff_ptr);
                    rep->buff_ptr += 2;
                } else {
                    Put_val16(htons(genericFlow->dstPort), rep->buff_ptr);
                    rep->buff_ptr += 2;
                    Put_val16(0, rep->buff_ptr);
                    rep->buff_ptr += 2;
                }
                Put_val8(genericFlow->proto, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(genericFlow->tcpFlags, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(genericFlow->fwdStatus, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(genericFlow->srcTos, rep->buff_ptr);
                rep->buff_ptr += 1;
            } break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)elementPtr;
                Put_val32(htonl(ipv4Flow->srcAddr), rep->buff_ptr);
                rep->buff_ptr += 4;
                Put_val32(htonl(ipv4Flow->dstAddr), rep->buff_ptr);
                rep->buff_ptr += 4;
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)elementPtr;
                Put_val64(htonll(ipv6Flow->srcAddr[0]), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->srcAddr[1]), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->dstAddr[0]), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(ipv6Flow->dstAddr[1]), rep->buff_ptr);
                rep->buff_ptr += 8;
            } break;
            case EXflowMiscID: {
                EXflowMisc_t *flowMisc = (EXflowMisc_t *)elementPtr;
                Put_val32(htonl(flowMisc->input), rep->buff_ptr);
                rep->buff_ptr += 4;
                Put_val32(htonl(flowMisc->output), rep->buff_ptr);
                rep->buff_ptr += 4;
                Put_val8(flowMisc->srcMask, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(flowMisc->dstMask, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(flowMisc->dir, rep->buff_ptr);
                rep->buff_ptr += 1;
                Put_val8(flowMisc->dstTos, rep->buff_ptr);
                rep->buff_ptr += 1;
            } break;
            case EXcntFlowID: {
                EXcntFlow_t *cntFlow = (EXcntFlow_t *)elementPtr;
                Put_val64(htonll(cntFlow->flows), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(cntFlow->outPackets), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(cntFlow->outBytes), rep->buff_ptr);
                rep->buff_ptr += 8;
            } break;
            case EXvLanID: {
                EXvLan_t *vLan = (EXvLan_t *)elementPtr;
                Put_val16(htons(vLan->srcVlan), rep->buff_ptr);
                rep->buff_ptr += 2;
                Put_val16(htons(vLan->dstVlan), rep->buff_ptr);
                rep->buff_ptr += 2;
            } break;
            case EXlayer2ID: {
                EXlayer2_t *layer2 = (EXlayer2_t *)elementPtr;
                Put_val16(htons(layer2->vlanID), rep->buff_ptr);
                rep->buff_ptr += 2;
                Put_val16(htons(layer2->postVlanID), rep->buff_ptr);
                rep->buff_ptr += 2;
                Put_val16(htons(layer2->customerVlanId), rep->buff_ptr);
                rep->buff_ptr += 2;
                Put_val16(htons(layer2->postCustomerVlanId), rep->buff_ptr);
                rep->buff_ptr += 2;
                Put_val8(layer2->ipVersion, rep->buff_ptr);
                rep->buff_ptr += 1;
            } break;
            case EXasRoutingID: {
                EXasRouting_t *asRouting = (EXasRouting_t *)elementPtr;
                Put_val32(htonl(asRouting->srcAS), rep->buff_ptr);
                rep->buff_ptr += 4;
                Put_val32(htonl(asRouting->dstAS), rep->buff_ptr);
                rep->buff_ptr += 4;
            } break;
            case EXbgpNextHopV4ID: {
                EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)elementPtr;
                Put_val32(htonl(bgpNextHopV4->ip), rep->buff_ptr);
                rep->buff_ptr += 4;
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)elementPtr;
                Put_val64(htonll(bgpNextHopV6->ip[0]), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(bgpNextHopV6->ip[1]), rep->buff_ptr);
                rep->buff_ptr += 8;
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)elementPtr;
                Put_val32(htonl(ipNextHopV4->ip), rep->buff_ptr);
                rep->buff_ptr += 4;
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)elementPtr;
                Put_val64(htonll(ipNextHopV6->ip[0]), rep->buff_ptr);
                rep->buff_ptr += 8;
                Put_val64(htonll(ipNextHopV6->ip[1]), rep->buff_ptr);
                rep->buff_ptr += 8;
            } break;
            case EXmplsLabelID: {
                EXmplsLabel_t *mplsLabel = (EXmplsLabel_t *)elementPtr;
                for (int i = 0; i < 10; i++) {
                    uint32_t val32 = htonl(mplsLabel->mplsLabel[i]);
                    Put_val24(val32, rep->buff_ptr);
                    rep->buff_ptr += 3;
                }
            } break;
            case EXmacAddrID: {
                EXmacAddr_t *macAddr = (EXmacAddr_t *)elementPtr;
                uint64_t val64 = htonll(macAddr->inSrcMac);
                Put_val48(val64, rep->buff_ptr);
                rep->buff_ptr += 6;
                val64 = htonll(macAddr->outDstMac);
                Put_val48(val64, rep->buff_ptr);
                rep->buff_ptr += 6;
                val64 = htonll(macAddr->inDstMac);
                Put_val48(val64, rep->buff_ptr);
                rep->buff_ptr += 6;
                val64 = htonll(macAddr->outSrcMac);
                Put_val48(val64, rep->buff_ptr);
                rep->buff_ptr += 6;
            } break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)elementPtr;
                Put_val32(htonl(asAdjacent->nextAdjacentAS), rep->buff_ptr);
                rep->buff_ptr += 4;
                Put_val32(htonl(asAdjacent->prevAdjacentAS), rep->buff_ptr);
                rep->buff_ptr += 4;
            } break;
        }
    }

    state->record_count++;
}

/* ============================================================================
 * V9 Encoder
 * ============================================================================ */

static int EncodeRecordV9(repeater_t *rep, recordHandle_t *handle) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (handle->numElements == 0 || !genericFlow) {
        dbg_printf("Skip record with 0 extensions or no generic flow\n");
        return 0;
    }

    // Initialize on first record
    if (!state->initialized) {
        state->msecBoot = genericFlow->msecFirst - 86400LL * 1000LL;
        state->sequence = 0;
        state->record_count = 0;
        state->template_count = 0;
        state->templates = NULL;
        state->data_flowset = NULL;
        state->data_flowset_id = 0;
        state->last_template_time = 0;
        state->initialized = 1;

        // Initialize V9 header
        netflow_v9_header_t *header = (netflow_v9_header_t *)rep->send_buffer;
        header->version = htons(9);
        header->SysUptime = 0;
        header->unix_secs = 0;
        header->count = 0;
        header->source_id = htonl(1);
        header->sequence = 0;

        rep->buff_ptr = rep->send_buffer + NETFLOW_V9_HEADER_LENGTH;
    }

    // Check if buffer was flushed - reset pointer
    if (rep->buff_ptr == rep->send_buffer) {
        rep->buff_ptr = rep->send_buffer + NETFLOW_V9_HEADER_LENGTH;
    }

    time_t now = time(NULL);
    outTemplate_t *tmpl = GetOutputTemplate(state, handle);
    if (!tmpl) {
        LogError("Failed to get output template for V9");
        return 0;
    }

    // Check if we need a new data flowset or template refresh
    if ((state->data_flowset_id != tmpl->template_id) || tmpl->needs_refresh) {
        // Close current data flowset
        CloseDataFlowset(rep, state);

        // Check space for template + data flowset header + one record
        size_t needed = tmpl->data_length + sizeof(data_flowset_t);
        if (tmpl->record_count == 0 || tmpl->needs_refresh) {
            needed += tmpl->flowset_length;
        }

        if (!CheckBufferSpace(rep, needed)) {
            rep->flush = 1;
            return 1;
        }

        // Add template if needed
        if (tmpl->record_count == 0 || tmpl->needs_refresh ||
            (now - tmpl->time_sent > MAX_TEMPLATE_LIFETIME)) {
            if (!AddTemplateFlowset(rep, state, tmpl)) {
                rep->flush = 1;
                return 1;
            }
        }

        // Start new data flowset
        dbg_printf("Add new data flowset for template %u\n", tmpl->template_id);
        state->data_flowset = (data_flowset_t *)rep->buff_ptr;
        state->data_flowset->flowset_id = tmpl->template_flowset->template_id;
        state->data_flowset_id = tmpl->template_id;
        rep->buff_ptr = (void *)state->data_flowset->data;
    }

    // Check space for one record
    if (!CheckBufferSpace(rep, tmpl->data_length)) {
        rep->flush = 1;
        return 1;
    }

    // Append the record
    dbg_printf("Add V9 record, template: %u, data_length: %u\n", tmpl->template_id, tmpl->data_length);
    AppendRecordV9(rep, state, handle);

    // Update template record count
    tmpl->record_count++;

    // Check if template needs refresh
    if (((tmpl->record_count & 0xFFF) == 0) || (now - tmpl->time_sent > MAX_TEMPLATE_LIFETIME)) {
        tmpl->needs_refresh = 1;
        dbg_printf("Schedule template refresh\n");
    }

    return 1;
}

/* ============================================================================
 * IPFIX Encoder
 * ============================================================================ */

static outTemplate_t *GetOutputTemplateIPFIX(encoder_state_t *state, recordHandle_t *recordHandle) {
    // IPFIX templates are similar to V9, but with template set ID = 2
    // Reuse V9 template generation logic with minor adjustments
    outTemplate_t *tmpl = GetOutputTemplate(state, recordHandle);
    if (tmpl && tmpl->template_flowset) {
        // Update flowset ID to IPFIX template set ID (2)
        tmpl->template_flowset->flowset_id = htons(IPFIX_TEMPLATE_FLOWSET_ID);
    }
    return tmpl;
}

static int EncodeRecordIPFIX(repeater_t *rep, recordHandle_t *handle) {
    int idx = rep->index;
    encoder_state_t *state = &encoder_state[idx];

    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle->extensionList[EXgenericFlowID];
    if (handle->numElements == 0 || !genericFlow) {
        dbg_printf("Skip record with 0 extensions or no generic flow\n");
        return 0;
    }

    // Initialize on first record
    if (!state->initialized) {
        state->msecBoot = genericFlow->msecFirst - 86400LL * 1000LL;
        state->sequence = 0;
        state->record_count = 0;
        state->template_count = 0;
        state->templates = NULL;
        state->data_flowset = NULL;
        state->data_flowset_id = 0;
        state->last_template_time = 0;
        state->initialized = 1;

        // Initialize IPFIX header
        ipfix_header_t *header = (ipfix_header_t *)rep->send_buffer;
        header->version = htons(10);
        header->length = 0;  // Will be set when flushing
        header->export_time = 0;
        header->sequence = 0;
        header->observation_domain = htonl(1);

        rep->buff_ptr = rep->send_buffer + IPFIX_HEADER_LENGTH;
    }

    // Check if buffer was flushed - reset pointer
    if (rep->buff_ptr == rep->send_buffer) {
        rep->buff_ptr = rep->send_buffer + IPFIX_HEADER_LENGTH;
    }

    time_t now = time(NULL);
    outTemplate_t *tmpl = GetOutputTemplateIPFIX(state, handle);
    if (!tmpl) {
        LogError("Failed to get output template for IPFIX");
        return 0;
    }

    // Check if we need a new data flowset or template refresh
    if ((state->data_flowset_id != tmpl->template_id) || tmpl->needs_refresh) {
        // Close current data flowset
        CloseDataFlowset(rep, state);

        // Check space for template + data flowset header + one record
        size_t needed = tmpl->data_length + sizeof(data_flowset_t);
        if (tmpl->record_count == 0 || tmpl->needs_refresh) {
            needed += tmpl->flowset_length;
        }

        if (!CheckBufferSpace(rep, needed)) {
            rep->flush = 1;
            return 1;
        }

        // Add template if needed
        if (tmpl->record_count == 0 || tmpl->needs_refresh ||
            (now - tmpl->time_sent > MAX_TEMPLATE_LIFETIME)) {
            if (!AddTemplateFlowset(rep, state, tmpl)) {
                rep->flush = 1;
                return 1;
            }
        }

        // Start new data flowset
        dbg_printf("Add new IPFIX data flowset for template %u\n", tmpl->template_id);
        state->data_flowset = (data_flowset_t *)rep->buff_ptr;
        state->data_flowset->flowset_id = tmpl->template_flowset->template_id;
        state->data_flowset_id = tmpl->template_id;
        rep->buff_ptr = (void *)state->data_flowset->data;
    }

    // Check space for one record
    if (!CheckBufferSpace(rep, tmpl->data_length)) {
        rep->flush = 1;
        return 1;
    }

    // Append the record (same format as V9)
    dbg_printf("Add IPFIX record, template: %u, data_length: %u\n", tmpl->template_id, tmpl->data_length);
    AppendRecordV9(rep, state, handle);

    // Update template record count
    tmpl->record_count++;

    // Check if template needs refresh
    if (((tmpl->record_count & 0xFFF) == 0) || (now - tmpl->time_sent > MAX_TEMPLATE_LIFETIME)) {
        tmpl->needs_refresh = 1;
        dbg_printf("Schedule IPFIX template refresh\n");
    }

    return 1;
}
