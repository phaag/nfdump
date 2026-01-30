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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "filter/filter.h"
#include "nfdump.h"
#include "nfxV3.h"
#include "privsep.h"
#include "repeater.h"
#include "util.h"

/* NetFlow v5 structures for encoding */
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

/* Per-repeater v5 encoder state */
typedef struct v5_encoder_state_s {
    uint64_t msecBoot;          // Device boot time in msec
    uint32_t sequence;          // Flow sequence number
    int record_count;           // Current record count in buffer
    int initialized;            // Whether msecBoot has been set
} v5_encoder_state_t;

/* Static array of encoder states (one per repeater) */
static v5_encoder_state_t encoder_state[MAX_REPEATERS];

// Forward declarations
static int EncodeRecordV5(repeater_t *rep, recordHandle_t *handle);
static void FlushRepeaterBuffer(repeater_t *rep, int rfd);
static int SendFilteredMessage(int rfd, int repeater_index, void *buffer, size_t len);

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

            // Initialize v5 header in buffer
            netflow_v5_header_t *header = (netflow_v5_header_t *)repeater[i].send_buffer;
            header->version = htons(5);
            header->count = 0;
            header->SysUptime = 0;
            header->unix_secs = 0;
            header->unix_nsecs = 0;
            header->flow_sequence = 0;
            header->engine_tag = 0;
            header->sampling_interval = 0;

            // Set buffer pointer past header
            repeater[i].buff_ptr = repeater[i].send_buffer + NETFLOW_V5_HEADER_LENGTH;
            repeater[i].flush = 0;

            // Set default netflow version if not specified
            if (repeater[i].netflow_version == 0) {
                repeater[i].netflow_version = 5;  // Default to v5 for now
            }

            dbg_printf("Initialized filtered repeater %d: %s:%s filter='%s'\n",
                       i, repeater[i].hostname, repeater[i].port, repeater[i].filter);
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
    }
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
            dbg_printf("Record matches filter for repeater %d\n", i);

            if (repeater[i].netflow_version == 5) {
                if (EncodeRecordV5(&repeater[i], &handle) > 0) {
                    sent_count++;
                }
            } else {
                // For now, default to v5 encoding
                // v9 support will be added later
                if (EncodeRecordV5(&repeater[i], &handle) > 0) {
                    sent_count++;
                }
            }

            // Check if buffer needs flushing
            if (repeater[i].flush) {
                FlushRepeaterBuffer(&repeater[i], rfd);
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
            FlushRepeaterBuffer(&repeater[i], rfd);
        }
    }
}

static int EncodeRecordV5(repeater_t *rep, recordHandle_t *handle) {
    int idx = rep->index;
    v5_encoder_state_t *state = &encoder_state[idx];

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

        state->sequence += NETFLOW_V5_MAX_RECORDS;  // Approximate, will be corrected on send
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

static void FlushRepeaterBuffer(repeater_t *rep, int rfd) {
    int idx = rep->index;
    v5_encoder_state_t *state = &encoder_state[idx];

    if (state->record_count == 0) return;

    // Calculate packet size
    size_t packet_size = NETFLOW_V5_HEADER_LENGTH + (state->record_count * NETFLOW_V5_RECORD_LENGTH);

    dbg_printf("Flushing filtered repeater %d: %d records, %zu bytes\n",
               idx, state->record_count, packet_size);

    // Send via privsep
    if (SendFilteredMessage(rfd, idx, rep->send_buffer, packet_size) < 0) {
        LogError("Failed to send filtered packet to repeater %s", rep->hostname);
    }

    // Reset state for next packet
    state->record_count = 0;
    rep->buff_ptr = rep->send_buffer + NETFLOW_V5_HEADER_LENGTH;
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
