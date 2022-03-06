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

#ifndef _METRIC_H
#define _METRIC_H 1

#include "nffile.h"
#include "nfxV3.h"

typedef struct message_header_s {
    char prefix;
    uint8_t version;
    uint16_t size;
    uint16_t numMetrics;
    uint16_t interval;
    uint64_t timeStamp;
    uint64_t uptime;
    char ident[128];
} message_header_t;

typedef struct metric_record_s {
    // Ident
    uint64_t exporterID;  // 32bit: exporter_id:16 engineType:8 engineID:*

    // flow stat
    uint64_t numflows_tcp;
    uint64_t numflows_udp;
    uint64_t numflows_icmp;
    uint64_t numflows_other;
    // bytes stat
    uint64_t numbytes_tcp;
    uint64_t numbytes_udp;
    uint64_t numbytes_icmp;
    uint64_t numbytes_other;
    // packet stat
    uint64_t numpackets_tcp;
    uint64_t numpackets_udp;
    uint64_t numpackets_icmp;
    uint64_t numpackets_other;
} metric_record_t;

typedef struct metric_chain_s {
    struct metric_chain_s *next;
    metric_record_t *record;
} metric_chain_t;

int OpenMetric(char *path, char *ident, int interval);

int CloseMetric(void);

void UpdateMetric(uint32_t exporterID, EXgenericFlow_t *genericFlow);

void *MetricThread(void *arg);

#define MetricExpporterID(r) (((r)->exporterID << 16) | (((r)->engineType << 8) | (r)->engineID))
#endif
