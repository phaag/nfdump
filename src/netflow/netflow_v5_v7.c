/*
 *  Copyright (c) 2009-2025, Peter Haag
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

#include "netflow_v5_v7.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "collector.h"
#include "exporter.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "util.h"

#define NETFLOW_V5_HEADER_LENGTH 24
#define NETFLOW_V5_RECORD_LENGTH 48
#define NETFLOW_V5_MAX_RECORDS 30

#define NETFLOW_V7_HEADER_LENGTH 24
#define NETFLOW_V7_RECORD_LENGTH 52
#define NETFLOW_V7_MAX_RECORDS 28

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

/* v7 structures */
typedef struct netflow_v7_header {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint32_t reserved;
} netflow_v7_header_t;

typedef struct netflow_v7_record {
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
    uint8_t flags;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad;
    uint32_t router_sc;
} netflow_v7_record_t;

// v5 exporter type
typedef struct exporter_v5_s {
    // struct exporter_s
    struct exporter_v5_s *next;

    // exporter information
    exporter_info_record_t info;  // exporter record nffile

    uint64_t packets;           // number of packets sent by this exporter
    uint64_t flows;             // number of flow records sent by this exporter
    uint32_t sequence_failure;  // number of sequence failures
    uint32_t padding_errors;    // number of sequence failures

    sampler_t *sampler;  // list of samplers associated with this exporter
    // end of struct exporter_s

    // sequence vars
    int first;
    int64_t last_sequence;
    int64_t sequence, distance;
    int64_t last_count;

    uint32_t outRecordSize;

} exporter_v5_t;

/* module limited globals */
static int printRecord;
static int32_t defaultSampling;
static uint32_t baseRecordSize;

// function prototypes
static exporter_v5_t *getExporter(FlowSource_t *fs, netflow_v5_header_t *header);

#include "nffile_inline.c"

int Init_v5_v7(int verbose, int32_t sampling) {
    assert(sizeof(netflow_v5_header_t) == NETFLOW_V5_HEADER_LENGTH);
    assert(sizeof(netflow_v5_record_t) == NETFLOW_V5_RECORD_LENGTH);

    printRecord = verbose > 2;
    defaultSampling = sampling;

    if (sampling < 0) {
        LogInfo("Init v5/v7: Overwrite sampling: %d", -defaultSampling);
    } else {
        LogInfo("Init v5/v7: Default sampling: %d", defaultSampling);
    }

    baseRecordSize = sizeof(recordHeaderV3_t) + EXgenericFlowSize + EXipv4FlowSize + EXflowMiscSize + EXasRoutingSize + EXipNextHopV4Size;

    return 1;

}  // End of Init_v5_input

static inline exporter_v5_t *getExporter(FlowSource_t *fs, netflow_v5_header_t *header) {
    exporter_v5_t **e = (exporter_v5_t **)&(fs->exporter_data);
    sampler_t *sampler;
    uint16_t engine_tag = ntohs(header->engine_tag);
    uint16_t version = ntohs(header->version);

    // search the matching v5 exporter
    while (*e) {
        if ((*e)->info.version == version && (*e)->info.id == engine_tag && (*e)->info.ip.V6[0] == fs->ip.V6[0] &&
            (*e)->info.ip.V6[1] == fs->ip.V6[1])
            return *e;
        e = &((*e)->next);
    }

    // nothing found
    *e = (exporter_v5_t *)calloc(1, sizeof(exporter_v5_t));
    if (!(*e)) {
        LogError("Process_v5: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    (*e)->next = NULL;
    (*e)->info.header.type = ExporterInfoRecordType;
    (*e)->info.header.size = sizeof(exporter_info_record_t);
    (*e)->info.version = version;
    (*e)->info.id = engine_tag;
    (*e)->info.ip = fs->ip;
    (*e)->info.sa_family = fs->sa_family;
    (*e)->info.sysid = 0;
    (*e)->sequence_failure = 0;
    (*e)->packets = 0;
    (*e)->flows = 0;
    (*e)->first = 1;

    char *ipstr = GetExporterIP(fs);
    if (fs->sa_family == PF_INET6) {
        (*e)->outRecordSize = baseRecordSize + EXipReceivedV6Size;
        dbg_printf("Process_v5: New IPv6 exporter %s - add EXipReceivedV6\n", ipstr);
    } else {
        (*e)->outRecordSize = baseRecordSize + EXipReceivedV4Size;
        dbg_printf("Process_v5: New IPv4 exporter %s - add EXipReceivedV4\n", ipstr);
    }

    FlushInfoExporter(fs, &((*e)->info));

    // sampling
    int32_t id = 0;
    uint32_t algorithm = 0;
    uint32_t interval = 0x3fff & ntohs(header->sampling_interval);
    dbg_printf("Extracted header sampling: algorithm: %u, interval: %u\n", algorithm, interval);
    if (defaultSampling < 0) {
        id = SAMPLER_OVERWRITE;
        interval = -defaultSampling;
        dbg_printf("Use overwrite sampling: %u\n", interval);
    } else if (interval > 0) {
        id = SAMPLER_GENERIC;
        algorithm = (0xC000 & ntohs(header->sampling_interval)) >> 14;
        dbg_printf("Use generic sampling: %u\n", interval);
    } else if (defaultSampling > 1) {
        id = SAMPLER_DEFAULT;
        interval = defaultSampling;
        dbg_printf("Use default sampling: %u\n", interval);
    }

    // sampler assigned ?
    if (id != 0) {
        interval--;
        sampler = (sampler_t *)malloc(sizeof(sampler_t));
        if (!sampler) {
            LogError("Process_v5: malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        (*e)->sampler = sampler;

        sampler->next = NULL;
        sampler->record.type = SamplerRecordType;
        sampler->record.size = sizeof(sampler_record_t);
        sampler->record.exporter_sysid = (*e)->info.sysid;
        sampler->record.id = id;
        sampler->record.packetInterval = 1;
        sampler->record.algorithm = algorithm;
        sampler->record.spaceInterval = interval;

        fs->dataBlock = AppendToBuffer(fs->nffile, fs->dataBlock, &(sampler->record), sampler->record.size);

        LogInfo(
            "Process_v5: New exporter: SysID: %u, engine id %u, type %u, IP: %s, algorithm: %i, "
            "packet interval: 1, packet space: %u\n",
            (*e)->info.sysid, (engine_tag & 0xFF), ((engine_tag >> 8) & 0xFF), ipstr, algorithm, interval);
    } else {
        (*e)->sampler = NULL;
        LogInfo("Process_v5: New exporter: SysID: %u, engine id %u, type %u, IP: %s", (*e)->info.sysid, (engine_tag & 0xFF),
                ((engine_tag >> 8) & 0xFF), ipstr);
    }

    return (*e);

}  // End of getExporter

void Process_v5_v7(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // v7 is treated as v5. it differs by the sequencer skip count only
    // map v5 data structure to input buffer
    netflow_v5_header_t *v5_header = (netflow_v5_header_t *)in_buff;

    exporter_v5_t *exporter = getExporter(fs, v5_header);
    if (!exporter) {
        LogError("Process_v5: Exporter NULL: Abort v5/v7 record processing");
        return;
    }
    exporter->packets++;

    uint16_t version = ntohs(v5_header->version);
    int rawRecordSize = version == 5 ? NETFLOW_V5_RECORD_LENGTH : NETFLOW_V7_RECORD_LENGTH;

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    int done = 0;
    while (!done) {
        // count check
        uint16_t count = ntohs(v5_header->count);
        // input buffer size check for all expected records
        if (size_left < (NETFLOW_V5_HEADER_LENGTH + count * rawRecordSize)) {
            LogError("Process_v5: Exporter: %s Not enough data to process v5 record. Abort v5/v7 record processing", GetExporterIP(fs));
            return;
        }

        // set output buffer memory
        void *outBuff = GetCurrentCursor(fs->dataBlock);
        if (!IsAvailable(fs->dataBlock, count * exporter->outRecordSize)) {
            // flush block - get an empty one
            fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
            // map output memory buffer
            outBuff = GetCursor(fs->dataBlock);
        }

        // sequence check
        if (exporter->first) {
            exporter->last_sequence = ntohl(v5_header->flow_sequence);
            exporter->sequence = exporter->last_sequence;
            exporter->first = 0;
        } else {
            exporter->last_sequence = exporter->sequence;
            exporter->sequence = ntohl(v5_header->flow_sequence);
            exporter->distance = exporter->sequence - exporter->last_sequence;
            // handle overflow
            if (exporter->distance < 0) {
                exporter->distance = 0xffffffff + exporter->distance + 1;
            }
            if (exporter->distance != exporter->last_count) {
                fs->nffile->stat_record->sequence_failure++;
                exporter->sequence_failure++;
            }
        }
        exporter->last_count = count;

        v5_header->SysUptime = ntohl(v5_header->SysUptime);
        v5_header->unix_secs = ntohl(v5_header->unix_secs);
        v5_header->unix_nsecs = ntohl(v5_header->unix_nsecs);

        /* calculate boot time in msec */
        uint64_t msecBoot =
            ((uint64_t)(v5_header->unix_secs) * 1000 + ((uint64_t)(v5_header->unix_nsecs) / 1000000)) - (uint64_t)(v5_header->SysUptime);

        // process all records
        netflow_v5_record_t *v5_record = (netflow_v5_record_t *)((void *)v5_header + NETFLOW_V5_HEADER_LENGTH);

        uint16_t engine_tag = ntohs(v5_header->engine_tag);
        uint8_t engineType = (engine_tag >> 8) & 0xFF;
        uint8_t engineID = (engine_tag & 0xFF);

        /* loop over each records associated with this header */
        uint32_t outSize = 0;
        for (int i = 0; i < count; i++) {
            // header data gets initialized by macro
            AddV3Header(outBuff, recordHeader);

            // header data
            recordHeader->engineType = engineType;
            recordHeader->engineID = engineID;
            recordHeader->exporterID = exporter->info.sysid;
            recordHeader->nfversion = 5;

            // Add v5 specific data
            PushExtension(recordHeader, EXgenericFlow, genericFlow);
            genericFlow->msecReceived = msecReceived;
            genericFlow->inPackets = ntohl(v5_record->dPkts);
            genericFlow->inBytes = ntohl(v5_record->dOctets);
            genericFlow->srcPort = ntohs(v5_record->srcPort);
            genericFlow->dstPort = ntohs(v5_record->dstPort);
            genericFlow->proto = v5_record->prot;
            genericFlow->srcTos = v5_record->tos;
            genericFlow->tcpFlags = v5_record->tcp_flags;

            PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
            ipv4Flow->srcAddr = ntohl(v5_record->srcaddr);
            ipv4Flow->dstAddr = ntohl(v5_record->dstaddr);

            // add these extensions only if they have non zero values
            if (v5_record->input || v5_record->output) {
                PushExtension(recordHeader, EXflowMisc, flowMisc);
                flowMisc->input = ntohs(v5_record->input);
                flowMisc->output = ntohs(v5_record->output);
            }

            if (v5_record->src_as || v5_record->dst_as) {
                PushExtension(recordHeader, EXasRouting, asRouting);
                asRouting->srcAS = ntohs(v5_record->src_as);
                asRouting->dstAS = ntohs(v5_record->dst_as);
            }

            if (v5_record->nexthop) {
                PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
                ipNextHopV4->ip = ntohl(v5_record->nexthop);
            }

            // post process required data

            // calculate msec values first/last
            uint64_t First = ntohl(v5_record->First);
            uint64_t Last = ntohl(v5_record->Last);
            uint64_t msecStart, msecEnd;

            if (First > Last) {
                /* First in msec, in case of msec overflow, between start and end */
                msecStart = msecBoot - 0x100000000LL + First;
            } else {
                msecStart = msecBoot + First;
            }

            /* end time in msecs */
            msecEnd = Last + msecBoot;

            // if overflow happened after flow ended but before got exported
            // the additional check > 100000 is required due to a CISCO IOS bug
            // CSCei12353 - thanks to Bojan
            if (Last > v5_header->SysUptime && ((Last - v5_header->SysUptime) > 100000)) {
                msecStart -= 0x100000000LL;
                msecEnd -= 0x100000000LL;
            }

            genericFlow->msecFirst = msecStart;
            genericFlow->msecLast = msecEnd;

            UpdateFirstLast(fs->nffile, msecStart, msecEnd);

            // add router IP
            if (fs->sa_family == PF_INET6) {
                PushExtension(recordHeader, EXipReceivedV6, ipReceivedV6);
                ipReceivedV6->ip[0] = fs->ip.V6[0];
                ipReceivedV6->ip[1] = fs->ip.V6[1];
            } else {
                PushExtension(recordHeader, EXipReceivedV4, ipReceivedV4);
                ipReceivedV4->ip = fs->ip.V4;
            }

            // sampling
            if (exporter->sampler && exporter->sampler->record.spaceInterval > 1) {
                genericFlow->inPackets *= (uint64_t)(exporter->sampler->record.spaceInterval + 1);
                genericFlow->inBytes *= (uint64_t)(exporter->sampler->record.spaceInterval + 1);
                SetFlag(recordHeader->flags, V3_FLAG_SAMPLED);
            }

            // Update stats
            switch (genericFlow->proto) {
                case IPPROTO_ICMP:
                    fs->nffile->stat_record->numflows_icmp++;
                    fs->nffile->stat_record->numpackets_icmp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_icmp += genericFlow->inBytes;
                    // fix odd CISCO behaviour for ICMP port/type in src port
                    if (genericFlow->srcPort != 0) {
                        uint8_t *s1 = (uint8_t *)&(genericFlow->srcPort);
                        uint8_t *s2 = (uint8_t *)&(genericFlow->dstPort);
                        s2[0] = s1[1];
                        s2[1] = s1[0];
                        genericFlow->srcPort = 0;
                    }
                    break;
                case IPPROTO_TCP:
                    fs->nffile->stat_record->numflows_tcp++;
                    fs->nffile->stat_record->numpackets_tcp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_tcp += genericFlow->inBytes;
                    break;
                case IPPROTO_UDP:
                    fs->nffile->stat_record->numflows_udp++;
                    fs->nffile->stat_record->numpackets_udp += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_udp += genericFlow->inBytes;
                    break;
                default:
                    fs->nffile->stat_record->numflows_other++;
                    fs->nffile->stat_record->numpackets_other += genericFlow->inPackets;
                    fs->nffile->stat_record->numbytes_other += genericFlow->inBytes;
            }
            exporter->flows++;
            fs->nffile->stat_record->numflows++;
            fs->nffile->stat_record->numpackets += genericFlow->inPackets;
            fs->nffile->stat_record->numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeader);
            UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);

            if (printRecord) {
                flow_record_short(stdout, recordHeader);
            }

            // advance to next input flow record
            outBuff += recordHeader->size;
            outSize += recordHeader->size;
            v5_record = (netflow_v5_record_t *)((void *)v5_record + rawRecordSize);

            if (recordHeader->size > exporter->outRecordSize) {
                LogError("Process_v5: Record size check failed! Expected: %u, counted: %u\n", exporter->outRecordSize, recordHeader->size);
                return;
            }

        }  // End of foreach v5 record

        // update file record size ( -> output buffer size )
        fs->dataBlock->NumRecords += count;
        fs->dataBlock->size += outSize;

        // still to go for this many input bytes
        size_left -= NETFLOW_V5_HEADER_LENGTH + count * rawRecordSize;

        // next header
        v5_header = (netflow_v5_header_t *)v5_record;

        // should never be < 0
        done = size_left <= 0;

    }  // End of while !done

    return;

}  // End of Process_v5
