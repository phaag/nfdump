/*
 *  Copyright (c) 2009-2026, Peter Haag
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
#include "ip128.h"
#include "logging.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV4.h"
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

// module limited globals
static int printRecord;
static int32_t defaultSampling;

#define BitMapSet(map, id) (map |= (1ULL << (id)))

// netflow v5 has at max all these extensions
// always EXgenericFlow, EXipv4Flow, optional at runtime EXinterface, EXasInfo EXasRoutingV4
// including EXipReceivedV4 or EXipReceivedV4, added at runtime
static const uint32_t extensionSize = EXgenericFlowSize + EXipv4FlowSize + EXinterfaceSize + EXasInfoSize + EXasRoutingV4Size;

// baseOffset of first extension with max 6 extension.
// offset table size = 16 - wastes 10bytes max without optional extensions
static const uint32_t baseOffset = sizeof(recordHeaderV4_t) + ALIGN8(6 * sizeof(uint16_t));

// function prototypes
static exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v5_header_t *header);

#include "nffile_inline.c"

int Init_v5_v7(int verbose, int32_t sampling) {
    LogVerbose("Init v5/v7");
    printRecord = verbose > 2;

    defaultSampling = sampling;
    if (sampling < 0) {
        LogInfo("Init v5/v7: Overwrite sampling: %d", -defaultSampling);
    } else {
        LogInfo("Init v5/v7: Default sampling: %d", defaultSampling);
    }

    return 1;
}  // End of Init_v5_v7

static inline int getSampler(netflow_v5_header_t *header, sampler_record_v4_t *sampler_record_v4) {
    uint32_t interval = 0;
    uint32_t cnt = 0;

    if (defaultSampling < 0) {
        // fill sampler record
        interval = -defaultSampling;
        dbg_printf("Use overwrite sampling: %u\n", interval);

        interval--;
        *sampler_record_v4 =
            (sampler_record_v4_t){.inUse = 1, .selectorID = SAMPLER_OVERWRITE, .algorithm = 0, .packetInterval = 1, .spaceInterval = interval};
        sampler_record_v4++;
        cnt++;

    } else if (defaultSampling > 1) {
        interval = defaultSampling;
        dbg_printf("Use default sampling: %u\n", interval);

        interval--;
        *sampler_record_v4 =
            (sampler_record_v4_t){.inUse = 1, .selectorID = SAMPLER_DEFAULT, .algorithm = 0, .packetInterval = 1, .spaceInterval = interval};
        sampler_record_v4++;
        cnt++;
    }

    interval = 0x3fff & ntohs(header->sampling_interval);
    if (interval > 0) {
        uint32_t algorithm = (0xC000 & ntohs(header->sampling_interval)) >> 14;

        // some netflow v5 exporter pack sampling information into the header
        dbg_printf("Extracted header sampling: Use generic sampling - algorithm: %u, interval: %u\n", algorithm, interval);

        interval--;
        *sampler_record_v4 =
            (sampler_record_v4_t){.inUse = 1, .selectorID = SAMPLER_GENERIC, .algorithm = algorithm, .packetInterval = 1, .spaceInterval = interval};
        sampler_record_v4++;
        cnt++;
    }

    return cnt;
}  // End of getSampler

static inline exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v5_header_t *header) {
    uint16_t engine_tag = ntohs(header->engine_tag);
    uint16_t version = ntohs(header->version);
    const exporter_key_t key = {.version = version, .id = engine_tag, .ip = fs->ipAddr};

    // fast cache
    if (fs->last_exp && EXPORTER_KEY_EQUAL(fs->last_key, key)) {
        return fs->last_exp;
    }

    exporter_table_t *tab = &fs->exporters;
    // Check load factor in case we need a new slot
    if ((tab->count * 4) >= (tab->capacity * 3)) {
        // expand exporter index
        expand_exporter_table(tab);
        tab = &fs->exporters;
    }

    // not identical of last exporter
    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = tab->capacity - 1;
    uint32_t i = hash & mask;

    for (;;) {
        exporter_entry_t *e = &tab->entries[i];
        // key does not exists - create new exporter
        if (!e->in_use) {
            sampler_record_v4_t sampler_record_v4[2] = {0};
            size_t recordSize = sizeof(exporter_info_record_v4_t);

            // in theory, 2 samplers may exist:
            // one from command line and one in the header
            size_t numSampler = getSampler(header, sampler_record_v4);
            recordSize += (numSampler * sizeof(sampler_record_v4_t));

            void *info = calloc(1, recordSize);
            if (info == NULL) {
                LogError("Process_v5: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            // create new exporter
            *e = (exporter_entry_t){.key = key, .sequence = UINT32_MAX, .sysID = AssignExporterID(), .in_use = 1, .info = info};
            tab->count++;

            *(e->info) = (exporter_info_record_v4_t){.header = (record_header_t){.type = ExporterInfoRecordV4Type, .size = recordSize},
                                                     .version = key.version,
                                                     .id = key.id,
                                                     .sysID = e->sysID,
                                                     .sampler_capacity = numSampler};
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->v5 = (exporter_v5_t){0};

            char ipstr[INET6_ADDRSTRLEN];
            ip128_2_str(&fs->ipAddr, ipstr);
            // precompute extension bitmap, for extensions always present
            // add optional extension at runtime
            uint64_t bitMap = 0;
            BitMapSet(bitMap, EXgenericFlowID);
            BitMapSet(bitMap, EXipv4FlowID);

            if (fs->sa_family == PF_INET6) {
                BitMapSet(bitMap, EXipReceivedV6ID);
                // max proposed output record size
                e->v5.outRecordSize = baseOffset + extensionSize + EXipReceivedV6Size;
                dbg_printf("Process_v5: New IPv6 exporter %s - add EXipReceivedV6\n", ipstr);
            } else {
                BitMapSet(bitMap, EXipReceivedV4ID);
                // max proposed output record size
                e->v5.outRecordSize = baseOffset + extensionSize + EXipReceivedV4Size;
                dbg_printf("Process_v5: New IPv4 exporter %s - add EXipReceivedV4\n", ipstr);
            }
            e->v5.bitMap = bitMap;

            LogInfo("Process_v5: New exporter: SysID: %u, engine id %u, type %u, IP: %s", e->info->sysID, (engine_tag & 0xFF),
                    ((engine_tag >> 8) & 0xFF), ipstr);
            for (int i = 0; i < 2; i++) {
                if (sampler_record_v4[i].inUse) {
                    e->info->samplers[i] = sampler_record_v4[i];
                    e->info->sampler_count++;
                    e->sampler_cache[i].ptr = &e->info->samplers[i];
                    e->sampler_count++;
                    LogInfo(
                        "Process_v5: New exporter: SysID: %u, IP: %s, Sampling: selectorID: %lld, algorithm: %i, packet interval: %u, packet space: "
                        "%u",
                        e->info->sysID, ipstr, sampler_record_v4[i].selectorID, sampler_record_v4[i].algorithm, sampler_record_v4[i].packetInterval,
                        sampler_record_v4[i].spaceInterval);
                }
            }
            e->sysID = e->info->sysID;

            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            fs->last_key = key;
            fs->last_exp = e;
            return e;
        }

        dbg_assert(tab->count < tab->capacity);
        // next slot
        i = (i + 1) & mask;
    }

    // unreached
    return NULL;

}  // End of getExporter

void Process_v5_v7(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // v7 is treated as v5. it differs by the sequencer skip count only
    // map v5 data structure to input buffer
    netflow_v5_header_t *v5_header = (netflow_v5_header_t *)in_buff;

    exporter_entry_t *exporter = getExporter(fs, v5_header);
    if (!exporter) {
        LogError("Process_v5: Exporter NULL: Abort v5/v7 record processing");
        return;
    }
    exporter->packets++;

    uint16_t version = ntohs(v5_header->version);

    // handle sampling once for this exporter
    // for v5 all samplers fit into the cache
    uint64_t interval = 0x3fff & ntohs(v5_header->sampling_interval);
    if (unlikely(exporter->sampler_count > 0)) {
        // SAMPLER_OVERWRITE
        sampler_record_v4_t *sampler = exporter->sampler_cache[0].ptr;
        if (sampler) {
            if (sampler->selectorID == SAMPLER_OVERWRITE) {
                interval = sampler->spaceInterval + 1;
                dbg_printf("Has overwrite sampler with interval: %llu\n", interval);
            } else if (interval == 0) {
                // SAMPLER_DEFAULT, if no sampling announced in header
                dbg_printf("Has other sampler with interval: %llu\n", interval);
                interval = sampler->spaceInterval + 1;
            }
        }
    }

    int rawRecordSize = version == 5 ? NETFLOW_V5_RECORD_LENGTH : NETFLOW_V7_RECORD_LENGTH;

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    uint16_t maxRecords = version == 5 ? NETFLOW_V5_MAX_RECORDS : NETFLOW_V7_MAX_RECORDS;

    int done = 0;
    while (!done) {
        // count check
        uint16_t count = ntohs(v5_header->count);
        if (count == 0 || count > maxRecords) {
            char ipstr[INET6_ADDRSTRLEN];
            LogError("Process_v5: Exporter: %s Invalid record count %u. Abort v5/v7 record processing", ip128_2_str(&fs->ipAddr, ipstr), count);
            return;
        }
        // input buffer size check for all expected records
        if (size_left < (NETFLOW_V5_HEADER_LENGTH + count * rawRecordSize)) {
            char ipstr[INET6_ADDRSTRLEN];
            LogError("Process_v5: Exporter: %s Not enough data to process v5 record. Abort v5/v7 record processing", ip128_2_str(&fs->ipAddr, ipstr));
            return;
        }

        // set output buffer memory
        uint8_t *outBuff = GetCurrentCursor(fs->dataBlock);
        if (!IsAvailable(fs->dataBlock, count * exporter->v5.outRecordSize)) {
            // flush block - get an empty one
            fs->dataBlock = PushBlock(fs->blockQueue, fs->dataBlock);
            // map output memory buffer
            outBuff = GetCursor(fs->dataBlock);
        }

        uint32_t seq = ntohl(v5_header->flow_sequence);
        if (exporter->sequence != UINT32_MAX) {
            uint32_t distance = seq - exporter->sequence;  // wrap-safe

            if (distance != exporter->v5.last_count) {
                fs->stat_record.sequence_failure++;
                exporter->sequence_failure++;
            }
        }

        exporter->sequence = seq;
        exporter->v5.last_count = count;

        uint32_t sysUptime = ntohl(v5_header->SysUptime);
        uint32_t unixSecs = ntohl(v5_header->unix_secs);
        uint32_t unixNsecs = ntohl(v5_header->unix_nsecs);

        /* calculate boot time in msec */
        uint64_t msecBoot = ((uint64_t)unixSecs * 1000 + ((uint64_t)unixNsecs / 1000000)) - (uint64_t)sysUptime;

        // process all records
        netflow_v5_record_t *v5_record = (netflow_v5_record_t *)((void *)v5_header + NETFLOW_V5_HEADER_LENGTH);

        uint16_t engine_tag = ntohs(v5_header->engine_tag);
        uint8_t engineType = (engine_tag >> 8) & 0xFF;
        uint8_t engineID = (engine_tag & 0xFF);

        /* loop over each records associated with this header */
        uint32_t outSize = 0;
        for (int i = 0; i < count; i++) {
            // zero entire fixed-size record at once
            memset(outBuff, 0, exporter->v5.outRecordSize);
            recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)outBuff;
            recordHeader->type = V4Record;
            recordHeader->extBitmap = exporter->v5.bitMap;
            recordHeader->engineType = engineType;
            recordHeader->engineID = engineID;
            recordHeader->exporterID = exporter->sysID;
            recordHeader->nfVersion = 5;

            // copy precomputed offset table
            uint16_t *offset = (uint16_t *)(outBuff + sizeof(recordHeaderV4_t));
            uint32_t nextOffset = baseOffset;

            // fill extensions
            EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(outBuff + nextOffset);
            *offset++ = nextOffset;
            nextOffset += EXgenericFlowSize;
            genericFlow->msecReceived = msecReceived;
            genericFlow->inPackets = ntohl(v5_record->dPkts);
            genericFlow->inBytes = ntohl(v5_record->dOctets);
            genericFlow->srcPort = ntohs(v5_record->srcPort);
            genericFlow->dstPort = ntohs(v5_record->dstPort);
            genericFlow->proto = v5_record->prot;
            genericFlow->srcTos = v5_record->tos;
            genericFlow->tcpFlags = v5_record->tcp_flags;

            EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)(outBuff + nextOffset);
            *offset++ = nextOffset;
            nextOffset += EXipv4FlowSize;
            ipv4Flow->srcAddr = ntohl(v5_record->srcaddr);
            ipv4Flow->dstAddr = ntohl(v5_record->dstaddr);

            if (v5_record->input || v5_record->output) {
                BitMapSet(recordHeader->extBitmap, EXinterfaceID);
                EXinterface_t *interface = (EXinterface_t *)(outBuff + nextOffset);
                *offset++ = nextOffset;
                nextOffset += EXinterfaceSize;
                interface->input = ntohs(v5_record->input);
                interface->output = ntohs(v5_record->output);
            }

            if (v5_record->src_as || v5_record->dst_as) {
                BitMapSet(recordHeader->extBitmap, EXasInfoID);
                EXasInfo_t *asInfo = (EXasInfo_t *)(outBuff + nextOffset);
                *offset++ = nextOffset;
                nextOffset += EXasInfoSize;
                asInfo->srcAS = ntohs(v5_record->src_as);
                asInfo->dstAS = ntohs(v5_record->dst_as);
            }

            if (v5_record->nexthop) {
                BitMapSet(recordHeader->extBitmap, EXasRoutingV4ID);
                EXasRoutingV4_t *nexthop = (EXasRoutingV4_t *)(outBuff + nextOffset);
                *offset++ = nextOffset;
                nextOffset += EXasRoutingV4Size;
                nexthop->nextHop = ntohl(v5_record->nexthop);
            }

            // post process data
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
            if (Last > sysUptime && ((Last - sysUptime) > 100000)) {
                msecStart -= 0x100000000LL;
                msecEnd -= 0x100000000LL;
            }

            genericFlow->msecFirst = msecStart;
            genericFlow->msecLast = msecEnd;

            UpdateFirstLast(fs, msecStart, msecEnd);

            // received-IP extension
            *offset++ = nextOffset;
            if (fs->sa_family == PF_INET6) {
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)(outBuff + nextOffset);
                nextOffset += EXipReceivedV6Size;
                uint64_t *ipv6 = (uint64_t *)fs->ipAddr.bytes;
                ipReceivedV6->ip[0] = ntohll(ipv6[0]);
                ipReceivedV6->ip[1] = ntohll(ipv6[1]);
                dbg_printf("Add IPv6 route IP extension\n");
            } else {
                EXipReceivedV4_t *ipReceivedV4 = (EXipReceivedV4_t *)(outBuff + nextOffset);
                nextOffset += EXipReceivedV4Size;
                uint32_t ip;
                memcpy(&ip, fs->ipAddr.bytes + 12, 4);
                ipReceivedV4->ip = ntohl(ip);
                dbg_printf("Add IPv4 route IP extension\n");
            }

            // done - update header
            recordHeader->numExtensions = __builtin_popcountll(recordHeader->extBitmap);
            recordHeader->size = nextOffset;

            // sampling
            if (unlikely(interval > 0)) {
                genericFlow->inPackets *= interval;
                genericFlow->inBytes *= interval;
                SetFlag(recordHeader->flags, V4_FLAG_SAMPLED);
                dbg_printf("Apply sampling rate: %llu\n", interval);
            }

            // Update stats
            switch (genericFlow->proto) {
                case IPPROTO_ICMP:
                    fs->stat_record.numflows_icmp++;
                    fs->stat_record.numpackets_icmp += genericFlow->inPackets;
                    fs->stat_record.numbytes_icmp += genericFlow->inBytes;
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
                    fs->stat_record.numflows_tcp++;
                    fs->stat_record.numpackets_tcp += genericFlow->inPackets;
                    fs->stat_record.numbytes_tcp += genericFlow->inBytes;
                    break;
                case IPPROTO_UDP:
                    fs->stat_record.numflows_udp++;
                    fs->stat_record.numpackets_udp += genericFlow->inPackets;
                    fs->stat_record.numbytes_udp += genericFlow->inBytes;
                    break;
                default:
                    fs->stat_record.numflows_other++;
                    fs->stat_record.numpackets_other += genericFlow->inPackets;
                    fs->stat_record.numbytes_other += genericFlow->inBytes;
            }
            exporter->flows++;
            fs->stat_record.numflows++;
            fs->stat_record.numpackets += genericFlow->inPackets;
            fs->stat_record.numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeader);
            UpdateMetric(fs->Ident, exporterIdent, genericFlow);

            if (printRecord) {
                flow_record_short(stdout, recordHeader);
            }

            // advance to next input flow record
            outBuff += recordHeader->size;
            outSize += recordHeader->size;
            v5_record = (netflow_v5_record_t *)((void *)v5_record + rawRecordSize);

            if (recordHeader->size > exporter->v5.outRecordSize) {
                LogError("Process_v5: Record size check failed! Expected: %u, counted: %u\n", exporter->v5.outRecordSize, recordHeader->size);
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
