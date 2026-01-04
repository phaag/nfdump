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

#include "netflow_v1.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "collector.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "util.h"

#define NETFLOW_V1_HEADER_LENGTH 16
#define NETFLOW_V1_RECORD_LENGTH 48
#define NETFLOW_V1_MAX_RECORDS 24

/* v1 structures */
typedef struct netflow_v1_header {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
} netflow_v1_header_t;

typedef struct netflow_v1_record {
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
    uint16_t pad1;
    uint8_t prot;
    uint8_t tos;
    uint8_t tcp_flags;
    uint8_t pad2[7];
} netflow_v1_record_t;

/* module limited globals */
static int printRecord;
static uint32_t baseRecordSize;

static inline exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v1_header_t *header);

/* functions */

int Init_v1(int verbose) {
    printRecord = verbose > 2;
    baseRecordSize = sizeof(recordHeaderV3_t) + EXgenericFlowSize + EXipv4FlowSize + EXflowMiscSize + EXipNextHopV4Size;

    LogVerbose("Init v1");
    return 1;
}  // End of Init_v1

// for v1, there is only one exporter possible - however, keep full code - compiler will optimise out anyway
static inline exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v1_header_t *header) {
    const exporter_key_t key = {.version = VERSION_NETFLOW_V1, .id = 0, .ip = fs->ipAddr};

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
            // create new exporter
            e->key = key;
            e->packets = 0;
            e->flows = 0;
            e->sequence_failure = 0;
            e->sequence = UINT32_MAX;
            e->in_use = 1;
            tab->count++;

            e->info = (exporter_info_record_t){.header = (record_header_t){.type = ExporterInfoRecordType, .size = sizeof(exporter_info_record_t)},
                                               .version = key.version,
                                               .id = key.id,
                                               .fill = 0,
                                               .sysid = 0};
            memcpy(e->info.ip, fs->ipAddr.bytes, 16);

            e->version.v1 = (exporter_v1_t){0};

            char *ipstr = ip128_2_str(&fs->ipAddr);
            if (fs->sa_family == PF_INET6) {
                e->version.v1.outRecordSize = baseRecordSize + EXipReceivedV6Size;
                dbg_printf("Process_v1: New IPv6 exporter %s - add EXipReceivedV6\n", ipstr);
            } else {
                e->version.v1.outRecordSize = baseRecordSize + EXipReceivedV4Size;
                dbg_printf("Process_v1: New IPv4 exporter %s - add EXipReceivedV4\n", ipstr);
            }

            FlushInfoExporter(fs, &e->info);
            LogInfo("Process_v1: SysID: %u, New exporter: IP: %s\n", e->info.sysid, ipstr);

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

void Process_v1(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // map v1 data structure to input buffer
    netflow_v1_header_t *v1_header = (netflow_v1_header_t *)in_buff;

    exporter_entry_t *exporter = getExporter(fs, v1_header);
    if (!exporter) {
        LogError("Process_v1: NULL Exporter: Abort v1 record processing");
        return;
    }
    exporter->packets++;

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    int done = 0;
    while (!done) {
        // count check
        uint16_t count = ntohs(v1_header->count);
        if (count > NETFLOW_V1_MAX_RECORDS) {
            LogError("Process_v1: Unexpected record count in header: %i. Abort v1 record processing", count);
            return;
        }

        // input buffer size check for all expected records
        if (size_left < (NETFLOW_V1_HEADER_LENGTH + count * NETFLOW_V1_RECORD_LENGTH)) {
            LogError("Process_v1: Not enough data to process v1 record. Abort v1 record processing");
            return;
        }

        // output buffer size check for all expected records
        void *outBuff = GetCurrentCursor(fs->dataBlock);
        if (!IsAvailable(fs->dataBlock, count * exporter->version.v1.outRecordSize)) {
            // flush block - get an empty one
            fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
            // map output memory buffer
            outBuff = GetCursor(fs->dataBlock);
        }

        v1_header->SysUptime = ntohl(v1_header->SysUptime);
        v1_header->unix_secs = ntohl(v1_header->unix_secs);
        v1_header->unix_nsecs = ntohl(v1_header->unix_nsecs);

        /* calculate boot time in msec */
        uint64_t msecBoot =
            ((uint64_t)(v1_header->unix_secs) * 1000 + ((uint64_t)(v1_header->unix_nsecs) / 1000000)) - (uint64_t)(v1_header->SysUptime);

        // process all records
        netflow_v1_record_t *v1_record = (netflow_v1_record_t *)((void *)v1_header + NETFLOW_V1_HEADER_LENGTH);

        /* loop over each records associated with this header */
        uint32_t outSize = 0;
        for (int i = 0; i < count; i++) {
            // header data gets initialized by macro
            AddV3Header(outBuff, recordHeader);
            recordHeader->exporterID = exporter->info.sysid;
            recordHeader->nfversion = 1;

            PushExtension(recordHeader, EXgenericFlow, genericFlow);
            genericFlow->msecReceived = msecReceived;
            genericFlow->inPackets = ntohl(v1_record->dPkts);
            genericFlow->inBytes = ntohl(v1_record->dOctets);
            genericFlow->srcPort = ntohs(v1_record->srcPort);
            genericFlow->dstPort = ntohs(v1_record->dstPort);
            genericFlow->proto = v1_record->prot;
            genericFlow->srcTos = v1_record->tos;
            genericFlow->tcpFlags = v1_record->tcp_flags;

            PushExtension(recordHeader, EXipv4Flow, ipv4Flow);
            ipv4Flow->srcAddr = ntohl(v1_record->srcaddr);
            ipv4Flow->dstAddr = ntohl(v1_record->dstaddr);

            if (v1_record->input || v1_record->output) {
                PushExtension(recordHeader, EXflowMisc, flowMisc);
                flowMisc->input = ntohs(v1_record->input);
                flowMisc->output = ntohs(v1_record->output);
            }

            if (v1_record->nexthop) {
                PushExtension(recordHeader, EXipNextHopV4, ipNextHopV4);
                ipNextHopV4->ip = ntohl(v1_record->nexthop);
            }

            // post process required data

            // calculate msec values first/last
            uint64_t First = ntohl(v1_record->First);
            uint64_t Last = ntohl(v1_record->Last);
            uint64_t msecStart, msecEnd;

            if (First > Last) {
                // First in msec, in case of msec overflow, between start and end
                msecStart = msecBoot - 0x100000000LL + First;
            } else {
                msecStart = msecBoot + First;
            }

            // end time in msecs
            msecEnd = Last + msecBoot;

            // if overflow happened after flow ended but before got exported
            if (Last > v1_header->SysUptime) {
                msecStart -= 0x100000000LL;
                msecEnd -= 0x100000000LL;
            }
            genericFlow->msecFirst = msecStart;
            genericFlow->msecLast = msecEnd;

            UpdateFirstLast(fs->nffile, msecStart, msecEnd);

            // router IP
            if (fs->sa_family == PF_INET6) {
                PushExtension(recordHeader, EXipReceivedV6, ipReceivedV6);
                memcpy((void *)ipReceivedV6->ip, fs->ipAddr.bytes, 16);
            } else {
                PushExtension(recordHeader, EXipReceivedV4, ipReceivedV4);
                memcpy(&ipReceivedV4->ip, fs->ipAddr.bytes + 12, 4);
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

            // advance output buffer
            outBuff += recordHeader->size;
            outSize += recordHeader->size;
            // advance input buffer to next flow record
            v1_record = (netflow_v1_record_t *)((void *)v1_record + NETFLOW_V1_RECORD_LENGTH);

            if (recordHeader->size > exporter->version.v1.outRecordSize) {
                LogError("Process_v1: Record size check failed! Expected: %u, counted: %u\n", exporter->version.v1.outRecordSize, recordHeader->size);
            }

        }  // End of foreach v1 record

        // update file record size ( -> output buffer size )
        fs->dataBlock->NumRecords += count;
        fs->dataBlock->size += outSize;

        // still to go for this many input bytes
        size_left -= NETFLOW_V1_HEADER_LENGTH + count * NETFLOW_V1_RECORD_LENGTH;

        // next header
        v1_header = (netflow_v1_header_t *)v1_record;

        // should never be < 0
        done = size_left <= 0;

    }  // End of while !done

    return;

} /* End of Process_v1 */
