/*
 *  Copyright (c) 2025-2026, Peter Haag
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

#include "nfd_raw.h"

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

#include "bookkeeper.h"
#include "collector.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV3.h"
#include "output_short.h"
#include "util.h"

/* module limited globals */
static int printRecord;

static inline exporter_entry_t *getExporter(FlowSource_t *fs, nfd_header_t *header);

/* functions */

#include "nffile_inline.c"

int Init_pcapd(int verbose) {
    printRecord = verbose;
    return 1;
}  // End of Init_pcapd

static inline exporter_entry_t *getExporter(FlowSource_t *fs, nfd_header_t *header) {
    const exporter_key_t key = {.version = VERSION_NFDUMP, .id = 0, .ip = fs->ipAddr};

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

            e->version.nfd = (exporter_nfd_t){0};

            FlushInfoExporter(fs, &e->info);

            char ipstr[INET6_ADDRSTRLEN];
            LogInfo("Process_nfd: SysID: %u, New exporter: IP: %s\n", e->info.sysid, ipstr, ip128_2_str(&fs->ipAddr, ipstr));

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

static void *GetExtension(recordHeaderV3_t *recordHeader, int extensionID) {
    size_t recSize = sizeof(recordHeaderV3_t);
    elementHeader_t *elementHeader = (elementHeader_t *)((void *)recordHeader + recSize);
    void *extension = NULL;
    dbg_printf("Check for extension: %u\n", extensionID);
    while (extension == NULL && recSize < recordHeader->size) {
        dbg_printf("Next extension: %u, size: %u\n", elementHeader->type, elementHeader->length);
        if (elementHeader->type == extensionID) {
            extension = (void *)elementHeader + sizeof(elementHeader_t);
        } else {
            // prevent potential endless loop with buggy record
            if (elementHeader->length == 0) return NULL;
            recSize += elementHeader->length;
            elementHeader = (elementHeader_t *)((void *)recordHeader + recSize);
        }
    }
    return extension;

}  // End of GetExtension

void Process_nfd(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // map pacpd data structure to input buffer
    nfd_header_t *pcapd_header = (nfd_header_t *)in_buff;

    exporter_entry_t *exporter = getExporter(fs, pcapd_header);
    if (!exporter) {
        LogError("Process_nfd: NULL Exporter: Skip pcapd record processing");
        return;
    }
    exporter->packets++;

    // reserve space in output stream for EXipReceivedVx
    uint32_t receivedSize = 0;
    if (fs->sa_family == PF_INET6)
        receivedSize = EXipReceivedV6Size;
    else
        receivedSize = EXipReceivedV4Size;

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    uint16_t count = ntohl(pcapd_header->numRecord);
    uint32_t numRecords = 0;
    dbg_printf("Process nfd packet: %" PRIu64 ", size: %zd, recordCnt: %u\n", exporter->packets, in_buff_cnt, count);

    if ((sizeof(nfd_header_t) + sizeof(recordHeaderV3_t)) > size_left) {
        LogError("Process_nfd: Not enough data.");
        return;
    }

    // 1st record
    recordHeaderV3_t *recordHeaderV3 = in_buff + sizeof(nfd_header_t);
    size_left -= sizeof(nfd_header_t);
    do {
        // output buffer size check
        dbg_printf("Next record - type: %u, size: %u\n", recordHeaderV3->type, recordHeaderV3->size);
        // verify received record.
        if (VerifyV3Record(recordHeaderV3) == 0) {
            LogError("Process_nfd: Corrupt nfd record: expected %u records, processd: %u", count, numRecords);
            return;
        }

        if (recordHeaderV3->size > size_left) {
            LogError("Process_nfd: record size error. Size v3header: %u > size left: %zd", recordHeaderV3->size, size_left);
            LogError("Process_nfd: expected %u records, processd: %u", count, numRecords);
            return;
        }

        if (!IsAvailable(fs->dataBlock, recordHeaderV3->size + receivedSize)) {
            // flush block - get an empty one
            fs->dataBlock = WriteBlock(fs->nffile, fs->dataBlock);
        }

        // copy record
        void *buffPtr = GetCurrentCursor(fs->dataBlock);
        memcpy(buffPtr, (void *)recordHeaderV3, recordHeaderV3->size);

        // add router IP at the end of copied record
        recordHeaderV3_t *copiedV3 = buffPtr;
        // add router IP

        if (GetExtension(recordHeaderV3, EXipReceivedV4ID) == NULL && GetExtension(recordHeaderV3, EXipReceivedV6ID) == NULL) {
            // no ip received extension
            // push IP received
            if (fs->sa_family == PF_INET6) {
                PushExtension(copiedV3, EXipReceivedV6, ipReceivedV6);
                uint64_t *ipv6 = (uint64_t *)fs->ipAddr.bytes;
                ipReceivedV6->ip[0] = ntohll(ipv6[0]);
                ipReceivedV6->ip[1] = ntohll(ipv6[1]);
                dbg_printf("Add IPv6 router IP extension\n");
            } else {
                PushExtension(copiedV3, EXipReceivedV4, ipReceivedV4);
                uint32_t ipv4;
                memcpy(&ipv4, fs->ipAddr.bytes + 12, 4);
                ipReceivedV4->ip = ntohl(ipv4);
                dbg_printf("Add IPv4 router IP extension\n");
            }
        } else {
            dbg_printf("Found existing IP received extension\n");
        }

        dbg_printf("Record: %u elements, size: %u\n\n", copiedV3->numElements, copiedV3->size);

        EXgenericFlow_t *genericFlow = GetExtension(recordHeaderV3, EXgenericFlowID);
        if (genericFlow) {
            genericFlow->msecReceived = msecReceived;

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
            fs->nffile->stat_record->numflows++;
            fs->nffile->stat_record->numpackets += genericFlow->inPackets;
            fs->nffile->stat_record->numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(recordHeaderV3);
            UpdateMetric(fs->nffile->ident, exporterIdent, genericFlow);
        }

        numRecords++;
        exporter->flows++;

        if (printRecord) {
            flow_record_short(stdout, copiedV3);
        }

        // update size_left
        size_left -= recordHeaderV3->size;

        // update record block
        fs->dataBlock->size += copiedV3->size;
        fs->dataBlock->NumRecords++;

        // advance input buffer to next flow record
        recordHeaderV3 = (recordHeaderV3_t *)((void *)recordHeaderV3 + recordHeaderV3->size);
    } while (size_left > sizeof(recordHeaderV3_t));

    if (size_left) LogInfo("Process_nfd(): bytes left in buffer: %zu", size_left);

    if (numRecords != count) LogInfo("Process_nfd(): expected %u records, processd: %u", count, numRecords);

    return;

} /* End of Process_nfd */
