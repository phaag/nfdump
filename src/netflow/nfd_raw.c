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
#include "logging.h"
#include "metric.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "nfxV4.h"
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
    (void)header;
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
            void *info = calloc(1, sizeof(exporter_info_record_v4_t));
            if (info == NULL) {
                LogError("Process_nfd: calloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            // create new exporter
            *e = (exporter_entry_t){.key = key, .sequence = UINT32_MAX, .sysID = AssignExporterID(), .in_use = 1, .info = info};
            tab->count++;

            *(e->info) =
                (exporter_info_record_v4_t){.header = (record_header_t){.type = ExporterInfoRecordV4Type, .size = sizeof(exporter_info_record_v4_t)},
                                            .version = key.version,
                                            .id = key.id,
                                            .sysID = e->sysID};
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->nfd = (exporter_nfd_t){0};

            char ipstr[INET6_ADDRSTRLEN];
            LogInfo("Process_nfd: SysID: %u, New exporter: IP: %s\n", e->sysID, ip128_2_str(&fs->ipAddr, ipstr));

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

static inline recordHeaderV4_t *InsertEXipReceived(void *buffPtr, const recordHeaderV4_t *recordHeaderV4, uint32_t outputSize, uint16_t receivedExtID,
                                                   uint32_t receivedSize, FlowSource_t *fs) {
    uint8_t oldNumExt = recordHeaderV4->numExtensions;
    uint8_t newNumExt = oldNumExt + 1;
    uint32_t oldOTSize = ALIGN8(oldNumExt * sizeof(uint16_t));
    uint32_t newOTSize = ALIGN8(newNumExt * sizeof(uint16_t));
    uint32_t offsetGrowth = newOTSize - oldOTSize;

    // Insert position: count set bits in bitmap below receivedExtID
    uint32_t insertPos = __builtin_popcountll(recordHeaderV4->extBitmap & ((1ULL << receivedExtID) - 1));

    // Copy and update header
    recordHeaderV4_t *copiedV4 = (recordHeaderV4_t *)buffPtr;
    memcpy(copiedV4, recordHeaderV4, sizeof(recordHeaderV4_t));
    copiedV4->numExtensions = newNumExt;
    copiedV4->extBitmap |= (1ULL << receivedExtID);
    copiedV4->size = outputSize;

    // Build new offset table with adjusted offsets
    uint16_t *oldOffsets = V4OffsetTable(recordHeaderV4);
    uint16_t *newOffsets = V4OffsetTable(copiedV4);
    for (uint32_t j = 0; j < insertPos; j++) {
        newOffsets[j] = oldOffsets[j] + offsetGrowth;
    }
    // New extension data goes at end of existing data (shifted by offset table growth)
    newOffsets[insertPos] = recordHeaderV4->size + offsetGrowth;
    for (uint32_t j = insertPos; j < oldNumExt; j++) {
        newOffsets[j + 1] = oldOffsets[j] + offsetGrowth;
    }
    // Zero-pad offset table alignment area
    uint32_t usedBytes = newNumExt * sizeof(uint16_t);
    if (usedBytes < newOTSize) {
        memset((uint8_t *)newOffsets + usedBytes, 0, newOTSize - usedBytes);
    }

    // Copy extension data from input
    void *oldData = (uint8_t *)recordHeaderV4 + sizeof(recordHeaderV4_t) + oldOTSize;
    void *newData = (uint8_t *)copiedV4 + sizeof(recordHeaderV4_t) + newOTSize;
    uint32_t dataSize = recordHeaderV4->size - sizeof(recordHeaderV4_t) - oldOTSize;
    memcpy(newData, oldData, dataSize);

    // Append EXipReceived extension data
    void *extPtr = (uint8_t *)copiedV4 + copiedV4->size - receivedSize;
    if (fs->sa_family == PF_INET6) {
        EXipReceivedV6_t *ipRcvd = (EXipReceivedV6_t *)extPtr;
        uint64_t *ipv6 = (uint64_t *)fs->ipAddr.bytes;
        ipRcvd->ip[0] = ntohll(ipv6[0]);
        ipRcvd->ip[1] = ntohll(ipv6[1]);
        dbg_printf("Add IPv6 router IP extension\n");
    } else {
        EXipReceivedV4_t *ipRcvd = (EXipReceivedV4_t *)extPtr;
        uint32_t ipv4;
        memcpy(&ipv4, fs->ipAddr.bytes + 12, 4);
        ipRcvd->ip = ntohl(ipv4);
        dbg_printf("Add IPv4 router IP extension\n");
    }

    return copiedV4;
}  // End of InsertEXipReceived

void Process_nfd(void *in_buff, ssize_t in_buff_cnt, FlowSource_t *fs) {
    // map pacpd data structure to input buffer
    nfd_header_t *pcapd_header = (nfd_header_t *)in_buff;

    exporter_entry_t *exporter = getExporter(fs, pcapd_header);
    if (!exporter) {
        LogError("Process_nfd: NULL Exporter: Skip pcapd record processing");
        return;
    }
    exporter->packets++;

    // EXipReceived extension parameters
    uint32_t receivedSize;
    uint16_t receivedExtID;
    if (fs->sa_family == PF_INET6) {
        receivedSize = EXipReceivedV6Size;
        receivedExtID = EXipReceivedV6ID;
    } else {
        receivedSize = EXipReceivedV4Size;
        receivedExtID = EXipReceivedV4ID;
    }

    // this many data to process
    ssize_t size_left = in_buff_cnt;

    // time received for this packet
    uint64_t msecReceived = ((uint64_t)fs->received.tv_sec * 1000LL) + (uint64_t)((uint64_t)fs->received.tv_usec / 1000LL);

    uint32_t count = ntohl(pcapd_header->numRecord);
    uint32_t numRecords = 0;
    dbg_printf("Process nfd packet: %" PRIu64 ", size: %zd, recordCnt: %u\n", exporter->packets, in_buff_cnt, count);

    if (count == 0) {
        LogError("Process_nfd: Empty packet.");
        return;
    }

    if ((sizeof(nfd_header_t) + sizeof(recordHeaderV4_t)) > size_left) {
        LogError("Process_nfd: Not enough data.");
        return;
    }

    // 1st record
    recordHeaderV4_t *recordHeaderV4 = in_buff + sizeof(nfd_header_t);
    size_left -= sizeof(nfd_header_t);
    while (size_left >= (ssize_t)sizeof(recordHeaderV4_t)) {
        // output buffer size check
        dbg_printf("Next record - type: %u, size: %u\n", recordHeaderV4->type, recordHeaderV4->size);
        // verify received record.
        if (VerifyV4Record(recordHeaderV4) == 0) {
            LogError("Process_nfd: Corrupt nfd record: expected %u records, processd: %u", count, numRecords);
            return;
        }

        if (recordHeaderV4->size > size_left) {
            LogError("Process_nfd: record size error. Size V4header: %u > size left: %zd", recordHeaderV4->size, size_left);
            LogError("Process_nfd: expected %u records, processd: %u", count, numRecords);
            return;
        }

        // Check if record already has EXipReceived
        int hasReceived = (recordHeaderV4->extBitmap & ((1ULL << EXipReceivedV4ID) | (1ULL << EXipReceivedV6ID))) != 0;

        // Calculate output record size accounting for potential EXipReceived insertion
        uint32_t outputSize;
        if (hasReceived) {
            outputSize = recordHeaderV4->size;
        } else {
            uint32_t oldOTSize = ALIGN8(recordHeaderV4->numExtensions * sizeof(uint16_t));
            uint32_t newOTSize = ALIGN8((recordHeaderV4->numExtensions + 1) * sizeof(uint16_t));
            outputSize = recordHeaderV4->size + (newOTSize - oldOTSize) + receivedSize;
        }

        if (!IsAvailable(fs->dataBlock, outputSize)) {
            // flush block - get an empty one
            fs->dataBlock = PushBlock(fs->blockQueue, fs->dataBlock);
        }

        void *buffPtr = GetCurrentCursor(fs->dataBlock);
        recordHeaderV4_t *copiedV4;

        if (hasReceived) {
            // Record already has EXipReceived - plain copy
            memcpy(buffPtr, (void *)recordHeaderV4, recordHeaderV4->size);
            copiedV4 = (recordHeaderV4_t *)buffPtr;
            dbg_printf("Found existing IP received extension\n");
        } else {
            copiedV4 = InsertEXipReceived(buffPtr, recordHeaderV4, outputSize, receivedExtID, receivedSize, fs);
        }

        dbg_printf("Record: %u elements, size: %u\n\n", copiedV4->numExtensions, copiedV4->size);

        EXgenericFlow_t *genericFlow = GetExtension(copiedV4, EXgenericFlow);
        if (genericFlow) {
            genericFlow->msecReceived = msecReceived;

            // Update stats
            switch (genericFlow->proto) {
                case IPPROTO_ICMP:
                    fs->stat_record.numflows_icmp++;
                    fs->stat_record.numpackets_icmp += genericFlow->inPackets;
                    fs->stat_record.numbytes_icmp += genericFlow->inBytes;
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
            fs->stat_record.numflows++;
            fs->stat_record.numpackets += genericFlow->inPackets;
            fs->stat_record.numbytes += genericFlow->inBytes;

            uint32_t exporterIdent = MetricExpporterID(copiedV4);
            UpdateMetric(fs->Ident, exporterIdent, genericFlow);
        }

        numRecords++;
        exporter->flows++;

        if (printRecord) {
            flow_record_short(stdout, copiedV4);
        }

        // update size_left
        size_left -= recordHeaderV4->size;

        // update record block
        fs->dataBlock->size += copiedV4->size;
        fs->dataBlock->NumRecords++;

        // advance input buffer to next flow record
        recordHeaderV4 = (recordHeaderV4_t *)((void *)recordHeaderV4 + recordHeaderV4->size);
    }

    if (size_left) LogInfo("Process_nfd(): bytes left in buffer: %zu", size_left);

    if (numRecords != count) LogInfo("Process_nfd(): expected %u records, processd: %u", count, numRecords);

    return;

} /* End of Process_nfd */
