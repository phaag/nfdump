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
#include "exporter.h"
#include "id.h"
#include "logging.h"
#include "metric.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfnet.h"
#include "nfxV4.h"
#include "output_short.h"
#include "util.h"

#define NETFLOW_V1_MAX_RECORDS 24

/* v1 structures */
typedef struct netflow_v1_header {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
} netflow_v1_header_t;
#define NETFLOW_V1_HEADER_LENGTH 16

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
#define NETFLOW_V1_RECORD_LENGTH 48

// module limited globals
static int printRecord;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// netflow v1 has at max all these extensions
// always EXgenericFlow, EXipv4Flow, optional at runtime EXinterface, EXasRoutingV4
// including EXipReceivedV4 or EXipReceivedV4, added at runtime
static const uint32_t extensionSize = EXgenericFlowSize + EXipv4FlowSize + EXinterfaceSize + EXasRoutingV4Size;

// baseOffset of first extension with max 5 extension.
// offset table size = 16 - wastes 12bytes max without optional extensions
#define NUMV1EXTENSIONS 5
static const uint32_t offsetSize = ALIGN8(NUMV1EXTENSIONS * sizeof(uint16_t));
static const uint32_t baseOffset = sizeof(recordHeaderV4_t) + offsetSize;

// function prototypes
static inline exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v1_header_t *header);

/* functions */

int Init_v1(int verbose) {
    LogVerbose("Init v1");
    printRecord = verbose > 2;

    return 1;
}  // End of Init_v1

// for v1, there is only one exporter possible - however, keep full code - compiler will optimise out anyway
static inline exporter_entry_t *getExporter(FlowSource_t *fs, netflow_v1_header_t *header) {
    (void)header;
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
            void *info = calloc(1, sizeof(exporter_info_record_v4_t));
            if (info == NULL) {
                LogError("Process_v1: malloc(): %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return NULL;
            }

            *e = (exporter_entry_t){.key = key, .sequence = UINT32_MAX, .sysID = AssignExporterID(), .in_use = 1, .info = info};
            *(e->info) = (exporter_info_record_v4_t){
                .type = ExporterInfoRecordV4Type,
                .size = sizeof(exporter_info_record_v4_t),
                .version = key.version,
                .id = key.id,
                .sysID = e->sysID,
            };
            memcpy(e->info->ip, fs->ipAddr.bytes, 16);

            e->v1 = (exporter_v1_t){0};
            tab->count++;

            char ipstr[INET6_ADDRSTRLEN];
            ip128_2_str(&fs->ipAddr, ipstr);

            if (fs->sa_family == PF_INET6) {
                e->v1.outRecordSize = baseOffset + extensionSize + EXipReceivedV6Size;
                dbg_printf("Process_v1: New IPv6 exporter %s - add EXipReceivedV6\n", ipstr);
            } else {
                e->v1.outRecordSize = baseOffset + extensionSize + EXipReceivedV4Size;
                dbg_printf("Process_v1: New IPv4 exporter %s - add EXipReceivedV4\n", ipstr);
            }

            LogInfo("Process_v1: SysID: %u, New exporter: IP: %s\n", e->info->sysID, ipstr);

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
        if (count == 0 || count > NETFLOW_V1_MAX_RECORDS) {
            LogError("Process_v1: Invalid record count %u in header. Abort v1 record processing", count);
            return;
        }

        // input buffer size check for all expected records
        if (size_left < (NETFLOW_V1_HEADER_LENGTH + count * NETFLOW_V1_RECORD_LENGTH)) {
            LogError("Process_v1: Not enough data to process v1 record. Abort v1 record processing");
            return;
        }

        // output buffer size check for all expected records
        uint8_t *outBuff = GetCursor(fs->dataBlock);
        if (!IsAvailable(fs->dataBlock, BLOCK_SIZE_V3, count * exporter->v1.outRecordSize)) {
            // flush block - get an empty one
            fs->dataBlock = PushBlockV3(fs->blockQueue, fs->dataBlock);
            // map output memory buffer
            outBuff = GetCursor(fs->dataBlock);
        }

        uint32_t sysUptime = ntohl(v1_header->SysUptime);
        uint32_t unixSecs = ntohl(v1_header->unix_secs);
        uint32_t unixNsecs = ntohl(v1_header->unix_nsecs);

        // calculate boot time in msec
        uint64_t msecBoot = ((uint64_t)unixSecs * 1000 + ((uint64_t)unixNsecs / 1000000)) - (uint64_t)sysUptime;

        // process all records
        netflow_v1_record_t *v1_record = (netflow_v1_record_t *)((void *)v1_header + NETFLOW_V1_HEADER_LENGTH);

        /* loop over each records associated with this header */
        uint32_t outSize = 0;
        for (int i = 0; i < count; i++) {
            // zero entire fixed-size record at once
            uint64_t bitMap = 0;
            BitMapSet(bitMap, EXgenericFlowID);
            BitMapSet(bitMap, EXipv4FlowID);
            BitMapSet(bitMap, EXinterfaceID);
            BitMapSet(bitMap, EXasRoutingV4ID);

            recordHeaderV4_t *recordHeader = (recordHeaderV4_t *)outBuff;
            *recordHeader = (recordHeaderV4_t){
                .type = V4Record,
                .extBitmap = bitMap,
                .exporterID = exporter->sysID,
                .nfVersion = VERSION_NETFLOW_V1,
            };

            // clear offset table
            uint16_t *offset = (uint16_t *)(outBuff + sizeof(recordHeaderV4_t));
            memset(offset, 0, offsetSize);
            uint32_t nextOffset = baseOffset;

            // direct pointers using precomputed offsets
            EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)(outBuff + nextOffset);
            *offset++ = nextOffset;
            nextOffset += EXgenericFlowSize;
            *genericFlow = (EXgenericFlow_t){
                .msecReceived = msecReceived,
                .inPackets = ntohl(v1_record->dPkts),
                .inBytes = ntohl(v1_record->dOctets),
                .srcPort = ntohs(v1_record->srcPort),
                .dstPort = ntohs(v1_record->dstPort),
                .proto = v1_record->prot,
                .srcTos = v1_record->tos,
                .tcpFlags = v1_record->tcp_flags,
            };

            EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)(outBuff + nextOffset);
            *offset++ = nextOffset;
            nextOffset += EXipv4FlowSize;
            ipv4Flow->srcAddr = ntohl(v1_record->srcaddr);
            ipv4Flow->dstAddr = ntohl(v1_record->dstaddr);

            if (v1_record->input || v1_record->output) {
                BitMapSet(recordHeader->extBitmap, EXinterfaceID);
                EXinterface_t *interface = (EXinterface_t *)(outBuff + nextOffset);
                *offset++ = nextOffset;
                nextOffset += EXinterfaceSize;
                interface->input = ntohs(v1_record->input);
                interface->output = ntohs(v1_record->output);
            }

            if (v1_record->nexthop) {
                BitMapSet(recordHeader->extBitmap, EXasRoutingV4ID);
                EXasRoutingV4_t *nexthop = (EXasRoutingV4_t *)(outBuff + nextOffset);
                *offset++ = nextOffset;
                nextOffset += EXasRoutingV4Size;
                nexthop->nextHop = ntohl(v1_record->nexthop);
                nexthop->bgpNextHop = 0;
            }

            // time calculations
            uint64_t First = ntohl(v1_record->First);
            uint64_t Last = ntohl(v1_record->Last);
            uint64_t msecStart, msecEnd;

            if (First > Last) {
                msecStart = msecBoot - 0x100000000LL + First;
            } else {
                msecStart = msecBoot + First;
            }
            msecEnd = Last + msecBoot;

            if (Last > sysUptime) {
                msecStart -= 0x100000000LL;
                msecEnd -= 0x100000000LL;
            }

            genericFlow->msecFirst = msecStart;
            genericFlow->msecLast = msecEnd;
            UpdateFirstLast(fs, msecStart, msecEnd);

            // received-IP extension
            *offset++ = nextOffset;
            if (fs->sa_family == PF_INET6) {
                BitMapSet(recordHeader->extBitmap, EXipReceivedV6ID);
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)(outBuff + nextOffset);
                nextOffset += EXipReceivedV6Size;
                uint64_t *ipv6 = (uint64_t *)fs->ipAddr.bytes;
                ipReceivedV6->ip[0] = ntohll(ipv6[0]);
                ipReceivedV6->ip[1] = ntohll(ipv6[1]);
                dbg_printf("Add IPv6 route IP extension\n");
            } else {
                BitMapSet(recordHeader->extBitmap, EXipReceivedV4ID);
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

            dbg(VerifyV4Record(recordHeader));
            if (printRecord) {
                flow_record_short(stdout, recordHeader);
            }

            // advance output buffer
            outBuff += recordHeader->size;
            outSize += recordHeader->size;

            // advance input buffer
            v1_record = (netflow_v1_record_t *)((uint8_t *)v1_record + NETFLOW_V1_RECORD_LENGTH);

            // sanity check
            if (recordHeader->size > exporter->v1.outRecordSize) {
                LogError("Process_v1: Record size mismatch! Expected %u, got %u", exporter->v1.outRecordSize, recordHeader->size);
            }
        }

        // update file record size ( -> output buffer size )
        fs->dataBlock->numRecords += count;
        fs->dataBlock->rawSize += outSize;

        // still to go for this many input bytes
        size_left -= NETFLOW_V1_HEADER_LENGTH + count * NETFLOW_V1_RECORD_LENGTH;

        // next header
        v1_header = (netflow_v1_header_t *)v1_record;

        // should never be < 0
        done = size_left <= 0;

    }  // End of while !done

    return;

}  // End of Process_v1