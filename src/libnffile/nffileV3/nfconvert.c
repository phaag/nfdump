/*
 *  Copyright (c) 2026, Peter Haag
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

#include "nfconvert.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "exporter.h"
#include "id.h"
#include "logging.h"
#include "nffileV2/nffileV2.h"
#include "nffileV2/nffileV2_def.h"
#include "nffileV2/nfxV3.h"
#include "nffileV2/uncompress.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"

// V2 file header — local definition matching the on-disk format
typedef struct fileHeaderV2_s {
    uint16_t magic;
    uint16_t version;
    uint32_t nfdversion;
    time_t created;
    uint8_t compression;
    uint8_t encryption;
    uint16_t appendixBlocks;
    uint32_t creator;
    off_t offAppendix;
    uint32_t BlockSize;
    uint32_t NumBlocks;
} fileHeaderV2_t;

// V2 stat_record — identical layout to current stat_record_t
// but kept local to avoid type confusion with the V2 file's local typedef
typedef stat_record_t statRecordV2_t;

#define MAX_EXPORTERS 65535
static exporter_table_t exporter_table = {0};
static struct exporter_array_s {
#define EXPORTER_BLOCK_SIZE 8
    uint32_t count;
    uint32_t capacity;
    exporter_entry_t **entries;
} exporter_array = {0};

// Context passed to nfreaderV2 thread
typedef struct convertCtx_s {
    int fd;               // file descriptor (positioned after header)
    uint32_t numBlocks;   // number of data blocks (not appendix)
    uint8_t compression;  // V2 compression type
    uint32_t blockSize;   // max uncompressed block size
    nffileV3_t *nffile;   // output V3 handle (for processQueue)
} convertCtx_t;

/*
 * V3 extension ID → V4 extension ID mapping table.
 * 0 means "not mapped" (extension dropped or handled specially).
 *
 * Notable merges:
 *   EX3bgpNextHopV4ID(8) + EX3ipNextHopV4ID(10) → EXasRoutingV4ID
 *   EX3bgpNextHopV6ID(9) + EX3ipNextHopV6ID(11) → EXasRoutingV6ID
 *   EX3nselCommonID(19)  + EX3natCommonID(25)    → EXnselCommonID
 *   EX3macAddrID(15) → EXinMacAddrID + EXoutMacAddrID (split)
 *
 * Notable drops:
 *   EX3samplerInfoID(18) — not in V4 (sampler info handled differently)
 *   EX3ipReceivedV4ID(12) → EXipReceivedV4ID (separate in V4, has align field)
 */
static const uint8_t mapV3toV4[MAXV3EXTENSIONS] = {
    [0] = 0,                                     // EXnull
    [EX3genericFlowID] = EXgenericFlowID,        // 1 → 1
    [EX3ipv4FlowID] = EXipv4FlowID,              // 2 → 2
    [EX3ipv6FlowID] = EXipv6FlowID,              // 3 → 3
    [EX3flowMiscID] = EXflowMiscID,              // 4 → 5 (interface split out)
    [EX3cntFlowID] = EXcntFlowID,                // 5 → 6
    [EX3vLanID] = EXvLanID,                      // 6 → 7
    [EX3asRoutingID] = EXasInfoID,               // 7 → 8
    [EX3bgpNextHopV4ID] = EXasRoutingV4ID,       // 8 → 9  (merged)
    [EX3bgpNextHopV6ID] = EXasRoutingV6ID,       // 9 → 10 (merged)
    [EX3ipNextHopV4ID] = EXasRoutingV4ID,        // 10 → 9  (merged)
    [EX3ipNextHopV6ID] = EXasRoutingV6ID,        // 11 → 10 (merged)
    [EX3ipReceivedV4ID] = EXipReceivedV4ID,      // 12 → 11
    [EX3ipReceivedV6ID] = EXipReceivedV6ID,      // 13 → 12
    [EX3mplsLabelID] = EXmplsID,                 // 14 → 13
    [EX3macAddrID] = EXinMacAddrID,              // 15 → 14 (split: also EXoutMacAddrID)
    [EX3asAdjacentID] = EXasAdjacentID,          // 16 → 16
    [EX3latencyID] = EXlatencyID,                // 17 → 17
    [EX3samplerInfoID] = 0,                      // 18 → dropped
    [EX3nselCommonID] = EXnselCommonID,          // 19 → 21 (merged with natCommon)
    [EX3natXlateIPv4ID] = EXnatXlateV4ID,        // 20 → 18
    [EX3natXlateIPv6ID] = EXnatXlateV6ID,        // 21 → 19
    [EX3natXlatePortID] = EXnatXlatePortID,      // 22 → 20
    [EX3nselAclID] = EXnselAclID,                // 23 → 22
    [EX3nselUserID] = EXnselUserID,              // 24 → 23
    [EX3natCommonID] = EXnselCommonID,           // 25 → 21 (merged)
    [EX3natPortBlockID] = EXnatPortBlockID,      // 26 → 24
    [EX3nbarAppID] = EXnbarAppID,                // 27 → 25
    [28] = 0,                                    // unused
    [EX3inPayloadID] = EXinPayloadID,            // 29 → 26
    [EX3outPayloadID] = EXoutPayloadID,          // 30 → 27
    [EX3tunIPv4ID] = EXtunnelV4ID,               // 31 → 28 (merged)
    [EX3tunIPv6ID] = EXtunnelV6ID,               // 32 → 29 (merged)
    [EX3observationID] = EXobservationID,        // 33 → 30
    [EX3inmonMetaID] = EXinmonMetaID,            // 34 → 31
    [EX3inmonFrameID] = EXinmonFrameID,          // 35 → 32
    [EX3vrfID] = EXvrfID,                        // 36 → 33
    [EX3pfinfoID] = EXpfinfoID,                  // 37 → 34
    [EX3layer2ID] = EXlayer2ID,                  // 38 → 35
    [EX3flowIdID] = EXflowIdID,                  // 39 → 36
    [EX3nokiaNatID] = EXnokiaNatID,              // 40 → 37
    [EX3nokiaNatStringID] = EXnokiaNatStringID,  // 41 → 38
    [EX3ipInfoID] = EXipInfoID,                  // 42 → 39
};

static void freeTables(void) {
    if (exporter_array.entries) {
        free(exporter_array.entries);
        exporter_array = (struct exporter_array_s){0};
    }
    if (exporter_table.entries) {
        free(exporter_table.entries);
        exporter_table = (exporter_table_t){0};
    }
}  // End of freeTables

static void expand_exporter_table(exporter_table_t *tab) {
    uint32_t old_cap = tab->capacity;
    exporter_entry_t *old_entries = tab->entries;

    uint32_t new_cap = old_cap == 0 ? 8 : old_cap * 2;
    exporter_entry_t *new_entries = calloc(new_cap, sizeof(exporter_entry_t));
    if (!new_entries) {
        LogError("expand_exporter_table: calloc failed");
        return;
    }

    tab->entries = new_entries;
    tab->capacity = new_cap;
    tab->count = 0;

    for (uint32_t i = 0; i < old_cap; i++) {
        exporter_entry_t *e = &old_entries[i];
        if (!e->in_use) continue;

        uint32_t h = EXPORTERHASH(e->key);
        uint32_t mask = new_cap - 1;
        uint32_t j = h & mask;

        while (new_entries[j].in_use) j = (j + 1) & mask;

        new_entries[j] = *e;
        tab->count++;
    }

    if (old_entries) free(old_entries);
}  // End of expand_exporter_table

static int AddV2ExporterStat(exporter_stats_record_t *stat_record) {
    if (stat_record->size < sizeof(exporter_stats_record_t)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return 0;
    }

    size_t expectedSize = sizeof(exporter_stats_record_t) + (stat_record->stat_count - 1) * sizeof(struct exporter_stat_s);
    if ((stat_record->stat_count == 0) || (stat_record->size != expectedSize)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return 0;
    }

    for (unsigned i = 0; i < stat_record->stat_count; i++) {
        uint32_t sysID = stat_record->stat[i].sysid;
        if (sysID >= MAX_EXPORTERS || sysID >= exporter_array.capacity) {
            LogError("exporter ID %u out of range in %s line %d", sysID, __FILE__, __LINE__);
            return 0;
        }

        exporter_entry_t *e = exporter_array.entries[sysID];
        if (e) {
            e->sequence_failure += stat_record->stat[i].sequence_failure;
            e->info->sequence_failure += stat_record->stat[i].sequence_failure;
            e->packets += stat_record->stat[i].packets;
            e->info->packets += stat_record->stat[i].packets;
            e->flows += stat_record->stat[i].flows;
            e->info->flows += stat_record->stat[i].flows;
            dbg_printf("Update exporter stat for SysID: %i: Sequence failures: %u, packets: %" PRIu64 ", flows: %" PRIu64 "\n", sysID,
                       e->sequence_failure, e->packets, e->flows);
        } else {
            LogError("Exporter SysID: %u not found! - Skip stat record record", sysID);
        }
    }

    return 1;

}  // End of AddV2ExporterStat

static int AddV2ExporterInfo(exporter_info_record_t *exporter_record) {
    if (exporter_record->size != sizeof(exporter_info_record_t)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return 0;
    }

    ip128_t ipAddr;
    memcpy(ipAddr.bytes, exporter_record->ip, sizeof(ip128_t));

    if (exporter_record->fill != 0) {
        // old sa_familiy information and IP address in host byte order
        uint64_t *u = (uint64_t *)ipAddr.bytes;
        u[0] = htonll(u[0]);
        u[1] = htonll(u[1]);
        if (exporter_record->fill == AF_INET) {
            ipAddr.bytes[10] = 0xFF;
            ipAddr.bytes[11] = 0xFF;
        }
        // convert to new representation
        memcpy(exporter_record->ip, ipAddr.bytes, sizeof(ip128_t));
        exporter_record->fill = 0;
    }

    // check for exhausted hash
    if ((exporter_table.count * 4) >= (exporter_table.capacity * 3)) {
        // expand exporter index
        expand_exporter_table(&exporter_table);
    }

    const exporter_key_t key = {.version = exporter_record->version, .id = exporter_record->id, .ip = ipAddr};

    uint32_t hash = EXPORTERHASH(key);
    uint32_t mask = exporter_table.capacity - 1;
    uint32_t i = hash & mask;

    for (;;) {
        // check for key
        exporter_entry_t *e = &exporter_table.entries[i];
        // key does not exists - insert new exporter
        if (!e->in_use) {
            // insert new exporter
            e->key = key;
            e->packets = 0;
            e->flows = 0;
            e->sequence_failure = 0;
            e->sequence = UINT32_MAX;
            e->in_use = 1;
            exporter_table.count++;

            uint32_t recordSize = sizeof(exporter_info_record_v4_t);
            e->info = malloc(recordSize);
            if (!e->info) {
                LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return 0;
            }
            *(e->info) = (exporter_info_record_v4_t){
                .type = ExporterInfoRecordV4Type,
                .size = recordSize,
                .id = exporter_record->id,
                .sysID = exporter_record->sysid,
                .version = exporter_record->version,
            };
            memcpy(e->info->ip, exporter_record->ip, sizeof(exporter_record->ip));

            if (exporter_array.capacity <= exporter_record->sysid) {
                uint32_t newCapacity = exporter_array.capacity + EXPORTER_BLOCK_SIZE;
                // exporter_record->sysid with uint16_t - max 65535
                while (newCapacity <= exporter_record->sysid) newCapacity += EXPORTER_BLOCK_SIZE;

                exporter_entry_t **tmp = realloc(exporter_array.entries, newCapacity * sizeof(exporter_entry_t *));
                if (!tmp) {
                    LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return 0;
                }
                memset(tmp + exporter_array.capacity, 0, (newCapacity - exporter_array.capacity) * sizeof(exporter_entry_t *));
                exporter_array.entries = tmp;
                exporter_array.capacity = newCapacity;
            }
            exporter_array.entries[exporter_record->sysid] = e;

            return 1;
        }
        // slot already occupied - same exporter
        if (EXPORTER_KEY_EQUAL(e->key, key)) {
            // same exporter - skip
            dbg_printf("Insert same exporter with sysID %u skipped\n", exporter_record->sysid);
            return 1;
        }

        dbg_assert(exporter_table.count < exporter_table.capacity);
        i = (i + 1) & mask;
    }

    // unreached
    return 1;

}  // End of AddV2ExporterInfo

static int AddV2SamplerRecord(sampler_record_V3_t *sampler_record) {
    uint16_t sysID = sampler_record->exporter_sysid;

    if (sysID >= exporter_array.capacity) {
        LogError("exporter ID %u out of range in %s line %d", sysID, __FILE__, __LINE__);
        return 0;
    }

    exporter_entry_t *e = exporter_array.entries[sysID];
    if (e) {
        if ((e->info->sampler_count + 1) > e->info->sampler_capacity) {
            // expand info record
            uint32_t numSampler = e->info->sampler_capacity == 0 ? 8 : 2 * e->info->sampler_capacity;
            size_t recordSize = sizeof(exporter_info_record_v4_t) + (numSampler * sizeof(sampler_record_v4_t));

            exporter_info_record_v4_t *newInfo = realloc(e->info, recordSize);
            if (!newInfo) {
                LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                return 0;
            }
            newInfo->sampler_capacity = numSampler;
            e->info = newInfo;
            e->info->size = recordSize;
        }
        uint32_t slot = e->info->sampler_count++;
        e->info->samplers[slot] = (sampler_record_v4_t){
            .inUse = 1,
            .algorithm = sampler_record->algorithm,
            .packetInterval = sampler_record->packetInterval,
            .spaceInterval = sampler_record->spaceInterval,
            .selectorID = sampler_record->id,
        };
    }

    return 1;
}  // End of AddV2SamplerRecord

static void AppendExporterBlock(nffileV3_t *nffile) {
    dbg_printf("Flush all exporters\n");
    if (exporter_table.count == 0) return;
    expBlockV3_t *expBlock = NULL;
    InitDataBlock(expBlock, BLOCK_SIZE_V3);

    // push exporter info to exporter block
    uint32_t available = BLOCK_SIZE_V3 - expBlock->rawSize;
    uint8_t *p = ResetCursor(expBlock);
    for (unsigned i = 0; i < exporter_table.capacity; i++) {
        // linear check for sysID exporter
        exporter_entry_t *e = &exporter_table.entries[i];
        if (!e->in_use) continue;
        exporter_info_record_v4_t *exporter_info = e->info;

        if (available < exporter_info->size) {
            queue_push(nffile->processQueue, expBlock);
            expBlock = NULL;
            InitDataBlock(expBlock, BLOCK_SIZE_V3);
            p = ResetCursor(expBlock);
            available = BLOCK_SIZE_V3 - expBlock->rawSize;
        }
        dbg_printf("Dump exporter: %u\n", exporter_info->sysID);
        memcpy(p, (void *)exporter_info, exporter_info->size);
        p += exporter_info->size;
        expBlock->rawSize += exporter_info->size;
        expBlock->numExporter++;
        available -= exporter_info->size;
    }
    queue_push(nffile->processQueue, expBlock);

}  // End of AppendExporterBlock

// Convert a single V3 record to V4 format.  Writes into 'out' buffer.
// Returns pointer past the end of the written V4 record, or NULL on error.
static uint8_t *ConvertRecordV3toV4(uint8_t *out, recordHeaderV3_t *v3) {
    uint8_t *p = (uint8_t *)(v3 + 1);
    uint8_t *end = (uint8_t *)v3 + v3->size;

    // Pass 1: build V4 bitmap
    uint64_t bitmap = 0;

    // EX3flowMiscID contains both interface + misc → add EXinterfaceID too
    while (p < end) {
        elementHeader_t *eh = (elementHeader_t *)p;
        uint16_t id = eh->type;
        if (id < MAXV3EXTENSIONS) {
            uint8_t v4id = mapV3toV4[id];
            if (v4id) bitmap |= (1ULL << v4id);
            // EX3flowMisc also produces EXinterface
            if (id == EX3flowMiscID) bitmap |= (1ULL << EXinterfaceID);
            // EX3macAddr produces both in+out
            if (id == EX3macAddrID) bitmap |= (1ULL << EXoutMacAddrID);
        }
        p += eh->length;
    }

    uint16_t numExt = __builtin_popcountll(bitmap);

    // Build V4 header
    recordHeaderV4_t *h = AddV4Header(out);
    h->exporterID = v3->exporterID;
    h->engineType = v3->engineType;
    h->engineID = v3->engineID;
    h->nfVersion = v3->nfversion;
    h->flags = v3->flags;
    h->extBitmap = bitmap;
    h->numExtensions = numExt;

    // Offset table
    uint32_t actual = numExt * 2;
    uint32_t aligned = ALIGN8(actual);
    uint16_t *offsets = (uint16_t *)((uint8_t *)h + sizeof(recordHeaderV4_t));
    memset(offsets, 0, aligned);
    h->size += aligned;
    uint32_t nextOffset = h->size;

    // Pass 2: convert extensions
    p = (uint8_t *)(v3 + 1);
    while (p < end) {
        elementHeader_t *eh = (elementHeader_t *)p;
        uint16_t id = eh->type;
        uint8_t *edata = p + sizeof(elementHeader_t);

        if (id < MAXV3EXTENSIONS) {
            uint8_t v4id = mapV3toV4[id];
            if (v4id) {
                uint32_t slot = __builtin_popcountll(bitmap & ((1ULL << v4id) - 1));
                offsets[slot] = nextOffset;

                switch (v4id) {
                    case EXgenericFlowID: {
                        EXgenericFlow_t *g = (EXgenericFlow_t *)((uint8_t *)h + nextOffset);
                        memcpy(g, edata, sizeof(*g));
                        nextOffset += sizeof(*g);
                        h->size += sizeof(*g);
                        break;
                    }
                    case EXipv4FlowID: {
                        EXipv4Flow_t *f = (EXipv4Flow_t *)((uint8_t *)h + nextOffset);
                        EX3ipv4Flow_t *f3 = (EX3ipv4Flow_t *)edata;
                        f->srcAddr = f3->srcAddr;
                        f->dstAddr = f3->dstAddr;
                        nextOffset += sizeof(*f);
                        h->size += sizeof(*f);
                        break;
                    }
                    case EXipv6FlowID: {
                        EXipv6Flow_t *f = (EXipv6Flow_t *)((uint8_t *)h + nextOffset);
                        memcpy(f, edata, sizeof(*f));
                        nextOffset += sizeof(*f);
                        h->size += sizeof(*f);
                        break;
                    }
                    case EXflowMiscID: {
                        // V3 has interface+misc combined; V4 splits them
                        // First emit EXinterface (already in bitmap)
                        EX3flowMisc_t *m3 = (EX3flowMisc_t *)edata;
                        {
                            uint32_t ifSlot = __builtin_popcountll(bitmap & ((1ULL << EXinterfaceID) - 1));
                            offsets[ifSlot] = nextOffset;
                            EXinterface_t *iface = (EXinterface_t *)((uint8_t *)h + nextOffset);
                            iface->input = m3->input;
                            iface->output = m3->output;
                            nextOffset += sizeof(*iface);
                            h->size += sizeof(*iface);
                        }
                        // Now emit EXflowMisc
                        offsets[slot] = nextOffset;
                        EXflowMisc_t *m = (EXflowMisc_t *)((uint8_t *)h + nextOffset);
                        m->srcMask = m3->srcMask;
                        m->dstMask = m3->dstMask;
                        m->direction = m3->dir;
                        m->biFlowDir = m3->biFlowDir;
                        m->dstTos = m3->dstTos;
                        m->flowEndReason = m3->flowEndReason;
                        m->align = 0;
                        nextOffset += sizeof(*m);
                        h->size += sizeof(*m);
                        break;
                    }
                    case EXcntFlowID: {
                        EXcntFlow_t *c = (EXcntFlow_t *)((uint8_t *)h + nextOffset);
                        memcpy(c, edata, sizeof(*c));
                        nextOffset += sizeof(*c);
                        h->size += sizeof(*c);
                        break;
                    }
                    case EXvLanID: {
                        EXvLan_t *v4 = (EXvLan_t *)((uint8_t *)h + nextOffset);
                        EX3vLan_t *v3x = (EX3vLan_t *)edata;
                        v4->srcVlan = v3x->srcVlan;
                        v4->dstVlan = v3x->dstVlan;
                        nextOffset += sizeof(*v4);
                        h->size += sizeof(*v4);
                        break;
                    }
                    case EXasInfoID: {
                        EXasInfo_t *a = (EXasInfo_t *)((uint8_t *)h + nextOffset);
                        EX3asRouting_t *a3 = (EX3asRouting_t *)edata;
                        a->srcAS = a3->srcAS;
                        a->dstAS = a3->dstAS;
                        nextOffset += sizeof(*a);
                        h->size += sizeof(*a);
                        break;
                    }
                    case EXasRoutingV4ID: {
                        EXasRoutingV4_t *r = (EXasRoutingV4_t *)((uint8_t *)h + nextOffset);
                        // Merged: may be bgpNextHop or ipNextHop — fill the right field
                        // Don't memset — second pass writes the other half
                        if (offsets[slot] != nextOffset) {
                            // Already placed by first contributor — update in place
                            r = (EXasRoutingV4_t *)((uint8_t *)h + offsets[slot]);
                        } else {
                            memset(r, 0, sizeof(*r));
                            nextOffset += sizeof(*r);
                            h->size += sizeof(*r);
                        }
                        if (id == EX3bgpNextHopV4ID) r->bgpNextHop = ((EX3bgpNextHopV4_t *)edata)->ip;
                        if (id == EX3ipNextHopV4ID) r->nextHop = ((EX3ipNextHopV4_t *)edata)->ip;
                        break;
                    }
                    case EXasRoutingV6ID: {
                        EXasRoutingV6_t *r = (EXasRoutingV6_t *)((uint8_t *)h + nextOffset);
                        if (offsets[slot] != nextOffset) {
                            r = (EXasRoutingV6_t *)((uint8_t *)h + offsets[slot]);
                        } else {
                            memset(r, 0, sizeof(*r));
                            nextOffset += sizeof(*r);
                            h->size += sizeof(*r);
                        }
                        if (id == EX3bgpNextHopV6ID) memcpy(r->bgpNextHop, ((EX3bgpNextHopV6_t *)edata)->ip, 16);
                        if (id == EX3ipNextHopV6ID) memcpy(r->nextHop, ((EX3ipNextHopV6_t *)edata)->ip, 16);
                        break;
                    }
                    case EXipReceivedV4ID: {
                        EXipReceivedV4_t *x = (EXipReceivedV4_t *)((uint8_t *)h + nextOffset);
                        x->ip = ((EX3ipReceivedV4_t *)edata)->ip;
                        x->align = 0;
                        nextOffset += sizeof(*x);
                        h->size += sizeof(*x);
                        break;
                    }
                    case EXipReceivedV6ID: {
                        EXipReceivedV6_t *x = (EXipReceivedV6_t *)((uint8_t *)h + nextOffset);
                        memcpy(x->ip, ((EX3ipReceivedV6_t *)edata)->ip, 16);
                        nextOffset += sizeof(*x);
                        h->size += sizeof(*x);
                        break;
                    }
                    case EXmplsID: {
                        EXmpls_t *m = (EXmpls_t *)((uint8_t *)h + nextOffset);
                        memcpy(m->label, ((EX3mplsLabel_t *)edata)->mplsLabel, sizeof(m->label));
                        nextOffset += sizeof(*m);
                        h->size += sizeof(*m);
                        break;
                    }
                    case EXinMacAddrID: {
                        // V3 has all 4 MACs in one ext; V4 splits in+out
                        EX3macAddr_t *m3 = (EX3macAddr_t *)edata;
                        EXinMacAddr_t *mi = (EXinMacAddr_t *)((uint8_t *)h + nextOffset);
                        mi->inSrcMac = m3->inSrcMac;
                        mi->outDstMac = m3->outDstMac;
                        nextOffset += sizeof(*mi);
                        h->size += sizeof(*mi);
                        // Also emit EXoutMacAddr
                        uint32_t outSlot = __builtin_popcountll(bitmap & ((1ULL << EXoutMacAddrID) - 1));
                        offsets[outSlot] = nextOffset;
                        EXoutMacAddr_t *mo = (EXoutMacAddr_t *)((uint8_t *)h + nextOffset);
                        mo->inDstMac = m3->inDstMac;
                        mo->outSrcMac = m3->outSrcMac;
                        nextOffset += sizeof(*mo);
                        h->size += sizeof(*mo);
                        break;
                    }
                    case EXasAdjacentID: {
                        EXasAdjacent_t *a = (EXasAdjacent_t *)((uint8_t *)h + nextOffset);
                        EX3asAdjacent_t *a3 = (EX3asAdjacent_t *)edata;
                        a->nextAdjacentAS = a3->nextAdjacentAS;
                        a->prevAdjacentAS = a3->prevAdjacentAS;
                        nextOffset += sizeof(*a);
                        h->size += sizeof(*a);
                        break;
                    }
                    case EXlatencyID: {
                        EXlatency_t *l = (EXlatency_t *)((uint8_t *)h + nextOffset);
                        EX3latency_t *l3 = (EX3latency_t *)edata;
                        l->msecClientNwDelay = l3->usecClientNwDelay;
                        l->msecServerNwDelay = l3->usecServerNwDelay;
                        l->msecApplLatency = l3->usecApplLatency;
                        nextOffset += sizeof(*l);
                        h->size += sizeof(*l);
                        break;
                    }
                    case EXnatXlateV4ID: {
                        EXnatXlateV4_t *n = (EXnatXlateV4_t *)((uint8_t *)h + nextOffset);
                        EX3natXlateIPv4_t *n3 = (EX3natXlateIPv4_t *)edata;
                        n->xlateSrcAddr = n3->xlateSrcAddr;
                        n->xlateDstAddr = n3->xlateDstAddr;
                        nextOffset += sizeof(*n);
                        h->size += sizeof(*n);
                        break;
                    }
                    case EXnatXlateV6ID: {
                        EXnatXlateV6_t *n = (EXnatXlateV6_t *)((uint8_t *)h + nextOffset);
                        memcpy(n->xlateSrcAddr, ((EX3natXlateIPv6_t *)edata)->xlateSrcAddr, 16);
                        memcpy(n->xlateDstAddr, ((EX3natXlateIPv6_t *)edata)->xlateDstAddr, 16);
                        nextOffset += sizeof(*n);
                        h->size += sizeof(*n);
                        break;
                    }
                    case EXnatXlatePortID: {
                        EXnatXlatePort_t *n = (EXnatXlatePort_t *)((uint8_t *)h + nextOffset);
                        EX3natXlatePort_t *n3 = (EX3natXlatePort_t *)edata;
                        n->xlateSrcPort = n3->xlateSrcPort;
                        n->xlateDstPort = n3->xlateDstPort;
                        n->align = 0;
                        nextOffset += sizeof(*n);
                        h->size += sizeof(*n);
                        break;
                    }
                    case EXnselCommonID: {
                        // Merged: nselCommon + natCommon → single V4 ext
                        EXnselCommon_t *n = (EXnselCommon_t *)((uint8_t *)h + nextOffset);
                        if (offsets[slot] != nextOffset) {
                            n = (EXnselCommon_t *)((uint8_t *)h + offsets[slot]);
                        } else {
                            memset(n, 0, sizeof(*n));
                            nextOffset += sizeof(*n);
                            h->size += sizeof(*n);
                        }
                        if (id == EX3nselCommonID) {
                            EX3nselCommon_t *n3 = (EX3nselCommon_t *)edata;
                            n->msecEvent = n3->msecEvent;
                            n->connID = n3->connID;
                            n->fwXevent = n3->fwXevent;
                            n->fwEvent = n3->fwEvent;
                            n->type = NSEL_LOGGING;
                        } else {
                            // EX3natCommonID
                            EX3natCommon_t *nc3 = (EX3natCommon_t *)edata;
                            n->msecEvent = nc3->msecEvent;
                            n->type = NSEL_NAT;
                            n->natEvent = nc3->natEvent;
                            n->natPoolID = nc3->natPoolID;
                        }
                        break;
                    }
                    case EXnselAclID: {
                        EXnselAcl_t *a = (EXnselAcl_t *)((uint8_t *)h + nextOffset);
                        memcpy(a->ingressAcl, ((EX3nselAcl_t *)edata)->ingressAcl, sizeof(a->ingressAcl));
                        memcpy(a->egressAcl, ((EX3nselAcl_t *)edata)->egressAcl, sizeof(a->egressAcl));
                        nextOffset += sizeof(*a);
                        h->size += sizeof(*a);
                        break;
                    }
                    case EXnselUserID: {
                        EXnselUser_t *u = (EXnselUser_t *)((uint8_t *)h + nextOffset);
                        memcpy(u->username, ((EX3nselUser_t *)edata)->username, sizeof(u->username));
                        nextOffset += sizeof(*u);
                        h->size += sizeof(*u);
                        break;
                    }
                    case EXnatPortBlockID: {
                        EXnatPortBlock_t *b = (EXnatPortBlock_t *)((uint8_t *)h + nextOffset);
                        memcpy(b, edata, sizeof(*b));
                        nextOffset += sizeof(*b);
                        h->size += sizeof(*b);
                        break;
                    }
                    case EXnbarAppID: {
                        EXnbarApp_t *n = (EXnbarApp_t *)((uint8_t *)h + nextOffset);
                        EX3nbarApp_t *n3 = (EX3nbarApp_t *)edata;
                        uint32_t len = (n3->id[0] << 24) | (n3->id[1] << 16) | (n3->id[2] << 8) | n3->id[3];
                        n->length = len;
                        memcpy(n->id, n3->id, len);
                        uint32_t extSize = sizeof(uint32_t) + len;
                        nextOffset += extSize;
                        h->size += extSize;
                        break;
                    }
                    case EXinPayloadID:
                    case EXoutPayloadID: {
                        EXPayload_t *pl = (EXPayload_t *)((uint8_t *)h + nextOffset);
                        uint32_t len = ((EXPayload_t *)edata)->size;
                        memcpy(pl, edata, sizeof(uint32_t) + len);
                        uint32_t extSize = sizeof(uint32_t) + len;
                        nextOffset += extSize;
                        h->size += extSize;
                        break;
                    }
                    case EXtunnelV4ID: {
                        EXtunnelV4_t *t = (EXtunnelV4_t *)((uint8_t *)h + nextOffset);
                        if (offsets[slot] != nextOffset) {
                            t = (EXtunnelV4_t *)((uint8_t *)h + offsets[slot]);
                        } else {
                            memset(t, 0, sizeof(*t));
                            nextOffset += sizeof(*t);
                            h->size += sizeof(*t);
                        }
                        EX3tunIPv4_t *t3 = (EX3tunIPv4_t *)edata;
                        t->srcAddr = t3->tunSrcAddr;
                        t->dstAddr = t3->tunDstAddr;
                        t->proto = t3->tunProto;
                        break;
                    }
                    case EXtunnelV6ID: {
                        EXtunnelV6_t *t = (EXtunnelV6_t *)((uint8_t *)h + nextOffset);
                        if (offsets[slot] != nextOffset) {
                            t = (EXtunnelV6_t *)((uint8_t *)h + offsets[slot]);
                        } else {
                            memset(t, 0, sizeof(*t));
                            nextOffset += sizeof(*t);
                            h->size += sizeof(*t);
                        }
                        EX3tunIPv6_t *t3 = (EX3tunIPv6_t *)edata;
                        memcpy(t->srcAddr, t3->tunSrcAddr, 16);
                        memcpy(t->dstAddr, t3->tunDstAddr, 16);
                        t->proto = t3->tunProto;
                        break;
                    }
                    case EXobservationID: {
                        EXobservation_t *o = (EXobservation_t *)((uint8_t *)h + nextOffset);
                        EX3observation_t *o3 = (EX3observation_t *)edata;
                        o->pointID = o3->pointID;
                        o->domainID = o3->domainID;
                        nextOffset += sizeof(*o);
                        h->size += sizeof(*o);
                        break;
                    }
                    case EXinmonMetaID: {
                        EXinmonMeta_t *m = (EXinmonMeta_t *)((uint8_t *)h + nextOffset);
                        EX3inmonMeta_t *m3 = (EX3inmonMeta_t *)edata;
                        m->frameSize = m3->frameSize;
                        m->linkType = m3->linkType;
                        m->align = 0;
                        nextOffset += sizeof(*m);
                        h->size += sizeof(*m);
                        break;
                    }
                    case EXinmonFrameID: {
                        EXinmonFrame_t *f = (EXinmonFrame_t *)((uint8_t *)h + nextOffset);
                        EX3inmonFrame_t *f3 = (EX3inmonFrame_t *)edata;
                        uint32_t len = 4;  // V3 fixed 4 bytes
                        f->length = len;
                        memcpy(f->packet, f3->packet, len);
                        uint32_t extSize = sizeof(uint32_t) + len;
                        nextOffset += extSize;
                        h->size += extSize;
                        break;
                    }
                    case EXvrfID: {
                        EXvrf_t *v = (EXvrf_t *)((uint8_t *)h + nextOffset);
                        EX3vrf_t *v3x = (EX3vrf_t *)edata;
                        v->egressVrf = v3x->egressVrf;
                        v->ingressVrf = v3x->ingressVrf;
                        nextOffset += sizeof(*v);
                        h->size += sizeof(*v);
                        break;
                    }
                    case EXpfinfoID: {
                        EXpfinfo_t *pf = (EXpfinfo_t *)((uint8_t *)h + nextOffset);
                        memcpy(pf, edata, sizeof(*pf));
                        nextOffset += sizeof(*pf);
                        h->size += sizeof(*pf);
                        break;
                    }
                    case EXlayer2ID: {
                        EXlayer2_t *l2 = (EXlayer2_t *)((uint8_t *)h + nextOffset);
                        memcpy(l2, edata, sizeof(*l2));
                        nextOffset += sizeof(*l2);
                        h->size += sizeof(*l2);
                        break;
                    }
                    case EXflowIdID: {
                        EXflowId_t *fid = (EXflowId_t *)((uint8_t *)h + nextOffset);
                        fid->flowId = ((EX3flowId_t *)edata)->flowId;
                        nextOffset += sizeof(*fid);
                        h->size += sizeof(*fid);
                        break;
                    }
                    case EXnokiaNatID: {
                        EXnokiaNat_t *nn = (EXnokiaNat_t *)((uint8_t *)h + nextOffset);
                        EX3nokiaNat_t *nn3 = (EX3nokiaNat_t *)edata;
                        nn->inServiceID = nn3->inServiceID;
                        nn->outServiceID = nn3->outServiceID;
                        nn->align = 0;
                        nextOffset += sizeof(*nn);
                        h->size += sizeof(*nn);
                        break;
                    }
                    case EXnokiaNatStringID: {
                        EXnokiaNatString_t *ns = (EXnokiaNatString_t *)((uint8_t *)h + nextOffset);
                        memcpy(ns->natSubString, ((EX3nokiaNatString_t *)edata)->natSubString, sizeof(ns->natSubString));
                        nextOffset += sizeof(*ns);
                        h->size += sizeof(*ns);
                        break;
                    }
                    case EXipInfoID: {
                        EXipInfo_t *ii = (EXipInfo_t *)((uint8_t *)h + nextOffset);
                        EX3ipInfo_t *ii3 = (EX3ipInfo_t *)edata;
                        ii->fragmentFlags = ii3->fragmentFlags;
                        ii->minTTL = ii3->minTTL;
                        ii->maxTTL = ii3->maxTTL;
                        ii->fill = 0;
                        ii->align = 0;
                        nextOffset += sizeof(*ii);
                        h->size += sizeof(*ii);
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        p += eh->length;
    }

    return out + h->size;
}  // End of ConvertRecordV3toV4

// Convert an entire V2 data block (DATA_BLOCK_TYPE_3) of V3 records
// into a V3-format dataBlockV3_t filled with V4 records.
static flowBlockV3_t *convertV2V3(convertCtx_t *ctx, dataBlockV2_t *blockV2, uint32_t outBlockSize) {
    // Initialize as flow block
    flowBlockV3_t *outBlock = NewFlowBlock(outBlockSize);
    if (!outBlock) return NULL;

    outBlock->compression = NOT_COMPRESSED;
    outBlock->encryption = NOT_ENCRYPTED;

    uint8_t *outPtr = (uint8_t *)outBlock + sizeof(flowBlockV3_t);
    uint8_t *outEnd = (uint8_t *)outBlock + outBlockSize;

    uint8_t *inPtr = (uint8_t *)blockV2 + sizeof(dataBlockV2_t);
    uint8_t *inEnd = inPtr + blockV2->size;
    uint32_t numRecords = 0;

    while (inPtr < inEnd) {
        recordHeader_t *recordHeader = (recordHeader_t *)inPtr;

        if (recordHeader->size < sizeof(recordHeader_t) || inPtr + recordHeader->size > inEnd) break;

        switch (recordHeader->type) {
            case V3Record: {
                recordHeaderV3_t *v3rec = (recordHeaderV3_t *)inPtr;

                // Worst case: V4 record can be ~2x V3 due to alignment + offset table.
                // Check conservative bound before converting.
                size_t maxV4Size = v3rec->size * 2 + 256;
                if (outPtr + maxV4Size > outEnd) {
                    // Output block full — should not happen with adequate blockSize
                    LogError("convertV2V3: output block overflow, skipping remaining records");
                    break;
                }

                uint8_t *next = ConvertRecordV3toV4(outPtr, v3rec);
                if (next) {
                    outPtr = next;
                    numRecords++;
                }
            } break;
            case ExporterInfoRecordType:
                AddV2ExporterInfo((exporter_info_record_t *)recordHeader);
                break;
            case ExporterStatRecordType:
                AddV2ExporterStat((exporter_stats_record_t *)recordHeader);
                break;
            case SamplerRecordType:
                AddV2SamplerRecord((sampler_record_V3_t *)recordHeader);
                break;
            default:
                LogInfo("convertV2V3: skip record type: %u", recordHeader->type);
        }
        // Skip non-V3Record types (ident, stat, slack — already handled in appendix)

        inPtr += recordHeader->size;
    }

    // Finalize block header
    outBlock->rawSize = (uint32_t)(outPtr - (uint8_t *)outBlock);
    outBlock->discSize = outBlock->rawSize;  // uncompressed on-disk = raw
    outBlock->numRecords = numRecords;

    return outBlock;
}  // End of convertV2V3

// Read and decompress a single V2 data block from fd.
// Returns a malloc'd dataBlockV2_t, or NULL on error/EOF.
static dataBlockV2_t *ReadBlockV2(int fd, uint8_t compression, uint32_t blockSize) {
    dataBlockV2_t *block = malloc(BUFFSIZE);
    if (!block) return NULL;

    ssize_t ret = read(fd, block, sizeof(dataBlockV2_t));
    if (ret <= 0) {
        free(block);
        return NULL;
    }
    if (ret != sizeof(dataBlockV2_t)) {
        LogError("ReadBlockV2: short header read: %zd", ret);
        free(block);
        return NULL;
    }

    if (block->size == 0 || block->size > (BUFFSIZE - sizeof(dataBlockV2_t))) {
        LogError("ReadBlockV2: invalid block size %u", block->size);
        free(block);
        return NULL;
    }

    // Read payload
    void *payload = (uint8_t *)block + sizeof(dataBlockV2_t);
    ret = read(fd, payload, block->size);
    if (ret != (ssize_t)block->size) {
        LogError("ReadBlockV2: short payload read: expected %u, got %zd", block->size, ret);
        free(block);
        return NULL;
    }

    // Determine effective compression
    int comp = compression;
    if (TestFlag(block->flags, FLAG_BLOCK_UNCOMPRESSED)) {
        comp = NOT_COMPRESSED_V2;
    }

    if (comp == NOT_COMPRESSED_V2) return block;

    // Decompress into a second buffer
    dataBlockV2_t *out = malloc(BUFFSIZE);
    if (!out) {
        free(block);
        return NULL;
    }

    int failed = 0;
    switch (comp) {
        case LZO_COMPRESSED_V2:
            if (Uncompress_BlockV2_LZO(block, out, blockSize) < 0) failed = 1;
            break;
        case LZ4_COMPRESSED_V2:
            if (Uncompress_BlockV2_LZ4(block, out, blockSize) < 0) failed = 1;
            break;
        case BZ2_COMPRESSED_V2:
            if (Uncompress_BlockV2_BZ2(block, out, blockSize) < 0) failed = 1;
            break;
        case ZSTD_COMPRESSED_V2:
            if (Uncompress_BlockV2_ZSTD(block, out, blockSize) < 0) failed = 1;
            break;
        default:
            LogError("ReadBlockV2: unknown compression %d", comp);
            failed = 1;
    }

    free(block);
    if (failed) {
        free(out);
        return NULL;
    }
    return out;
}  // End of ReadBlockV2

// Read appendix blocks (stat_record + ident) from V2 file
static int ReadAppendixV2(int fd, fileHeaderV2_t *hdr, stat_record_t *stat_record, char **ident) {
    if (hdr->appendixBlocks == 0) return 1;

    off_t curPos = lseek(fd, 0, SEEK_CUR);
    if (curPos < 0) return 0;

    if (lseek(fd, hdr->offAppendix, SEEK_SET) < 0) {
        LogError("ReadAppendixV2: lseek to appendix failed: %s", strerror(errno));
        return 0;
    }

    uint32_t blockSize = hdr->BlockSize ? hdr->BlockSize : WRITE_BUFFSIZE;

    for (int i = 0; i < hdr->appendixBlocks; i++) {
        dataBlockV2_t *block = ReadBlockV2(fd, hdr->compression, blockSize);
        if (!block) {
            LogError("ReadAppendixV2: failed to read appendix block %d", i);
            lseek(fd, curPos, SEEK_SET);
            return 0;
        }

        uint8_t *ptr = (uint8_t *)block + sizeof(dataBlockV2_t);
        size_t processed = 0;
        for (uint32_t j = 0; j < block->NumRecords; j++) {
            recordHeader_t *recordHeader = (recordHeader_t *)ptr;
            uint8_t *data = ptr + sizeof(recordHeader_t);
            uint16_t dataSize = recordHeader->size - sizeof(recordHeader_t);

            switch (recordHeader->type) {
                case TYPE_IDENT:
                    if (*ident) free(*ident);
                    if (dataSize < IDENTLEN) {
                        *ident = strndup((char *)data, dataSize);
                    }
                    break;
                case TYPE_STAT:
                    if (dataSize == sizeof(stat_record_t)) {
                        memcpy(stat_record, data, sizeof(stat_record_t));
                    }
                    break;
                default:
                    break;
            }
            processed += recordHeader->size;
            ptr += recordHeader->size;
            if (processed > block->size) break;
        }
        free(block);
    }

    lseek(fd, curPos, SEEK_SET);
    return 1;
}  // End of ReadAppendixV2

static void *nfreaderV2(void *arg) {
    convertCtx_t *ctx = (convertCtx_t *)arg;
    nffileV3_t *nffile = ctx->nffile;

    dbg_printf("nfreaderV2 enter: %p\n", (void *)pthread_self());

    // Block signals in worker thread
    sigset_t set = {0};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);

    // V4 records are slightly larger per record due to offset tables.
    // Use 2x V2 block size to ensure output blocks never overflow.
    uint32_t outBlockSize = ctx->blockSize * 2;
    if (outBlockSize < BLOCK_SIZE_V3) outBlockSize = BLOCK_SIZE_V3;

    unsigned blockCount = 0;
    for (uint32_t i = 0; i < ctx->numBlocks; i++) {
        dataBlockV2_t *v2block = ReadBlockV2(ctx->fd, ctx->compression, ctx->blockSize);
        if (!v2block) {
            LogError("nfreaderV2: failed to read block %u", i);
            break;
        }

        // Only convert DATA_BLOCK_TYPE_3 — skip others
        if (v2block->type != DATA_BLOCK_TYPE_3) {
            free(v2block);
            continue;
        }

        flowBlockV3_t *v3block = convertV2V3(ctx, v2block, outBlockSize);
        free(v2block);

        if (!v3block) {
            LogError("nfreaderV2: conversion failed for block %u", i);
            break;
        }

        // Skip empty blocks
        if (v3block->rawSize <= sizeof(dataBlockV3_t)) {
            FreeDataBlock(v3block);
            continue;
        }

        if (queue_push(nffile->processQueue, (void *)v3block) == QUEUE_CLOSED) {
            FreeDataBlock(v3block);
            dbg_printf("nfreaderV2: processQueue closed\n");
            break;
        }
        blockCount++;
    }

    close(ctx->fd);
    free(ctx);

    if (exporter_table.count > 0) {
        // send exporter block
        AppendExporterBlock(nffile);
        freeTables();
    }
    queue_close(nffile->processQueue);

    dbg_printf("nfreaderV2 done - converted %u blocks\n", blockCount);
    pthread_exit(NULL);
}  // End of nfreaderV2

nffileV3_t *ConvertFileV2(const char *filename) {
    if (!filename) return NULL;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        LogError("ConvertFileV2: open() failed for '%s': %s", filename, strerror(errno));
        return NULL;
    }

    // Read V2 file header
    fileHeaderV2_t hdr;
    ssize_t ret = read(fd, &hdr, sizeof(hdr));
    if (ret != sizeof(hdr)) {
        LogError("ConvertFileV2: short read on header for '%s'", filename);
        close(fd);
        return NULL;
    }

    if (hdr.magic != MAGIC) {
        LogError("ConvertFileV2: bad magic 0x%X in '%s'", hdr.magic, filename);
        close(fd);
        return NULL;
    }
    if (hdr.version != LAYOUT_VERSION_2) {
        LogError("ConvertFileV2: unexpected version %u in '%s'", hdr.version, filename);
        close(fd);
        return NULL;
    }

    // Initialize V2 decompression library
    if (!InitUncompress_V2()) {
        LogError("ConvertFileV2: InitUncompress_V2 failed");
        close(fd);
        return NULL;
    }

    uint32_t blockSize = hdr.BlockSize ? hdr.BlockSize : WRITE_BUFFSIZE;

    // Read appendix (stat_record + ident)
    stat_record_t *stat_record = calloc(1, sizeof(stat_record_t));
    if (!stat_record) {
        close(fd);
        return NULL;
    }
    stat_record->msecFirstSeen = 0x7fffffffffffffff;

    char *ident = NULL;
    if (hdr.appendixBlocks) {
        struct stat sb;
        if (fstat(fd, &sb) == 0 && hdr.offAppendix < sb.st_size) {
            ReadAppendixV2(fd, &hdr, stat_record, &ident);
        }
    }

    // Create V3 file handle (1 worker thread)
    nffileV3_t *nffile = NewFile(1, DefaultQueueSize);
    if (!nffile) {
        free(stat_record);
        free(ident);
        close(fd);
        return NULL;
    }

    // Populate the V3 handle
    nffile->fd = -1;  // nfreaderV2 owns the fd, not the handle
    nffile->fileName = strdup(filename);
    nffile->stat_record = stat_record;
    nffile->ident = ident;

    // Synthesize a minimal V3 file header for callers that inspect it
    fileHeaderV3_t *fakeHeader = calloc(1, sizeof(fileHeaderV3_t));
    if (!fakeHeader) {
        CloseFileV3(nffile);
        close(fd);
        return NULL;
    }
    fakeHeader->magic = HEADER_MAGIC_V3;
    fakeHeader->layoutVersion = LAYOUT_VERSION_2;  // flag: converted from V2
    fakeHeader->nfdVersion = hdr.nfdversion;
    fakeHeader->created = (uint64_t)hdr.created;
    fakeHeader->creator = hdr.creator;
    fakeHeader->blockSize = blockSize * 2;  // V4 blocks can be larger
    nffile->fileHeader = fakeHeader;

    // Prepare conversion context
    convertCtx_t *ctx = malloc(sizeof(convertCtx_t));
    if (!ctx) {
        CloseFileV3(nffile);
        close(fd);
        return NULL;
    }
    *ctx = (convertCtx_t){
        .fd = fd,
        .numBlocks = hdr.NumBlocks,
        .compression = hdr.compression,
        .blockSize = blockSize,
        .nffile = nffile,
    };

    // Spawn nfreaderV2 thread
    int err = pthread_create(&nffile->worker[0], NULL, nfreaderV2, ctx);
    if (err) {
        LogError("ConvertFileV2: pthread_create failed: %s", strerror(err));
        free(ctx);
        close(fd);
        CloseFileV3(nffile);
        return NULL;
    }

    dbg_printf("ConvertFileV2: opened '%s' (%u blocks, compression %u)\n", filename, hdr.NumBlocks, hdr.compression);
    return nffile;
}  // End of ConvertFileV2
