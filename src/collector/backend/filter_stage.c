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

#include "backend/filter_stage.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "exporter.h"
#include "filter/filter.h"
#include "id.h"
#include "logging.h"
#include "nfxV4.h"
#include "queue.h"
#include "stat_record.h"

// MapV4RecordHandle() only - no dependency beyond nfxV4.h/logging.h, safe to
// use with the minimal libnffilter engine. Do NOT pull in nfdump_inline.c's
// FreeRecordHandle() here: it unconditionally calls sslFree(), which does not
// exist in libnffilter. That cleanup is for EXin/outPayloadHandle scratch
// state, which the minimal engine's payload preprocessors never allocate in
// the first place (see filter.c's NFFILTER_FULL guards), so there is nothing
// to free after FilterRecord() returns.
#include "nffile_inline.c"

#define FILTER_STAGE_QUEUE_DEPTH 64
#define FILTER_EXPORTER_TALLY_MIN_CAPACITY 32u

typedef struct filtered_exporter_s {
    uint32_t exporterID;
    uint64_t flows;
    bool used;
} filtered_exporter_t;

typedef struct filter_stage_ctx_s {
    void *engine;       // this thread's own FilterCloneEngine() copy
    queue_t *inQueue;   // == fs->blockQueue upstream queue
    queue_t *outQueue;  // the backend's downstream queue

    /* nffile only: cumulative retained V4 record counts by exporter sysID.
     * UDP never receives exporter blocks, so its filter stage does not create
     * this table and adds no exporter-accounting work to its hot path.
     */
    filtered_exporter_t *exporters;
    size_t exporterCapacity;
    size_t numExporters;
    bool rewriteExporterMetadata;

    /* nffile only: fold retained records into a filtered cycle stat_record
     * (see UpdateFilteredStatRecord/ApplyFilteredStatRecord below). Set once
     * at init from the same isNffileBackend the caller passed for
     * rewriteExporterMetadata, but tracked separately since the two must not
     * be conflated: rewriteExporterMetadata can be disabled later at runtime
     * (tally allocation failure), which has nothing to do with whether stat
     * bookkeeping is worth doing. UDP send backend discards both
     * BLOCK_TYPE_EXP blocks and the stat_record inside BLOCK_TYPE_MSG cycle
     * messages (see remote_backend.c) — a UDP-forwarded flow is re-accounted
     * from scratch by the receiving nfcapd's Process_nfd(), which builds its
     * own single synthetic exporter (keyed by source IP; the nfd wire
     * protocol carries no exporter or stat metadata at all) and its own
     * stat_record straight from the records it actually decodes. Computing
     * either piece of bookkeeping here for a UDP-backed FlowSource would just
     * be discarded work on the hot path. */
    bool trackStatRecord;
} filter_stage_ctx_t;

static noreturn void *filter_stage_thread(void *arg);

static int InitFilteredExporters(filter_stage_ctx_t *ctx, uint32_t sourceCapacity) {
    size_t capacity = FILTER_EXPORTER_TALLY_MIN_CAPACITY;
    size_t required = (size_t)sourceCapacity * 2;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) return 0;
        capacity <<= 1;
    }

    ctx->exporters = calloc(capacity, sizeof(filtered_exporter_t));
    if (!ctx->exporters) return 0;
    ctx->exporterCapacity = capacity;
    return 1;
}  // End of InitFilteredExporters

static filtered_exporter_t *FindFilteredExporter(const filter_stage_ctx_t *ctx, uint32_t exporterID) {
    size_t slot = ((uint64_t)exporterID * 2654435761u) & (ctx->exporterCapacity - 1);
    for (;;) {
        filtered_exporter_t *entry = &ctx->exporters[slot];
        if (!entry->used || entry->exporterID == exporterID) return entry;
        slot = (slot + 1) & (ctx->exporterCapacity - 1);
    }
}  // End of FindFilteredExporter

static int GrowFilteredExporters(filter_stage_ctx_t *ctx) {
    if (ctx->exporterCapacity > SIZE_MAX / 2) return 0;

    size_t newCapacity = ctx->exporterCapacity << 1;
    filtered_exporter_t *newExporters = calloc(newCapacity, sizeof(filtered_exporter_t));
    if (!newExporters) return 0;

    filtered_exporter_t *oldExporters = ctx->exporters;
    size_t oldCapacity = ctx->exporterCapacity;
    ctx->exporters = newExporters;
    ctx->exporterCapacity = newCapacity;
    for (size_t i = 0; i < oldCapacity; i++) {
        if (!oldExporters[i].used) continue;
        *FindFilteredExporter(ctx, oldExporters[i].exporterID) = oldExporters[i];
    }
    free(oldExporters);
    return 1;
}  // End of GrowFilteredExporters

static void CountFilteredExporter(filter_stage_ctx_t *ctx, uint32_t exporterID) {
    if (!ctx->rewriteExporterMetadata) return;

    filtered_exporter_t *entry = FindFilteredExporter(ctx, exporterID);
    bool newEntry = !entry->used;
    if (newEntry && (ctx->numExporters + 1) * 10 >= ctx->exporterCapacity * 7 && !GrowFilteredExporters(ctx)) {
        LogError("Filter stage: unable to grow exporter metadata tally; forwarding exporter metadata unchanged");
        free(ctx->exporters);
        ctx->exporters = NULL;
        ctx->exporterCapacity = ctx->numExporters = 0;
        ctx->rewriteExporterMetadata = false;
        return;
    }

    if (newEntry) entry = FindFilteredExporter(ctx, exporterID);
    if (newEntry) {
        entry->used = true;
        entry->exporterID = exporterID;
        ctx->numExporters++;
    }
    entry->flows++;
}  // End of CountFilteredExporter

static uint64_t FilteredExporterFlows(const filter_stage_ctx_t *ctx, uint32_t exporterID) {
    if (!ctx->rewriteExporterMetadata) return 0;
    filtered_exporter_t *entry = FindFilteredExporter(ctx, exporterID);
    return entry->used ? entry->flows : 0;
}  // End of FilteredExporterFlows

/* Exporter blocks hold cumulative counts. Replace only flows: packets count
 * received NetFlow/IPFIX/sFlow datagrams and sequence failures are exporter
 * transport state, neither of which can be derived from retained V4 records. */
static void RewriteExporterMetadata(filter_stage_ctx_t *ctx, expBlockV3_t *block) {
    uint8_t *ptr = (uint8_t *)block + sizeof(expBlockV3_t);
    uint8_t *eob = (uint8_t *)block + block->rawSize;

    for (uint32_t i = 0; i < block->numExporter; i++) {
        if ((size_t)(eob - ptr) < sizeof(exporter_info_record_v4_t)) {
            LogError("Filter stage: truncated exporter metadata block");
            return;
        }
        exporter_info_record_v4_t *info = (exporter_info_record_v4_t *)ptr;
        if (info->size < sizeof(exporter_info_record_v4_t) || info->size > (size_t)(eob - ptr)) {
            LogError("Filter stage: invalid exporter metadata record size %u", info->size);
            return;
        }
        info->flows = FilteredExporterFlows(ctx, info->sysID);
        ptr += info->size;
    }
}  // End of RewriteExporterMetadata

/*
 * ApplyFilteredStatRecord — the frontend's cycle statistics describe all
 * decoded records. Replace their record-derived part with the retained total;
 * sequence failures remain exporter/transport bookkeeping and must survive
 * filtering unchanged.
 */
static void ApplyFilteredStatRecord(stat_record_t *dst, const stat_record_t *filtered) {
    uint64_t sequence_failure = dst->sequence_failure;
    *dst = *filtered;
    dst->sequence_failure = sequence_failure;
}  // End of ApplyFilteredStatRecord

/*
 * FilterFlowBlock — evaluate every V4 record in a flow block against engine,
 * compacting non-matching records out in place. Recomputes numRecords,
 * rawSize, extensionBitmap, msecFirst and msecLast from the surviving
 * records only. Retained records are folded into *filteredStat so the caller
 * can replace the cycle's record-derived statistics with exact values.
 */
static void FilterFlowBlock(filter_stage_ctx_t *ctx, flowBlockV3_t *block, stat_record_t *filteredStat) {
    uint8_t *const base = (uint8_t *)block;
    uint8_t *readPtr = base + sizeof(flowBlockV3_t);
    uint8_t *writePtr = readPtr;
    uint8_t *const eob = base + block->rawSize;

    uint32_t survivors = 0;
    uint64_t extensionBitmap = 0;
    uint64_t msecFirst = 0;
    uint64_t msecLast = 0;
    uint64_t recordCounter = 0;
    recordHandle_t handle;

    while (readPtr < eob) {
        recordHeader_t *rec = (recordHeader_t *)readPtr;
        if (rec->size < sizeof(recordHeader_t) || (uint64_t)(readPtr - base) + rec->size > block->rawSize) {
            LogError("FilterFlowBlock: corrupt record size %u — truncating block", rec->size);
            break;
        }
        uint32_t recSize = rec->size;
        int keep = 1;

        if (rec->type == V4Record) {
            recordHeaderV4_t *v4 = (recordHeaderV4_t *)rec;
            recordCounter++;
            if (MapV4RecordHandle(&handle, v4, recordCounter)) {
                keep = FilterRecord(ctx->engine, &handle);
                if (keep) {
                    if (ctx->trackStatRecord)
                        UpdateRecordStat(filteredStat, (EXgenericFlow_t *)handle.extensionList[EXgenericFlowID],
                                         (EXcntFlow_t *)handle.extensionList[EXcntFlowID]);
                    CountFilteredExporter(ctx, v4->exporterID);
                    extensionBitmap |= v4->extBitmap;
                    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)handle.extensionList[EXgenericFlowID];
                    if (genericFlow) {
                        if (msecFirst == 0 || genericFlow->msecFirst < msecFirst) msecFirst = genericFlow->msecFirst;
                        if (genericFlow->msecLast > msecLast) msecLast = genericFlow->msecLast;
                    }
                }
            } else {
                // Corrupt/unmappable record: keep it rather than silently
                // drop data on a mapping error unrelated to the filter itself.
                LogError("FilterFlowBlock: failed to map V4 record %" PRIu64 " — keeping unfiltered", recordCounter);
            }
        } else {
            // Non-V4 record types are not expected inside a flow block from
            // any current collector frontend; keep unfiltered rather than
            // risk dropping data of a type this stage does not understand.
            LogError("FilterFlowBlock: unexpected record type %u in flow block — keeping unfiltered", rec->type);
        }

        if (keep) {
            if (writePtr != readPtr) memmove(writePtr, readPtr, recSize);
            writePtr += recSize;
            survivors++;
        }
        readPtr += recSize;
    }

    block->numRecords = survivors;
    block->rawSize = (uint32_t)(writePtr - base);
    block->extensionBitmap = extensionBitmap;
    block->msecFirst = msecFirst;
    block->msecLast = msecLast;

}  // End of FilterFlowBlock

int Init_FilterStage(FlowSource_t *fs, void *baseEngine, bool isNffileBackend) {
    if (!baseEngine) return 1;  // no -F configured: nothing to do

    filter_stage_ctx_t *ctx = calloc(1, sizeof(filter_stage_ctx_t));
    if (!ctx) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    ctx->engine = FilterCloneEngine(baseEngine);
    if (!ctx->engine) {
        LogError("Init_FilterStage: FilterCloneEngine failed");
        free(ctx);
        return 0;
    }

    ctx->rewriteExporterMetadata = isNffileBackend;
    ctx->trackStatRecord = isNffileBackend;
    if (ctx->rewriteExporterMetadata && !InitFilteredExporters(ctx, fs->exporters.capacity)) {
        LogError("Init_FilterStage: exporter metadata tally allocation failed");
        DisposeFilter(ctx->engine);
        free(ctx);
        return 0;
    }

    ctx->inQueue = queue_init(FILTER_STAGE_QUEUE_DEPTH);
    if (!ctx->inQueue) {
        LogError("Init_FilterStage: queue_init failed");
        DisposeFilter(ctx->engine);
        free(ctx);
        return 0;
    }

    ctx->outQueue = fs->blockQueue;  // the backend's own queue
    fs->filterCtx = ctx;
    fs->blockQueue = ctx->inQueue;  // frontend now feeds the filter stage

    int err = pthread_create(&fs->filterTid, NULL, filter_stage_thread, fs);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        fs->blockQueue = ctx->outQueue;
        fs->filterCtx = NULL;
        queue_free(ctx->inQueue);
        free(ctx->exporters);
        DisposeFilter(ctx->engine);
        free(ctx);
        return 0;
    }

    return 1;

}  // End of Init_FilterStage

void Close_FilterStage(FlowSource_t *fs) {
    if (!fs || !fs->filterCtx) return;

    filter_stage_ctx_t *ctx = (filter_stage_ctx_t *)fs->filterCtx;

    queue_close(ctx->inQueue);
    dbg_printf("Join filter stage thread\n");
    if (fs->filterTid) pthread_join(fs->filterTid, NULL);
    fs->filterTid = 0;

    // Restore fs->blockQueue to alias the backend's own queue again, so the
    // caller's subsequent Close_*_backend() call closes/joins exactly as it
    // does without a filter stage (its own queue_close() on it is then a
    // harmless, idempotent no-op — the filter thread already closed it).
    fs->blockQueue = ctx->outQueue;

    queue_free(ctx->inQueue);
    free(ctx->exporters);
    DisposeFilter(ctx->engine);
    free(ctx);
    fs->filterCtx = NULL;

}  // End of Close_FilterStage

int InitFilterStages(collector_ctx_t *ctx) {
    if (!ctx->filterEngine) return 1;

    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        if (!Init_FilterStage(fs, ctx->filterEngine, fs->isNffileBackend)) return 0;
    }
    return 1;

}  // End of InitFilterStages

void CloseFilterStages(const collector_ctx_t *ctx) {
    if (!ctx->filterEngine) return;

    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        Close_FilterStage(fs);
    }

}  // End of CloseFilterStages

/*
 * filter_stage_thread — pop blocks from the ingress queue, filter
 * BLOCK_TYPE_FLOW blocks in place, forward everything else (including
 * emptied-out flow blocks, which are dropped instead) to the backend queue in
 * the same order they were received. Exits when the ingress queue is closed
 * (the frontend is done producing, or shutdown is in progress), closing the
 * backend queue in turn so the backend thread also winds down.
 *
 * filteredStat accumulates the stat_record contribution of every retained
 * record since the last cycle message, but only when ctx->trackStatRecord is
 * set (nffile backend). cycle_message_t::stat_record is built by the
 * frontend (fs->stat_record) before any filtering happens, so it is a
 * pre-filter total; when a BLOCK_TYPE_MSG cycle message reaches this thread,
 * its record-derived fields are replaced with filteredStat and then reset.
 * Ordering is safe because a cycle's flow blocks are always pushed before
 * its message block (PeriodicCycle/EmitCycleMessage), and this thread drains
 * its single ingress queue strictly in order. For a UDP send backend
 * (trackStatRecord false) filteredStat is left untouched at all zeroes and
 * the cycle message's stat_record is passed through unmodified — the UDP
 * backend only reads its `done` flag and discards the rest (see
 * remote_backend.c), so folding retained records into it would be wasted
 * work on this thread's hot path.
 */
static noreturn void *filter_stage_thread(void *arg) {
    FlowSource_t *fs = (FlowSource_t *)arg;
    filter_stage_ctx_t *ctx = (filter_stage_ctx_t *)fs->filterCtx;
    stat_record_t filteredStat = {0};

    dbg_printf("%s() thread startup\n", __func__);

    for (;;) {
        dataBlockV3_t *block = (dataBlockV3_t *)queue_pop(ctx->inQueue);
        if (block == QUEUE_CLOSED) break;

        switch (block->type) {
            case BLOCK_TYPE_FLOW:
                FilterFlowBlock(ctx, (flowBlockV3_t *)block, &filteredStat);
                if (((flowBlockV3_t *)block)->numRecords == 0) {
                    dbg_printf("%s() block fully filtered out — drop\n", __func__);
                    FreeDataBlock(block);
                    continue;
                }
                break;
            case BLOCK_TYPE_MSG: {
                cycle_message_t *msg = (cycle_message_t *)ResetCursor((msgBlockV3_t *)block);
                if (msg->type == MESSAGE_CYCLE) {
                    if (ctx->trackStatRecord) ApplyFilteredStatRecord(&msg->stat_record, &filteredStat);
                    memset(&filteredStat, 0, sizeof(filteredStat));
                }
            } break;
            case BLOCK_TYPE_EXP:
                if (ctx->rewriteExporterMetadata) RewriteExporterMetadata(ctx, (expBlockV3_t *)block);
                break;
            default:
                break;
        }

        if (queue_push(ctx->outQueue, block) == QUEUE_CLOSED) {
            FreeDataBlock(block);
            break;
        }
    }

    queue_close(ctx->outQueue);

    dbg_printf("%s() exit\n", __func__);
    pthread_exit(NULL);

}  // End of filter_stage_thread
