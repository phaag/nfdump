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

/*
 * Optional post-decode, pre-backend record filter stage (-F).
 *
 * Sits between the collector frontend and whichever backend is attached to a
 * FlowSource:
 *
 *   frontend (netflow/sflow/nfpcapd decoders)
 *     -> fs->blockQueue                    (unchanged either way)
 *     -> [filter stage, only if -F given]
 *     -> backend's own queue
 *     -> nffile_backend_thread / udpsend_backend_thread
 *
 * When no -F is given, fs->blockQueue is exactly the queue the backend reads
 * from, as before this feature existed — zero extra thread, zero extra queue,
 * zero overhead. When -F is given, Init_FilterStage() retargets fs->blockQueue
 * to a new ingress queue that only the filter thread reads from, and forwards
 * filtered blocks to the backend's own queue (captured before the retarget).
 * The frontend producers and the backend consumers are therefore completely
 * unaware a filter stage exists — neither needs to change.
 *
 * The filter thread evaluates the shared, compiled libnffilter engine
 * (collector_ctx_t.filterEngine — plain-element filters only; see
 * filter/filter.c's NFFILTER_FULL guards) against every V4 record in each
 * BLOCK_TYPE_FLOW block, compacting non-matching records out in place. Only
 * one filter thread is ever needed per FlowSource: the compiled engine has no
 * per-thread mutable state once MaxMind/Tor/DNS/SSL/JA3/JA4/regex are
 * excluded (FilterCloneEngine() is still used for symmetry with nfdump's
 * pattern, but is a cheap struct copy — see filter.c).
 *
 * Non-flow blocks are forwarded in order. For an nffile backend, exporter
 * metadata flow counts are adjusted to the retained V4 records, and the
 * cycle message's stat_record is replaced with the filtered totals. A UDP
 * send backend does neither: it discards BLOCK_TYPE_EXP blocks outright and
 * only reads the `done` flag out of the cycle message (see
 * remote_backend.c), so exporter/stat bookkeeping for it would just be
 * computed and thrown away. That accounting isn't missed on the wire either
 * — the receiving nfcapd's Process_nfd() builds its own single synthetic
 * exporter (keyed by source IP) and its own stat_record directly from the
 * records it decodes, since the nfd UDP protocol carries no exporter or stat
 * metadata to begin with. A flow block left with zero surviving records is
 * dropped rather than forwarded, for either backend.
 */

#ifndef _FILTER_STAGE_H
#define _FILTER_STAGE_H 1

#include <stdbool.h>

#include "collector.h"
#include "flowsource.h"

/*
 * Init_FilterStage — wrap fs->blockQueue with a filter stage for this single
 * FlowSource. Must be called after Init_*_backend()/Launch_*_backend() (or
 * their orchestration equivalents) have already set fs->blockQueue to the
 * backend's queue - Init_FilterStage() captures that queue and repoints
 * fs->blockQueue to a new ingress queue that the filter thread reads from.
 *
 * baseEngine  the compiled libnffilter engine (collector_ctx_t.filterEngine).
 *             If NULL, this is a no-op and returns success — the caller is
 *             expected to skip calling this at all when -F was not given,
 *             but a NULL check is included defensively.
 *
 * isNffileBackend  true when fs is backed by an nffile backend: rewrite
 *                  cumulative exporter flow counts to retained V4-record
 *                  counts, and replace the cycle message's stat_record with
 *                  the filtered totals. false for a UDP send backend, which
 *                  discards both exporter blocks and the cycle stat_record
 *                  regardless (see filter_stage.c's file header comment for
 *                  why that bookkeeping is unneeded on the UDP path).
 *
 * Returns 1 on success, 0 on error (fs->blockQueue is left untouched on
 * error, so the backend keeps working unfiltered rather than being left in a
 * half-wired state).
 */
int Init_FilterStage(FlowSource_t *fs, void *baseEngine, bool isNffileBackend);

/*
 * Close_FilterStage — close the ingress queue, join the filter thread, and
 * free its per-thread engine clone. Restores fs->blockQueue to alias the
 * backend's own queue again, so the subsequent Close_*_backend() call's own
 * (now redundant, harmless — queue_close() is idempotent) queue_close() and
 * pthread_join() on the backend thread behave exactly as they do without a
 * filter stage. A no-op if this FlowSource never had a filter stage
 * (fs->filterCtx == NULL).
 *
 * Must be called before the corresponding Close_*_backend() call.
 */
void Close_FilterStage(FlowSource_t *fs);

/*
 * Orchestration — mirrors InitBackend()/CloseBackend() in nffile_backend.h:
 * operate over every currently-registered FlowSource in ctx (via
 * NextFlowSource(), so -w/-n/-M static and already-materialised dynamic
 * sources are all covered). Used by nfcapd/sfcapd; -M sources created later,
 * at runtime, are wired individually via Init_FilterStage() at their own
 * creation site (see process_packet() in nfcapd.c/sfcapd.c).
 *
 * No-op (returns 1) if ctx->filterEngine is NULL, i.e. -F was not given.
 */
int InitFilterStages(collector_ctx_t *ctx);

/* No-op if ctx->filterEngine is NULL. */
void CloseFilterStages(const collector_ctx_t *ctx);

#endif /* _FILTER_STAGE_H */
