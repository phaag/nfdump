/*
 *  Copyright (c) 2024-2026, Peter Haag
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

#ifndef _NFTHREADS_H
#define _NFTHREADS_H 1

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    pthread_mutex_t workerMutex;
    pthread_cond_t workerCond;
    pthread_cond_t controllerCond;
    int workersWaiting;
    int numWorkers;
} pthread_control_barrier_t;

/*
 * Program pipeline role — tells GetThreadConfig() how to split the budget.
 *
 * TC_ROLE_WRITE_ONLY  nfcapd, sfcapd, nfpcapd, ft2nfdump
 *   Collect → nffile writers only; no file-read pipeline.
 *   Writers are capped at a codec-specific ceiling (LZ4→8, ZSTD→12)
 *   to avoid L3 cache thrashing.  Pipeline-aware callers reserve fixed
 *   non-writer threads before writers are sized.
 *
 * TC_ROLE_TRANSFORM  nfanon, nfmeta
 *   Three-stage: nffile-readers → app-workers → nffile-writers.
 *   App workers (anonymization, bloom indexing) sit between decompress
 *   and compress.  Default split: ~20% workers, remainder for I/O.
 *
 * TC_ROLE_ANALYZE  nfdump, nfprofile, nftrack
 *   Read → filter-workers (primary bottleneck) → optional write.
 *   Filter workers are sized according to the active stages; readers are
 *   sized to feed them; writers are optional and codec-capped.
 */
typedef enum {
    TC_ROLE_WRITE_ONLY = 0,
    TC_ROLE_TRANSFORM,
    TC_ROLE_ANALYZE,
} tcRole_t;

typedef struct threadPipeline_s {
    tcRole_t role;
    bool hasReaders;
    bool hasWriters;
    bool hasWorkers;
    uint32_t fixedThreads;
} threadPipeline_t;

/*
 * Per-role thread counts returned by GetThreadConfig().
 *
 * role       program role — tells mmapFileV3 how to derive the per-file
 *            reader count from the live writers/filters values:
 *              WRITE_ONLY → readers = 0
 *              TRANSFORM  → ref = writers  (readers balance against compressors)
 *              ANALYZE    → ref = filters  (readers balance against filter workers)
 * writers    nfwriter compression threads  (→ InitNewFileV3 / NumWorkers)
 * filters    application worker threads:
 *              ANALYZE    → filter workers
 *              TRANSFORM  → anonymization / bloom workers
 *              WRITE_ONLY → 0
 * readers    estimated at startup; authoritative count recomputed per-file
 *            by DeriveReaderCount(ref, actualFileCompression)
 * workers    = writers  (backward-compat alias)
 * *Override  set when the matching threads.* key forced that count
 */
typedef struct {
    tcRole_t role;
    uint32_t readers;
    uint32_t writers;
    uint32_t filters;
    uint32_t workers;   /* = writers */
    uint8_t readersOverride;
    uint8_t writersOverride;
} threadConfig_t;

/* --- function prototypes ------------------------------------------------- */

/*
 * GetThreadConfig — stage-aware thread-budget entry point.
 *
 * requested   : -W value (0 = auto from sysconf; conf limitCores caps auto)
 * compression : output codec (0/UNDEF treated as LZ4 default)
 * pipeline    : describes which stages are active and how many threads are
 *               pre-allocated as fixed infrastructure (see threadPipeline_t)
 *
 * Conf/override keys (via nfdump.conf [threads] section or -x flag):
 *   threads.readers        = N   (0 = auto)
 *   threads.writers        = N   (0 = auto)
 *   threads.filters        = N   (0 = auto)
 *   threads.workerFraction = N   (integer %, default 20; TRANSFORM role)
 *   threads.filterFraction = N   (integer %, default 50; ANALYZE role)
 */
threadConfig_t GetThreadConfig(uint32_t requested, uint16_t compression, threadPipeline_t pipeline);

/*
 * DeriveReaderCount — per-file nfreader count, called from mmapFileV3().
 *
 * ref         : NumReaderRef (= tc.readerRef set by Init_nffile)
 * compression : actual codec read from the file header
 *
 * Returns 0 when ref==0 (WRITE_ONLY); otherwise round(ref / C_file).
 * Respects threads.readers conf override.
 */
uint32_t DeriveReaderCount(uint32_t ref, uint16_t compression);

pthread_control_barrier_t *pthread_control_barrier_init(uint32_t numWorkers);

void pthread_control_barrier_destroy(pthread_control_barrier_t *barrier);

void pthread_control_barrier_wait(pthread_control_barrier_t *barrier);

void pthread_controller_wait(pthread_control_barrier_t *barrier);

void pthread_control_barrier_release(pthread_control_barrier_t *barrier);

#endif
