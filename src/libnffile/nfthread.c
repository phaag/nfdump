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

#include "nfthread.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nfthread.h"
#include "util.h"

static const struct roleDescriptor_s {
    char *roleString;
} roleDescriptor[] = {
    [TC_ROLE_WRITE_ONLY] = {"TC_ROLE_WRITE_ONLY"},
    [TC_ROLE_TRANSFORM] = {"TC_ROLE_TRANSFORM"},
    [TC_ROLE_ANALYZE] = {"TC_ROLE_ANALYZE"},
};

/* -----------------------------------------------------------------------
 * Static helpers
 * ----------------------------------------------------------------------- */

/* Per-codec properties, indexed by the on-disk compression code (nffileV3.h:
 * UNDEF=0, NOT=1, LZO=2, BZ2=3, LZ4=4, ZSTD=5).
 *
 * readerCost  fixed-point compress/decompress time ratio C, scaled by
 *             COST_SCALE (so e.g. LZO's C=2.5 is stored as 5).  0 means
 *             uncompressed / I/O bound, handled specially by callers.
 * maxWriters  practical writer ceiling: LZ4/LZO/BZ2 saturate the L3 cache
 *             beyond ~8 threads; ZSTD is compute-bound and scales further;
 *             NOT_COMPRESSED is I/O bound so extra writers just contend.
 * maxReaders  practical reader ceiling: decompression is the only reason to
 *             run more than a couple of readers, so the cap tracks how
 *             compute-bound the codec is. No machine benefits from dozens
 *             of reader threads regardless of core count.
 */
#define COST_SCALE 2

typedef struct {
    uint16_t readerCost;
    uint32_t maxWriters;
    uint32_t maxReaders;
} codecInfo_t;

static const codecInfo_t codecTable[] = {
    [0] = {4, 8, 8},    // UNDEF: assume LZ4
    [1] = {0, 2, 1},    // NOT_COMPRESSED: I/O bound
    [2] = {5, 8, 8},    // LZO
    [3] = {6, 8, 8},    // BZ2
    [4] = {4, 8, 8},    // LZ4
    [5] = {10, 12, 16}, // ZSTD: compute-bound, scales more
};
#define CODEC_TABLE_LEN (sizeof(codecTable) / sizeof(codecTable[0]))

static const codecInfo_t *codecInfo(uint16_t compression) {
    return compression < CODEC_TABLE_LEN ? &codecTable[compression] : &codecTable[0];  // unknown: safe LZ4 default
}

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

static uint32_t max_u32(uint32_t a, uint32_t b) { return a > b ? a : b; }

/* Compute-bound share of `total`, i.e. round(total * C/(1+C)) done in
 * integer arithmetic, where C = cost/COST_SCALE.  Used to split a thread
 * budget between an I/O stage and a stage whose cost scales with the codec.
 * Callers must handle cost==0 (uncompressed) themselves. */
static uint32_t splitByCost(uint32_t total, uint32_t cost) {
    uint32_t denom = COST_SCALE + cost;
    return (2 * total * cost + denom) / (2 * denom);
}

/* -----------------------------------------------------------------------
 * DeriveReaderCount — per-file nfreader count. Used both as a final count
 * (called from mmapFileV3() with the actual on-disk codec) and as a startup
 * estimate inside GetThreadConfig() (with the configured output codec).
 *
 * A hard threads.readers override is handled at the call site via
 * threadConfig.readersOverride; this function only applies the formula.
 * ----------------------------------------------------------------------- */
uint32_t DeriveReaderCount(uint32_t ref, uint16_t compression) {
    if (ref == 0) return 0;  // TC_ROLE_WRITE_ONLY: no readers

    const codecInfo_t *info = codecInfo(compression);
    if (info->readerCost == 0) return 1;  // NOT_COMPRESSED: 1 reader always enough

    uint32_t r = (4 * ref + info->readerCost) / (2 * info->readerCost);  // round(ref / C)
    if (r < 1) r = 1;
    // For compressed files with at least 2 workers to supply, use at least 2
    // readers.  A single reader can become a latency bottleneck under page-fault
    // spikes even when the C ratio says one suffices; the second reader is cheap
    // because readers are not subtracted from the alloc budget.
    if (ref >= 2 && r < 2) r = 2;
    return min_u32(r, info->maxReaders);
}  // End of DeriveReaderCount

/* -----------------------------------------------------------------------
 * GetThreadConfig — the single thread-coresUsed entry point.
 * ----------------------------------------------------------------------- */
threadConfig_t GetThreadConfig(uint32_t requested, uint16_t compression, threadPipeline_t pipeline) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 2;

    // Per-role conf overrides (0 = auto-derive)
    int confReaders = (int)ConfGetValue("threads.readers");
    int confWriters = (int)ConfGetValue("threads.writers");
    int confFilters = (int)ConfGetValue("threads.workers");

    // coresUsed: explicit -W → conf limitCores (or legacy maxworkers) → all online cores
    uint32_t coresUsed;
    if (requested > 0) {
        coresUsed = requested;
        if (requested > (uint32_t)cores) {
            LogInfo("Requested cores: %u exceeds %ld online cores; limitCores will be clamped to %ld", requested, cores, cores);
            coresUsed = cores;
        }
    } else {
        int confMax = (int)ConfGetValue("limitCores");
        if (confMax <= 0) confMax = (int)ConfGetValue("maxworkers");  // backward compat
        if (confMax > cores) {
            LogInfo("Configured cores: %d exceeds %ld online cores; limitCores will be clamped to %ld", confMax, cores, cores);
            confMax = (int)cores;
        }
        coresUsed = (confMax > 0) ? (uint32_t)confMax : (uint32_t)cores;
    }

    const codecInfo_t *info = codecInfo(compression);
    uint32_t cost = info->readerCost;
    uint32_t alloc = coresUsed;
    if (pipeline.fixedThreads > 0) {
        alloc = (coresUsed > pipeline.fixedThreads) ? coresUsed - pipeline.fixedThreads : 1;
    }

    uint32_t writers = 0;
    uint32_t workers = 0;

    switch (pipeline.role) {
        case TC_ROLE_WRITE_ONLY: {
            /*
             * Collectors have no nffile read pipeline — full coresUsed to writers,
             * but capped at the codec's practical ceiling to avoid L3 thrashing
             * and to leave CPU for the collector hot path.
             */
            if (pipeline.hasWriters) {
                writers = min_u32(alloc, info->maxWriters);
                if (writers < 1) writers = 1;
            }
            break;
        }

        case TC_ROLE_TRANSFORM: {
            /*
             * Three-stage: nffile-reader → app-worker → nffile-writer.
             * Reserve a fraction of the coresUsed for the application workers
             * (anonymization, bloom); split the rest between I/O threads.
             */
            const uint32_t wfracPercent = 20;

            uint32_t workers_n = pipeline.hasWorkers ? (alloc * wfracPercent + 50) / 100 : 0;
            if (pipeline.hasWorkers && workers_n < 1) workers_n = 1;
            if (workers_n >= alloc) workers_n = (alloc > 2) ? alloc / 3 : 1;

            uint32_t io = alloc > workers_n ? alloc - workers_n : 0;
            if (pipeline.hasWriters && cost == 0) {
                writers = min_u32(2, max_u32(io, 1));
            } else if (pipeline.hasWriters) {
                writers = splitByCost(io, cost);
                if (writers < 1) writers = 1;
                uint32_t capped = min_u32(writers, info->maxWriters);
                if (pipeline.hasWorkers && capped < writers) workers_n += writers - capped;
                writers = capped;
            }
            if (!pipeline.hasWriters && pipeline.hasWorkers) {
                workers_n = alloc;
            }
            if (pipeline.hasWriters && pipeline.hasWorkers) {
                uint32_t est_r = pipeline.hasReaders ? DeriveReaderCount(writers, compression) : 0;
                uint32_t used = workers_n + writers + est_r;
                if (used < alloc) workers_n += alloc - used;
            }
            workers = workers_n;
            break;
        }

        case TC_ROLE_ANALYZE: {
            /*
             * Read → filter-workers (primary CPU work) → optional write.
             * Filter workers are sized for the active stages; readers are
             * sized to feed them; writers use remaining capped coresUsed.
             * Write+filter run: fixed 50% of alloc to workers; remainder
             *   split between readers (derived) and writers (capped).
             * Read-only run: codec-calibrated C/(1+C) split.
             */
            if (pipeline.hasWorkers) {
                if (pipeline.hasWriters) {
                    const uint32_t ffracPercent = 50;
                    workers = (alloc * ffracPercent + 50) / 100;
                    if (workers < 1) workers = 1;
                    if (alloc >= 4 && workers < 2) workers = 2;
                    if (workers > alloc) workers = alloc;

                    uint32_t est_r = pipeline.hasReaders ? DeriveReaderCount(workers, compression) : 0;
                    uint32_t used = workers + est_r;
                    writers = (used < alloc) ? alloc - used : 1;
                    writers = min_u32(writers, info->maxWriters);
                    if (writers < 1) writers = 1;

                    if (used + writers < alloc) {
                        // Give any remainder back to workers, weighted by how
                        // compute-bound the codec is (same split as above).
                        uint32_t remaining = alloc - used - writers;
                        uint32_t add = cost == 0 ? remaining : max_u32(1, splitByCost(remaining, cost));
                        workers += min_u32(add, remaining);
                    }
                } else if (pipeline.hasReaders) {
                    workers = cost == 0 ? max_u32(alloc > 1 ? alloc - 1 : 1, 1) : splitByCost(alloc, cost);
                    if (workers < 1) workers = 1;
                } else {
                    workers = alloc;
                }
            } else if (pipeline.hasWriters) {
                uint32_t est_r = pipeline.hasReaders ? 1 : 0;
                writers = (alloc > est_r) ? alloc - est_r : 1;
                writers = min_u32(writers, info->maxWriters);
                if (writers < 1) writers = 1;
            }
            break;
        }

        default:
            writers = coresUsed;
            workers = 0;
            break;
    }

    // Hard per-role conf overrides take priority over the formula
    if (confWriters > 0) writers = (uint32_t)confWriters;
    if (confFilters > 0) workers = (uint32_t)confFilters;
    if (!pipeline.hasWriters && confWriters <= 0) writers = 0;
    if (!pipeline.hasWorkers && confFilters <= 0) workers = 0;

    // Startup reader estimate: derive ref from the final writers/workers so that
    // conf overrides are always reflected.  mmapFileV3() repeats this calculation
    // at each file open using the actual file codec.
    uint32_t ref = 0;
    if (pipeline.hasReaders) {
        switch (pipeline.role) {
            case TC_ROLE_ANALYZE:   ref = workers > 0 ? workers : 1; break;
            case TC_ROLE_TRANSFORM: ref = writers > 0 ? writers : workers; break;
            default: break;
        }
    }
    uint32_t readers = confReaders > 0 ? (uint32_t)confReaders : DeriveReaderCount(ref, compression);

    LogVerbose(
        "GetThreadConfig: role=%s coresUsed=%u fixed=%u alloc=%u codec=%u → "
        "writers=%u workers=%u readers(est)=%u ref=%u",
        roleDescriptor[pipeline.role], coresUsed, pipeline.fixedThreads, alloc, compression, writers, workers, readers, ref);

    return (threadConfig_t){
        .role = pipeline.role,
        .readers = readers,
        .writers = writers,
        .workers = workers,
        .readersOverride = confReaders > 0,
        .writersOverride = confWriters > 0,
    };
}  // End of GetThreadConfig

// initialize barrier for numWorkers + 1 controller
pthread_control_barrier_t *pthread_control_barrier_init(uint32_t numWorkers) {
    if (numWorkers == 0) {
        errno = EINVAL;
        return NULL;
    }

    pthread_control_barrier_t *barrier = calloc(1, sizeof(pthread_control_barrier_t));
    if (!barrier) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    int err = pthread_mutex_init(&barrier->workerMutex, 0);
    if (err != 0) {
        LogError("pthread_mutex_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        free(barrier);
        return NULL;
    }

    err = 0;
    if ((err = pthread_cond_init(&barrier->workerCond, 0)) != 0 || (err = pthread_cond_init(&barrier->controllerCond, 0)) != 0) {
        LogError("pthread_cond_init() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        pthread_mutex_destroy(&barrier->workerMutex);
        free(barrier);
        return NULL;
    }

    barrier->numWorkers = numWorkers;
    barrier->workersWaiting = 0;

    return barrier;

}  // End of pthread_barrier_init

// destroy mutex/cond variables
void pthread_control_barrier_destroy(pthread_control_barrier_t *barrier) {
    pthread_cond_destroy(&barrier->workerCond);
    pthread_cond_destroy(&barrier->controllerCond);
    pthread_mutex_destroy(&barrier->workerMutex);
}  // End of pthread_control_barrier_destroy

// enter the barrier and block execution.
// If all workers are waiting, signal the controller
void pthread_control_barrier_wait(pthread_control_barrier_t *barrier) {
    pthread_mutex_lock(&barrier->workerMutex);
    barrier->workersWaiting++;
    dbg_printf("Worker wait: %d\n", barrier->workersWaiting);
    if (barrier->workersWaiting >= barrier->numWorkers) {
        pthread_cond_broadcast(&barrier->controllerCond);
    }
    pthread_cond_wait(&barrier->workerCond, &(barrier->workerMutex));
    dbg_printf("Worker awake\n");
    pthread_mutex_unlock(&barrier->workerMutex);

}  // End of pthread_control_barrier_wait

// wait for all workers to reach the barrier.
// if all workers wait, controller continues
void pthread_controller_wait(pthread_control_barrier_t *barrier) {
    dbg_printf("Controller wait\n");
    pthread_mutex_lock(&barrier->workerMutex);
    while (barrier->workersWaiting < barrier->numWorkers)
        // wait for all workers
        pthread_cond_wait(&barrier->controllerCond, &(barrier->workerMutex));

    pthread_mutex_unlock(&barrier->workerMutex);
    dbg_printf("Controller wait done.\n");

}  // End of pthread_controller_wait

// release barrier and let all workers continue
void pthread_control_barrier_release(pthread_control_barrier_t *barrier) {
    dbg_printf("Controller release\n");
    pthread_mutex_lock(&barrier->workerMutex);
    barrier->workersWaiting = 0;
    pthread_cond_broadcast(&barrier->workerCond);
    pthread_mutex_unlock(&barrier->workerMutex);
    dbg_printf("Controller release done\n");

}  // End of pthread_control_barrier_release
