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

/* Compress/decompress time ratio C for a codec.
 * Codec values must match nffileV3.h: UNDEF=0, NOT=1, LZO=2, BZ2=3, LZ4=4, ZSTD=5.
 * Returns 0.0 for uncompressed (I/O bound, treated specially by callers).
 * UNDEF_COMPRESSED (0) defaults to LZ4 as the most common codec. */
static float compressionRatio(uint16_t compression) {
    switch (compression) {
        case 0:
            return 2.0f;  // UNDEF: assume LZ4
        case 1:
            return 0.0f;  // NOT_COMPRESSED: I/O bound
        case 2:
            return 2.5f;  // LZO_COMPRESSED
        case 3:
            return 3.0f;  // BZ2_COMPRESSED
        case 4:
            return 2.0f;  // LZ4_COMPRESSED
        case 5:
            return 5.0f;  // ZSTD_COMPRESSED
        default:
            return 2.0f;  // unknown: safe LZ4 default
    }
}

/* Maximum sensible writer count for WRITE_ONLY collectors.
 * LZ4: L3 cache pressure dominates beyond ~8 threads.
 * ZSTD: compute-bound, scales further.
 * NOT_COMPRESSED / UNDEF: I/O bound or unknown. */
static uint32_t writeCap(uint16_t compression) {
    switch (compression) {
        case 0:
            return 8;  // UNDEF: assume LZ4
        case 1:
            return 2;  // NOT_COMPRESSED: I/O bound
        case 2:
            return 8;  // LZO
        case 3:
            return 8;  // BZ2
        case 4:
            return 8;  // LZ4
        case 5:
            return 12;  // ZSTD: compute-bound, scales more
        default:
            return 8;
    }
}

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

static uint32_t max_u32(uint32_t a, uint32_t b) { return a > b ? a : b; }

static uint32_t readerEstimate(uint32_t ref, uint16_t compression) {
    if (ref == 0) return 0;

    float C = compressionRatio(compression);
    if (C < 1.0f) return 1;

    uint32_t readers = (uint32_t)((float)ref / C + 0.5f);
    return readers < 1 ? 1 : readers;
}

static uint32_t addBalancedWorkers(uint32_t baseWorkers, uint32_t spare, uint16_t compression) {
    if (spare == 0) return baseWorkers;

    float C = compressionRatio(compression);
    if (C < 1.0f) return baseWorkers + spare;

    uint32_t add = (uint32_t)((float)spare * C / (1.0f + C) + 0.5f);
    if (add < 1) add = 1;
    if (add > spare) add = spare;

    return baseWorkers + add;
}

/* -----------------------------------------------------------------------
 * DeriveReaderCount — per-file nfreader count, called from mmapFileV3().
 *
 * A hard threads.readers override is handled at the call site in mmapFileV3
 * via threadConfig.readersOverride; this function only applies the formula.
 * ----------------------------------------------------------------------- */
uint32_t DeriveReaderCount(uint32_t ref, uint16_t compression) {
    if (ref == 0) return 0;  // TC_ROLE_WRITE_ONLY: no readers

    float C = compressionRatio(compression);
    if (C < 1.0f) return 1;  // NOT_COMPRESSED: 1 reader always enough

    uint32_t r = (uint32_t)((float)ref / C + 0.5f);
    if (r < 1) r = 1;
    // For compressed files with at least 2 workers to supply, use at least 2
    // readers.  A single reader can become a latency bottleneck under page-fault
    // spikes even when the C ratio says one suffices; the second reader is cheap
    // because readers are not subtracted from the alloc budget.
    if (ref >= 2 && r < 2) r = 2;
    return r;
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
    int confFilters = (int)ConfGetValue("threads.filters");

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

    float C = compressionRatio(compression);
    uint32_t alloc = coresUsed;
    if (pipeline.fixedThreads > 0) {
        alloc = (coresUsed > pipeline.fixedThreads) ? coresUsed - pipeline.fixedThreads : 1;
    }

    uint32_t writers = 0;
    uint32_t filters = 0;

    switch (pipeline.role) {
        case TC_ROLE_WRITE_ONLY: {
            /*
             * Collectors have no nffile read pipeline — full coresUsed to writers,
             * but capped at the codec's practical ceiling to avoid L3 thrashing
             * and to leave CPU for the collector hot path.
             */
            if (pipeline.hasWriters) {
                writers = min_u32(alloc, writeCap(compression));
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
            const float wfrac = 0.20f;

            uint32_t workers_n = pipeline.hasWorkers ? (uint32_t)((float)alloc * wfrac + 0.5f) : 0;
            if (pipeline.hasWorkers && workers_n < 1) workers_n = 1;
            if (workers_n >= alloc) workers_n = (alloc > 2) ? alloc / 3 : 1;

            uint32_t io = alloc > workers_n ? alloc - workers_n : 0;
            if (pipeline.hasWriters && C < 1.0f) {
                writers = min_u32(2, max_u32(io, 1));
            } else if (pipeline.hasWriters) {
                writers = (uint32_t)((float)io * C / (1.0f + C) + 0.5f);
                if (writers < 1) writers = 1;
                uint32_t capped = min_u32(writers, writeCap(compression));
                if (pipeline.hasWorkers && capped < writers) workers_n += writers - capped;
                writers = capped;
            }
            if (!pipeline.hasWriters && pipeline.hasWorkers) {
                workers_n = alloc;
            }
            if (pipeline.hasWriters && pipeline.hasWorkers) {
                uint32_t est_r = pipeline.hasReaders ? readerEstimate(writers, compression) : 0;
                uint32_t used = workers_n + writers + est_r;
                if (used < alloc) workers_n += alloc - used;
            }
            filters = workers_n;
            break;
        }

        case TC_ROLE_ANALYZE: {
            /*
             * Read → filter-workers (primary CPU work) → optional write.
             * Filter workers are sized for the active stages; readers are
             * sized to feed them; writers use remaining capped coresUsed.
             * Write+filter run: fixed 50% of alloc to filters; remainder
             *   split between readers (derived) and writers (capped).
             * Read-only run: codec-calibrated C/(1+C) split.
             */
            if (pipeline.hasWorkers) {
                if (pipeline.hasWriters) {
                    const float ffrac = 0.50f;
                    filters = (uint32_t)((float)alloc * ffrac + 0.5f);
                    if (filters < 1) filters = 1;
                    if (alloc >= 4 && filters < 2) filters = 2;
                    if (filters > alloc) filters = alloc;

                    uint32_t est_r = pipeline.hasReaders ? readerEstimate(filters, compression) : 0;
                    uint32_t used = filters + est_r;
                    writers = (used < alloc) ? alloc - used : 1;
                    writers = min_u32(writers, writeCap(compression));
                    if (writers < 1) writers = 1;

                    if (used + writers < alloc) {
                        filters = addBalancedWorkers(filters, alloc - used - writers, compression);
                    }
                } else if (pipeline.hasReaders) {
                    if (C < 1.0f) {
                        filters = alloc > 1 ? alloc - 1 : 1;
                    } else {
                        filters = (uint32_t)((float)alloc * C / (1.0f + C) + 0.5f);
                        if (filters < 1) filters = 1;
                    }
                } else {
                    filters = alloc;
                }
            } else if (pipeline.hasWriters) {
                uint32_t est_r = pipeline.hasReaders ? 1 : 0;
                writers = (alloc > est_r) ? alloc - est_r : 1;
                writers = min_u32(writers, writeCap(compression));
                if (writers < 1) writers = 1;
            }
            break;
        }

        default:
            writers = coresUsed;
            filters = 0;
            break;
    }

    // Hard per-role conf overrides take priority over the formula
    if (confWriters > 0) writers = (uint32_t)confWriters;
    if (confFilters > 0) filters = (uint32_t)confFilters;
    if (!pipeline.hasWriters && confWriters <= 0) writers = 0;
    if (!pipeline.hasWorkers && confFilters <= 0) filters = 0;

    // Startup reader estimate: derive ref from the final writers/filters so that
    // conf overrides are always reflected.  mmapFileV3() repeats this calculation
    // at each file open using the actual file codec.
    uint32_t ref = 0;
    if (pipeline.hasReaders) {
        switch (pipeline.role) {
            case TC_ROLE_ANALYZE:   ref = filters > 0 ? filters : 1; break;
            case TC_ROLE_TRANSFORM: ref = writers > 0 ? writers : filters; break;
            default: break;
        }
    }
    uint32_t readers = confReaders > 0 ? (uint32_t)confReaders : DeriveReaderCount(ref, compression);

    LogVerbose(
        "GetThreadConfig: role=%s coresUsed=%u fixed=%u alloc=%u codec=%u → "
        "writers=%u filters=%u readers(est)=%u ref=%u",
        roleDescriptor[pipeline.role], coresUsed, pipeline.fixedThreads, alloc, compression, writers, filters, readers, ref);

    return (threadConfig_t){
        .role = pipeline.role,
        .readers = readers,
        .writers = writers,
        .filters = filters,
        .workers = writers,
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
