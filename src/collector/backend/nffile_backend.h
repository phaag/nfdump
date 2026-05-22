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
 * nffile backend — writes collected flows to nfcapd files on disk.
 *
 * The nffile backend is the default backend used by nfcapd and sfcapd.
 * Each FlowSource gets its own nffile_backend_ctx_t, blockQueue, and
 * background nffile_backend_thread that drains the queue and handles
 * periodic file rotation.
 */

#ifndef _NFFILE_BACKEND_H
#define _NFFILE_BACKEND_H 1

#include <pthread.h>
#include <stdint.h>

#include "collector.h"
#include "flowsource.h"
#include "nffileV3/nffileV3.h"

typedef struct nffile_backend_ctx_s {
    char Ident[IDENTLEN];  // source identifier

    book_handle_t *book_handle;  // book_handle for statistics of all files
    char *datadir;               // base dir to store flow files
    char *tmpFileName;           // name of tmp collection file
    uint32_t subdir;             // index of sub dir layout - see nffile.h
    nffileV3_t *nffile;          // nffile handle

    // const args
    char *time_extension;            // parameter passing
    uint32_t creator;                // creator - nfcapd or sfcapd
    uint16_t compressType;           // compression type
    uint16_t compressLevel;          // compression Level
    const crypto_ctx_t *crypto_ctx;  // encryption context; NULL = not encrypted
    int pfd;                         // launcher socket

    // collector param
    queue_t *blockQueue;  // queue from collector
    // launcher
    queue_t *msgQueue;  // queue for launcher

    pthread_t self;

} nffile_backend_ctx_t;

/*
 * Per-FlowSource lifecycle — called by the orchestration functions below, or
 * directly by tools that manage their own FlowSources (e.g. nfpcapd).
 */

/* Initialise the nffile backend context for a single FlowSource.
 * Requires fs->backend_ctx to be pre-allocated (done by newFlowSource()).
 * Returns 0 on success, 1 on error. */
int Init_nffile_backend(FlowSource_t *fs, const nffile_backend_ctx_t *init_nffile_ctx);

/* Start the nffile backend thread for a single FlowSource.
 * Returns 1 on success, 0 on error. */
int Launch_nffile_backend(FlowSource_t *fs);

/* Drain the queue, join the backend thread, and free the context. */
void close_nffile_backend(FlowSource_t *fs, int expire);

/*
 * Orchestration — operate over all FlowSources in a collector_ctx_t.
 * Used by nfcapd and sfcapd which manage a pool of FlowSources.
 */

/* Initialise the nffile backend for every FlowSource in ctx.
 * Returns 1 on success, 0 if any source failed (partial state is cleaned up). */
int InitBackend(const collector_ctx_t *ctx, const nffile_backend_ctx_t *init_nffile_ctx);

/* Launch the nffile backend thread for every FlowSource in ctx.
 * Returns 1 on success, 0 if any thread failed to start. */
int LaunchBackend(collector_ctx_t *ctx);

/* Close all nffile backends (drain, join, free) for every FlowSource in ctx. */
int CloseBackend(const collector_ctx_t *ctx, int expire);

#endif /* _NFFILE_BACKEND_H */
