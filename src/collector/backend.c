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

#include "backend.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bookkeeper.h"
#include "collector.h"
#include "flowsource.h"
#include "launch.h"
#include "logging.h"
#include "nffileV3/nffileV3.h"
#include "util.h"

static noreturn void *nffile_backend_thread(void *arg);

// requires backend_ctx to be allocated and set
// return err status - 1 on error, 0 otherwise
int Init_nffile_backend(FlowSource_t *fs, const nffile_backend_ctx_t *init_nffile_ctx) {
    nffile_backend_ctx_t *nffile_ctx = (nffile_backend_ctx_t *)fs->backend_ctx;
    book_handle_t *book_handle = book_open(nffile_ctx->datadir, getpid());
    if (book_handle == BOOK_FAILED || book_handle == BOOK_EXISTS) {
        LogError("Initialize bookkeeper failed");
        return 1;
    }

    nffile_ctx->creator = init_nffile_ctx->creator;
    nffile_ctx->compressType = init_nffile_ctx->compressType;
    nffile_ctx->compressLevel = init_nffile_ctx->compressLevel;
    nffile_ctx->encryption = init_nffile_ctx->encryption;
    nffile_ctx->time_extension = init_nffile_ctx->time_extension;
    nffile_ctx->msgQueue = init_nffile_ctx->msgQueue;
    nffile_ctx->pfd = init_nffile_ctx->pfd;
    nffile_ctx->blockQueue = queue_init(64);
    nffile_ctx->book_handle = book_handle;
    fs->blockQueue = nffile_ctx->blockQueue;

    // return err if no queue
    return nffile_ctx->blockQueue == NULL ? 1 : 0;

}  // End of Init_nffile_backend

// requires backend_ctx to be allocated and set
// if one flowsource failed to initialize, fail for the entire backend
// return ok status - 1 if ok, 0 otherwise
int InitBackend(const collector_ctx_t *ctx, const nffile_backend_ctx_t *init_nffile_ctx) {
    // Init
    int err = 0;
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        err += Init_nffile_backend(fs, init_nffile_ctx);
    }

    if (err) {
        // release all already allocated bookkeepers
        CloseBackend(ctx, 0);
        return 0;
    }

    return 1;
}  // End of InitBackend

void close_nffile_backend(FlowSource_t *fs, int expire) {
    (void)expire;
    if (fs->blockQueue) queue_close(fs->blockQueue);

    dbg_printf("Join backend thread\n");

    if (fs->tid) pthread_join(fs->tid, NULL);
    fs->tid = 0;

    nffile_backend_ctx_t *nffile_ctx = (nffile_backend_ctx_t *)fs->backend_ctx;
    if (nffile_ctx->book_handle) {
        book_close(nffile_ctx->book_handle);
        nffile_ctx->book_handle = NULL;
    }
    free(nffile_ctx->datadir);
    free(nffile_ctx->tmpFileName);
    free(nffile_ctx);
    fs->backend_ctx = NULL;
}  // End of close_nffile_backend

int CloseBackend(const collector_ctx_t *ctx, int expire) {
    dbg_printf("%s() enter\n", __func__);

    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        close_nffile_backend(fs, expire);
    }
    return 1;
}  // End of Close_nffile_backend

// launch nffile backend for this flowsource
int Launch_nffile_backend(FlowSource_t *fs) {
    fs->tid = 0;
    int err = pthread_create(&fs->tid, NULL, nffile_backend_thread, fs->backend_ctx);
    if (err) {
        LogError("pthread_create() failed: %s", strerror(err));
        return 0;
    }
    return 1;
}  // End of Launch_nffile_backend

// Launch all nffile backends of all configured flowsources
int LaunchBackend(collector_ctx_t *ctx) {
    for (FlowSource_t *fs = NextFlowSource(ctx); fs != NULL; fs = NextFlowSource(NULL)) {
        if (!Launch_nffile_backend(fs)) return 0;
    }
    return 1;
}  // End of Launch_nffile_backend

static int BackendRotateCycle(nffile_backend_ctx_t *nffile_ctx, msgBlockV3_t *dataBlock, int pfd, int *done) {
    // periodic file rotation
    dbg_printf("Enter backend RotateCycle. pdf: %d, done: %d\n", pfd, *done);

    uint32_t available = dataBlock->rawSize - sizeof(msgBlockV3_t);
    cycle_message_t *msghdr = ResetCursor(dataBlock);
    if (msghdr->type != MESSAGE_CYCLE || available < sizeof(cycle_message_t)) {
        LogError("Received bad or unknown message type: %u, length: %u", msghdr->type, available);
        return 0;
    }

    nffileV3_t *nffile = nffile_ctx->nffile;
    // not expected
    if (nffile == NULL) return 0;

    // early signal the writers, that we are done
    queue_close(nffile->processQueue);

    cycle_message_t cycle_message = {0};
    memcpy(&cycle_message, msghdr, sizeof(cycle_message_t));
    *done = cycle_message.done;

    struct tm local_tm = {0};
    struct tm *now = localtime_r(&cycle_message.when, &local_tm);
    if (now == NULL) {
        LogError("Received bad message: %s", strerror(errno));
        return 0;
    }
    char isoExtension[32];
    strftime(isoExtension, sizeof(isoExtension), nffile_ctx->time_extension, now);

    dbg_printf("Backend nffile rotation - time: %s, done: %u\n", isoExtension, cycle_message.done);

    char nfcapd_filename[MAXPATHLEN];
    nfcapd_filename[0] = '\0';

    int pos = SetupPath(now, nffile_ctx->datadir, nffile_ctx->subdir, nfcapd_filename);
    char *p = nfcapd_filename + (ptrdiff_t)pos;
    snprintf(p, MAXPATHLEN - pos - 1, "nfcapd.%s", isoExtension);
    nfcapd_filename[MAXPATHLEN - 1] = '\0';
    dbg_printf("SetupPath(): %s for: %s\n", nfcapd_filename, nffile->fileName);

    // update stat record
    // if no flows were collected, fs->msecLast is still 0
    // set msecFirst and msecLast and to start of this time slot
    memcpy(nffile->stat_record, &cycle_message.stat_record, sizeof(stat_record_t));
    nffile->ident = strdup(nffile_ctx->Ident);
    if (nffile->stat_record->msecLastSeen == 0) {
        nffile->stat_record->msecFirstSeen = 1000LL * (uint64_t)cycle_message.when;
        nffile->stat_record->msecLastSeen = nffile->stat_record->msecFirstSeen;
    }

    // Close file
    FlushFileV3(nffile);

    // if rename fails, we are in big trouble, as we need to get rid of the old .current
    // file otherwise, we will loose flows and can not continue collecting new flows
    if (RenameAppendV3(nffile->fileName, nfcapd_filename) < 0) {
        LogError("Ident: %s, Can't rename dump file: %s", nffile_ctx->Ident, strerror(errno));

        // we do not update the books here, as the file failed to rename properly
        // otherwise the books may be wrong
    } else {
        struct stat fstat;

        // Update books
        stat(nfcapd_filename, &fstat);
        book_update(nffile_ctx->book_handle, cycle_message.when, (uint64_t)(STAT_BLOCK_SIZE * fstat.st_blocks));
    }

    if (nffile_ctx->msgQueue) {
        // compile argument %f
        // nfcapd_filename => full path - cut of datadir/
        char *filename = nfcapd_filename + strlen(nffile_ctx->datadir) + 1;  //
        if (SendLauncherMessage(nffile_ctx->msgQueue, cycle_message.when, isoExtension, filename, nffile_ctx->datadir, nffile->ident) < 0) {
            LogError("Disable launcher due to errors");
            queue_close(nffile_ctx->msgQueue);
            nffile_ctx->msgQueue = NULL;
        }
    }

    CloseFileV3(nffile);
    nffile_ctx->nffile = NULL;

    if (cycle_message.done) return 1;

    // open new - next file
    int retry = 0;
    do {
        nffile = OpenNewFileTmpV3(nffile_ctx->tmpFileName, nffile_ctx->creator, nffile_ctx->compressType, nffile_ctx->compressLevel,
                                  nffile_ctx->encryption);
        if (nffile) break;

        retry++;
        usleep(1000);
    } while (retry < 2);

    if (nffile) {
        nffile_ctx->nffile = nffile;
    } else {
        LogError("Ident: %s, Can't re-open empty flow file", nffile_ctx->Ident);
        // unrecoverable error
        return 0;
    }

    return 1;

}  // End of BackendRotateCycle

static noreturn void *nffile_backend_thread(void *arg) {
    nffile_backend_ctx_t *nffile_ctx = (nffile_backend_ctx_t *)arg;

    dbg_printf("%s() thread startup\n", __func__);

    queue_t *blockQueue = nffile_ctx->blockQueue;  // queue from upstream collector

    nffile_ctx->nffile =
        OpenNewFileTmpV3(nffile_ctx->tmpFileName, nffile_ctx->creator, nffile_ctx->compressType, nffile_ctx->compressLevel, nffile_ctx->encryption);
    if (!nffile_ctx->nffile) {
        // closing the queue prevents the upstream collector to push new data blocks
        queue_close(blockQueue);
        pthread_exit(NULL);
    }

    uint32_t cnt = 0;
    int done = 0;
    while (!done) {
        dataBlockV3_t *dataBlock = queue_pop(blockQueue);
        if (dataBlock == QUEUE_CLOSED) {
            dbg_printf("%s() queue closed - exit loop\n", __func__);
            break;
        }

        dbg_printf("%s() receive datablock type %u\n", __func__, dataBlock->type);
        switch (dataBlock->type) {
            case BLOCK_TYPE_FLOW:
            case BLOCK_TYPE_ARRAY:
            case BLOCK_TYPE_EXP: {
                dbg_printf("%s() process next datablock\n", __func__);
                queue_push(nffile_ctx->nffile->processQueue, dataBlock);
                cnt++;
            } break;
            case BLOCK_TYPE_MSG: {
                dbg_printf("%s() process message block\n", __func__);
                if (!BackendRotateCycle(nffile_ctx, (msgBlockV3_t *)dataBlock, nffile_ctx->pfd, &done)) {
                    LogError("File rotation cycle failed for ident: %s", nffile_ctx->Ident);
                }
                FreeDataBlock(dataBlock);
            } break;
            default:
                LogError("Backend: received unknown block type %u", dataBlock->type);
        }
    }

    dbg_printf("%s() - exit loop - processed %u data blocks\n", __func__, cnt);
    (void)cnt;

    if (nffile_ctx->nffile) {
        DeleteFileV3(nffile_ctx->nffile);
    }

    dbg_printf("%s() thread exit\n", __func__);
    pthread_exit(NULL);

}  // End of nffile_backend_thread
