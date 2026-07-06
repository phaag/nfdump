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

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"
#include "flist.h"
#include "id.h"
#include "logging.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nffile_inline.c"
#include "nfthread.h"
#include "nfxV4.h"
#include "queue.h"
#include "util.h"

static void usage(char *name);
static void process_data(const char *wfile, int numWorkers, int verbose);

typedef struct {
    queue_t *inputQueue;
    queue_t *outputQueue;
    uint32_t blockSize;
} workerArgs_t;

static void usage(char *name) {
    printf(
        "usage %s [options]\n"
        "-h\t\tthis text you see right here\n"
        "-r <path>\tread input from file or directory\n"
        "-w <file>\twrite all output to this file\n"
        "-v <num>\tverbose level\n"
        "\t\tif -w is omitted, each input file is replaced in-place\n"
        "-W <num>\tSet core limit to <num> CPU cores (0 = all online cores)\n"
        "-x <key>=<value>\tOverride a config parameter at runtime (repeatable).\n",
        name);
}  // End of usage

/* bloomHandle_t is defined in bloom.h */

static const struct {
    uint16_t metaType;
    size_t bpOffset;
} kBloomDefs[4] = {
    {META_TYPE_BLOOM_SRC_IPV4, offsetof(bloomHandle_t, srcIPv4bloom)},
    {META_TYPE_BLOOM_DST_IPV4, offsetof(bloomHandle_t, dstIPv4bloom)},
    {META_TYPE_BLOOM_SRC_IPV6, offsetof(bloomHandle_t, srcIPv6bloom)},
    {META_TYPE_BLOOM_DST_IPV6, offsetof(bloomHandle_t, dstIPv6bloom)},
};

/*
 * Write four META bloom records at the cursor and set each bloomHandle
 * pointer into the block so subsequent BloomAdd* calls update them in-place.
 */
static void addBloomHandle(flowBlockV3_t *dataBlock, bloomHandle_t *bloomHandle) {
    for (int i = 0; i < 4; i++) {
        void *cur = GetCursor(dataBlock);
        metaRecordHeader_t *hdr = (metaRecordHeader_t *)cur;
        *hdr = (metaRecordHeader_t){
            .type = METARecord,
            .metaType = kBloomDefs[i].metaType,
            .size = sizeof(metaRecordHeader_t) + sizeof(bloomFilter_t),
        };
        bloomFilter_t **bp = (bloomFilter_t **)((uint8_t *)bloomHandle + kBloomDefs[i].bpOffset);
        *bp = (bloomFilter_t *)((uint8_t *)cur + sizeof(metaRecordHeader_t));
        BloomInit(*bp);

        dataBlock->numRecords++;
        dataBlock->rawSize += hdr->size;
    }
}  // End of addBloomHandle

/*
 * Add the flow's src/dst IPs to the block's bloom filters and track the
 * per-block time window.  Only called for V4Record entries.
 */
static void updateMetaData(bloomHandle_t *bloomHandle, recordHandle_t *recordHandle, uint64_t *firstSeen, uint64_t *lastSeen) {
    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
    EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)recordHandle->extensionList[EXipv4FlowID];
    EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)recordHandle->extensionList[EXipv6FlowID];

    if (ipv4Flow) {
        BloomAddIPv4(bloomHandle->srcIPv4bloom, ipv4Flow->srcAddr);
        BloomAddIPv4(bloomHandle->dstIPv4bloom, ipv4Flow->dstAddr);
    }
    if (ipv6Flow) {
        BloomAddIPv6(bloomHandle->srcIPv6bloom, (const uint8_t *)ipv6Flow->srcAddr);
        BloomAddIPv6(bloomHandle->dstIPv6bloom, (const uint8_t *)ipv6Flow->dstAddr);
    }
    if (genericFlow) {
        if (genericFlow->msecFirst && genericFlow->msecFirst < *firstSeen) *firstSeen = genericFlow->msecFirst;
        if (genericFlow->msecLast && genericFlow->msecLast > *lastSeen) *lastSeen = genericFlow->msecLast;
    }
}  // End of updateMetaData

/*
 * Worker thread: pops flow blocks from inputQueue, strips any pre-existing
 * META records, adds fresh bloom-filter META records, and pushes the
 * annotated output blocks to outputQueue.
 */
static void *workerThread(void *arg) {
    workerArgs_t *workerArgs = (workerArgs_t *)arg;

    bloomHandle_t bloomHandle = {0};
    uint64_t firstSeen = UINT64_MAX;
    uint64_t lastSeen = 0;
    flowBlockV3_t *dataBlock_w = NewFlowBlock(workerArgs->blockSize);
    addBloomHandle(dataBlock_w, &bloomHandle);

    flowBlockV3_t *dataBlock_r = queue_pop(workerArgs->inputQueue);
    while (dataBlock_r != QUEUE_CLOSED) {
        recordHeaderV4_t *recordPtr = ResetCursor(dataBlock_r);

        uint32_t sumSize = 0;
        recordHandle_t recordHandle = {0};
        for (int i = 0; i < (int)dataBlock_r->numRecords; i++) {
            if ((sumSize + recordPtr->size) > dataBlock_r->rawSize || recordPtr->size < sizeof(recordHeaderV4_t)) {
                LogError("Corrupt data block. Inconsistent record size in %s line %d", __FILE__, __LINE__);
                FreeDataBlock(dataBlock_r);
                FreeDataBlock(dataBlock_w);
                queue_close(workerArgs->outputQueue);
                pthread_exit(NULL);
            }
            sumSize += recordPtr->size;

            if (recordPtr->type == METARecord) goto NEXT_REC;

            if (!IsAvailable(dataBlock_w, workerArgs->blockSize, recordPtr->size)) {
                dataBlock_w->msecFirst = (firstSeen != UINT64_MAX) ? firstSeen : 0;
                dataBlock_w->msecLast = lastSeen;
                dataBlock_w->extensionBitmap |= dataBlock_r->extensionBitmap;
                queue_push(workerArgs->outputQueue, dataBlock_w);

                dataBlock_w = NewFlowBlock(workerArgs->blockSize);
                addBloomHandle(dataBlock_w, &bloomHandle);

                firstSeen = UINT64_MAX;
                lastSeen = 0;
            }

            if (recordPtr->type == V4Record) {
                memset(&recordHandle, 0, sizeof(recordHandle));
                MapV4RecordHandle(&recordHandle, recordPtr, 0);
                updateMetaData(&bloomHandle, &recordHandle, &firstSeen, &lastSeen);
            }

            memcpy(GetCursor(dataBlock_w), recordPtr, recordPtr->size);
            dataBlock_w->numRecords++;
            dataBlock_w->rawSize += recordPtr->size;

        NEXT_REC:
            recordPtr = (recordHeaderV4_t *)((void *)recordPtr + recordPtr->size);
        }

        dataBlock_w->extensionBitmap |= dataBlock_r->extensionBitmap;
        FreeDataBlock(dataBlock_r);
        dataBlock_r = queue_pop(workerArgs->inputQueue);
    }

    if (dataBlock_w->numRecords) {
        queue_push(workerArgs->outputQueue, dataBlock_w);
    }
    queue_close(workerArgs->outputQueue);

    pthread_exit(NULL);
}  // End of workerThread

/*
 * Flush the current output block and finalize the output file.
 *
 * wfile == NULL (in-place mode):
 *   The output was written to a temporary file created by OpenNewFileTmpV3.
 *   Save the temp path, close, then rename it atomically over srcFile.
 *   On rename failure the original file is left untouched.
 *
 * wfile != NULL (named output):
 *   Just flush and close; the file stays at wfile.
 *   Pass closeIt=0 to keep the file open across multiple input files.
 */
/*
 * Finalize and close nffile_w.  All data blocks have already been pushed to
 * nffile_w->processQueue by workers; this only needs to write the file footer.
 *
 * wfile == NULL (in-place): rename the temp file over srcFile atomically.
 * wfile != NULL (named output): just close the file.
 */
static int flushAndClose(nffileV3_t *nffile_w, const char *wfile, const char *srcFile) {
    FlushFileV3(nffile_w);

    if (!wfile) {
        /* In-place: rename temp over original. */
        char *tmpName = strdup(nffile_w->fileName);
        CloseFileV3(nffile_w);
        if (!tmpName) {
            LogError("strdup() failed: %s", strerror(errno));
            return 0;
        }
        if (rename(tmpName, srcFile) != 0) {
            LogError("rename(%s, %s) failed: %s", tmpName, srcFile, strerror(errno));
            unlink(tmpName);
            free(tmpName);
            return 0;
        }
        free(tmpName);
    } else {
        CloseFileV3(nffile_w);
    }
    return 1;
}  // End of flushAndClose

/*
 * process_data — two modes controlled by wfile:
 *
 * wfile != NULL: all input files are merged into one output at wfile.
 *   The output is opened once before the first input file and closed at
 *   the very end.
 *
 * wfile == NULL: each input file is processed independently.
 *   A temporary file is created next to the input via OpenNewFileTmpV3
 *   and renamed atomically over the original on success.
 */
/*
 * process_data — two modes controlled by wfile:
 *
 * wfile != NULL: all input files are merged into one output at wfile.
 *   The output file is opened once; workers are launched and joined once
 *   per input file but the output file stays open across all of them.
 *
 * wfile == NULL: each input file is processed independently (in-place).
 *   A temporary file is created next to each input via OpenNewFileTmpV3
 *   and renamed atomically over the original after that file's workers
 *   have finished.
 *
 * For each input file the main thread:
 *   1. Launches numWorkers worker threads.
 *   2. Reads every block: non-flow blocks pass through directly;
 *      flow blocks are pushed to the workers via inputQueue.
 *   3. Closes inputQueue — workers drain it and terminate, each
 *      calling queue_close(outputQueue) on exit.
 *   4. Drains outputQueue until QUEUE_CLOSED, forwarding annotated
 *      blocks to nffile_w->processQueue.
 *   5. Joins workers and frees the per-file queues.
 *   6. Finalizes (and optionally renames) the output file.
 */
static void process_data(const char *wfile, int numWorkers, int verbose) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    int blk_count = 0;
    int file_count = 0;

    setvbuf(stdout, (char *)NULL, _IONBF, 0);

    nffileV3_t *nffile_r = GetNextFile();
    if (!nffile_r) {
        LogError("Empty file list. No files to process");
        return;
    }

    workerArgs_t workerArgs = {0};
    nffileV3_t *nffile_w = NULL;
    char srcFile[MAXPATHLEN] = {0};
    pthread_t *tids = calloc(numWorkers, sizeof(pthread_t));
    if (!tids) {
        LogError("calloc() error: %s", strerror(errno));
        if (nffile_w) CloseFileV3(nffile_w);
        CloseFileV3(nffile_r);
        return;
    }
    if (verbose > 1) printf("Use %u workers\n", numWorkers);

    // In single-output mode, open the output file once
    if (wfile) {
        nffile_w = OpenNewFileV3(wfile, CREATOR_NFDUMP, nffile_r->compression, 0, NULL);
        if (!nffile_w) {
            CloseFileV3(nffile_r);
            return;
        }
        SetIdent(nffile_w, nffile_r->ident);
        __builtin_memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
        if (verbose > 1) printf("Output: %s\n", wfile);

        // Launch workers for this file
        workerArgs = (workerArgs_t){
            .inputQueue = queue_init(16),
            .outputQueue = queue_init(16),
            .blockSize = nffile_r->fileHeader->blockSize,
        };
        queue_producers(workerArgs.outputQueue, numWorkers);

        for (int i = 0; i < numWorkers; i++) {
            int err = pthread_create(&tids[i], NULL, workerThread, &workerArgs);
            if (err) {
                LogError("pthread_create() error: %s", strerror(err));
                exit(255);
            }
        }
    }

    while (nffile_r) {
        // In per-file mode, open a fresh output file for each input
        if (!wfile) {
            if (!nffile_r->fileName) {
                LogError("Cannot determine input file name for in-place replacement");
                CloseFileV3(nffile_r);
                break;
            }
            strncpy(srcFile, nffile_r->fileName, sizeof(srcFile) - 1);
            char tmpPath[MAXPATHLEN];
            snprintf(tmpPath, sizeof(tmpPath), "%s.XXXXXX", srcFile);
            nffile_w = OpenNewFileTmpV3(tmpPath, CREATOR_NFDUMP, nffile_r->compression, 0, NULL);
            if (!nffile_w) {
                LogError("Failed to open output for %s", srcFile);
                CloseFileV3(nffile_r);
                break;
            }
            SetIdent(nffile_w, nffile_r->ident);
            __builtin_memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
            file_count++;
            if (verbose) printf("  %i Processing %s\r", file_count, srcFile);

            // Launch workers for this file
            workerArgs = (workerArgs_t){
                .inputQueue = queue_init(16),
                .outputQueue = queue_init(16),
                .blockSize = nffile_r->fileHeader->blockSize,
            };
            queue_producers(workerArgs.outputQueue, numWorkers);

            for (int i = 0; i < numWorkers; i++) {
                int err = pthread_create(&tids[i], NULL, workerThread, &workerArgs);
                if (err) {
                    LogError("pthread_create() error: %s", strerror(err));
                    exit(255);
                }
            }
        }

        /* Push all blocks from the current input file while concurrently
         * draining the output queue to prevent deadlock.
         *
         * Deadlock scenario without draining:
         *   inputQueue full  → main blocks on queue_push(inputQueue)
         *   outputQueue full → workers block on queue_push(outputQueue)
         *   Nobody drains outputQueue → circular wait.
         * With queue sizes of 8+8=16, any file with >16 flow blocks can hit this.
         *
         * Fix: use queue_try_push so we never block on inputQueue.  When it is
         * full, drain one output block (blocking) — this unblocks a worker,
         * which then pops from inputQueue, freeing space for our retry.
         * After each successful push, also do a non-blocking sweep of any
         * additional ready output blocks.                                      */
        while (1) {
            flowBlockV3_t *dataBlock_r = ReadBlockV3(nffile_r);
            if (dataBlock_r == NULL) break;

            // push non flow blocks directly to file queue
            if (dataBlock_r->type != BLOCK_TYPE_FLOW) {
                PushBlockV3(nffile_w->processQueue, dataBlock_r);
                continue;
            }
            if (verbose) printf("\r%c", spinner[blk_count & 0x3]);
            blk_count++;

            /*
             * Try to push; if inputQueue is full drain one output block
             * (blocking) until space becomes available
             */
            while (queue_try_push(workerArgs.inputQueue, dataBlock_r) == QUEUE_FULL) {
                flowBlockV3_t *dataBlock_w = queue_pop(workerArgs.outputQueue);
                if (dataBlock_w != QUEUE_CLOSED) PushBlockV3(nffile_w->processQueue, dataBlock_w);
            }

            // Non-blocking sweep: forward any already-finished output blocks
            flowBlockV3_t *dataBlock_w = queue_try_pop(workerArgs.outputQueue);
            while (dataBlock_w != QUEUE_EMPTY && dataBlock_w != QUEUE_CLOSED) {
                PushBlockV3(nffile_w->processQueue, dataBlock_w);
                dataBlock_w = queue_try_pop(workerArgs.outputQueue);
            }
        }

        // In per-file mode: Signal workers: no more input for this file
        // finalize and rename before opening the next file. */
        if (!wfile) {
            // per file mode
            queue_close(workerArgs.inputQueue);
            // drain last blocks
            flowBlockV3_t *dataBlock_w = queue_pop(workerArgs.outputQueue);
            while (dataBlock_w != QUEUE_CLOSED) {
                PushBlockV3(nffile_w->processQueue, dataBlock_w);
                dataBlock_w = queue_pop(workerArgs.outputQueue);
            }

            // join workers
            for (int i = 0; i < numWorkers; i++) pthread_join(tids[i], NULL);

            if (!flushAndClose(nffile_w, NULL, srcFile)) break;
            nffile_w = NULL;

            queue_free(workerArgs.inputQueue);
            queue_free(workerArgs.outputQueue);
        }

        CloseFileV3(nffile_r);
        nffile_r = GetNextFile();
    }

    if (wfile && nffile_w) {
        // single file mode
        queue_close(workerArgs.inputQueue);
        // drain last blocks
        flowBlockV3_t *dataBlock_w = queue_pop(workerArgs.outputQueue);
        while (dataBlock_w != QUEUE_CLOSED) {
            PushBlockV3(nffile_w->processQueue, dataBlock_w);
            dataBlock_w = queue_pop(workerArgs.outputQueue);
        }

        // join workers
        for (int i = 0; i < numWorkers; i++) pthread_join(tids[i], NULL);

        flushAndClose(nffile_w, wfile, srcFile);
        nffile_w = NULL;

        queue_free(workerArgs.inputQueue);
        queue_free(workerArgs.outputQueue);

        printf("\rProcessed %d flow blocks\n", blk_count);
    }
    free(tids);
    printf("\rProcessed %d flow blocks across %d file(s)\n", blk_count, file_count);

}  // End of process_data

int main(int argc, char **argv) {
    flist_t flist = {0};
    char *wfile = NULL;
    int limitCores = 0;
    int verbose = 1;

    int c;
    while ((c = getopt(argc, argv, "hr:v:w:W:x:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                if (TestPath(optarg, S_IFREG) == PATH_OK) {
                    flist.single_file = strdup(optarg);
                } else if (TestPath(optarg, S_IFDIR) == PATH_OK) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("%s is not a file or directory", optarg);
                    exit(255);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            case 'W':
                CheckArgLen(optarg, 16);
                limitCores = atoi(optarg);
                if (limitCores < 0) {
                    LogError("-W: core limit must be a non-negative integer");
                    exit(EXIT_FAILURE);
                }
                if (limitCores > 0) {
                    long onlineCores = sysconf(_SC_NPROCESSORS_ONLN);
                    if (onlineCores > 0 && limitCores > (int)onlineCores)
                        LogInfo("-W %d exceeds %ld online cores; budget will be clamped to %ld",
                                limitCores, onlineCores, onlineCores);
                }
                break;
            case 'v':
                CheckArgLen(optarg, 16);
                verbose = atoi(optarg);
                if (verbose <= 0 || verbose > 4) {
                    LogError("log level %i out of range 1..4", verbose);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'x':
                CheckArgLen(optarg, 256);
                if (!ConfSetOverride(optarg)) {
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (!InitLog(NOSYSLOG, argv[0], NULL, verbose)) {
        exit(EXIT_FAILURE);
    }

    if (ConfOpen(NULL, "nfmeta", NULL) < 0) exit(EXIT_FAILURE);

    queue_t *fileList = SetupInputFileSequence(&flist);
    // Budget split: readers, bloom filter workers, writers
    threadPipeline_t pipeline = {
        .role = TC_ROLE_TRANSFORM,
        .hasReaders = true,  // reader threads
        .hasWriters = true,  // writer threads
        .hasWorkers = true,  // bloom filter workers
        .fixedThreads = 1,   // main processing thread - process_data()
    };
    threadConfig_t threadConfig = GetThreadConfig(limitCores, LZ4_COMPRESSED, pipeline);
    if (!fileList || !Init_nffile(threadConfig, fileList)) exit(255);

    process_data(wfile, threadConfig.filters, verbose);
    return 0;
}  // End of main
