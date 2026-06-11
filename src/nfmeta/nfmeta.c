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
#include "nfxV4.h"
#include "util.h"

static void usage(char *name);
static void process_data(const char *wfile);

static void usage(char *name) {
    printf(
        "usage %s [options]\n"
        "-h\t\tthis text you see right here\n"
        "-r <path>\tread input from file or directory\n"
        "-w <file>\twrite all output to this file\n"
        "\t\tif -w is omitted, each input file is replaced in-place\n",
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
static int flushAndClose(nffileV3_t *nffile_w, flowBlockV3_t *dataBlock_w, uint64_t firstSeen, uint64_t lastSeen, const char *wfile,
                         const char *srcFile, int closeIt) {
    dataBlock_w->msecFirst = (firstSeen != UINT64_MAX) ? firstSeen : 0;
    dataBlock_w->msecLast = lastSeen;
    FlushBlockV3(nffile_w, dataBlock_w);
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
    } else if (closeIt) {
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
static void process_data(const char *wfile) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    int blk_count = 0;
    int file_count = 0;

    setvbuf(stdout, (char *)NULL, _IONBF, 0);

    nffileV3_t *nffile_r = GetNextFile();
    if (!nffile_r) {
        LogError("Empty file list. No files to process");
        return;
    }

    nffileV3_t *nffile_w = NULL;
    flowBlockV3_t *dataBlock_w = NULL;
    bloomHandle_t bloomHandle = {0};
    uint64_t firstSeen = UINT64_MAX, lastSeen = 0;
    char srcFile[MAXPATHLEN] = {0}; /* original path for in-place rename */

    /* In single-output mode, open the output file once here using the
     * first input file's compression settings.                        */
    if (wfile) {
        nffile_w = OpenNewFileV3(wfile, CREATOR_NFDUMP, nffile_r->compression, 0, NULL);
        if (!nffile_w) {
            CloseFileV3(nffile_r);
            return;
        }
        SetIdent(nffile_w, nffile_r->ident);
        __builtin_memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
        dataBlock_w = NewFlowBlock(nffile_w->fileHeader->blockSize);
        addBloomHandle(dataBlock_w, &bloomHandle);
        printf("Output: %s\n", wfile);
    }

    int done = 0;
    while (!done) {
        /* In per-file mode, open a fresh output file for each new input. */
        if (!wfile && !nffile_w) {
            if (!nffile_r->fileName) {
                LogError("Cannot determine input file name for in-place replacement");
                CloseFileV3(nffile_r);
                return;
            }
            strncpy(srcFile, nffile_r->fileName, sizeof(srcFile) - 1);
            nffile_w = OpenNewFileTmpV3(srcFile, CREATOR_NFDUMP, nffile_r->compression, 0, NULL);
            if (!nffile_w) {
                LogError("Failed to open output for %s", srcFile);
                CloseFileV3(nffile_r);
                return;
            }
            SetIdent(nffile_w, nffile_r->ident);
            __builtin_memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));
            dataBlock_w = NewFlowBlock(nffile_w->fileHeader->blockSize);
            addBloomHandle(dataBlock_w, &bloomHandle);
            firstSeen = UINT64_MAX;
            lastSeen = 0;
            file_count++;
            printf("  %i Processing %s\r", file_count, srcFile);
        }

        flowBlockV3_t *dataBlock_r = ReadBlockV3(nffile_r);

        if (!dataBlock_r) {
            /* Current input file exhausted. */
            if (!wfile) {
                /* Per-file mode: finalize this output and rename. */
                if (!flushAndClose(nffile_w, dataBlock_w, firstSeen, lastSeen, NULL, srcFile, 1)) {
                    CloseFileV3(nffile_r);
                    return;
                }
                nffile_w = NULL; /* reset so next iteration opens a new one */
                dataBlock_w = NULL;
            }

            CloseFileV3(nffile_r);
            nffile_r = GetNextFile();
            if (!nffile_r) {
                done = 1;
            }
            continue;
        }

        if (dataBlock_r->type != BLOCK_TYPE_FLOW) {
            /* Non-flow blocks (ident, array, exporter, …) pass through unmodified. */
            PushBlockV3(nffile_w->processQueue, dataBlock_r);
            continue;
        }

        printf("\r%c", spinner[blk_count & 0x3]);
        blk_count++;

        recordHandle_t recordHandle = {0};
        recordHeaderV4_t *record_ptr = ResetCursor(dataBlock_r);
        uint32_t sumSize = 0;
        uint64_t processed = 0;

        for (int i = 0; i < (int)dataBlock_r->numRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock_r->rawSize || record_ptr->size < sizeof(recordHeaderV4_t)) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            // skip existing meta record, we rebuild them
            if (record_ptr->type == METARecord) continue;

            if (record_ptr->type == V4Record) {
                memset(&recordHandle, 0, sizeof(recordHandle));
                MapV4RecordHandle(&recordHandle, record_ptr, ++processed);
            }

            /* If the output block is full, flush it and start a fresh one. */
            if (!IsAvailable(dataBlock_w, nffile_w->fileHeader->blockSize, record_ptr->size)) {
                dataBlock_w->msecFirst = (firstSeen != UINT64_MAX) ? firstSeen : 0;
                dataBlock_w->msecLast = lastSeen;
                PushBlockV3(nffile_w->processQueue, dataBlock_w);
                InitDataBlock(dataBlock_w, nffile_w->fileHeader->blockSize);
                firstSeen = UINT64_MAX;
                lastSeen = 0;
                addBloomHandle(dataBlock_w, &bloomHandle);
            }
            if (record_ptr->type == V4Record) updateMetaData(&bloomHandle, &recordHandle, &firstSeen, &lastSeen);

            memcpy(GetCursor(dataBlock_w), record_ptr, record_ptr->size);
            dataBlock_w->numRecords++;
            dataBlock_w->rawSize += record_ptr->size;

            record_ptr = (recordHeaderV4_t *)((void *)record_ptr + record_ptr->size);
        }

        FreeDataBlock(dataBlock_r);
    }  // while (!done)

    /* Finalize the output. */
    if (wfile) {
        /* Single-output mode: flush and close the one output file. */
        flushAndClose(nffile_w, dataBlock_w, firstSeen, lastSeen, wfile, NULL, 1);
        printf("\rProcessed %d flow blocks\n", blk_count);
    } else {
        printf("\rProcessed %d flow blocks across %d file(s)\n", blk_count, file_count);
    }
}  // End of process_data

int main(int argc, char **argv) {
    flist_t flist = {0};
    char *wfile = NULL;
    char *configFile = NULL;
    int limitCores = 0;

    int c;
    while ((c = getopt(argc, argv, "f:hr:w:W:x:")) != EOF) {
        switch (c) {
            case 'f':
                configFile = optarg;
                break;
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
                    LogError("Invalid number of worker threads: %d", limitCores);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'x':
                CheckArgLen(optarg, 256);
                if (!ConfSetOverride(optarg)) exit(EXIT_FAILURE);
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (ConfOpen(configFile, "nfmeta", NULL) < 0) exit(EXIT_FAILURE);

    // Compression is read from each input file; UNDEF lets GetThreadConfig
    // default to LZ4 assumptions for the I/O split.
    threadConfig_t tc = GetThreadConfig(limitCores, UNDEF_COMPRESSED, TC_ROLE_TRANSFORM);

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(tc, fileList)) exit(255);

    process_data(wfile);
    return 0;
}
