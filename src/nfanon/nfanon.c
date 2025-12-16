/*
 *  Copyright (c) 2009-2025, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "barrier.h"
#include "config.h"
#include "flist.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfxV3.h"
#include "panonymizer.h"
#include "util.h"

#define MAXANONWORKERS 8

typedef struct worker_param_s {
    int self;
    int numWorkers;
    int anon_src;
    int anon_dst;
    dataBlock_t **dataBlock;

    // sync barrier
    pthread_control_barrier_t *barrier;
} worker_param_t;

/* Function Prototypes */
static void usage(char *name);

static inline void AnonRecord(recordHeaderV3_t *v3Record, int anon_src, int anon_dst);

static void process_data(char *wfile, int verbose, worker_param_t **workerList, int numWorkers, pthread_control_barrier_t *barrier);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here.\n"
        "-K <key>\tAnonymize IP addresses using CryptoPAn with key <key>.\n"
        "-s\t\tPreserve source address.\n"
        "-d\t\tPreserve destination address.\n"
        "-q\t\tDo not print progress spinnen and filenames.\n"
        "-r <path>\tread input from single file or all files in directory.\n"
        "-t <num>\tnumber of worker threads. Max depends on cores online\n"
        "-w <file>\tName of output file. Defaults to input file.\n",
        name);
} /* usage */

static inline void AnonRecord(recordHeaderV3_t *v3Record, int anon_src, int anon_dst) {
    elementHeader_t *elementHeader;
    uint32_t size = sizeof(recordHeaderV3_t);

    void *p = (void *)v3Record;
    void *eor = p + v3Record->size;

    if (v3Record->size < size) {
        LogError("v3Record - unexpected size: '%u'", v3Record->size);
        return;
    }

    SetFlag(v3Record->flags, V3_FLAG_ANON);
    dbg_printf("Record announces %u extensions with total size %u\n", v3Record->numElements, v3Record->size);
    // first record header
    elementHeader = (elementHeader_t *)(p + sizeof(recordHeaderV3_t));
    for (int i = 0; i < v3Record->numElements; i++) {
        uint64_t anon_ip[2];
        dbg_printf("[%i] next extension: %u: %s\n", i, elementHeader->type,
                   elementHeader->type < MAXEXTENSIONS ? extensionTable[elementHeader->type].name : "<unknown>");
        switch (elementHeader->type) {
            case EXnull:
                break;
            case EXgenericFlowID:
                break;
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) ipv4Flow->srcAddr = anonymize(ipv4Flow->srcAddr);
                if (anon_dst) ipv4Flow->dstAddr = anonymize(ipv4Flow->dstAddr);
            } break;
            case EXipv6FlowID: {
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) {
                    anonymize_v6(ipv6Flow->srcAddr, anon_ip);
                    ipv6Flow->srcAddr[0] = anon_ip[0];
                    ipv6Flow->srcAddr[1] = anon_ip[1];
                }

                if (anon_dst) {
                    anonymize_v6(ipv6Flow->srcAddr, anon_ip);
                    ipv6Flow->dstAddr[0] = anon_ip[0];
                    ipv6Flow->dstAddr[1] = anon_ip[1];
                }
            } break;
            case EXflowMiscID:
                break;
            case EXcntFlowID:
                break;
            case EXvLanID:
                break;
            case EXasRoutingID: {
                EXasRouting_t *asRouting = (EXasRouting_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) asRouting->srcAS = 0;
                if (anon_dst) asRouting->dstAS = 0;
            } break;
            case EXbgpNextHopV4ID: {
                EXbgpNextHopV4_t *bgpNextHopV4 = (EXbgpNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                bgpNextHopV4->ip = anonymize(bgpNextHopV4->ip);
            } break;
            case EXbgpNextHopV6ID: {
                EXbgpNextHopV6_t *bgpNextHopV6 = (EXbgpNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(bgpNextHopV6->ip, anon_ip);
                bgpNextHopV6->ip[0] = anon_ip[0];
                bgpNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipNextHopV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipNextHopV4->ip = anonymize(ipNextHopV4->ip);
            } break;
            case EXipNextHopV6ID: {
                EXipNextHopV6_t *ipNextHopV6 = (EXipNextHopV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipNextHopV6->ip, anon_ip);
                ipNextHopV6->ip[0] = anon_ip[0];
                ipNextHopV6->ip[1] = anon_ip[1];
            } break;
            case EXipReceivedV4ID: {
                EXipNextHopV4_t *ipNextHopV4 = (EXipNextHopV4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                ipNextHopV4->ip = anonymize(ipNextHopV4->ip);
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                anonymize_v6(ipReceivedV6->ip, anon_ip);
                ipReceivedV6->ip[0] = anon_ip[0];
                ipReceivedV6->ip[1] = anon_ip[1];
            } break;
            case EXmplsLabelID:
                break;
            case EXmacAddrID:
                break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)((void *)elementHeader + sizeof(elementHeader_t));
                asAdjacent->nextAdjacentAS = 0;
                asAdjacent->prevAdjacentAS = 0;
            } break;
            case EXlatencyID:
                break;
            case EXnselCommonID:
                break;
            case EXnatXlateIPv4ID: {
                EXnatXlateIPv4_t *natXlateIPv4 = (EXnatXlateIPv4_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) natXlateIPv4->xlateSrcAddr = anonymize(natXlateIPv4->xlateSrcAddr);
                if (anon_dst) natXlateIPv4->xlateDstAddr = anonymize(natXlateIPv4->xlateDstAddr);
            } break;
            case EXnatXlateIPv6ID: {
                EXnatXlateIPv6_t *natXlateIPv6 = (EXnatXlateIPv6_t *)((void *)elementHeader + sizeof(elementHeader_t));
                if (anon_src) {
                    anonymize_v6(natXlateIPv6->xlateSrcAddr, anon_ip);
                    natXlateIPv6->xlateSrcAddr[0] = anon_ip[0];
                    natXlateIPv6->xlateSrcAddr[1] = anon_ip[1];
                }
                if (anon_dst) {
                    anonymize_v6(natXlateIPv6->xlateDstAddr, anon_ip);
                    natXlateIPv6->xlateDstAddr[0] = anon_ip[0];
                    natXlateIPv6->xlateDstAddr[1] = anon_ip[1];
                }
            } break;
                // default:
                // skip other and unknown extension
        }

        size += elementHeader->length;
        elementHeader = (elementHeader_t *)((void *)elementHeader + elementHeader->length);

        if ((void *)elementHeader > eor) {
            LogError("ptr error - elementHeader > eor");
            exit(255);
        }
    }

}  // End of AnonRecord

static void process_data(char *wfile, int verbose, worker_param_t **workerList, int numWorkers, pthread_control_barrier_t *barrier) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    char *outFile = NULL;
    char *cfile = NULL;

    int cnt = 1;
    nffile_t *nffile_r = NewFile(NULL);
    nffile_t *nffile_w = NULL;

    dataBlock_t *nextBlock = NULL;
    dataBlock_t *dataBlock = NULL;
    // map datablock for workers - all workers
    // process the same block but different records
    for (int i = 0; i < numWorkers; i++) {
        // set new datablock for all workers
        workerList[i]->dataBlock = &dataBlock;
    }

    // wait for workers ready to start
    pthread_controller_wait(barrier);

    int blk_count = 0;
    int done = 0;
    while (!done) {
        // get next data block
        dataBlock = nextBlock;
        if (dataBlock == NULL) {
            // nffile_w is NULL for 1st entry in while loop
            if (nffile_w) {
                FinaliseFile(nffile_w);
                CloseFile(nffile_w);
                if (wfile == NULL && rename(outFile, cfile) < 0) {
                    LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return;
                }
            }

            if (GetNextFile(nffile_r) == NULL) {
                done = 1;
                printf("\nDone\n");
                continue;
            }

            cfile = nffile_r->fileName;
            if (!cfile) {
                LogError("(NULL) input file name error in %s line %d", __FILE__, __LINE__);
                CloseFile(nffile_r);
                DisposeFile(nffile_r);
                return;
            }
            if (verbose) printf(" %i Processing %s\r", cnt++, cfile);

            char pathBuff[MAXPATHLEN];
            if (wfile == NULL) {
                // prepare output file
                snprintf(pathBuff, MAXPATHLEN - 1, "%s-tmp", cfile);
                pathBuff[MAXPATHLEN - 1] = '\0';
                outFile = pathBuff;
            } else {
                outFile = wfile;
            }

            nffile_w = OpenNewFile(outFile, NULL, CREATOR_NFANON, FILE_COMPRESSION(nffile_r), NOT_ENCRYPTED);
            if (!nffile_w) {
                // can not create output file
                CloseFile(nffile_r);
                DisposeFile(nffile_r);
                return;
            }

            SetIdent(nffile_w, FILE_IDENT(nffile_r));
            memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));

            // read first block from next file
            nextBlock = ReadBlock(nffile_r, NULL);
            continue;
        }

        if (verbose) {
            printf("\r%c", spinner[blk_count & 0x3]);
            blk_count++;
        }

        if (dataBlock->type != DATA_BLOCK_TYPE_2 && dataBlock->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u. Write block unmodified", dataBlock->type);
            dataBlock = WriteBlock(nffile_w, dataBlock);
            nextBlock = ReadBlock(nffile_r, NULL);
            continue;
        }

        dbg_printf("Next block: %d, Records: %u\n", blk_count, dataBlock->NumRecords);
        // release workers from barrier
        pthread_control_barrier_release(barrier);

        // prefetch next block
        nextBlock = ReadBlock(nffile_r, NULL);

        // wait for all workers, work done on previous block
        pthread_controller_wait(barrier);

        // write modified block
        FlushBlock(nffile_w, dataBlock);

    }  // while

    // done! - signal all workers to terminate
    dataBlock = NULL;
    pthread_control_barrier_release(barrier);

    FreeDataBlock(dataBlock);
    DisposeFile(nffile_r);
    DisposeFile(nffile_w);

    if (verbose) LogError("Processed %i files", --cnt);

}  // End of process_data

__attribute__((noreturn)) static void *worker(void *arg) {
    worker_param_t *worker_param = (worker_param_t *)arg;

    uint32_t self = worker_param->self;
    uint32_t numWorkers = worker_param->numWorkers;

    // wait in barrier after launch
    pthread_control_barrier_wait(worker_param->barrier);

    while (*(worker_param->dataBlock)) {
        dataBlock_t *dataBlock = *(worker_param->dataBlock);
        dbg_printf("Worker %i working on %p\n", self, dataBlock);

        uint32_t recordCount = 0;

        record_header_t *record_ptr = GetCursor(dataBlock);
        uint32_t sumSize = 0;
        for (int i = 0; i < dataBlock->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock->size || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                goto SKIP;
            }
            sumSize += record_ptr->size;

            // check, if this is our record
            if ((i % numWorkers) == self) {
                // our record - work on it
                recordCount++;

                // work on our record
                switch (record_ptr->type) {
                    case V3Record:
                        AnonRecord((recordHeaderV3_t *)record_ptr, worker_param->anon_src, worker_param->anon_dst);
                        break;
                    case ExporterInfoRecordType:
                    case ExporterStatRecordType:
                    case SamplerRecordType:
                    case NbarRecordType:
                        // Silently skip exporter/sampler records
                        break;

                    default: {
                        LogError("Skip unknown record: %u type %i", recordCount, record_ptr->type);
                    }
                }
            }
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

        dbg_printf("Worker %i: datablock completed. Records processed: %u\n", self, recordCount);

    SKIP:
        // Done
        // wait in barrier for next data record
        pthread_control_barrier_wait(worker_param->barrier);
    }

    dbg_printf("Worker %d done.\n", worker_param->self);
    pthread_exit(NULL);
}  // End of worker

static worker_param_t **LauchWorkers(pthread_t *tid, int numWorkers, int anon_src, int anon_dst, pthread_control_barrier_t *barrier) {
    if (numWorkers > MAXWORKERS) {
        LogError("LaunchWorkers: number of worker: %u > max workers: %u", numWorkers, MAXWORKERS);
        return NULL;
    }

    worker_param_t **workerList = calloc(numWorkers, sizeof(worker_param_t *));
    if (!workerList) NULL;

    for (int i = 0; i < numWorkers; i++) {
        worker_param_t *worker_param = calloc(1, sizeof(worker_param_t));
        if (!worker_param) NULL;

        worker_param->barrier = barrier;
        worker_param->self = i;
        worker_param->anon_src = anon_src;
        worker_param->anon_dst = anon_dst;
        worker_param->dataBlock = NULL;
        worker_param->numWorkers = numWorkers;
        workerList[i] = worker_param;

        int err = pthread_create(&(tid[i]), NULL, worker, (void *)worker_param);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
    }
    return workerList;

}  // End of LaunchWorkers

static void WaitWorkersDone(pthread_t *tid, int numWorkers) {
    // wait for all nfwriter threads to exit
    for (int i = 0; i < numWorkers; i++) {
        if (tid[i]) {
            int err = pthread_join(tid[i], NULL);
            if (err) {
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            }
            tid[i] = 0;
        }
    }
}  // End of WaitWorkersDone

int main(int argc, char **argv) {
    char *wfile = NULL;
    char CryptoPAnKey[32] = {0};
    flist_t flist = {0};

    int numWorkers = MAXANONWORKERS;
    int verbose = 1;
    int anon_src = 1;
    int anon_dst = 1;
    int c;
    while ((c = getopt(argc, argv, "hsdK:L:qr:t:w:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
                break;
            case 'K':
                CheckArgLen(optarg, 66);
                if (!ParseCryptoPAnKey(optarg, CryptoPAnKey)) {
                    LogError("Invalid key '%s' for CryptoPAn", optarg);
                    exit(255);
                }
                PAnonymizer_Init((uint8_t *)CryptoPAnKey);
                break;
            case 'L':
                if (!InitLog(0, "argv[0]", optarg, 0)) exit(255);
                break;
            case 's':
                anon_src = 0;
                break;
            case 'd':
                anon_dst = 0;
                break;
            case 'q':
                verbose = 0;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                if (TestPath(optarg, S_IFREG) == PATH_OK) {
                    flist.single_file = strdup(optarg);
                } else if (TestPath(optarg, S_IFDIR) == PATH_OK) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("%s is not a file or directory", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 't':
                CheckArgLen(optarg, 4);
                numWorkers = atoi(optarg);
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (CryptoPAnKey[0] == '\0') {
        LogError("Expect -K <key>");
        usage(argv[0]);
        exit(255);
    }

    if ((anon_src + anon_dst) == 0) {
        LogError("Preserving src IP and dst IP does not make sense for nfanon");
        usage(argv[0]);
        exit(255);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(0, fileList)) exit(255);

    // check numWorkers depending on cores online
    numWorkers = GetNumWorkers(numWorkers);

    pthread_control_barrier_t *barrier = pthread_control_barrier_init(numWorkers);
    if (!barrier) exit(255);

    pthread_t tid[MAXWORKERS] = {0};
    dbg_printf("Launch Workers\n");
    worker_param_t **workerList = LauchWorkers(tid, numWorkers, anon_src, anon_dst, barrier);
    if (!workerList) {
        LogError("Failed to launch workers");
        exit(255);
    }

    // make stdout unbuffered for progress pointer
    setvbuf(stdout, (char *)NULL, _IONBF, 0);
    process_data(wfile, verbose, workerList, numWorkers, barrier);

    WaitWorkersDone(tid, numWorkers);
    pthread_control_barrier_destroy(barrier);

    return 0;
}
