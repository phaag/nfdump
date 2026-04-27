/*
 *  Copyright (c) 2009-2026, Peter Haag
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
#include "exporter.h"
#include "flist.h"
#include "id.h"
#include "ip128.h"
#include "logging.h"
#include "nbar.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffileV3/nffileV3.h"
#include "nfxV4.h"
#include "panonymizer.h"
#include "util.h"

#define MAXANONWORKERS 8

typedef struct worker_param_s {
    int self;
    int numWorkers;
    int anon_src;
    int anon_dst;
    flowBlockV3_t **dataBlock;

    // sync barrier
    pthread_control_barrier_t *barrier;
} worker_param_t;

static const uint8_t prefix[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};

/* Function Prototypes */
static void usage(char *name);

static inline void AnonExporterInfo(exporter_info_record_v4_t *exporter_record);

static inline void AnonRecord(recordHeaderV4_t *v4Record, int anon_src, int anon_dst);

static void process_data(char *wfile, int verbose, worker_param_t **workerList, int numWorkers, pthread_control_barrier_t *barrier);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-C <file>\tRead optional config file.\n"
        "-h\t\tthis text you see right here.\n"
        "-K <key>\tAnonymize IP addresses using CryptoPAn with key <key>.\n"
        "-s\t\tPreserve source address.\n"
        "-d\t\tPreserve destination address.\n"
        "-q\t\tDo not print progress spinnen and filenames.\n"
        "-r <path>\tread input from single file or all files in directory.\n"
        "-v level\tSet verbose level.\n"
        "-w <file>\tName of output file. Defaults to input file.\n"
        "-W <num>\tOptionally set the number of workers to compress flows\n",
        name);
} /* usage */

static inline void AnonExporterInfo(exporter_info_record_v4_t *exporter_record) {
    if (exporter_record->size < sizeof(exporter_info_record_v4_t)) {
        LogError("Corrupt exporter record in %s line %d", __FILE__, __LINE__);
        return;
    }

    int is_mapped_v4 = memcmp(exporter_record->ip, prefix, sizeof(prefix)) == 0;
    // anonymizing an IPv4/IPv6 combind record is more complicated,
    // the the anonimizer expects host order bytes and has seperate
    // functions for IPv4 and IPv6
    if (is_mapped_v4) {
        // anonymise IPv4
        uint32_t ipv4;
        __builtin_memcpy(&ipv4, exporter_record->ip + 12, sizeof(uint32_t));
        ipv4 = anonymize(ntohl(ipv4));
        ipv4 = htonl(ipv4);
        __builtin_memcpy(exporter_record->ip + 12, &ipv4, sizeof(uint32_t));
    } else {
        // anonymise IPv6
        uint8_t anon_ip[16];
        anonymize_v6(exporter_record->ip, anon_ip);
        memcpy(exporter_record->ip, anon_ip, 16);
    }

#ifdef DEVEL
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, exporter_record->ip, s, INET6_ADDRSTRLEN);
    printf("Exporter: %s\n", s);
#endif

}  // End of AnonExporterInfo

static inline void AnonRecord(recordHeaderV4_t *v4Record, int anon_src, int anon_dst) {
    uint8_t *p = (void *)v4Record;

    if (v4Record->size < sizeof(recordHeaderV4_t)) {
        LogError("v4Record - unexpected size: '%u'", v4Record->size);
        return;
    }

    SetFlag(v4Record->flags, V4_FLAG_ANON);
    dbg_printf("Record announces %u extensions with total size %u\n", v4Record->numExtensions, v4Record->size);

    uint64_t bitMap = v4Record->extBitmap;
    uint8_t *recordBase = p;
    uint16_t *offset = (uint16_t *)(recordBase + sizeof(recordHeaderV4_t));
    while (bitMap) {
        uint64_t t = bitMap & -bitMap;
        uint32_t extID = __builtin_ctzll(bitMap);
        bitMap ^= t;

        uint8_t *extension = recordBase + *offset++;

        switch (extID) {
            case EXipv4FlowID: {
                EXipv4Flow_t *ipv4Flow = (EXipv4Flow_t *)extension;
                if (anon_src) ipv4Flow->srcAddr = anonymize(ipv4Flow->srcAddr);
                if (anon_dst) ipv4Flow->dstAddr = anonymize(ipv4Flow->dstAddr);
            } break;
            case EXipv6FlowID: {
                uint8_t anon_ip[16];
                EXipv6Flow_t *ipv6Flow = (EXipv6Flow_t *)extension;
                if (anon_src) {
                    uint64_t tmp[2] = {htonll(ipv6Flow->srcAddr[0]), htonll(ipv6Flow->srcAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    ipv6Flow->srcAddr[0] = ntohll(tmp[0]);
                    ipv6Flow->srcAddr[1] = ntohll(tmp[1]);
                }

                if (anon_dst) {
                    uint64_t tmp[2] = {htonll(ipv6Flow->dstAddr[0]), htonll(ipv6Flow->dstAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    ipv6Flow->dstAddr[0] = ntohll(tmp[0]);
                    ipv6Flow->dstAddr[1] = ntohll(tmp[1]);
                }
            } break;
            case EXasInfoID: {
                EXasInfo_t *asInfo = (EXasInfo_t *)extension;
                if (anon_src) asInfo->srcAS = 0;
                if (anon_dst) asInfo->dstAS = 0;
            } break;
            case EXasRoutingV4ID: {
                EXasRoutingV4_t *asRouting = (EXasRoutingV4_t *)extension;
                asRouting->nextHop = anonymize(asRouting->nextHop);
                asRouting->bgpNextHop = anonymize(asRouting->bgpNextHop);
            } break;
            case EXasRoutingV6ID: {
                EXasRoutingV6_t *asRouting = (EXasRoutingV6_t *)extension;
                uint8_t anon_ip[16];
                // convert host-order uint64_t[2] to network-order bytes for CryptoPAn
                uint64_t tmp[2] = {htonll(asRouting->nextHop[0]), htonll(asRouting->nextHop[1])};
                anonymize_v6((uint8_t *)tmp, anon_ip);
                __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                asRouting->nextHop[0] = ntohll(tmp[0]);
                asRouting->nextHop[1] = ntohll(tmp[1]);
                tmp[0] = htonll(asRouting->bgpNextHop[0]);
                tmp[1] = htonll(asRouting->bgpNextHop[1]);
                anonymize_v6((uint8_t *)tmp, anon_ip);
                __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                asRouting->bgpNextHop[0] = ntohll(tmp[0]);
                asRouting->bgpNextHop[1] = ntohll(tmp[1]);
            } break;
            case EXasAdjacentID: {
                EXasAdjacent_t *asAdjacent = (EXasAdjacent_t *)extension;
                asAdjacent->nextAdjacentAS = 0;
                asAdjacent->prevAdjacentAS = 0;
            } break;
            case EXipReceivedV4ID: {
                EXipReceivedV4_t *ipReceived = (EXipReceivedV4_t *)extension;
                ipReceived->ip = anonymize(ipReceived->ip);
            } break;
            case EXipReceivedV6ID: {
                EXipReceivedV6_t *ipReceivedV6 = (EXipReceivedV6_t *)extension;
                uint8_t anon_ip[16];
                // convert host-order uint64_t[2] to network-order bytes for CryptoPAn
                uint64_t tmp[2] = {htonll(ipReceivedV6->ip[0]), htonll(ipReceivedV6->ip[1])};
                anonymize_v6((uint8_t *)tmp, anon_ip);
                __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                ipReceivedV6->ip[0] = ntohll(tmp[0]);
                ipReceivedV6->ip[1] = ntohll(tmp[1]);
            } break;
            case EXnatXlateV4ID: {
                EXnatXlateV4_t *natXlateIPv4 = (EXnatXlateV4_t *)extension;
                if (anon_src) natXlateIPv4->xlateSrcAddr = anonymize(natXlateIPv4->xlateSrcAddr);
                if (anon_dst) natXlateIPv4->xlateDstAddr = anonymize(natXlateIPv4->xlateDstAddr);
            } break;
            case EXnatXlateV6ID: {
                EXnatXlateV6_t *natXlateIPv6 = (EXnatXlateV6_t *)extension;
                uint8_t anon_ip[16];
                if (anon_src) {
                    // convert host-order uint64_t[2] to network-order bytes for CryptoPAn
                    uint64_t tmp[2] = {htonll(natXlateIPv6->xlateSrcAddr[0]), htonll(natXlateIPv6->xlateSrcAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    natXlateIPv6->xlateSrcAddr[0] = ntohll(tmp[0]);
                    natXlateIPv6->xlateSrcAddr[1] = ntohll(tmp[1]);
                }
                if (anon_dst) {
                    uint64_t tmp[2] = {htonll(natXlateIPv6->xlateDstAddr[0]), htonll(natXlateIPv6->xlateDstAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    natXlateIPv6->xlateDstAddr[0] = ntohll(tmp[0]);
                    natXlateIPv6->xlateDstAddr[1] = ntohll(tmp[1]);
                }
            } break;
            case EXtunnelV4ID: {
                EXtunnelV4_t *tunnel = (EXtunnelV4_t *)extension;
                if (anon_src) {
                    tunnel->srcAddr = anonymize(tunnel->srcAddr);
                }
                if (anon_dst) {
                    tunnel->dstAddr = anonymize(tunnel->dstAddr);
                }
            } break;
            case EXtunnelV6ID: {
                EXtunnelV6_t *tunnel = (EXtunnelV6_t *)extension;
                uint8_t anon_ip[16];
                if (anon_src) {
                    uint64_t tmp[2] = {htonll(tunnel->srcAddr[0]), htonll(tunnel->srcAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    tunnel->srcAddr[0] = ntohll(tmp[0]);
                    tunnel->srcAddr[1] = ntohll(tmp[1]);
                }
                if (anon_dst) {
                    uint64_t tmp[2] = {htonll(tunnel->dstAddr[0]), htonll(tunnel->dstAddr[1])};
                    anonymize_v6((uint8_t *)tmp, anon_ip);
                    __builtin_memcpy(tmp, anon_ip, sizeof(tmp));
                    tunnel->dstAddr[0] = ntohll(tmp[0]);
                    tunnel->dstAddr[1] = ntohll(tmp[1]);
                }
            } break;
        }
    }

}  // End of AnonRecord

static void process_data(char *wfile, int verbose, worker_param_t **workerList, int numWorkers, pthread_control_barrier_t *barrier) {
    const char spinner[4] = {'|', '/', '-', '\\'};
    char *outFile = NULL;
    char *cfile = NULL;

    int cnt = 1;
    nffileV3_t *nffile_r = NULL;
    nffileV3_t *nffile_w = NULL;

    flowBlockV3_t *nextBlock = NULL;
    flowBlockV3_t *dataBlock = NULL;
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
                FlushFileV3(nffile_w);
                CloseFileV3(nffile_w);
                if (wfile == NULL && rename(outFile, cfile) < 0) {
                    LogError("rename() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                    return;
                }
            }

            CloseFileV3(nffile_r);
            nffile_r = GetNextFile();
            if (nffile_r == NULL) {
                done = 1;
                printf("\nDone\n");
                continue;
            }

            cfile = nffile_r->fileName;
            if (!cfile) {
                LogError("(NULL) input file name error in %s line %d", __FILE__, __LINE__);
                CloseFileV3(nffile_r);
                return;
            }
            if (verbose) printf("  %i Processing %s\r", cnt++, cfile);

            char pathBuff[MAXPATHLEN];
            if (wfile == NULL) {
                // prepare output file
                snprintf(pathBuff, MAXPATHLEN - 1, "%s-tmp", cfile);
                pathBuff[MAXPATHLEN - 1] = '\0';
                outFile = pathBuff;
            } else {
                outFile = wfile;
            }

            uint32_t compressType = nffile_r->compression;
            uint32_t compressLevel = nffile_r->compressionLevel;
            nffile_w = OpenNewFileV3(outFile, CREATOR_NFANON, compressType, compressLevel, NOT_ENCRYPTED);
            if (!nffile_w) {
                // can not create output file
                CloseFileV3(nffile_r);
                return;
            }

            SetIdent(nffile_w, nffile_r->ident);
            __builtin_memcpy((void *)nffile_w->stat_record, (void *)nffile_r->stat_record, sizeof(stat_record_t));

            // read first block from next file
            nextBlock = ReadBlockV3(nffile_r);
            continue;
        }

        if (verbose) {
            printf("\r%c", spinner[blk_count & 0x3]);
            blk_count++;
        }

        if (dataBlock->type != BLOCK_TYPE_FLOW) {
            LogError("Can't process block type %u. Write block unmodified", dataBlock->type);
            WriteBlockV3(nffile_w, dataBlock);
            InitDataBlock(dataBlock, nffile_w->fileHeader->blockSize);
            nextBlock = ReadBlockV3(nffile_r);
            continue;
        }

        dbg_printf("Next block: %d, Records: %u\n", blk_count, dataBlock->numRecords);
        // release workers from barrier
        pthread_control_barrier_release(barrier);

        // prefetch next block
        nextBlock = ReadBlockV3(nffile_r);

        // wait for all workers, work done on previous block
        pthread_controller_wait(barrier);

        // write modified block
        WriteBlockV3(nffile_w, dataBlock);

    }  // while

    // done! - signal all workers to terminate
    dataBlock = NULL;
    pthread_control_barrier_release(barrier);

    FreeDataBlock(dataBlock);

    if (verbose) LogError("Processed %i files", --cnt);

}  // End of process_data

static void *worker_thread(void *arg) {
    worker_param_t *worker_param = (worker_param_t *)arg;

    uint32_t self = worker_param->self;
    uint32_t numWorkers = worker_param->numWorkers;

    // wait in barrier after launch
    pthread_control_barrier_wait(worker_param->barrier);

    while (*(worker_param->dataBlock)) {
        flowBlockV3_t *dataBlock = *(worker_param->dataBlock);
        dbg_printf("Worker %i working on %p\n", self, dataBlock);

        uint32_t recordCount = 0;

        recordHeader_t *record_ptr = ResetCursor(dataBlock);
        uint32_t sumSize = 0;
        for (int i = 0; i < (int)dataBlock->numRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock->rawSize || (record_ptr->size < sizeof(recordHeader_t))) {
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
                    case V4Record:
                        AnonRecord((recordHeaderV4_t *)record_ptr, worker_param->anon_src, worker_param->anon_dst);
                        break;
                    case ExporterInfoRecordV4Type:
                        AnonExporterInfo((exporter_info_record_v4_t *)record_ptr);
                        break;
                    default: {
                        // Silently skip unknown records
                    }
                }
            }
            // Advance pointer by number of bytes for netflow record
            record_ptr = (recordHeader_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

        dbg_printf("Worker %i: datablock completed. Records processed: %u\n", self, recordCount);
        (void)recordCount;

    SKIP:
        // Done
        // wait in barrier for next data record
        pthread_control_barrier_wait(worker_param->barrier);
    }

    dbg_printf("Worker %d done.\n", worker_param->self);
    free(worker_param);
    pthread_exit(NULL);
}  // End of worker_thread

static worker_param_t **LauchWorkers(pthread_t *tid, int numWorkers, int anon_src, int anon_dst, pthread_control_barrier_t *barrier) {
    worker_param_t **workerList = calloc(numWorkers, sizeof(worker_param_t *));
    if (!workerList) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    for (int i = 0; i < numWorkers; i++) {
        worker_param_t *worker_param = calloc(1, sizeof(worker_param_t));
        if (!worker_param) {
            LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        worker_param->barrier = barrier;
        worker_param->self = i;
        worker_param->anon_src = anon_src;
        worker_param->anon_dst = anon_dst;
        worker_param->dataBlock = NULL;
        worker_param->numWorkers = numWorkers;
        workerList[i] = worker_param;

        int err = pthread_create(&(tid[i]), NULL, worker_thread, (void *)worker_param);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
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
                LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            }
            tid[i] = 0;
        }
    }
}  // End of WaitWorkersDone

int main(int argc, char **argv) {
    char *wfile = NULL;
    char CryptoPAnKey[32] = {0};
    flist_t flist = {0};

    char *configFile = NULL;
    int numWorkers = 0;
    int verbose = -1;
    int anon_src = 1;
    int anon_dst = 1;
    int c;
    while ((c = getopt(argc, argv, "C:hsdK:qr:t:v:w:W:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'C':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, NOCONF) == 0) {
                    configFile = optarg;
                } else {
                    if (!CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                    configFile = optarg;
                }
                break;
            case 'K':
                CheckArgLen(optarg, 66);
                if (!ParseCryptoPAnKey(optarg, CryptoPAnKey)) {
                    LogError("Invalid key '%s' for CryptoPAn", optarg);
                    exit(255);
                }
                PAnonymizer_Init((uint8_t *)CryptoPAnKey);
                break;
            case 's':
                anon_src = 0;
                break;
            case 'd':
                anon_dst = 0;
                break;
            case 'q':
                LogError("Option -q deprecated. Use -v 0");
                exit(EXIT_FAILURE);
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
            case 'v':
                verbose = ParseVerbose(verbose, optarg);
                if (verbose < 0) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            case 't':
                // legacy option - fall through
                LogError("Legacy option. Use -W <num> to select the number of workers");
                /* fallthrough */
            case 'W':
                CheckArgLen(optarg, 16);
                numWorkers = atoi(optarg);
                if (numWorkers < 0) {
                    LogError("Invalid number of working threads: %d", numWorkers);
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

    if (ConfOpen(configFile, "nfanon") < 0) exit(EXIT_FAILURE);

    // check numWorkers depending on cores online
    numWorkers = GetNumWorkers(numWorkers);

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(numWorkers, fileList)) exit(255);

    pthread_control_barrier_t *barrier = pthread_control_barrier_init(numWorkers);
    if (!barrier) exit(255);

    pthread_t *tid = calloc(numWorkers, sizeof(pthread_t));
    if (!tid) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
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

    free(tid);
    free(workerList);

    return 0;
}
