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

#include "nfdump.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "barrier.h"
#include "compress/nfcompress.h"
#include "conf/nfconf.h"
#include "config.h"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif
#include "exporter.h"
#include "filter/filter.h"
#include "flist.h"
#include "id.h"
#include "ifvrf.h"
#include "logging.h"
#include "maxmind/maxmind.h"
#include "nbar.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nffileV3/nfconvert.h"
#include "nffileV3/nffileV3.h"
#include "nflowcache.h"
#include "nfnet.h"
#include "nfprof.h"
#include "nfstat.h"
#include "output.h"
#include "ssl/ssl.h"
#include "tor/tor.h"
#include "util.h"
#include "version.h"

extern char *FilterFilename;

typedef struct dataHandle_s {
    flowBlockV3_t *dataBlock;
    char *ident;
    uint64_t blockCnt;
    uint64_t recordCnt;
} dataHandle_t;

typedef struct prepareArgs_s {
    queue_t *prepareQueue;
    uint32_t processedBlocks;
    uint32_t skippedBlocks;
} prepareArgs_t;

typedef struct filterArgs_s {
    _Atomic unsigned self;
    _Atomic uint64_t processedRecords;
    _Atomic uint64_t passedRecords;
    unsigned hasGeoDB;
    unsigned numWorkers;
    void *engine;
    timeWindow_t *timeWindow;
    queue_t *prepareQueue;
    queue_t *processQueue;
} filterArgs_t;

typedef struct filterStat_s {
    uint32_t processedRecords;
    uint32_t passedRecords;
} filterStat_t;

static uint64_t total_bytes = 0;
static uint64_t totalRecords = 0;
static uint64_t totalPassed = 0;
static uint32_t skippedBlocks = 0;
static uint64_t t_firstMsec = 0, t_lastMsec = 0;
static _Atomic uint32_t abortProcessing = 0;

enum processType { FLOWSTAT = 1, ELEMENTSTAT, ELEMENTFLOWSTAT, SORTRECORDS, WRITEFILE, PRINTRECORD };

/* Function Prototypes */
static void usage(char *name);

static int SetStat(char *str, int *element_stat, int *flow_stat);

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] [\"filter\"]\n"
        "-h\t\tthis text you see right here\n"
        "-V\t\tPrint version and exit.\n"
        "-a\t\tAggregate netflow data.\n"
        "-A <expr>[/net]\tHow to aggregate: ',' sep list of tags see nfdump(1)\n"
        "\t\tor subnet aggregation: srcip4/24, srcip6/64.\n"
        "-b\t\tAggregate netflow records as bidirectional flows.\n"
        "-B\t\tAggregate netflow records as bidirectional flows - Guess direction.\n"
        "-C <file>\tRead optional config file.\n"
        "-r <file>\tread input from file\n"
        "-w <file>\twrite output to file\n"
        "-f\t\tread netflow filter from file\n"
        "-n\t\tDefine number of top N for stat or sorted output.\n"
        "-c\t\tLimit number of matching records\n"
        "-G <geoDB>\tUse this nfdump geoDB to lookup country/location.\n"
        "-H <torDB>\tUse nfdump torDB to lookup tor info.\n"
        "-N\t\tPrint plain numbers\n"
        "-s <expr>[/<order>]\tGenerate statistics for <expr> any valid record element.\n"
        "\t\tand ordered by <order>: packets, bytes, flows, bps pps and bpp.\n"
        "-q\t\tQuiet: Do not print the header and bottom stat lines.\n"
        "-i <ident>\tChange Ident to <ident> in file given by -r.\n"
        "-J=<comp>\tModify file compression to comp. comp identical with -z.\n"
        "-z=lzo\t\tLZO compress flows in output file.\n"
        "-z=bz2\t\tBZIP2 compress flows in output file.\n"
        "-z=lz4[:level]\tLZ4 compress flows in output file.\n"
        "-z=zstd[:level]\tZSTD compress flows in output file.\n"
        "-l <expr>\tSet limit on packets for line and packed output format.\n"
        "\t\tkey: 32 character string or 64 digit hex string starting with 0x.\n"
        "-L <expr>\tSet limit on bytes for line and packed output format.\n"
        "-I \t\tPrint netflow summary statistics info from file or range of files (-r, -R).\n"
        "-g \t\tPrint gnuplot stat line for each nfcapd file (-r, -R).\n"
        "-M <expr>\tRead input from multiple directories.\n"
        "\t\t/dir/dir1:dir2:dir3 Read the same files from '/dir/dir1' '/dir/dir2' and "
        "'/dir/dir3'.\n"
        "\t\trequests either -r filename or -R firstfile:lastfile without pathnames\n"
        "-m\t\tdeprecated\n"
        "-O <order> Sort order for aggregated flows - tstart, tend, flows, packets bps pps bbp "
        "etc.\n"
        "-R <expr>\tRead input from sequence of files.\n"
        "\t\t/any/dir  Read all files in that directory.\n"
        "\t\t/dir/file Read all files beginning with 'file'.\n"
        "\t\t/dir/file1:file2: Read all files from 'file1' to file2.\n"
        "-o <mode>\tUse <mode> to print out netflow records:\n"
        "\t\t raw      Raw record dump.\n"
        "\t\t line     Standard output line format.\n"
        "\t\t long     Standard output line format with additional fields.\n"
        "\t\t extended Even more information.\n"
        "\t\t csv      ',' separated, machine parseable output format.\n"
        "\t\t json     json output format.\n"
        "\t\t ndjson   ndjson log output format (one json object per line).\n"
        "\t\t null     no flow records, only statistics output.\n"
        "\t\t fmt:...  user selected line output format. See nfdump(1)\n"
        "\t\t csv:...  user selected csv output format. See nfdump(1)\n"
        "\t\tmode may be extended by '6' for full IPv6 listing. e.g.long6, extended6.\n"
        "-6\t\tPrint full length of IPv6 addresses in fmt output instead of condensed.\n"
        "-E <file>\tPrint exporter and sampling info for collected flows.\n"
        "-v <file>\tverify netflow data file. Print version and blocks.\n"
        "-W <num>\tOptionally set the number of workers to compress flows\n"
        "-X\t\tDump Filtertable and exit (debug option).\n"
        "-Z\t\tCheck filter syntax and exit.\n"
        "-t <time>\ttime window for filtering packets\n"
        "\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n"
#ifdef HAVE_LIBSODIUM
        "-K[=passphrase|@keyfile]\tDecrypt encrypted input files (and encrypt output with -w). Passphrase from argument, key file, or interactive "
        "prompt.\n"
#endif
        ,
        name);
} /* usage */

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams) {
    static double duration;
    uint64_t bps, pps, bpp;
    char byte_str[32], packet_str[32], bps_str[32], pps_str[32], bpp_str[32];

    bps = pps = bpp = 0;
    if (stat_record->msecLastSeen) {
        duration = (stat_record->msecLastSeen - stat_record->msecFirstSeen) / 1000.0;
    } else {
        // no flows to report
        duration = 0;
    }
    if (duration > 0 && stat_record->msecLastSeen > 0) {
        bps = (stat_record->numbytes << 3) / duration;  // bits per second. ( >> 3 ) -> * 8 to convert octets into bits
        pps = stat_record->numpackets / duration;       // packets per second
        bpp = stat_record->numpackets ? stat_record->numbytes / stat_record->numpackets : 0;  // Bytes per Packet
    }
    if (outputParams->mode == MODE_CSV) {
        printf("Summary\n");
        printf("flows,bytes,packets,avg_bps,avg_pps,avg_bpp\n");
        printf("%llu,%llu,%llu,%llu,%llu,%llu\n", (long long unsigned)stat_record->numflows, (long long unsigned)stat_record->numbytes,
               (long long unsigned)stat_record->numpackets, (long long unsigned)bps, (long long unsigned)pps, (long long unsigned)bpp);
    } else {
        ScaleByteValue(byte_str, sizeof(byte_str), stat_record->numbytes, outputParams->printPlain, WIDTH_VAR);
        ScaleCountValue(packet_str, sizeof(packet_str), stat_record->numpackets, outputParams->printPlain, WIDTH_VAR);
        ScaleByteValue(bps_str, sizeof(bps_str), bps, outputParams->printPlain, WIDTH_VAR);
        ScaleCountValue(pps_str, sizeof(pps_str), pps, outputParams->printPlain, WIDTH_VAR);
        ScaleByteValue(bpp_str, sizeof(bpp_str), bpp, outputParams->printPlain, WIDTH_VAR);
        printf(
            "Summary: total flows: %llu, total bytes: %s, total packets: %s, avg bps: %s, avg pps: "
            "%s, avg bpp: %s\n",
            (unsigned long long)stat_record->numflows, byte_str, packet_str, bps_str, pps_str, bpp_str);
    }

}  // End of PrintSummary

static int SetStat(char *str, int *element_stat, int *flow_stat) {
    char *statType = strdup(str);
    char *optOrder = strchr(statType, '/');
    if (optOrder) {
        // orderBy given
        *optOrder++ = 0;
    }

    int ret = 0;
    if (strncasecmp(statType, "record", 6) == 0) {
        if (SetRecordStat(statType, optOrder)) {
            *flow_stat = 1;
            ret = 1;
        } else {
            LogError("Failed to parse record stat option: %s", str);
        }
    } else {
        if (SetElementStat(statType, optOrder)) {
            *element_stat = 1;
            ret = 1;
        } else {
            LogError("Failed to parse element stat option: %s", str);
        }
    }

    free(statType);
    return ret;

}  // End of SetStat

static void PrintStat(stat_record_t *s, char *ident) {
    if (s == NULL) return;

    // format info: make compiler happy with conversion to (unsigned long long),
    // which does not change the size of the parameter
    printf("Ident: %s\n", ident);
    printf("Flows: %llu\n", (unsigned long long)s->numflows);
    printf("Flows_tcp: %llu\n", (unsigned long long)s->numflows_tcp);
    printf("Flows_udp: %llu\n", (unsigned long long)s->numflows_udp);
    printf("Flows_icmp: %llu\n", (unsigned long long)s->numflows_icmp);
    printf("Flows_other: %llu\n", (unsigned long long)s->numflows_other);
    printf("Packets: %llu\n", (unsigned long long)s->numpackets);
    printf("Packets_tcp: %llu\n", (unsigned long long)s->numpackets_tcp);
    printf("Packets_udp: %llu\n", (unsigned long long)s->numpackets_udp);
    printf("Packets_icmp: %llu\n", (unsigned long long)s->numpackets_icmp);
    printf("Packets_other: %llu\n", (unsigned long long)s->numpackets_other);
    printf("Bytes: %llu\n", (unsigned long long)s->numbytes);
    printf("Bytes_tcp: %llu\n", (unsigned long long)s->numbytes_tcp);
    printf("Bytes_udp: %llu\n", (unsigned long long)s->numbytes_udp);
    printf("Bytes_icmp: %llu\n", (unsigned long long)s->numbytes_icmp);
    printf("Bytes_other: %llu\n", (unsigned long long)s->numbytes_other);
    printf("First: %llu\n", s->msecFirstSeen / 1000LL);
    printf("Last: %llu\n", s->msecLastSeen / 1000LL);
    printf("msec_first: %llu\n", s->msecFirstSeen % 1000LL);
    printf("msec_last: %llu\n", s->msecLastSeen % 1000LL);
    printf("Sequence failures: %llu\n", (unsigned long long)s->sequence_failure);
}  // End of PrintStat

static void PrintGNUplotSumStat(nffileV3_t *nffile) {
    char *dateString = strstr(nffile->fileName, "nfcapd.");
    if (dateString) {
        dateString += 7;
        time_t when = ISO2UNIX(dateString);
        struct tm ts;
        localtime_r(&when, &ts);
        char datestr[64];
        strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", &ts);
        printf("%s,%llu,%llu,%llu\n", datestr, (long long unsigned)nffile->stat_record->numflows, (long long unsigned)nffile->stat_record->numpackets,
               (long long unsigned)nffile->stat_record->numbytes);
    } else {
        printf("No datestring\n");
    }
}  // End of PrintGNUplotSumStat

static void FreeRecordHandle(recordHandle_t *handle) {
    payloadHandle_t *payloadHandle = (payloadHandle_t *)handle->extensionList[EXinPayloadHandle];
    if (payloadHandle) {
        if (payloadHandle->dns) free(payloadHandle->dns);
        if (payloadHandle->ssl) sslFree(payloadHandle->ssl);
        if (payloadHandle->ja3) free(payloadHandle->ja3);
        if (payloadHandle->ja4) free(payloadHandle->ja4);
        free(payloadHandle);
        handle->extensionList[EXinPayloadHandle] = NULL;
    }
    payloadHandle = (payloadHandle_t *)handle->extensionList[EXoutPayloadHandle];
    if (payloadHandle) {
        if (payloadHandle->dns) free(payloadHandle->dns);
        if (payloadHandle->ssl) sslFree(payloadHandle->ssl);
        if (payloadHandle->ja3) free(payloadHandle->ja3);
        if (payloadHandle->ja4) free(payloadHandle->ja4);
        free(payloadHandle);
        handle->extensionList[EXoutPayloadHandle] = NULL;
    }
}  // End of FreeRecordHandle

static void ProcessArrayBlock(arrayBlockV3_t *arrayBlock) {
    dbg_printf("ARRAY block, type: %u, size: %u, numElements: %u, elementSize: %u\n", arrayBlock->elementType, arrayBlock->rawSize,
               arrayBlock->numElements, arrayBlock->elementSize);

    switch (arrayBlock->elementType) {
        case NbarRecordType:
            AddNbarRecords(arrayBlock);
            break;
        case VrfNameRecordType:
            AddVrfNameRecords(arrayBlock);
            break;
        case IfNameRecordType:
            AddIfNameRecords(arrayBlock);
            break;
        default:
            LogError("Skip unknow arrayblock, type: %u, elementSize: %u, numElements: %u", arrayBlock->type, arrayBlock->elementSize,
                     arrayBlock->numElements);
    }

}  // End of ProcessArrayBlock

static void *prepareThread(void *arg) {
    prepareArgs_t *prepareArgs = (prepareArgs_t *)arg;

    dbg_printf("prepareThread started\n");

    // dispatch args
    queue_t *prepareQueue = prepareArgs->prepareQueue;
    nffileV3_t *nffile = GetNextFile();
    if (nffile == NULL) {
        queue_close(prepareQueue);
        dbg_printf("prepareThread exit\n");
        pthread_exit(NULL);
    }
    t_firstMsec = nffile->stat_record->msecFirstSeen;
    t_lastMsec = nffile->stat_record->msecLastSeen;

    dataHandle_t *dataHandle = NULL;
    uint64_t recordCnt = 0;
    unsigned processedBlocks = 0;
    unsigned skippedBlocks = 0;

    int done = nffile == NULL;
    while (!done) {
        if (dataHandle == NULL) {
            dataHandle = calloc(1, sizeof(dataHandle_t));
            dataHandle->ident = nffile->ident != NULL ? strdup(nffile->ident) : NULL;
        }
        dataHandle->dataBlock = ReadBlockV3(nffile);
        dataHandle->blockCnt = ++processedBlocks;

        // get next data block from file
        if (dataHandle->dataBlock == NULL) {
            // continue with next file
            CloseFileV3(nffile);
            nffile = GetNextFile();
            if (nffile == NULL) {
                done = 1;
            } else {
                if (nffile->stat_record->msecFirstSeen < t_firstMsec) t_firstMsec = nffile->stat_record->msecFirstSeen;
                if (nffile->stat_record->msecLastSeen > t_lastMsec) t_lastMsec = nffile->stat_record->msecLastSeen;
                if (dataHandle->ident) free(dataHandle->ident);
                dataHandle->ident = nffile->ident != NULL ? strdup(nffile->ident) : NULL;
            }
            continue;
        }

        switch (dataHandle->dataBlock->type) {
            case BLOCK_TYPE_FLOW:
                // processed blocks
                break;
            case BLOCK_TYPE_ARRAY:
                ProcessArrayBlock((arrayBlockV3_t *)dataHandle->dataBlock);
                break;
            case BLOCK_TYPE_EXP:
                dbg_printf("prepareThread - Skip exporter block\n");
                break;
            case BLOCK_TYPE_META:
                break;
            case BLOCK_TYPE_IDENT:
                dbg_printf("prepareThread - Skip ident block\n");
                break;
            default:
                LogError("Unknown block type %u. Skip block", dataHandle->dataBlock->type);
                skippedBlocks++;
                FreeDataBlock(dataHandle->dataBlock);
                dataHandle->dataBlock = NULL;
                continue;
        }

        dataHandle->recordCnt = recordCnt;
        recordCnt += (uint64_t)dataHandle->dataBlock->numRecords;
        queue_push(prepareQueue, (void *)dataHandle);
        dataHandle = NULL;
        done = abortProcessing;
#ifdef DEVEL
        if (abortProcessing) printf("prepareThread() abortProcessing\n");
#endif
    }  // while(!done)

    dbg_printf("prepareThread done. blocks processed: %u, skipped: %u\n", processedBlocks, skippedBlocks);
    if (abortProcessing) {
        if (nffile) queue_abort(nffile->processQueue);
        queue_abort(prepareQueue);
    } else {
        queue_close(prepareQueue);
    }
    CloseFileV3(nffile);

    prepareArgs->processedBlocks = processedBlocks;
    prepareArgs->skippedBlocks = skippedBlocks;
    dbg_printf("prepareThread exit\n");
    pthread_exit(NULL);

}  // End of prepareThread

static void *filterThread(void *arg) {
    filterArgs_t *filterArgs = (filterArgs_t *)arg;

#ifdef DEVEL
    uint32_t numBlocks = 0;
    uint32_t self = ++filterArgs->self;
    printf("Filter thread %i started\n", self);
#endif

    // dispatch vars
    queue_t *prepareQueue = filterArgs->prepareQueue;
    queue_t *processQueue = filterArgs->processQueue;
    void *engine = FilterCloneEngine(filterArgs->engine);
    unsigned hasGeoDB = filterArgs->hasGeoDB;

    timeWindow_t *timeWindow = filterArgs->timeWindow;

    // time window of all matched flows
    uint64_t twin_msecFirst, twin_msecLast;
    twin_msecFirst = twin_msecLast = 0;
    if (timeWindow) {
        twin_msecFirst = timeWindow->msecFirst;
        if (timeWindow->msecLast)
            twin_msecLast = timeWindow->msecLast;
        else
            twin_msecLast = 0x7FFFFFFFFFFFFFFFLL;
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (recordHandle == NULL) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }

    // counters for this thread
    uint64_t processedRecords = 0;
    uint64_t passedRecords = 0;
    while (1) {
        // append data blocks
        dataHandle_t *dataHandle = queue_pop(prepareQueue);
        if (dataHandle == QUEUE_CLOSED)  // no more blocks
            break;

        if (dataHandle->dataBlock->type != BLOCK_TYPE_FLOW) {
            // skip none flow block and push them to the next stage
            dbg_printf("Filter thread skip block type: %u\n", dataHandle->dataBlock->type);
            queue_push(processQueue, dataHandle);
            continue;
        }

        // sequential record counter from input
        // set with new block
        uint64_t recordCounter = dataHandle->recordCnt;

        FilterSetParam(engine, dataHandle->ident, hasGeoDB);

        flowBlockV3_t *dataBlock = dataHandle->dataBlock;

#ifdef DEVEL
        numBlocks++;
        printf("Filter thread %i working on Block: %llu, records: %u\n", self, dataHandle->blockCnt, dataBlock->numRecords);
#endif

        recordHeader_t *record_ptr = ResetCursor(dataBlock);
        uint32_t matched = 0;
        uint32_t dataRecords = 0;
        for (int i = 0; i < (int)dataBlock->numRecords; i++) {
            processedRecords++;
            recordCounter++;

            // work on our record
            if (record_ptr->type == V4Record) {
                recordHeaderV4_t *recordHeaderV4 = (recordHeaderV4_t *)record_ptr;
                dataRecords++;
                int match = MapV4RecordHandle(recordHandle, recordHeaderV4, recordCounter);
                // Time based filter
                // if no time filter is given, the result is always true
                if (timeWindow && match) {
                    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
                    if (genericFlow) {
                        match = (genericFlow->msecFirst > twin_msecFirst && genericFlow->msecLast < twin_msecLast);
                    } else {
                        match = 0;
                    }
                }

                if (match) {
                    // filter netflow record with user supplied filter
                    match = FilterRecord(engine, recordHandle);
                }
                if (match) {  // record passed all filters
                    SetFlag(recordHeaderV4->flags, V4_FLAG_PASSED);
                    passedRecords++;
                    matched++;
                } else {
                    ClearFlag(recordHeaderV4->flags, V4_FLAG_PASSED);
                }
                FreeRecordHandle(recordHandle);
            } else {
                LogError("Skip unknown record: %" PRIu64 " type %i", recordCounter, record_ptr->type);
            }

            // Advance pointer by number of bytes for netflow record
            record_ptr = (recordHeader_t *)((void *)record_ptr + record_ptr->size);
        }

        if (matched || dataBlock->numRecords > dataRecords) {
            // we have matched flows
            dbg_printf("Filter thread %u: dataBlock: %llu, matched %u/%u flow records. Total records in datablock: %u\n", self, dataHandle->blockCnt,
                       matched, dataRecords, dataBlock->numRecords);
            queue_push(processQueue, dataHandle);
        } else {
            // no matched flows and only data records - short end
            dbg_printf("Filter thread %i - no matching data records: skip block\n", self);
            FreeDataBlock(dataHandle->dataBlock);
            free(dataHandle->ident);
            free(dataHandle);
            dataHandle = NULL;
        }
    }

    if (abortProcessing)
        queue_abort(processQueue);
    else
        queue_close(processQueue);

    dbg_printf("FilterThread %d done. blocks: %u records: %" PRIu64 " \n", self, numBlocks, processedRecords);

    free(recordHandle);
    filterArgs->processedRecords += processedRecords;
    filterArgs->passedRecords += passedRecords;
    pthread_exit(NULL);
}  // End of filterThread

static stat_record_t process_data(void *engine, int processMode, char *wfile, RecordPrinter_t print_record, timeWindow_t *timeWindow,
                                  uint64_t limitRecords, outputParams_t *outputParams, int compressType, int compressLevel, int numWorkers,
                                  const crypto_ctx_t *crypto_ctx) {
    stat_record_t stat_record = {0};
    stat_record.msecFirstSeen = 0x7fffffffffffffffLL;

    // launch prepareThread
    prepareArgs_t prepareArgs = {.prepareQueue = queue_init(8)};
    pthread_t tidPrepare;
    int err = pthread_create(&tidPrepare, NULL, prepareThread, (void *)&prepareArgs);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        exit(255);
    }

    filterArgs_t filterArgs = {
        .engine = engine,
        .numWorkers = numWorkers,
        .prepareQueue = prepareArgs.prepareQueue,
        .processQueue = queue_init(8),
        .timeWindow = timeWindow,
        .hasGeoDB = outputParams->hasGeoDB,
    };
    queue_producers(filterArgs.processQueue, numWorkers);

    pthread_t *tid = calloc(numWorkers, sizeof(pthread_t));
    if (!tid) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }
    for (int i = 0; i < (int)numWorkers; i++) {
        int err = pthread_create(&(tid[i]), NULL, filterThread, (void *)&filterArgs);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
            exit(255);
        }
    }

    nffileV3_t *nffile_w = NULL;
    flowBlockV3_t *dataBlock_w = NULL;
    // prepare output file if requested
    if (wfile) {
        nffile_w = OpenNewFileV3(wfile, CREATOR_NFDUMP, compressType, compressLevel, crypto_ctx);
        if (!nffile_w) {
            stat_record.msecFirstSeen = 0;
            return stat_record;
        }
        dataBlock_w = NewFlowBlock(nffile_w->fileHeader->blockSize);
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));

    // number of flows passed the filter
    dbg(uint32_t numBlocks = 0);
    int done = 0;
    while (!done) {
        dataHandle_t *dataHandle = queue_pop(filterArgs.processQueue);
        if (dataHandle == QUEUE_CLOSED) {  // no more blocks
            done = 1;
            continue;
        }

        dbg(numBlocks++);
        flowBlockV3_t *dataBlock = dataHandle->dataBlock;
        recordHeader_t *record_ptr = ResetCursor(dataBlock);

        uint64_t recordCounter = dataHandle->recordCnt;
        if (outputParams->ident) free(outputParams->ident);
        outputParams->ident = dataHandle->ident;

        // successfully read block
        total_bytes += dataBlock->rawSize;

        dbg_printf("processData() Next block: %d, type: %u, size: %u\n", numBlocks, dataBlock->type, dataBlock->rawSize);

        if (dataBlock->type != BLOCK_TYPE_FLOW) {
            if (wfile) {
                dbg_printf("Flush non flow block type: %u\n", dataBlock->type);
                PushBlockV3(nffile_w->processQueue, dataBlock);
            }

            continue;
        }
        for (int i = 0; i < (int)dataBlock->numRecords && !abortProcessing; i++) {
            recordCounter++;
            // process records
            switch (record_ptr->type) {
                case V4Record: {
                    recordHeaderV4_t *recordHeaderV4 = (recordHeaderV4_t *)record_ptr;
                    // check if filter matched
                    if (TestFlag(recordHeaderV4->flags, V4_FLAG_PASSED) == 0) goto NEXT;

                    // clear filter flag after use
                    ClearFlag(recordHeaderV4->flags, V4_FLAG_PASSED);
                    totalRecords++;
                    MapV4RecordHandle(recordHandle, (recordHeaderV4_t *)record_ptr, recordCounter);
                    // check if we are done, if -c option was set
                    if (limitRecords) abortProcessing = totalRecords >= limitRecords;

                    UpdateStatRecord(&stat_record, recordHandle);

                    switch (processMode) {
                        case FLOWSTAT:
                            AddFlowCache(recordHandle);
                            break;
                        case ELEMENTSTAT:
                            AddElementStat(recordHandle);
                            break;
                        case ELEMENTFLOWSTAT:
                            AddFlowCache(recordHandle);
                            AddElementStat(recordHandle);
                            break;
                        case SORTRECORDS:
                            InsertFlow(recordHandle);
                            break;
                        case WRITEFILE:
                            dataBlock_w = AppendToBuffer(nffile_w, dataBlock_w, (void *)record_ptr, record_ptr->size);
                            break;
                        case PRINTRECORD:
                            print_record(stdout, recordHandle, outputParams);
                            break;
                    }
                    FreeRecordHandle(recordHandle);

                } break;
                default: {
                    LogError("Skip unknown record type %i\n", record_ptr->type);
                }
            }
        NEXT:
            // Advance pointer by number of bytes for netflow record
            record_ptr = (recordHeader_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

        // free resources
        FreeDataBlock(dataHandle->dataBlock);
        free(dataHandle);
        dataHandle = NULL;
    }  // while

    dbg_printf("processData() done\n");

    free(recordHandle);

    // flush output file
    if (nffile_w) {
        // flush current buffer to disc
        FlushBlockV3(nffile_w, dataBlock_w);
        SetIdent(nffile_w, outputParams->ident);

        /* Copy stat info and close file */
        memcpy((void *)nffile_w->stat_record, (void *)&stat_record, sizeof(stat_record_t));
        FlushFileV3(nffile_w);
        CloseFileV3(nffile_w);
    }

    dbg_printf("processData() wait for prepare thread\n");
    err = pthread_join(tidPrepare, NULL);
    if (err != 0) {
        LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
    }

    dbg_printf("processData() wait for filter threads\n");
    for (int i = 0; i < (int)numWorkers; i++) {
        err = pthread_join(tid[i], NULL);
        if (err) {
            LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(err));
        }
        dbg_printf("processData() filter thread: %d\n", i);
    }
    free(tid);

    totalPassed = filterArgs.passedRecords;
    skippedBlocks = prepareArgs.skippedBlocks;
    return stat_record;

}  // End of process_data

int main(int argc, char **argv) {
    stat_record_t sum_stat;
    outputParams_t *outputParams;
    RecordPrinter_t print_record;
    nfprof_t profile_data;
    char *wfile, *ffile, *filter, *tstring, *stat_type;
    char *print_format;
    char *print_order, *query_type, *configFile, *aggr_fmt;
    int element_stat, fdump;
    int flow_stat, aggregate, aggregate_mask, bidir;
    int print_stat, gnuplot_stat, syntax_only, numWorkers;
    int GuessDir, ModifyCompress;
    uint32_t limitRecords;
    char Ident[IDENTLEN];
    flist_t flist = {0};
    void *postFilter = NULL;

#ifdef DEVEL
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    printf("CPUs online %ld\n", nprocs);
#endif
    wfile = ffile = filter = tstring = stat_type = NULL;
    fdump = aggregate = 0;
    aggregate_mask = 0;
    bidir = 0;
    syntax_only = 0;
    flow_stat = 0;
    print_stat = 0;
    gnuplot_stat = 0;
    element_stat = 0;
    limitRecords = 0;
    skippedBlocks = 0;
    numWorkers = 0;
    GuessDir = 0;

    print_format = NULL;
    print_record = NULL;
    print_order = NULL;
    query_type = NULL;
    ModifyCompress = 0;
    aggr_fmt = NULL;

    configFile = NULL;
    uint32_t compressType = NOT_COMPRESSED;
    uint32_t compressLevel = 0;
    crypto_ctx_t *crypto_ctx = NULL;
    char *geo_file = getenv("NFGEODB");
    char *tor_file = getenv("NFTORDB");

    outputParams = (outputParams_t *)calloc(1, sizeof(outputParams_t));
    if (!outputParams) {
        LogError("calloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    outputParams->topN = -1;

    Ident[0] = '\0';
    int c;
    while ((c = getopt(argc, argv, "6aA:Bbc:C:D:E:G:s:gH:hK::n:i:jf:qyz::r:v:w:J:M:NImO:P:R:XZt:TVv:W:o:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'a':
                aggregate = 1;
                break;
            case 'A':
                CheckArgLen(optarg, 128);
                if (strlen(optarg) > 128) {
                    LogError("Aggregate mask format length error");
                    exit(EXIT_FAILURE);
                }
                if (aggregate_mask) {
                    LogError("Multiple aggregation masks not allowed");
                    exit(EXIT_FAILURE);
                }
                aggr_fmt = optarg;
                aggregate_mask = 1;
                break;
            case 'B':
                GuessDir = 1;
            case 'b':

                bidir = 1;
                // implies
                aggregate = 1;
                print_format = "biline";
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
            case 'D':
                LogInfo("Set nameserver option is deprecated - using nameserver in resolf.conf instead");
                break;
            case 'E': {
                CheckArgLen(optarg, MAXPATHLEN);
                if (CheckPath(optarg, S_IFREG)) PrintExporters(optarg);
                exit(EXIT_SUCCESS);
            } break;
            case 'g':
                gnuplot_stat = 1;
                break;
            case 'G':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, "none") != 0 && !CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                geo_file = strdup(optarg);
                break;
            case 'H':
                CheckArgLen(optarg, MAXPATHLEN);
                if (strcmp(optarg, "none") != 0 && !CheckPath(optarg, S_IFREG)) exit(EXIT_FAILURE);
                tor_file = strdup(optarg);
                // outputParams->doTag = 1;
                break;
            case 'X':
                fdump = 1;
                break;
            case 'Z':
                syntax_only = 1;
                break;
            case 'q':
                outputParams->quiet = 1;
                break;
            case 'j':
                if (compressType != NOT_COMPRESSED) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                compressType = BZ2_COMPRESSED;
                break;
            case 'y':
                if (compressType != NOT_COMPRESSED) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                compressType = LZ4_COMPRESSED;
                break;
            case 'z':
                if (compressType != NOT_COMPRESSED) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                if (optarg == NULL) {
                    compressType = LZO_COMPRESSED;
                } else {
                    if (!ParseCompression(optarg, &compressType, &compressLevel)) {
                        LogError("Usage for option -z: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            case 'c': {
                CheckArgLen(optarg, 16);
                int l = atoi(optarg);
                if (l > 0) limitRecords = (uint32_t)l;
                if (!limitRecords) {
                    LogError("Option -c needs a number > 0");
                    exit(EXIT_FAILURE);
                }
            } break;
            case 's':
                CheckArgLen(optarg, 64);
                stat_type = optarg;
                if (!SetStat(stat_type, &element_stat, &flow_stat)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'V': {
                printf("%s: %s\n", argv[0], versionString());
                exit(EXIT_SUCCESS);
            } break;
            case 'N':
                outputParams->printPlain = 1;
                break;
            case 'f':
                if (!CheckPath(optarg, S_IFREG)) exit(255);
                ffile = optarg;
                break;
            case 't':
                CheckArgLen(optarg, 32);
                tstring = optarg;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.single_file = strdup(optarg);
                break;
            case 'm':
                print_order = "tstart";
                Parse_PrintOrder(print_order);
                LogError("Option -m deprecated. Use '-O tstart' instead");
                break;
            case 'M':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.multiple_dirs = strdup(optarg);
                break;
            case 'I':
                print_stat++;
                break;
            case 'o':  // output mode
                CheckArgLen(optarg, 512);
                print_format = optarg;
                // limit input chars
                break;
            case 'O': {  // stat order by
                CheckArgLen(optarg, 32);
                int ret;
                print_order = optarg;
                ret = Parse_PrintOrder(print_order);
                if (ret < 0) {
                    LogError("Unknown print order '%s'", print_order);
                    ListFlowPrintOrder();
                    exit(EXIT_FAILURE);
                }
            } break;
            case 'P': {  // stat order by
                CheckArgLen(optarg, 256);
                postFilter = strdup(optarg);
            } break;
            case 'R':
                CheckArgLen(optarg, MAXPATHLEN);
                if (!flist.multiple_files) {
                    flist.multiple_files = strdup(optarg);
                } else {
                    LogError("Multiple files option already set: %s", flist.multiple_files);
                }
                break;
            case 'w':
                CheckArgLen(optarg, MAXPATHLEN);
                wfile = optarg;
                break;
            case 'n':
                CheckArgLen(optarg, 16);
                outputParams->topN = atoi(optarg);
                if (outputParams->topN < 0) {
                    LogError("TopnN number %i out of range", outputParams->topN);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'T':
                outputParams->doTag = 1;
                break;
            case 'i':
                CheckArgLen(optarg, IDENTLEN);
                strncpy(Ident, optarg, IDENTLEN);
                Ident[IDENTLEN - 1] = 0;
                if (strchr(Ident, ' ')) {
                    LogError("Ident must not contain spaces");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'J':
                if (!ParseCompression(optarg, &compressType, &compressLevel)) {
                    LogError("Expected -J=<comp>, See arguments for -z");
                    exit(EXIT_FAILURE);
                }
                ModifyCompress = 1;
                break;
            case 'v':
                CheckArgLen(optarg, 16);
                query_type = optarg;
                break;
            case 'W':
                CheckArgLen(optarg, 16);
                numWorkers = atoi(optarg);
                if (numWorkers < 0) {
                    LogError("Invalid number of working threads: %d", numWorkers);
                    exit(EXIT_FAILURE);
                }
                break;
            case '6':  // print long IPv6 addr
                Setv6Mode(1);
                break;
            case 'K': {
                char *pp = ParsePassphrase(optarg, "Enter passphrase: ");
                if (!pp) exit(EXIT_FAILURE);
                crypto_ctx = NewCryptoCtx(pp);
                memset(pp, 0, strlen(pp));
                free(pp);
                if (!crypto_ctx) {
                    LogError("Failed to initialize encryption context");
                    exit(EXIT_FAILURE);
                }
                RegisterReadCryptoCtx(crypto_ctx);
                break;
            }
            default:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (argc - optind > 0) {
        filter = strdup(argv[optind++]);
        while (argc - optind > 0) {
            char *arg = argv[optind++];
            CheckArgLen(arg, 128);
            filter = (char *)realloc(filter, strlen(filter) + strlen(arg) + 2);
            if (!filter) {
                LogError("realloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                exit(EXIT_FAILURE);
            }
            strcat(filter, " ");
            strcat(filter, arg);
        }
    }

    if (configFile && syntax_only) {
        ConfInventory(configFile);
        exit(EXIT_SUCCESS);
    }

    if (query_type) {
        if (flist.single_file == NULL) {
            LogError("Missing file to %s. Add -r <file>", query_type);
            exit(EXIT_FAILURE);
        }
        if (strcmp(query_type, "check") == 0) {
            exit(VerifyFileV3(flist.single_file, 0) == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
        } else if (strcmp(query_type, "check-verbose") == 0) {
            exit(VerifyFileV3(flist.single_file, 1) == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
        } else if (strcmp(query_type, "repair") == 0) {
            ReWriteV3(flist.single_file);
        } else {
            LogError("Unknown mode to verify file: %s. Use -v check, or -v repair", query_type);
        }
        exit(EXIT_SUCCESS);
    }
    if (!filter && ffile) {
        filter = ReadFilter(ffile);
        if (filter == NULL) {
            exit(255);
        }

        FilterFilename = ffile;
    }

    // if no filter is given, set the default ip filter which passes through every flow
    if (!filter || strlen(filter) == 0) filter = "any";

    void *engine = CompileFilter(filter);
    if (!engine) {
        LogError("Compile filter failed!");
        exit(EXIT_FAILURE);
    }

    if (postFilter) {
        outputParams->postFilter = CompileFilter(postFilter);
        if (!outputParams->postFilter) exit(254);
    }

    if (fdump) {
        DumpEngine(engine);
        if (outputParams->postFilter) {
            printf("\nPost filter:\n");
            DumpEngine(outputParams->postFilter);
        }
        exit(EXIT_SUCCESS);
    }

    if (syntax_only) exit(EXIT_SUCCESS);

    if (!InitExporterList()) {
        exit(EXIT_FAILURE);
    }

    if (ConfOpen(configFile, "nfdump") < 0) exit(EXIT_FAILURE);

    numWorkers = GetNumWorkers(numWorkers);

    if (outputParams->topN < 0) {
        if (flow_stat || element_stat) {
            outputParams->topN = 10;
        } else {
            outputParams->topN = 0;
        }
    }
    if (wfile) outputParams->quiet = 1;

    if ((element_stat && !flow_stat) && aggregate_mask) {
        LogError("Warning: Aggregation ignored for element statistics\n");
        aggregate_mask = 0;
    }

    if (!flow_stat && aggregate_mask) {
        aggregate = 1;
    }

    if (tstring) {
        flist.timeWindow = ScanTimeFrame(tstring);
        if (!flist.timeWindow) exit(EXIT_FAILURE);
    }

    if (flist.multiple_dirs == NULL && flist.single_file == NULL && flist.multiple_files == NULL) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(numWorkers, fileList)) exit(EXIT_FAILURE);

    // Modify compression
    if (ModifyCompress) {
        if (!flist.single_file && !flist.multiple_files) {
            LogError("Expected -r <file> or -R <dir> to change compression");
            exit(EXIT_FAILURE);
        }
        ModifyCompressFile(compressType, compressLevel);
        exit(EXIT_SUCCESS);
    }

    // Change Ident only
    if (flist.single_file && strlen(Ident) > 0) {
        if (ChangeIdent(flist.single_file, Ident)) {
            LogInfo("Successfully changed ident to %s for %s", Ident, flist.single_file);
            exit(EXIT_SUCCESS);
        } else {
            LogInfo("Failed to change ident to %s for %s", Ident, flist.single_file);
            exit(EXIT_FAILURE);
        }
        exit(ChangeIdent(flist.single_file, Ident) ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    if (print_stat) {
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s)");
            exit(EXIT_FAILURE);
        }

        memset((void *)&sum_stat, 0, sizeof(stat_record_t));
        sum_stat.msecFirstSeen = 0x7fffffffffffffff;
        nffileV3_t *nffile = GetNextFile();
        if (!nffile) {
            LogError("Error open file: %s", strerror(errno));
            exit(250);
        }
        char *ident = NULL;
        if (nffile->ident) {
            ident = strdup(nffile->ident);
        }
        while (nffile != NULL) {
            SumStatRecords(&sum_stat, nffile->stat_record);
            CloseFileV3(nffile);
            nffile = GetNextFile();
        }
        PrintStat(&sum_stat, ident);
        free(ident);
        exit(EXIT_SUCCESS);
    }

    if (geo_file == NULL) {
        geo_file = ConfGetString("geodb.path");
    }
    if (geo_file && strcmp(geo_file, "none") == 0) {
        geo_file = NULL;
    }
    if (geo_file) {
        if (!CheckPath(geo_file, S_IFREG) || !LoadMaxMind(geo_file)) {
            LogError("Error reading geo location DB file %s", geo_file);
            exit(EXIT_FAILURE);
        }
        outputParams->hasGeoDB = true;
    }

    if (tor_file == NULL) {
        tor_file = ConfGetString("tordb.path");
    }
    if (tor_file && strcmp(tor_file, "none") == 0) {
        tor_file = NULL;
    }
    if (tor_file) {
        if (!CheckPath(tor_file, S_IFREG) || !LoadTorTree(tor_file)) {
            LogError("Error reading tor info DB file %s", tor_file);
            exit(EXIT_FAILURE);
        }
        outputParams->hasTorDB = true;
    }
    if ((aggregate || flow_stat || print_order) && !Init_FlowCache(outputParams->hasGeoDB)) exit(250);

    if (aggregate && (flow_stat || element_stat)) {
        aggregate = 0;
        LogError("Command line switch -s overwrites -a\n");
    }

    if (bidir && !SetBidirAggregation()) {
        exit(EXIT_FAILURE);
    }

    if (aggr_fmt) {
        // custom aggregation mask overwrites any output format
        print_format = ParseAggregateMask(print_format, aggr_fmt);
        if (!print_format) {
            exit(EXIT_FAILURE);
        }
    }
    if (element_stat && !Init_StatTable(outputParams->hasGeoDB)) exit(250);

    if (gnuplot_stat) {
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s).\n");
            exit(EXIT_FAILURE);
        }

        nffileV3_t *nffile = GetNextFile();
        if (!nffile) {
            LogError("Error open file: %s\n", strerror(errno));
            exit(250);
        }
        printf("# yyyy-mm-dd HH:MM:SS,flows,packets,bytes\n");
        while (nffile != NULL) {
            PrintGNUplotSumStat(nffile);
            CloseFileV3(nffile);
            nffile = GetNextFile();
        }
        exit(EXIT_SUCCESS);
    }

    print_record = SetupOutputMode(print_format, outputParams);

    if (!print_record) {
        LogError("Unknown output mode '%s'\n", print_format);
        PrintOutputHelp();
        exit(EXIT_FAILURE);
    }

    if (print_order && flow_stat) {
        printf("-s record and -O (-m) are mutually exclusive options\n");
        exit(EXIT_FAILURE);
    }

    if (!(flow_stat || element_stat)) {
        PrintProlog(outputParams);
    }

    int processMode = PRINTRECORD;
    if (aggregate || flow_stat) {
        processMode = FLOWSTAT;
        if (element_stat) processMode = ELEMENTFLOWSTAT;
    } else if (element_stat) {
        processMode = ELEMENTSTAT;
    } else if (print_order != NULL) {
        processMode = SORTRECORDS;
    } else if (wfile) {
        processMode = WRITEFILE;
    }

    nfprof_start(&profile_data);
    sum_stat = process_data(engine, processMode, wfile, print_record, flist.timeWindow, limitRecords, outputParams, compressType, compressLevel,
                            numWorkers, crypto_ctx);
    nfprof_end(&profile_data, totalRecords);

    if (totalPassed == 0) {
        printf("No matching flows\n");
    }

    if (aggregate || print_order) {
        if (wfile) {
            nffileV3_t *nffile = OpenNewFileV3(wfile, CREATOR_NFDUMP, compressType, compressLevel, crypto_ctx);
            if (!nffile) exit(EXIT_FAILURE);
            SetIdent(nffile, outputParams->ident);
            if (ExportFlowTable(nffile, aggregate, bidir, GuessDir)) {
                FlushFileV3(nffile);
            } else {
                FlushFileV3(nffile);
                unlink(wfile);
            }
        } else {
            PrintFlowTable(print_record, outputParams, GuessDir);
        }
    }

    if (flow_stat) {
        PrintFlowStat(print_record, outputParams);
    }

    if (element_stat) {
        PrintElementStat(&sum_stat, outputParams, print_record);
    }

    if (!(flow_stat || element_stat)) {
        PrintEpilog(outputParams);
    }

    if (!outputParams->quiet) {
        switch (outputParams->mode) {
            case MODE_RAW:
                break;
            case MODE_NULL:
            case MODE_FMT:
                PrintSummary(&sum_stat, outputParams);
                if (t_lastMsec == 0) {
                    printf("Time window: <unknown>\n");
                } else {
                    char string[128];
                    if (flist.timeWindow) {
                        if (flist.timeWindow->msecFirst && (flist.timeWindow->msecFirst > t_firstMsec)) t_firstMsec = flist.timeWindow->msecFirst;
                        if (flist.timeWindow->msecLast && (flist.timeWindow->msecLast < t_lastMsec)) t_lastMsec = flist.timeWindow->msecLast;
                    }
                    uint64_t durationMsec = t_lastMsec - t_firstMsec;
                    printf("Time window: %s, Duration: %s\n", TimeString(t_firstMsec, t_lastMsec),
                           ScaleDuration(string, sizeof(string), durationMsec, outputParams->printPlain, WIDTH_VAR));
                }
                printf("Total records processed: %" PRIu64 ", passed: %" PRIu64 ", Blocks skipped: %u, Bytes read: %llu\n", totalRecords, totalPassed,
                       skippedBlocks, (unsigned long long)total_bytes);
                nfprof_print(&profile_data, stdout);
                break;
            case MODE_CSV:
            case MODE_CSV_FAST:
                break;
            case MODE_JSON:
            case MODE_NDJSON:
                break;
        }

    }  // else - no output

#ifdef DEVEL
    DumpNbarList();
#endif
    Dispose_FlowTable();
    Dispose_StatTable();
    RegisterReadCryptoCtx(NULL);
    FreeCryptoCtx(crypto_ctx);

    return 0;
}
