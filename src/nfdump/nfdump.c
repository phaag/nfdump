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
#include "conf/nfconf.h"
#include "config.h"
#include "exporter.h"
#include "filter/filter.h"
#include "flist.h"
#include "ifvrf.h"
#include "maxmind/maxmind.h"
#include "nbar.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "nfdump_1_6_x.h"
#include "nffile.h"
#include "nflowcache.h"
#include "nfnet.h"
#include "nfprof.h"
#include "nfstat.h"
#include "nfx.h"
#include "nfxV3.h"
#include "output.h"
#include "tor/tor.h"
#include "util.h"
#include "version.h"

extern char *FilterFilename;

#define MAXANONWORKERS 8
#define MAX_FILTER_THREADS 32

typedef struct dataHandle_s {
    dataBlock_t *dataBlock;
    char *ident;
    uint64_t recordCnt;
} dataHandle_t;

typedef struct prepareArgs_s {
    queue_t *prepareQueue;
    uint32_t processedBlocks;
    uint32_t skippedBlocks;
} prepareArgs_t;

typedef struct filterArgs_s {
    _Atomic int self;
    int numWorkers;
    void *engine;
    timeWindow_t *timeWindow;
    int hasGeoDB;
    queue_t *prepareQueue;
    queue_t *processQueue;
    _Atomic uint64_t processedRecords;
    _Atomic uint64_t passedRecords;
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

extern exporter_t **exporter_list;

/* Function Prototypes */
static void usage(char *name);

static int SetStat(char *str, int *element_stat, int *flow_stat);

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams);

static stat_record_t process_data(void *engine, int processMode, char *wfile, RecordPrinter_t print_record, timeWindow_t *timeWindow,
                                  uint64_t limitRecords, outputParams_t *outputParams, int compress);

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
        "-D <dns>\tUse nameserver <dns> for host lookup.\n"
        "-G <geoDB>\tUse this nfdump geoDB to lookup country/location.\n"
        "-H <torDB>\tUse nfdump torDB to lookup tor info.\n"
        "-N\t\tPrint plain numbers\n"
        "-s <expr>[/<order>]\tGenerate statistics for <expr> any valid record element.\n"
        "\t\tand ordered by <order>: packets, bytes, flows, bps pps and bpp.\n"
        "-q\t\tQuiet: Do not print the header and bottom stat lines.\n"
        "-i <ident>\tChange Ident to <ident> in file given by -r.\n"
        "-J <num>\tModify file compression: 0: uncompressed - 1: LZO - 2: BZ2 - 3: LZ4 - 4: ZSTD"
        "compressed.\n"
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
        "-x <file>\tverify extension records in netflow data file.\n"
        "-X\t\tDump Filtertable and exit (debug option).\n"
        "-Z\t\tCheck filter syntax and exit.\n"
        "-t <time>\ttime window for filtering packets\n"
        "\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n",
        name);
} /* usage */

static void PrintSummary(stat_record_t *stat_record, outputParams_t *outputParams) {
    static double duration;
    uint64_t bps, pps, bpp;
    numStr byte_str, packet_str, bps_str, pps_str, bpp_str;

    bps = pps = bpp = 0;
    if (stat_record->lastseen) {
        duration = (stat_record->lastseen - stat_record->firstseen) / 1000.0;
    } else {
        // no flows to report
        duration = 0;
    }
    if (duration > 0 && stat_record->lastseen > 0) {
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
        format_number(stat_record->numbytes, byte_str, outputParams->printPlain, VAR_LENGTH);
        format_number(stat_record->numpackets, packet_str, outputParams->printPlain, VAR_LENGTH);
        format_number(bps, bps_str, outputParams->printPlain, VAR_LENGTH);
        format_number(pps, pps_str, outputParams->printPlain, VAR_LENGTH);
        format_number(bpp, bpp_str, outputParams->printPlain, VAR_LENGTH);
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

__attribute__((noreturn)) static void *prepareThread(void *arg) {
    prepareArgs_t *prepareArgs = (prepareArgs_t *)arg;

    dbg_printf("prepareThread started\n");

    // dispatch args
    queue_t *prepareQueue = prepareArgs->prepareQueue;
    nffile_t *nffile = GetNextFile(NULL);
    if (nffile == NULL) {
        queue_close(prepareQueue);
        dbg_printf("prepareThread exit\n");
        pthread_exit(NULL);
    }
    t_firstMsec = nffile->stat_record->firstseen;
    t_lastMsec = nffile->stat_record->lastseen;

    dataHandle_t *dataHandle = NULL;
    uint64_t recordCnt = 0;
    int processedBlocks = 0;
    int skippedBlocks = 0;

    int done = nffile == NULL;
    while (!done) {
        if (dataHandle == NULL) {
            dataHandle = calloc(1, sizeof(dataHandle_t));
            dataHandle->ident = nffile->ident != NULL ? strdup(nffile->ident) : NULL;
        }
        dataHandle->dataBlock = ReadBlock(nffile, NULL);

        // get next data block from file
        if (dataHandle->dataBlock == NULL) {
            // continue with next file
            if (GetNextFile(nffile) == NULL) {
                done = 1;
            } else {
                if (nffile->stat_record->firstseen < t_firstMsec) t_firstMsec = nffile->stat_record->firstseen;
                if (nffile->stat_record->lastseen > t_lastMsec) t_lastMsec = nffile->stat_record->lastseen;
                if (dataHandle->ident) free(dataHandle->ident);
                dataHandle->ident = nffile->ident != NULL ? strdup(nffile->ident) : NULL;
            }
            continue;
        }

        processedBlocks++;
        switch (dataHandle->dataBlock->type) {
            case DATA_BLOCK_TYPE_1:
                LogError("nfdump 1.5.x block type 1 no longer supported. Skip block");
                goto SKIP;
                break;
            case DATA_BLOCK_TYPE_2: {
                dataBlock_t *v3DataBlock = NewDataBlock();
                ConvertBlockType2(dataHandle->dataBlock, v3DataBlock);
                FreeDataBlock(dataHandle->dataBlock);
                dataHandle->dataBlock = v3DataBlock;
            } break;
            case DATA_BLOCK_TYPE_3:
                // processed blocks
                break;
            case DATA_BLOCK_TYPE_4:
                // silently skipped
                goto SKIP;
                break;
            default:
                LogError("Unknown block type %u. Skip block", dataHandle->dataBlock->type);
            SKIP:
                skippedBlocks++;
                continue;
        }

        dataHandle->recordCnt = recordCnt;
        recordCnt += (uint64_t)dataHandle->dataBlock->NumRecords;
        queue_push(prepareQueue, (void *)dataHandle);
        dataHandle = NULL;
        done = abortProcessing;
#ifdef DEVEL
        if (abortProcessing) printf("prepareThread() abortProcessing\n");
#endif
    }  // while(!done)

    dbg_printf("prepareThread done. blocks processed: %u, skipped: %u\n", processedBlocks, skippedBlocks);
    queue_close(prepareQueue);
    CloseFile(nffile);

    prepareArgs->processedBlocks = processedBlocks;
    prepareArgs->skippedBlocks = skippedBlocks;
    dbg_printf("prepareThread exit\n");
    pthread_exit(NULL);

}  // End of prepareThread

__attribute__((noreturn)) static void *filterThread(void *arg) {
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
    int hasGeoDB = filterArgs->hasGeoDB;

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

        // sequential record counter from input
        // set with new block
        uint64_t recordCounter = dataHandle->recordCnt;

        FilterSetParam(engine, dataHandle->ident, hasGeoDB);

        dataBlock_t *dataBlock = dataHandle->dataBlock;

#ifdef DEVEL
        numBlocks++;
        printf("Filter thread %i working on next Block: %u, records: %u\n", self, numBlocks, dataBlock->NumRecords);
#endif

        record_header_t *record_ptr = GetCursor(dataBlock);
        uint32_t sumSize = 0;
        for (int i = 0; i < dataBlock->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > dataBlock->size || (record_ptr->size < sizeof(record_header_t))) {
                if (sumSize == dataBlock->size) {
                    LogError("DataBlock count error");
                    LogError("DataBlock: count: %u, size: %u. Found: %u, size: %u", dataBlock->NumRecords, dataBlock->size, i, sumSize);
                    dataBlock->NumRecords = i;
                    break;
                }
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                LogError("DataBlock: count: %u, size: %u. Found: %u, size: %u", dataBlock->NumRecords, dataBlock->size, i, sumSize);
                sumSize = 0;
                break;
            }
            sumSize += record_ptr->size;
            processedRecords++;
            recordCounter++;

            // work on our record
            switch (record_ptr->type) {
                case CommonRecordType:
                    printf("Need to convert record type: %u\n", CommonRecordType);
                    sumSize = 0;
                    break;
                case V3Record: {
                    recordHeaderV3_t *recordHeaderV3 = (recordHeaderV3_t *)record_ptr;
                    int match = MapRecordHandle(recordHandle, recordHeaderV3, recordCounter);
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
                        SetFlag(recordHeaderV3->flags, V3_FLAG_PASSED);
                        passedRecords++;
                    } else {
                        ClearFlag(recordHeaderV3->flags, V3_FLAG_PASSED);
                    }

                } break;
                case ExtensionMapType:
                case ExporterInfoRecordType:
                case ExporterStatRecordType:
                case SamplerRecordType:
                case NbarRecordType:
                case IfNameRecordType:
                case VrfNameRecordType:
                    // Silently skip exporter/sampler records
                    break;

                default: {
                    LogError("Skip unknown record: %" PRIu64 " type %i", recordCounter, record_ptr->type);
                }
            }

            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);
        }
        dbg_printf("Filter thread %i push next block: %u\n", self, numBlocks);
        if (sumSize) queue_push(processQueue, dataHandle);
    }

    // Close the queue so this producer is removed. Once the filtering is done, the data block views can be consumed from the queue.
    queue_close(processQueue);
    dbg_printf("FilterThread %d done. blocks: %u records: %" PRIu64 " \n", self, numBlocks, processedRecords);

    free(recordHandle);
    filterArgs->processedRecords += processedRecords;
    filterArgs->passedRecords += passedRecords;
    pthread_exit(NULL);
}  // End of filterThread

static stat_record_t process_data(void *engine, int processMode, char *wfile, RecordPrinter_t print_record, timeWindow_t *timeWindow,
                                  uint64_t limitRecords, outputParams_t *outputParams, int compress) {
    stat_record_t stat_record = {0};
    stat_record.firstseen = 0x7fffffffffffffffLL;

    // launch prepareThread
    prepareArgs_t prepareArgs = {.prepareQueue = queue_init(8)};
    pthread_t tidPrepare;
    int err = pthread_create(&tidPrepare, NULL, prepareThread, (void *)&prepareArgs);
    if (err) {
        LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        exit(255);
    }

    // check numWorkers depending on cores online
    uint32_t numWorkers = GetNumWorkers(0);
    filterArgs_t filterArgs = {
        .engine = engine,
        .numWorkers = numWorkers,
        .prepareQueue = prepareArgs.prepareQueue,
        .processQueue = queue_init(8),
        .timeWindow = timeWindow,
        .hasGeoDB = outputParams->hasGeoDB,
    };
    queue_producers(filterArgs.processQueue, numWorkers);

    // The thread IDs are stored on the stack and the number of threads seems very reasonable.
    // But we have to check whether the number of workers does not exceed this amount or we will write outside of bounds.
    if (numWorkers > MAX_FILTER_THREADS)
    {
        LogError("The number of requested workers: %i exceeds the maximum of %i. Setting number of workers to %i", numWorkers, MAX_FILTER_THREADS, MAX_FILTER_THREADS);
        numWorkers = MAX_FILTER_THREADS;
    }

    // Create filter workers.
    pthread_t tidFilter[MAX_FILTER_THREADS];
    for (int i = 0; i < numWorkers; i++) {
        int err = pthread_create(&(tidFilter[i]), NULL, filterThread, (void *)&filterArgs);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
    }

    nffile_t *nffile_w = NULL;
    dataBlock_t *dataBlock_w = NULL;
    // prepare output file if requested
    if (wfile) {
        nffile_w = OpenNewFile(wfile, NULL, CREATOR_NFDUMP, compress, NOT_ENCRYPTED);
        if (!nffile_w) {
            stat_record.firstseen = 0;
            return stat_record;
        }
        dataBlock_w = WriteBlock(nffile_w, NULL);
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));

    // number of flows passed the filter
    dbg(uint32_t numBlocks = 0);
    int done = 0;
    while (!done) {
        // Consume data block views from the queue until no more are available. The filter threads fill up this queue in the background.
        // When there is no more data to be processed, the queue is closed from the filter threads and 'done' will be set to 1.
        dataHandle_t *dataHandle = queue_pop(filterArgs.processQueue);
        if (dataHandle == QUEUE_CLOSED) {  // no more blocks
            done = 1;
            continue;
        }

        dbg(numBlocks++);
        dataBlock_t *dataBlock = dataHandle->dataBlock;
        record_header_t *record_ptr = GetCursor(dataBlock);

        uint64_t recordCounter = dataHandle->recordCnt;
        outputParams->ident = dataHandle->ident;

        // successfully read block
        total_bytes += dataBlock->size;

        dbg_printf("processData() Next block: %d, Records: %u\n", numBlocks, dataBlock->NumRecords);

        for (int i = 0; i < dataBlock->NumRecords && !abortProcessing; i++) {
            recordCounter++;
            // process records
            switch (record_ptr->type) {
                case V3Record: {
                    recordHeaderV3_t *recordHeaderV3 = (recordHeaderV3_t *)record_ptr;
                    // check if filter matched
                    if (TestFlag(recordHeaderV3->flags, V3_FLAG_PASSED) == 0) goto NEXT;

                    // clear filter flag after use
                    ClearFlag(recordHeaderV3->flags, V3_FLAG_PASSED);
                    totalRecords++;
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, recordCounter);
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

                } break;
                case ExtensionMapType:
                    printf("ExtensionMap no longer handled here!\n");
                    break;
                case ExporterInfoRecordType: {
                    int ret = AddExporterInfo((exporter_info_record_t *)record_ptr);
                    if (ret != 0) {
                        if (nffile_w) dataBlock_w = AppendToBuffer(nffile_w, dataBlock_w, (void *)record_ptr, record_ptr->size);
                    } else {
                        LogError("Failed to add Exporter Record\n");
                    }
                } break;
                case ExporterStatRecordType:
                    AddExporterStat((exporter_stats_record_t *)record_ptr);
                    break;
                case SamplerLegacyRecordType: {
                    if (AddSamplerLegacyRecord((samplerV0_record_t *)record_ptr) == 0) LogError("Failed to add legacy Sampler Record\n");
                } break;
                case SamplerRecordType: {
                    int ret = AddSamplerRecord((sampler_record_t *)record_ptr);
                    if (ret != 0) {
                        if (nffile_w) dataBlock_w = AppendToBuffer(nffile_w, dataBlock_w, (void *)record_ptr, record_ptr->size);
                    } else {
                        LogError("Failed to add Sampler Record\n");
                    }
                } break;
                case NbarRecordType: {
                    arrayRecordHeader_t *nbarRecord = (arrayRecordHeader_t *)record_ptr;
#ifdef DEVEL
                    printf("Found nbar record: %u elements\n", nbarRecord->numElements);
                    PrintNbarRecord(nbarRecord);
#endif
                    AddNbarRecord(nbarRecord);
                } break;
                case IfNameRecordType: {
                    arrayRecordHeader_t *arrayRecordHeader = (arrayRecordHeader_t *)record_ptr;
                    AddIfNameRecord(arrayRecordHeader);
                } break;

                case VrfNameRecordType: {
                    arrayRecordHeader_t *arrayRecordHeader = (arrayRecordHeader_t *)record_ptr;
                    AddVrfNameRecord(arrayRecordHeader);
                } break;
                case LegacyRecordType1:
                case LegacyRecordType2:
                case CommonRecordV0Type:
                    LogError("Skip lagecy record type: %d", record_ptr->type);
                    break;
                default: {
                    LogError("Skip unknown record type %i\n", record_ptr->type);
                }
            }
        NEXT:
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);

        }  // for all records

        // Free the data handle here and the associated block. The 'ident' pointer is used elsewhere so this is freed elsewhere.
        FreeDataBlock(dataHandle->dataBlock);
        if (dataHandle->ident) {
            outputParams->ident = dataHandle->ident;
            free(dataHandle);
        }
    }  // while

    dbg_printf("processData() done\n");

    // flush output file
    if (nffile_w) {
        // flush current buffer to disc
        FlushBlock(nffile_w, dataBlock_w);
        SetIdent(nffile_w, outputParams->ident);

        /* Copy stat info and close file */
        memcpy((void *)nffile_w->stat_record, (void *)&stat_record, sizeof(stat_record_t));
        CloseUpdateFile(nffile_w);
        DisposeFile(nffile_w);
    }

    dbg_printf("processData() wait for prepare thread\n");
    if (pthread_join(tidPrepare, NULL)) {
        LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
    }

    dbg_printf("processData() wait for filter threads\n");
    for (int i = 0; i < numWorkers; i++) {
        if (pthread_join(tidFilter[i], NULL)) {
            LogError("pthread_join() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        }
        dbg_printf("processData() filter thread: %d\n", i);
    }

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
    char *print_order, *query_file, *configFile, *nameserver, *aggr_fmt;
    int element_stat, fdump;
    int flow_stat, aggregate, aggregate_mask, bidir;
    int print_stat, gnuplot_stat, syntax_only, compress, worker;
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
    compress = NOT_COMPRESSED;
    worker = 0;
    GuessDir = 0;
    nameserver = NULL;

    print_format = NULL;
    print_record = NULL;
    print_order = NULL;
    query_file = NULL;
    ModifyCompress = -1;
    aggr_fmt = NULL;

    configFile = NULL;
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
    while ((c = getopt(argc, argv, "6aA:Bbc:C:D:E:G:s:gH:hn:i:jf:qyz::r:v:w:J:M:NImO:P:R:XZt:TVv:W:x:o:")) != EOF) {
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
                CheckArgLen(optarg, 64);
                nameserver = optarg;
                if (!SetNameserver(nameserver)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'E': {
                CheckArgLen(optarg, MAXPATHLEN);
                if (!InitExporterList()) {
                    exit(EXIT_FAILURE);
                }
                flist.single_file = strdup(optarg);
                queue_t *fileList = SetupInputFileSequence(&flist);
                if (!fileList || !Init_nffile(1, fileList)) exit(EXIT_FAILURE);
                PrintExporters();
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
                if (compress) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                compress = BZ2_COMPRESSED;
                break;
            case 'y':
                if (compress) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                compress = LZ4_COMPRESSED;
                break;
            case 'z':
                if (compress) {
                    LogError("Use one compression only: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                if (optarg == NULL) {
                    compress = LZO_COMPRESSED;
                } else {
                    compress = ParseCompression(optarg);
                }
                if (compress == -1) {
                    LogError("Usage for option -z: set -z=lzo, -z=lz4, -z=bz2 or z=zstd for valid compression formats");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'c':
                CheckArgLen(optarg, 16);
                limitRecords = atoi(optarg);
                if (!limitRecords) {
                    LogError("Option -c needs a number > 0");
                    exit(EXIT_FAILURE);
                }
                break;
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
                ModifyCompress = ParseCompression(optarg);
                if (ModifyCompress < 0) {
                    LogError("Expected -J <arg>, 0 for uncompressed, 1, LZO, 2, BZ2, 3, LZ4");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'x': {
                CheckArgLen(optarg, MAXPATHLEN);
                InitExtensionMaps(NO_EXTENSION_LIST);
                flist.single_file = strdup(optarg);
                queue_t *fileList = SetupInputFileSequence(&flist);
                if (!fileList || !Init_nffile(1, fileList)) exit(EXIT_FAILURE);
                DumpExMaps();
                exit(EXIT_SUCCESS);
            } break;
            case 'v':
                CheckArgLen(optarg, MAXPATHLEN);
                query_file = optarg;
                if (!QueryFile(query_file, fdump))
                    exit(EXIT_FAILURE);
                else
                    exit(EXIT_SUCCESS);
                break;
            case 'W':
                CheckArgLen(optarg, 16);
                worker = atoi(optarg);
                if (worker < 0 || worker > MAXWORKERS) {
                    LogError("Number of working threads out of range 1..%d", MAXWORKERS);
                    exit(EXIT_FAILURE);
                }
                break;
            case '6':  // print long IPv6 addr
                Setv6Mode(1);
                break;
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
    if (!engine) exit(254);

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

    if (ConfOpen(configFile, "nfdump") < 0) exit(EXIT_FAILURE);

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
    if (!fileList || !Init_nffile(worker, fileList)) exit(EXIT_FAILURE);

    // Modify compression
    if (ModifyCompress >= 0) {
        if (!flist.single_file && !flist.multiple_files) {
            LogError("Expected -r <file> or -R <dir> to change compression\n");
            exit(EXIT_FAILURE);
        }
        ModifyCompressFile(ModifyCompress);
        exit(EXIT_SUCCESS);
    }

    // Change Ident only
    if (flist.single_file && strlen(Ident) > 0) {
        ChangeIdent(flist.single_file, Ident);
        exit(EXIT_SUCCESS);
    }

    if (print_stat) {
        nffile_t *nffile;
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s).\n");
            exit(EXIT_FAILURE);
        }

        memset((void *)&sum_stat, 0, sizeof(stat_record_t));
        sum_stat.firstseen = 0x7fffffffffffffff;
        nffile = GetNextFile(NULL);
        if (!nffile) {
            LogError("Error open file: %s\n", strerror(errno));
            exit(250);
        }
        char *ident = NULL;
        if (nffile->ident) {
            ident = strdup(nffile->ident);
        }
        while (nffile != NULL) {
            SumStatRecords(&sum_stat, nffile->stat_record);
            nffile = GetNextFile(nffile);
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
        nffile_t *nffile;
        if (!flist.single_file && !flist.multiple_files && !flist.multiple_dirs) {
            LogError("Expect data file(s).\n");
            exit(EXIT_FAILURE);
        }

        nffile = GetNextFile(NULL);
        if (!nffile) {
            LogError("Error open file: %s\n", strerror(errno));
            exit(250);
        }
        printf("# yyyy-mm-dd HH:MM:SS,flows,packets,bytes\n");
        while (nffile != NULL) {
            PrintGNUplotSumStat(nffile);
            nffile = GetNextFile(nffile);
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
    sum_stat = process_data(engine, processMode, wfile, print_record, flist.timeWindow, limitRecords, outputParams, compress);
    nfprof_end(&profile_data, totalRecords);

    if (totalPassed == 0) {
        printf("No matching flows\n");
    }

    if (aggregate || print_order) {
        if (wfile) {
            nffile_t *nffile = OpenNewFile(wfile, NULL, CREATOR_NFDUMP, compress, NOT_ENCRYPTED);
            if (!nffile) exit(EXIT_FAILURE);
            SetIdent(nffile, outputParams->ident);
            if (ExportFlowTable(nffile, aggregate, bidir, GuessDir)) {
                CloseUpdateFile(nffile);
            } else {
                CloseFile(nffile);
                unlink(wfile);
            }
            DisposeFile(nffile);
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
                    if (flist.timeWindow) {
                        if (flist.timeWindow->msecFirst && (flist.timeWindow->msecFirst > t_firstMsec)) t_firstMsec = flist.timeWindow->msecFirst;
                        if (flist.timeWindow->msecLast && (flist.timeWindow->msecLast < t_lastMsec)) t_lastMsec = flist.timeWindow->msecLast;
                    }
                    uint64_t durationMsec = t_lastMsec - t_firstMsec;
                    printf("Time window: %s, Duration:%s\n", TimeString(t_firstMsec, t_lastMsec), DurationString(durationMsec));
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

    // Free the multiple files list if used.
    if (flist.multiple_files) free(flist.multiple_files);

    // Free the output params struct and the ident. At this point, the 'outputParams' pointer should never be NULL since thsis check exists further up.
    if (outputParams->ident) free(outputParams->ident);
    free(outputParams);

#ifdef DEVEL
    DumpNbarList();
#endif

    Dispose_FlowTable();
    Dispose_StatTable();

    return 0;
}
