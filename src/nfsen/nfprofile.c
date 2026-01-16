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
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "barrier.h"
#include "conf/nfconf.h"
#include "filter/filter.h"
#include "flist.h"
#include "maxmind.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstatfile.h"
#include "nfxV3.h"
#include "profile.h"
#include "tor.h"
#include "util.h"
#include "version.h"

/* Local Variables */
#ifdef HAVE_INFLUXDB
char influxdb_url[1024] = "";
#endif

#define PROFILEWRITERS 2
#define MAXPROFILERS 8

typedef struct worker_param_s {
    int self;
    uint32_t numWorkers;
    uint32_t numChannels;
    profile_channel_info_t *channels;
    dataBlock_t **dataBlock;

    // sync barrier
    pthread_control_barrier_t *barrier;
} worker_param_t;

/* Function Prototypes */
static void usage(char *name);

static profile_param_info_t *ParseParams(char *profile_datadir);

static void process_data(profile_channel_info_t *channels, unsigned int numChannels, time_t tslot, worker_param_t **workerList, int numWorkers,
                         pthread_control_barrier_t *barrier, int hasGeoDB);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here\n"
        "-V\t\tPrint version and exit.\n"
        "-M <expr>\tRead input from multiple directories.\n"
        "-r\t\tread input from file\n"
        "-f\t\tfilename with filter syntaxfile\n"
        "-p\t\tprofile data dir.\n"
        "-P\t\tprofile stat dir.\n"
        "-s\t\tprofile subdir.\n"
        "-Z\t\tCheck filter syntax and exit.\n"
        "-S subdir\tSub directory format. see nfcapd(1) for format\n"
        "-z=lzo\t\tLZO compress flows in output file.\n"
        "-z=bz2\t\tBZIP2 compress flows in output file.\n"
        "-z=lz4[:level]\tLZ4 compress flows in output file.\n"
        "-z=zstd[:level]\tZSTD compress flows in output file.\n"
#ifdef HAVE_INFLUXDB
        "-i <influxurl>\tInfluxdb url for stats (example: http://localhost:8086/write?db=mydb&u=pippo&p=paperino)\n"
#endif
        "-t <time>\ttime for RRD update\n",
        name);
} /* usage */

__attribute__((noreturn)) static void *worker(void *arg) {
    worker_param_t *worker_param = (worker_param_t *)arg;

    uint32_t self = worker_param->self;
    uint32_t numWorkers = worker_param->numWorkers;
    uint32_t numChannels = worker_param->numChannels;
    profile_channel_info_t *channels = worker_param->channels;

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        pthread_exit(NULL);
    }

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
                exit(255);
            }
            sumSize += record_ptr->size;
            recordCount++;

            switch (record_ptr->type) {
                case V3Record:
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, recordCount);

                    for (int j = self; j < numChannels; j += numWorkers) {
                        int match;

                        // apply profile filter
                        void *engine = channels[j].engine;
                        match = FilterRecord(engine, recordHandle);

                        // if profile filter failed -> next profile
                        if (!match) continue;

                        // filter was successful -> continue record processing

                        // update statistics
                        UpdateStatRecord(&channels[j].stat_record, recordHandle);

                        // do we need to write data to new file - shadow profiles do not have files.
                        // check if we need to flush the output buffer
                        if (channels[j].nffile != NULL) {
                            // write record to output buffer
                            channels[j].dataBlock = AppendToBuffer(channels[j].nffile, channels[j].dataBlock, (void *)record_ptr, record_ptr->size);
                        }

                    }  // End of for all channels

                    break;
                case ExporterInfoRecordType: {
                    for (int j = self; j < numChannels; j += numWorkers) {
                        if (channels[j].nffile != NULL) {
                            // flush new exporter
                            channels[j].dataBlock = AppendToBuffer(channels[j].nffile, channels[j].dataBlock, (void *)record_ptr, record_ptr->size);
                        }
                    }
                } break;
                case SamplerLegacyRecordType:
                case SamplerRecordType: {
                    for (int j = self; j < numChannels; j += numWorkers) {
                        if (channels[j].nffile != NULL) {
                            // flush new map
                            channels[j].dataBlock = AppendToBuffer(channels[j].nffile, channels[j].dataBlock, (void *)record_ptr, record_ptr->size);
                        }
                    }
                } break;
                case NbarRecordType:
                case IfNameRecordType:
                case VrfNameRecordType:
                    for (int j = self; j < numChannels; j += numWorkers) {
                        if (channels[j].nffile != NULL) {
                            // flush new map
                            channels[j].dataBlock = AppendToBuffer(channels[j].nffile, channels[j].dataBlock, (void *)record_ptr, record_ptr->size);
                        }
                    }
                    break;
                case LegacyRecordType1:
                case LegacyRecordType2:
                case ExporterStatRecordType:
                    // Silently skip exporter records
                    break;
                default: {
                    LogError("Skip unknown record type %i", record_ptr->type);
                }
            }
            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((pointer_addr_t)record_ptr + record_ptr->size);

        }  // End of for all umRecords

        // Done
        // wait in barrier for next data record
        pthread_control_barrier_wait(worker_param->barrier);
    }

    dbg_printf("Worker %d done.\n", worker_param->self);
    pthread_exit(NULL);

    // unreached
}  // End of worker

static worker_param_t **LauchWorkers(pthread_t *tid, int numWorkers, pthread_control_barrier_t *barrier, profile_channel_info_t *channels,
                                     uint32_t numChannels) {
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
        worker_param->dataBlock = NULL;
        worker_param->numWorkers = numWorkers;
        worker_param->channels = channels;
        worker_param->numChannels = numChannels;
        workerList[i] = worker_param;

        int err = pthread_create(&(tid[i]), NULL, worker, (void *)worker_param);
        if (err) {
            LogError("pthread_create() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
    }
    return workerList;

}  // End of LaunchWorkers

static void process_data(profile_channel_info_t *channels, unsigned int numChannels, time_t tslot, worker_param_t **workerList, int numWorkers,
                         pthread_control_barrier_t *barrier, int hasGeoDB) {
    dataBlock_t *nextBlock = NULL;
    dataBlock_t *dataBlock = NULL;
    // map datablock for workers - all workers
    // process the same block but different channels
    for (int i = 0; i < numWorkers; i++) {
        // set new datablock for all workers
        workerList[i]->dataBlock = &dataBlock;
    }

    // wait for workers ready to start
    pthread_controller_wait(barrier);

    nffile_t *nffile = NULL;
    int done = 0;
    while (!done) {
        // get next data block from file
        dataBlock = nextBlock;
        if (dataBlock == NULL) {
            nffile = GetNextFile();
            if (nffile == NULL) {
                done = 1;
                continue;
            }
            for (int j = 0; j < numChannels; j++) {
                // set ident to file engines
                void *engine = channels[j].engine;
                FilterSetParam(engine, nffile->ident, hasGeoDB);
            }
            // read first block and continue
            nextBlock = ReadBlock(nffile, NULL);
            continue;
        }

        if (dataBlock->type != DATA_BLOCK_TYPE_2 && dataBlock->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u. Skip block", dataBlock->type);
            nextBlock = ReadBlock(nffile, NULL);
            continue;
        }

        dbg_printf("Next block: Records: %u\n", dataBlock->NumRecords);
        // release workers from barrier
        pthread_control_barrier_release(barrier);

        // get next block while worker are processing the previous one
        nextBlock = ReadBlock(nffile, NULL);
        if (nextBlock == NULL) {
            DisposeFile(nffile);
        }
        // wait for all workers, work done on this block
        pthread_controller_wait(barrier);
        // free processed block
        FreeDataBlock(dataBlock);

    }  // End of while !done

    // done! - signal all workers to terminate
    dataBlock = NULL;
    pthread_control_barrier_release(barrier);

    DisposeFile(nffile);

    // do we need to write data to new file - shadow profiles do not have files.
    // write all used blocks first, then close the files
    for (int j = 0; j < numChannels; j++) {
        if (channels[j].nffile != NULL) {
            // flush output buffer
            FlushBlock(channels[j].nffile, channels[j].dataBlock);
            *channels[j].nffile->stat_record = channels[j].stat_record;
            FinaliseFile(channels[j].nffile);
            DisposeFile(channels[j].nffile);
        }
    }

}  // End of process_data

static profile_param_info_t *ParseParams(char *profile_datadir) {
    char line[512], path[MAXPATHLEN];
    profile_param_info_t *profile_list;
    profile_param_info_t **list = &profile_list;

    profile_list = NULL;
    while ((fgets(line, 512, stdin) != NULL)) {
        line[511] = '\0';

        if (*list == NULL) *list = (profile_param_info_t *)malloc(sizeof(profile_param_info_t));
        // else we come from a continue statement with illegal data - overwrite

        if (!*list) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }

        (*list)->next = NULL;
        (*list)->profilegroup = NULL;
        (*list)->profilename = NULL;
        (*list)->channelname = NULL;
        (*list)->channel_sourcelist = NULL;
        (*list)->profiletype = 0;

        // delete '\n' at the end of line
        // format of stdin config line:
        // <profilegroup>#<profilename>#<profiletype>#<channelname>#<channel_sourcelist>
        char *p = strchr(line, '\n');
        if (p) *p = '\0';
        LogInfo("Process line '%s'\n", line);

        char *q = line;
        p = strchr(q, '#');
        if (p) *p = '\0';

        char *s = line;

        // safety check: if no separator found loop to next line
        if (!p) {
            LogError("Incomplete line - channel skipped");
            continue;
        }

        q = p;
        q++;

        p = strchr(q, '#');
        if (p) *p = '\0';

        snprintf(path, MAXPATHLEN - 1, "%s/%s/%s", profile_datadir, s, q);
        path[MAXPATHLEN - 1] = '\0';

        struct stat stat_buf;
        if (stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode)) {
            LogError("profile '%s' not found in group %s. Skipped", q, s);
            continue;
        }

        (*list)->profilegroup = strdup(s);
        (*list)->profilename = strdup(q);

        // safety check: if no separator found loop to next line
        if (!p) {
            LogError("Incomplete line - channel skipped");
            continue;
        }

        q = p;
        q++;

        p = strchr(q, '#');
        if (p) *p = '\0';

        s = q;
        while (*s) {
            if (*s < '0' || *s > '9') {
                LogError("Not a valid number: %s", q);
                s = NULL;
                break;
            }
            s++;
        }
        if (s == NULL) continue;

        (*list)->profiletype = (int)strtol(q, (char **)NULL, 10);

        // safety check: if no separator found loop to next line
        if (!p) {
            LogError("Incomplete line - channel skipped");
            continue;
        }

        q = p;
        q++;

        p = strchr(q, '#');
        if (p) *p = '\0';

        snprintf(path, MAXPATHLEN - 1, "%s/%s/%s/%s", profile_datadir, (*list)->profilegroup, (*list)->profilename, q);
        path[MAXPATHLEN - 1] = '\0';
        if (stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode)) {
            LogError("channel '%s' in profile '%s' not found. Skipped", q, (*list)->profilename);
            continue;
        }

        (*list)->channelname = strdup(q);

        if (!p) {
            LogError("Incomplete line - Skipped");
            continue;
        }

        q = p;
        q++;

        p = strchr(q, '#');
        if (p) *p = '\0';

        // Skip leading '| chars
        while (*q && *q == '|') {
            q++;
        }
        s = q;

        // if q is already empty ( '\0' ) loop is not processed
        while (*s) {
            // as s[0] is not '\0' s[1] may be '\0' but still valid and in range
            if (s[0] == '|' && s[1] == '|') {
                char *t = s;
                t++;
                while (*t) {  // delete this empty channel name
                    t[0] = t[1];
                    t++;
                }
            } else
                s++;
        }
        // we have no doublicate '|' here any more
        // check if last char is an extra '|'
        if (*q && (q[strlen(q) - 1] == '|')) q[strlen(q) - 1] = '\0';

        if (*q && (strcmp(q, "*") != 0)) (*list)->channel_sourcelist = strdup(q);

        list = &((*list)->next);
    }

    if (*list != NULL) {
        free(*list);
        *list = NULL;
    }

    if (ferror(stdin)) {
        LogError("fgets() error: %s", strerror(errno));
        return NULL;
    }

    return profile_list;

}  // End of ParseParams

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
    unsigned int numChannels, compress;
    profile_param_info_t *profile_list;
    char *ffile, *filename, *syslog_facility;
    char *profile_datadir, *profile_statdir;
    int c, syntax_only, subdir_index, stdin_profile_params;
    time_t tslot;
    flist_t flist;

    int numWorkers = MAXPROFILERS;
    memset((void *)&flist, 0, sizeof(flist));
    profile_datadir = NULL;
    profile_statdir = NULL;
    tslot = 0;
    syntax_only = 0;
    compress = NOT_COMPRESSED;
    subdir_index = 0;
    profile_list = NULL;
    stdin_profile_params = 0;
    syslog_facility = "daemon";

    // default file names
    ffile = "filter.txt";
    while ((c = getopt(argc, argv, "Ip:P:hi:f:jr:L:M:S:t:Vyz::Z")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'I':
                stdin_profile_params = 1;
                break;
            case 'L':
                CheckArgLen(optarg, 32);
                syslog_facility = strdup(optarg);
                break;
            case 'Z':
                syntax_only = 1;
                break;
            case 'p':
                CheckArgLen(optarg, MAXPATHLEN);
                profile_datadir = optarg;
                break;
            case 'P':
                CheckArgLen(optarg, MAXPATHLEN);
                profile_statdir = optarg;
                break;
            case 'S':
                CheckArgLen(optarg, 2);
                subdir_index = atoi(optarg);
                break;
            case 'V':
                printf("%s: %s\n", argv[0], versionString());
                exit(0);
                break;
            case 'f':
                CheckArgLen(optarg, MAXPATHLEN);
                ffile = optarg;
                break;
            case 't':
                CheckArgLen(optarg, 32);
                tslot = atoi(optarg);
                break;
            case 'M':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.multiple_dirs = strdup(optarg);
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.single_file = strdup(optarg);
                break;
            case 'j':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(255);
                }
                compress = BZ2_COMPRESSED;
                break;
            case 'y':
                if (compress) {
                    LogError("Use one compression: -z for LZO, -j for BZ2 or -y for LZ4 compression");
                    exit(255);
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
#ifdef HAVE_INFLUXDB
            case 'i':
                if (optarg != NULL)
                    strncpy(influxdb_url, optarg, 1024);
                else {
                    LogError("Missing argument for -i <influx URL>");
                    exit(255);
                }
                influxdb_url[1023] = '\0';
                break;
#endif
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (!InitLog(1, argv[0], syslog_facility, 1)) {
        exit(EXIT_FAILURE);
    }

    if (!CheckSubDir(subdir_index)) {
        exit(EXIT_FAILURE);
    }

    if (!profile_datadir) {
        LogError("Profile data directory required!");
        exit(EXIT_FAILURE);
    }

    if (!profile_statdir) {
        profile_statdir = profile_datadir;
    }

    struct stat stat_buf;
    if (stat(profile_datadir, &stat_buf) || !S_ISDIR(stat_buf.st_mode)) {
        LogError("'%s' not a directory", profile_datadir);
        exit(EXIT_FAILURE);
    }

    if (stdin_profile_params) {
        profile_list = ParseParams(profile_datadir);
        if (!profile_list) {
            exit(EXIT_FAILURE);
        }
    }

    // read default config
    if (ConfOpen(NULL, "nfdump") < 0) exit(EXIT_FAILURE);

    if (syntax_only) {
        filename = NULL;
        flist.single_file = NULL;
    } else {
        char *p;
        if (flist.single_file == NULL) {
            LogError("-r filename required!");
            exit(EXIT_FAILURE);
        }
        p = strrchr(flist.single_file, '/');
        filename = p == NULL ? flist.single_file : ++p;
        if (strlen(filename) == 0) {
            LogError("Filename error: zero length filename");
            exit(EXIT_FAILURE);
        }
    }

    int __attribute__((unused)) hasGeoDB = false;
    char *geoDBfile = ConfGetString("geodb.path");
    if (geoDBfile && strcmp(geoDBfile, "none") == 0) {
        geoDBfile = NULL;
    }
    if (geoDBfile) {
        if (!CheckPath(geoDBfile, S_IFREG) || !LoadMaxMind(geoDBfile)) {
            LogError("Error reading geo location DB file %s", geoDBfile);
            exit(EXIT_FAILURE);
        }
        hasGeoDB = true;
    }

    __attribute__((unused)) int hasTorDB = false;
    char *torDBfile = ConfGetString("tordb.path");
    if (torDBfile && strcmp(torDBfile, "none") == 0) {
        torDBfile = NULL;
    }
    if (torDBfile) {
        if (!CheckPath(torDBfile, S_IFREG) || !LoadTorTree(torDBfile)) {
            LogError("Error reading tor info DB file %s", torDBfile);
            exit(EXIT_FAILURE);
        }
        hasTorDB = true;
    }

    if (chdir(profile_datadir)) {
        LogError("Error can't chdir to '%s': %s", profile_datadir, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (!flist.single_file) {
        LogError("Input file (-r) required!");
        exit(EXIT_FAILURE);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(PROFILEWRITERS, fileList)) exit(254);

    numChannels = InitChannels(profile_datadir, profile_statdir, profile_list, ffile, filename, subdir_index, syntax_only, compress);

    // nothing to do
    if (numChannels == 0) {
        LogInfo("No channels to process");
        return 0;
    }

    if (syntax_only) {
        printf("Syntax check done.\n");
        return 0;
    }

    // check numWorkers depending on cores online
    numWorkers = GetNumWorkers(numWorkers);

    pthread_control_barrier_t *barrier = pthread_control_barrier_init(numWorkers);
    if (!barrier) exit(EXIT_FAILURE);

    profile_channel_info_t *channels = GetChannelInfoList();

    pthread_t tid[MAXWORKERS] = {0};
    dbg_printf("Launch Workers\n");
    worker_param_t **workerList = LauchWorkers(tid, numWorkers, barrier, channels, numChannels);
    if (!workerList) {
        LogError("Failed to launch workers");
        exit(EXIT_FAILURE);
    }

    process_data(channels, numChannels, tslot, workerList, numWorkers, barrier, hasGeoDB);

    WaitWorkersDone(tid, numWorkers);
    pthread_control_barrier_destroy(barrier);

    UpdateChannels(tslot);
#if 0
    VerifyFiles();
#endif
    return 0;
}
