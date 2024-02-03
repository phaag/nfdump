/*
 *  Copyright (c) 2009-2024, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *	   this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *	   this list of conditions and the following disclaimer in the documentation
 *	   and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *	   used to endorse or promote products derived from this software without
 *	   specific prior written permission.
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
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "exporter.h"
#include "filter.h"
#include "flist.h"
#include "nbar.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftrack_rrd.h"
#include "nfxV3.h"
#include "util.h"
#include "version.h"

// We have 288 slot ( 1 day ) for stat record
#define AVG_STAT 1

/* Global Variables */
int byte_mode, packet_mode;
uint32_t byte_limit, packet_limit;  // needed for linking purpose only

/* Function Prototypes */
static void usage(char *name);

static int CheckRunningOnce(char *pidfile);

static data_row *process(void *engine);

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] [\"filter\"]\n"
        "-h\t\tthis text you see right here\n"
        "-l\t\tLast update of Ports DB\n"
        "-V\t\tPrint version and exit.\n"
        "-I\t\tInitialize Ports DB files.\n"
        "-d <db_dir>\tPorts DB directory.\n"
        "-r <input>\tread from file. default: stdin\n"
        "-p\t\tOnline output mode.\n"
        "-s\t\tCreate port statistics for timeslot -t\n"
        "-t <time>\tTimeslot for statistics\n"
        "-S\t\tCreate port statistics for last day\n"
        "-w <file>\twrite output to file\n"
        "-f <filter>\tfilter syntaxfile\n",
        name);
} /* usage */

static int CheckRunningOnce(char *pidfile) {
    int pidf;
    pid_t pid;
    char pidstr[32];

    pidf = open(pidfile, O_RDONLY, 0);
    if (pidf > 0) {
        // pid file exists
        char s[32];
        ssize_t len;
        len = read(pidf, (void *)s, 31);
        close(pidf);
        s[31] = '\0';
        if (len < 0) {
            LogError("read() error existing pid file: %s\n", strerror(errno));
            return 0;
        } else {
            unsigned long pid = atol(s);
            if (pid == 0) {
                // garbage - use this file
                unlink(pidfile);
            } else {
                if (kill(pid, 0) == 0) {
                    // process exists
                    LogError("An nftrack process with pid %lu is already running!\n", pid);
                    return 0;
                } else {
                    // no such process - use this file
                    LogError("The nftrack process with pid %lu died unexpectedly!\n", pid);
                    unlink(pidfile);
                }
            }
        }
    }

    pid = getpid();
    pidf = open(pidfile, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (pidf == -1) {
        LogError("Error opening nftrack pid file: '%s' %s", pidfile, strerror(errno));
        return 0;
    }
    snprintf(pidstr, 31, "%lu\n", (unsigned long)pid);
    if (write(pidf, pidstr, strlen(pidstr)) <= 0) {
        LogError("Error write nftrack pid file: '%s' %s", pidfile, strerror(errno));
    }
    close(pidf);

    return 1;

}  // End of CheckRunningOnce

static data_row *process(void *engine) {
    nffile_t *nffile;
    int i, done, ret;
    data_row *port_table;

    nffile = GetNextFile(NULL);
    if (!nffile) {
        LogError("GetNextFile() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }
    if (nffile == EMPTY_LIST) {
        LogError("Empty file list. No files to process\n");
        return NULL;
    }

    port_table = (data_row *)calloc(65536, sizeof(data_row));
    if (!port_table) {
        LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    uint32_t processed = 0;
    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    done = 0;
    while (!done) {
        // get next data block from file
        ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'\n", nffile->fileName);
                else
                    LogError("Read error in file '%s': %s\n", nffile->fileName, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF: {
                nffile_t *next = GetNextFile(nffile);
                if (next == EMPTY_LIST) {
                    done = 1;
                }
                if (next == NULL) {
                    done = 1;
                    LogError("Unexpected end of file list\n");
                }
                // else continue with next file
                continue;

            } break;  // not really needed
        }

        if (nffile->block_header->type != DATA_BLOCK_TYPE_2 && nffile->block_header->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u\n", nffile->block_header->type);
            continue;
        }

        record_header_t *record_ptr = nffile->buff_ptr;
        uint32_t sumSize = 0;
        for (i = 0; i < nffile->block_header->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d\n", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record: {
                    processed++;
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, processed);
                    int ret = FilterRecord(engine, recordHandle, nffile->ident);

                    if (ret == 0) {  // record failed to pass the filter
                        // increment pointer by number of bytes for netflow record
                        record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);
                        // go to next record
                        continue;
                    }

                    // Add to stat record
                    EXgenericFlow_t *genericFlow = (EXgenericFlow_t *)recordHandle->extensionList[EXgenericFlowID];
                    if (genericFlow) {
                        if (genericFlow->proto == IPPROTO_TCP) {
                            port_table[genericFlow->dstPort].proto[tcp].type[flows]++;
                            port_table[genericFlow->dstPort].proto[tcp].type[packets] += genericFlow->inPackets;
                            port_table[genericFlow->dstPort].proto[tcp].type[bytes] += genericFlow->inBytes;
                        } else if (genericFlow->proto == IPPROTO_UDP) {
                            port_table[genericFlow->dstPort].proto[udp].type[flows]++;
                            port_table[genericFlow->dstPort].proto[udp].type[packets] += genericFlow->inPackets;
                            port_table[genericFlow->dstPort].proto[udp].type[bytes] += genericFlow->inBytes;
                        }
                    }
                } break;
                case ExporterInfoRecordType:
                case ExporterStatRecordType:
                case SamplerRecordType:
                case NbarRecordType:
                    // Silently skip exporter records
                    break;
                default: {
                    LogError("Skip unknown record type %i\n", record_ptr->type);
                }
            }

            // Advance pointer by number of bytes for netflow record
            record_ptr = (record_header_t *)((void *)record_ptr + record_ptr->size);
        }
    }  // while

    CloseFile(nffile);
    DisposeFile(nffile);

    return port_table;

}  // End of process

int main(int argc, char **argv) {
    struct stat stat_buff;
    char *wfile, *ffile, *filter, *timeslot, *DBdir;
    char datestr[64];
    char pidfile[MAXPATHLEN];
    int c, ffd, ret, DBinit, AddDB, GenStat, AvStat, output_mode, topN;
    unsigned int lastupdate;
    data_row *port_table;
    time_t when;
    struct tm *t1;
    flist_t flist;

    memset((void *)&flist, 0, sizeof(flist));

    wfile = ffile = filter = DBdir = timeslot = NULL;
    DBinit = AddDB = GenStat = AvStat = 0;
    lastupdate = output_mode = 0;
    topN = 10;
    while ((c = getopt(argc, argv, "d:hln:pr:st:w:AIM:L:R:SV")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'I':
                DBinit = 1;
                break;
            case 'M':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.multiple_dirs = strdup(optarg);
                break;
            case 'R':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.multiple_files = strdup(optarg);
                break;
            case 'd':
                DBdir = strdup(optarg);
                ret = stat(DBdir, &stat_buff);
                if (!(stat_buff.st_mode & S_IFDIR)) {
                    fprintf(stderr, "No such directory: %s\n", DBdir);
                    exit(255);
                }
                break;
            case 'l':
                lastupdate = 1;
                break;
            case 'n':
                topN = atoi(optarg);
                if (topN < 0) {
                    fprintf(stderr, "TopnN number %i out of range\n", topN);
                    exit(255);
                }
                break;
            case 'p':
                output_mode = 1;
                break;
            case 'r':
                CheckArgLen(optarg, MAXPATHLEN);
                flist.single_file = strdup(optarg);
                break;
            case 'w':
                wfile = strdup(optarg);
                break;
            case 's':
                GenStat = 1;
                break;
            case 't':
                timeslot = optarg;
                if (!ISO2UNIX(timeslot)) {
                    exit(255);
                }
                break;
            case 'A':
                AddDB = 1;
                break;
            case 'L':
                if (!InitLog(0, "nftrack", optarg, 0)) exit(255);
                break;
            case 'S':
                AvStat = 1;
                break;
            case 'V':
                printf("%s: %s\n", argv[0], versionString());
                exit(0);
                break;
            default:
                usage(argv[0]);
                exit(0);
        }
    }

    if (argc - optind > 1) {
        usage(argv[0]);
        exit(255);
    } else {
        /* user specified a pcap filterr */
        filter = argv[optind];
    }

    if (!filter && ffile) {
        if (stat(ffile, &stat_buff)) {
            LogError("stat() filter file: '%s' %s", ffile, strerror(errno));
            exit(255);
        }
        filter = (char *)malloc(stat_buff.st_size);
        if (!filter) {
            LogError("malloc() allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
            exit(255);
        }
        ffd = open(ffile, O_RDONLY);
        if (ffd < 0) {
            LogError("open() filter file: '%s' %s", ffile, strerror(errno));
            exit(255);
        }
        ret = read(ffd, (void *)filter, stat_buff.st_size);
        if (ret < 0) {
            LogError("read() filter file: '%s' %s", ffile, strerror(errno));
            close(ffd);
            exit(255);
        }
        close(ffd);
    }

    if (!DBdir) {
        LogError("DB directory required\n");
        exit(255);
    }

    InitStat(DBdir);

    // check if pid file exists and if so, if a process with registered pid is running
    snprintf(pidfile, MAXPATHLEN - 1, "%s/nftrack.pid", DBdir);
    pidfile[MAXPATHLEN - 1] = '\0';
    if (!CheckRunningOnce(pidfile)) {
        LogError("Run once check failed.\n");
        exit(255);
    }

    if (!filter) filter = "any";

    void *engine = CompileFilter(filter);
    if (!engine) {
        unlink(pidfile);
        exit(254);
    }

    if (DBinit) {
        when = time(NULL);
        when -= ((when % 300) + 300);
        InitStatFile();
        if (!CreateRRDBs(DBdir, when)) {
            LogError("Init DBs failed\n");
            unlink(pidfile);
            exit(255);
        }
        LogInfo("Port DBs initialized.\n");
        unlink(pidfile);
        exit(0);
    }

    if (lastupdate) {
        when = RRD_LastUpdate(DBdir);
        if (!when) {
            unlink(pidfile);
            exit(255);
        }
        t1 = localtime(&when);
        strftime(datestr, 63, "%b %d %Y %T", t1);
        LogInfo("Last Update: %i, %s\n", (int)when, datestr);
        unlink(pidfile);
        exit(0);
    }

    port_table = NULL;
    if (flist.multiple_dirs || flist.multiple_files || flist.single_file) {
        queue_t *fileList = SetupInputFileSequence(&flist);
        if (!Init_nffile(DEFAULTWORKERS, fileList)) exit(254);
        port_table = process(engine);
        //		Lister(port_table);
        if (!port_table) {
            unlink(pidfile);
            exit(255);
        }
        if (AddDB) {
            if (!timeslot) {
                LogError("Timeslot required!\n");
                unlink(pidfile);
                exit(255);
            }
            UpdateStat(port_table, ISO2UNIX(timeslot));
            RRD_StoreDataRow(DBdir, timeslot, port_table);
        }
    }

    if (AvStat) {
        port_table = GetStat();
        if (!port_table) {
            LogError("Unable to get port table!\n");
            unlink(pidfile);
            exit(255);
        }
        // DoStat
        Generate_TopN(port_table, topN, AVG_STAT, 0, output_mode, wfile);
    }

    if (GenStat) {
        when = ISO2UNIX(timeslot);
        if (!port_table) {
            if (!timeslot) {
                LogError("Timeslot required!\n");
                unlink(pidfile);
                exit(255);
            }
            port_table = RRD_GetDataRow(DBdir, when);
        }
        if (!port_table) {
            LogError("Unable to get port table!\n");
            unlink(pidfile);
            exit(255);
        }
        // DoStat
        Generate_TopN(port_table, topN, 0, when, output_mode, wfile);
    }

    CloseStat();
    unlink(pidfile);

    return 0;
}
