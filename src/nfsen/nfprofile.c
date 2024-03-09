/*
 *  Copyright (c) 2009-2024, Peter Haag
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

#include "exporter.h"
#include "flist.h"
#include "nbar.h"
#include "nfconf.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstatfile.h"
#include "nfxV3.h"
#include "profile.h"
#include "util.h"
#include "version.h"

/* Local Variables */
#ifdef HAVE_INFLUXDB
char influxdb_url[1024] = "";
#endif

/* Function Prototypes */
static void usage(char *name);

static profile_param_info_t *ParseParams(char *profile_datadir);

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot);

/* Functions */

#include "nfdump_inline.c"
#include "nffile_inline.c"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tthis text you see right here\n"
        "-V\t\tPrint version and exit.\n"
        "-D <dns>\tUse nameserver <dns> for host lookup.\n"
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

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot) {
    nffile_t *nffile = GetNextFile(NULL);
    if (!nffile) {
        LogError("GetNextFile() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return;
    }
    if (nffile == EMPTY_LIST) {
        LogError("Empty file list. No files to process");
        return;
    }

    recordHandle_t *recordHandle = calloc(1, sizeof(recordHandle_t));
    if (!recordHandle) {
        LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno));
        return;
    }
    uint32_t processed = 0;
    int done = 0;
    while (!done) {
        // get next data block from file
        int ret = ReadBlock(nffile);

        switch (ret) {
            case NF_CORRUPT:
            case NF_ERROR:
                if (ret == NF_CORRUPT)
                    LogError("Skip corrupt data file '%s'", nffile->fileName);
                else
                    LogError("Read error in file '%s': %s", nffile->fileName, strerror(errno));
                // fall through - get next file in chain
            case NF_EOF: {
                nffile_t *next = GetNextFile(nffile);
                if (next == EMPTY_LIST) {
                    done = 1;
                    continue;
                }
                if (next == NULL) {
                    done = 1;
                    continue;
                    LogError("Unexpected end of file list");
                }

                continue;

            } break;  // not really needed
        }

        if (nffile->block_header->type != DATA_BLOCK_TYPE_2 && nffile->block_header->type != DATA_BLOCK_TYPE_3) {
            LogError("Can't process block type %u. Skip block", nffile->block_header->type);
            continue;
        }

        record_header_t *record_ptr = nffile->buff_ptr;
        uint32_t sumSize = 0;
        for (int i = 0; i < nffile->block_header->NumRecords; i++) {
            if ((sumSize + record_ptr->size) > ret || (record_ptr->size < sizeof(record_header_t))) {
                LogError("Corrupt data file. Inconsistent block size in %s line %d", __FILE__, __LINE__);
                exit(255);
            }
            sumSize += record_ptr->size;

            switch (record_ptr->type) {
                case V3Record:
                    processed++;
                    MapRecordHandle(recordHandle, (recordHeaderV3_t *)record_ptr, processed);

                    for (int j = 0; j < num_channels; j++) {
                        int match;

                        // apply profile filter
                        void *engine = channels[j].engine;
                        match = FilterRecord(engine, recordHandle, FILE_IDENT(nffile), NOGEODB);

                        // if profile filter failed -> next profile
                        if (!match) continue;

                        // filter was successful -> continue record processing

                        // update statistics
                        UpdateStatRecord(&channels[j].stat_record, recordHandle);

                        // do we need to write data to new file - shadow profiles do not have files.
                        // check if we need to flush the output buffer
                        if (channels[j].nffile != NULL) {
                            // write record to output buffer
                            AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
                        }

                    }  // End of for all channels

                    break;
                case ExporterInfoRecordType: {
                    int err = AddExporterInfo((exporter_info_record_t *)record_ptr);
                    if (err != 0) {
                        for (int j = 0; j < num_channels; j++) {
                            if (channels[j].nffile != NULL && err == 1) {
                                // flush new exporter
                                AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
                            }
                        }
                    } else {
                        LogError("Failed to add Exporter Record");
                    }
                } break;
                case SamplerLegacyRecordType: {
                    if (AddSamplerLegacyRecord((samplerV0_record_t *)record_ptr) == 0) LogError("Failed to add legacy Sampler Record\n");
                } break;
                case SamplerRecordType: {
                    int err = AddSamplerRecord((sampler_record_t *)record_ptr);
                    if (err != 0) {
                        for (int j = 0; j < num_channels; j++) {
                            if (channels[j].nffile != NULL && err == 1) {
                                // flush new map
                                AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
                            }
                        }
                    } else {
                        LogError("Failed to add Sampler Record");
                    }
                } break;
                case NbarRecordType:
                case IfNameRecordType:
                case VrfNameRecordType:
                    for (int j = 0; j < num_channels; j++) {
                        if (channels[j].nffile != NULL) {
                            // flush new map
                            AppendToBuffer(channels[j].nffile, (void *)record_ptr, record_ptr->size);
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
    }      // End of while !done

    // Close input
    CloseFile(nffile);
    DisposeFile(nffile);

    // do we need to write data to new file - shadow profiles do not have files.
    // write all used blocks first, then close the files
    for (int j = 0; j < num_channels; j++) {
        if (channels[j].nffile != NULL) {
            // flush output buffer
            if (channels[j].nffile->block_header->NumRecords) {
                if (WriteBlock(channels[j].nffile) <= 0) {
                    LogError("Failed to flush output buffer to disk: '%s'", strerror(errno));
                }
            }
            *channels[j].nffile->stat_record = channels[j].stat_record;
        }
    }
    for (int j = 0; j < num_channels; j++) {
        if (channels[j].nffile != NULL) {
            CloseUpdateFile(channels[j].nffile);
            DisposeFile(channels[j].nffile);
            channels[j].nffile = NULL;
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

int main(int argc, char **argv) {
    unsigned int num_channels, compress;
    profile_param_info_t *profile_list;
    char *ffile, *filename, *syslog_facility;
    char *profile_datadir, *profile_statdir, *nameserver;
    int c, syntax_only, subdir_index, stdin_profile_params;
    time_t tslot;
    flist_t flist;

    memset((void *)&flist, 0, sizeof(flist));
    profile_datadir = NULL;
    profile_statdir = NULL;
    tslot = 0;
    syntax_only = 0;
    compress = NOT_COMPRESSED;
    subdir_index = 0;
    profile_list = NULL;
    nameserver = NULL;
    stdin_profile_params = 0;
    syslog_facility = "daemon";

    // default file names
    ffile = "filter.txt";
    while ((c = getopt(argc, argv, "D:Ip:P:hi:f:jr:L:M:S:t:Vyz::Z")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'D':
                CheckArgLen(optarg, 64);
                nameserver = optarg;
                if (!SetNameserver(nameserver)) {
                    exit(255);
                }
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

    if (subdir_index && !InitHierPath(subdir_index)) {
        exit(255);
    }

    if (!profile_datadir) {
        LogError("Profile data directory required!");
        exit(255);
    }

    if (!profile_statdir) {
        profile_statdir = profile_datadir;
    }

    struct stat stat_buf;
    if (stat(profile_datadir, &stat_buf) || !S_ISDIR(stat_buf.st_mode)) {
        LogError("'%s' not a directory", profile_datadir);
        exit(255);
    }

    if (stdin_profile_params) {
        profile_list = ParseParams(profile_datadir);
        if (!profile_list) {
            exit(254);
        }
    }

    if (syntax_only) {
        filename = NULL;
        flist.single_file = NULL;
    } else {
        char *p;
        if (flist.single_file == NULL) {
            LogError("-r filename required!");
            exit(255);
        }
        p = strrchr(flist.single_file, '/');
        filename = p == NULL ? flist.single_file : ++p;
        if (strlen(filename) == 0) {
            LogError("Filename error: zero length filename");
            exit(254);
        }
    }

    if (chdir(profile_datadir)) {
        LogError("Error can't chdir to '%s': %s", profile_datadir, strerror(errno));
        exit(255);
    }

    num_channels = InitChannels(profile_datadir, profile_statdir, profile_list, ffile, filename, subdir_index, syntax_only, compress);

    // nothing to do
    if (num_channels == 0) {
        LogInfo("No channels to process");
        return 0;
    }

    if (syntax_only) {
        printf("Syntax check done.\n");
        return 0;
    }

    if (!flist.single_file) {
        LogError("Input file (-r) required!");
        exit(255);
    }

    if (!InitExporterList()) {
        exit(255);
    }

    queue_t *fileList = SetupInputFileSequence(&flist);
    if (!fileList || !Init_nffile(DEFAULTWORKERS, fileList)) exit(254);

    process_data(GetChannelInfoList(), num_channels, tslot);

    UpdateChannels(tslot);
#if 0
    VerifyFiles();
#endif
    return 0;
}
