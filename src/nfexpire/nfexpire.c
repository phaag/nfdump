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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_FTS_H
#include <fts.h>
#else
#include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open fts_open_compat
#define fts_read fts_read_compat
#define fts_set fts_set_compat
#endif

#include "bookkeeper.h"
#include "expire.h"
#include "logging.h"
#include "nfstatfile.h"
#include "util.h"

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tThis text\n"
        "-l datadir\tList stat from directory\n"
        "-e datadir\tExpire data in directory\n"
        "-n\t\tdryrun mode. Do not delete but report\n"
        "-r datadir\tRescan data directory\n"
        "-u datadir\tUpdate expire params from collector logging at <datadir>\n"
        "-s size\t\tmax size: scales b bytes, k kilo, m mega, g giga t tera\n"
        "-T runtime\tmaximum nfexpire run time: nfexpire terminates after this amount of seconds\n"
        "-t lifetime\tmaximum life time of data: scales: w week, d day, H hour, M minute\n"
        "-w watermark\tlow water mark in %% for expire.\n",
        name);

}  // End of usage

static channel_t *GetChannelList(char *datadir, int is_profile) {
    channel_t **c, *channel;
    stringlist_t dirlist = {0};
    struct stat stat_buf;

    // Generate list of directories
    if (is_profile) {
        DIR *PDIR = opendir(datadir);
        struct dirent *entry;
        if (!PDIR) {
            LogError("Can't read profiledir '%s': %s", datadir, strerror(errno));
            return NULL;
        }
        while ((entry = readdir(PDIR)) != NULL) {
            char stringbuf[MAXPATHLEN];
            snprintf(stringbuf, MAXPATHLEN - 1, "%s/%s", datadir, entry->d_name);
            stringbuf[MAXPATHLEN - 1] = '\0';

            if (stat(stringbuf, &stat_buf)) {
                LogError("Can't stat '%s': %s", stringbuf, strerror(errno));
                continue;
            }
            if (!S_ISDIR(stat_buf.st_mode)) continue;

            // skip all '.' entries -> make .anything invisible to nfprofile
            if (entry->d_name[0] == '.') continue;

            InsertString(&dirlist, stringbuf);
        }
        closedir(PDIR);
    } else {
        InsertString(&dirlist, datadir);
    }

    channel = NULL;
    c = &channel;
    for (int i = 0; i < (int)dirlist.num_strings; i++) {
        *c = (channel_t *)calloc(1, sizeof(channel_t));
        if (!*c) {
            LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
            return NULL;
        }
        (*c)->next = NULL;
        (*c)->datadir = dirlist.list[i];

        book_handle_t *book_handle = book_attach((*c)->datadir);
        if (BOOK_NOT_EXISTS) {
            // no existing bookkeeper - create a new one
            book_handle = book_open((*c)->datadir, 0);
            if (book_handle == BOOK_FAILED) {
                book_handle = NULL;
                LogError("Failed to initialize bookkeeper for %s", (*c)->datadir);
                exit(EXIT_FAILURE);
            }
        }

        // valid bookkeeper
        (*c)->book_handle = book_handle;

        c = &(*c)->next;
    }

    return channel;

}  // End of GetChannelList

static int VerifyChannels(const channel_t *channel, int do_rescan) {
    // process do_rescan, if needed
    const channel_t *current_channel = channel;
    while (current_channel) {
        if (do_rescan || current_channel->book_handle->bookkeeper->dirty) {
            // A rescan is needed, if no book file exists or the book is dirty for some reason
            int maxTries = 3;
            int ok = 0;
            do {
                LogInfo("Re-scanning files in %s .. ", current_channel->datadir);
                ok = RescanDir(current_channel);
                if (!ok) {
                    LogVerbose("Failed to rescan directory: %s", current_channel->datadir);
                }
                maxTries--;
            } while (ok == 0 && maxTries > 0);

            if (maxTries == 0) {
                LogError("Could not rescan directory %s", current_channel->datadir);
                return 0;
            }

            LogInfo("Updated bookkeeping for %s", current_channel->datadir);
        }
        current_channel = current_channel->next;
    }

    return 1;
}  // End of VerifyChannels

static void PrintBookKeeper(bookkeeper_t *bookkeeper) {
    if (!bookkeeper) {
        LogError("No bookkeeper record available");
        return;
    }

    printf("Collector pid   : %lu\n", (unsigned long)bookkeeper->nfcapd_pid);
    printf("Record sequence : %llu\n", (unsigned long long)bookkeeper->sequence);

    char string[32];
    struct tm local_ts;
    struct tm *ts;
    time_t t = bookkeeper->first;
    ts = localtime_r(&t, &local_ts);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
    string[31] = '\0';
    printf("First           : %s\n", bookkeeper->first ? string : "<not set>");

    t = bookkeeper->last;
    ts = localtime_r(&t, &local_ts);
    strftime(string, 31, "%Y-%m-%d %H:%M:%S", ts);
    string[31] = '\0';
    printf("Last            : %s\n", bookkeeper->last ? string : "<not set>");
    printf("Number of files : %llu\n", (unsigned long long)bookkeeper->numfiles);
    printf("Total file size : %llu\n", (unsigned long long)bookkeeper->filesize);
    printf("Max file size   : %llu\n", (unsigned long long)bookkeeper->max_filesize);
    printf("Max life time   : %llu\n", (unsigned long long)bookkeeper->max_lifetime);
    printf("Watermark       : %llu\n", (unsigned long long)bookkeeper->watermark);
    printf("Dirty           : %llu\n", (unsigned long long)bookkeeper->dirty);

}  // End of PrintBookKeeper

int main(int argc, char **argv) {
    int do_rescan, do_expire, print_stat, do_update_param, is_profile, nfsen_format;
    char *datadir;
    uint32_t runtime;
    channel_t *channel, *current_channel;

    time_t maxlife = 0;
    uint64_t maxsize = 0;
    uint64_t low_water = 0;
    datadir = NULL;
    int dryrun = 0;
    do_rescan = 0;
    do_expire = 0;
    do_update_param = 0;
    is_profile = 0;
    print_stat = 0;
    nfsen_format = 0;
    runtime = 0;

    int c;
    while ((c = getopt(argc, argv, "e:hl:nT:Ypr:s:t:u:w:")) != EOF) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'l':
                if (TestPath(optarg, S_IFDIR) != PATH_OK) {
                    LogError("No such directory: %s", optarg);
                }
                datadir = optarg;
                print_stat = 1;
                break;
            case 'p':
                is_profile = 1;
                break;
            case 'r':
                if (TestPath(optarg, S_IFDIR) != PATH_OK) {
                    LogError("No such directory: %s", optarg);
                }
                datadir = optarg;
                do_rescan = 1;
                print_stat = 1;
                break;
            case 'e':
                if (TestPath(optarg, S_IFDIR) != PATH_OK) {
                    LogError("No such directory: %s", optarg);
                }
                datadir = optarg;
                do_expire = 1;
                print_stat = 1;
                break;
            case 'n':
                dryrun = 1;
                break;
            case 's':
                if (maxsize) {
                    LogError("Max size already set");
                    exit(EXIT_FAILURE);
                }
                if (ParseSizeDef(optarg, &maxsize) == 0) exit(250);
                break;
            case 't':
                CheckArgLen(optarg, 32);
                if (maxlife) {
                    LogError("Max lifetime already set");
                    exit(EXIT_FAILURE);
                }
                if (ParseTimeDef(optarg, &maxlife) == 0) exit(250);
                break;
            case 'u':
                if (TestPath(optarg, S_IFDIR) != PATH_OK) {
                    LogError("No such directory: %s", optarg);
                }
                datadir = optarg;
                do_update_param = 1;
                break;
            case 'w':
                if (low_water) {
                    LogError("Low water already set");
                    exit(EXIT_FAILURE);
                }
                low_water = strtoll(optarg, NULL, 10);
                if (low_water <= 0 || low_water >= 100) {
                    LogError("Low water mark needs to be a 0 < value < 100%%");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'T':
                runtime = strtoll(optarg, NULL, 10);
                if (runtime < 0 || runtime > 3600) {
                    LogError("Runtime > 3600 (1h)");
                    exit(250);
                }
                break;
            case 'Y':
                nfsen_format = 1;
                break;
            default:
                usage(argv[0]);
                exit(250);
        }
    }

    datadir = realpath(datadir, NULL);

    if (!datadir) {
        LogError("Data directory %s", datadir);
        LogError("realpath() in %s:%d: %s", __FILE__, __LINE__, strerror(errno));
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (TestPath(datadir, S_IFDIR) != PATH_OK) {
        LogError("Not a directory: %s", datadir);
        exit(EXIT_FAILURE);
    }

    channel = GetChannelList(datadir, is_profile);
    if (!channel) {
        LogError("Failed to get channel list");
        exit(EXIT_FAILURE);
    }

    if (!VerifyChannels(channel, do_rescan)) {
        LogError("Failed to verify channels");
        exit(EXIT_FAILURE);
    }

    if (dryrun && runtime) {
        LogInfo("Disable timeout for dryrun");
        runtime = 0;
    }

    // now process do_expire if required
    if (do_expire) {
        uint32_t expired_files = 0;
        uint64_t expired_size = 0;
        time_t expired_time;

        int ok = 0;
        if (is_profile) {
            ok = ExpireProfile("Profile", channel, maxsize, maxlife, low_water, runtime, dryrun);
            for (channel_t *ch = channel; ch; ch = ch->next) {
                expired_files += ch->expired_files;
                expired_size += ch->expired_size;
            }
        } else {
            ok = ExpireDir(channel, maxsize, maxlife, low_water, runtime, dryrun);
            expired_files = channel->expired_files;
            expired_size = channel->expired_size;
        }
        expired_time = channel->expired_time;
        // Report, what we have done
        LogInfo("Expire %s:", ok ? "successfully terminated" : "failed");
        LogInfo("Expired files:      %llu", (unsigned long long)(expired_files));
        char string[64];
        LogInfo("Expired file size:  %s", ScaleValue(string, sizeof(string), expired_size));
        LogInfo("Expired time range: %s", ScaleTime(string, sizeof(string), expired_time));
    }

    if (do_update_param) {
        if (is_profile) {
            LogError("nfexpire cannot update profile parameters");
            exit(EXIT_FAILURE);
        }
        // single flow directory
        LogInfo("Update expire settings for %d", channel->datadir);
        book_set_limits(channel->book_handle, maxlife, maxsize, low_water);
        print_stat = 1;
    }

    if (print_stat) {
        bookkeeper_t bookkeeper;
        if (is_profile) {
            bookkeeper_t total_bookkeeper = {0};
            for (channel_t *ch = channel; ch; ch = ch->next) {
                book_get(ch->book_handle, &bookkeeper);
                total_bookkeeper.filesize += bookkeeper.filesize;
                if (total_bookkeeper.first == 0 || bookkeeper.first < total_bookkeeper.first) total_bookkeeper.first = bookkeeper.first;
                if (total_bookkeeper.last == 0 || bookkeeper.last > total_bookkeeper.last) total_bookkeeper.last = bookkeeper.last;
            }

            if (nfsen_format) {
                printf("Stat|%llu|%llu|%llu\n", (unsigned long long)total_bookkeeper.filesize, (unsigned long long)total_bookkeeper.first,
                       (unsigned long long)total_bookkeeper.last);
            } else
                PrintBookKeeper(&total_bookkeeper);
        } else if (nfsen_format) {
            printf("Stat|%llu|%llu|%llu\n", (unsigned long long)channel->book_handle->bookkeeper->filesize,
                   (unsigned long long)channel->book_handle->bookkeeper->first, (unsigned long long)channel->book_handle->bookkeeper->last);
        } else {
            book_get(channel->book_handle, &bookkeeper);
            PrintBookKeeper(&bookkeeper);
        }
    }

    current_channel = channel;
    while (current_channel) {
        book_close(current_channel->book_handle);
        if (is_profile)
            // write legacu .nfsts file
            WriteStatInfo(NULL);

        current_channel = current_channel->next;
    }

    return 0;
}
