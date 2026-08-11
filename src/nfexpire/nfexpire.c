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

// How long a run waits for another live nfexpire process to release a
// channel it holds, before giving up: 30 retries, one second apart.
#define EXPIRE_LOCK_MAX_RETRIES 30
#define EXPIRE_LOCK_RETRY_SECONDS 1

static void usage(char *name) {
    printf(
        "usage %s [options] \n"
        "-h\t\tThis text\n"
        "-l datadir\tList stat from directory\n"
        "-e datadir\tExpire data in directory\n"
        "-n\t\tdryrun mode. Do not delete but report\n"
        "-r datadir\tRescan data directory\n"
        "-u datadir\tStore -s/-t/-w as the persistent default expire params for <datadir>\n"
        "-p\t\tLegacy NfSen profile mode\n"
        "-Y\t\tPrint NfSen-compatible statistics\n"
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
        (*c)->dirfd = -1;

        book_handle_t *book_handle = NULL;
        book_status_t status = book_attach((*c)->datadir, &book_handle);
        if (status == BOOK_ERR_NOT_EXISTS) {
            // no existing bookkeeper - create a new one
            if (book_open((*c)->datadir, 0, &book_handle) != BOOK_OK) {
                LogError("Failed to initialize bookkeeper for %s", (*c)->datadir);
                exit(EXIT_FAILURE);
            }
        } else if (status != BOOK_OK) {
            LogError("Failed to attach bookkeeper for %s", (*c)->datadir);
            exit(EXIT_FAILURE);
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
        if (ExpireStopRequested()) return -1;
        if (do_rescan || book_is_dirty(current_channel->book_handle)) {
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
            } while (ok == 0 && !ExpireStopRequested() && maxTries > 0);

            if (ExpireStopRequested()) return -1;

            if (!ok) {
                LogError("Could not rescan directory %s", current_channel->datadir);
                return 0;
            }

            LogInfo("Updated bookkeeping for %s", current_channel->datadir);
        }
        current_channel = current_channel->next;
    }

    return 1;
}  // End of VerifyChannels

// Release every channel lock claimed so far, up to (but not including)
// 'stop'. stop == NULL releases the whole list. Used both for the final,
// successful cleanup and to roll back a partial claim before a retry.
static void ReleaseChannelLocksUpTo(channel_t *channel, const channel_t *stop) {
    for (channel_t *ch = channel; ch && ch != stop; ch = ch->next) {
        book_release_expire(ch->book_handle);
    }
}  // End of ReleaseChannelLocksUpTo

static void ReleaseChannelLocks(channel_t *channel) { ReleaseChannelLocksUpTo(channel, NULL); }  // End of ReleaseChannelLocks

// Claim every channel's exclusive nfexpire lock as a single all-or-nothing
// unit - a profile's channels are expired in lockstep by ExpireDir(), so a
// partial claim (some channels ours, some still held by another process)
// would be worse than no claim at all. If any channel is currently held by
// another live nfexpire process, release whatever this attempt managed to
// claim and retry the whole set a second later, for up to
// EXPIRE_LOCK_MAX_RETRIES seconds before giving up.
static int AcquireChannelLocks(channel_t *channel) {
    pid_t self = getpid();

    for (int attempt = 0; attempt <= EXPIRE_LOCK_MAX_RETRIES; attempt++) {
        if (ExpireStopRequested()) return -1;
        channel_t *busy = NULL;
        pid_t holder = 0;

        for (channel_t *ch = channel; ch; ch = ch->next) {
            if (ExpireStopRequested()) {
                ReleaseChannelLocksUpTo(channel, ch);
                return -1;
            }
            pid_t this_holder = 0;
            book_status_t status = book_claim_expire(ch->book_handle, self, &this_holder);
            if (status == BOOK_OK) continue;
            if (status == BOOK_ERR_EXISTS) {
                busy = ch;
                holder = this_holder;
                break;
            }
            // I/O failure - not something a retry can fix
            LogError("Failed to claim exclusive access to %s", ch->datadir);
            ReleaseChannelLocksUpTo(channel, ch);
            return 0;
        }

        if (!busy) return 1;  // every channel claimed

        ReleaseChannelLocksUpTo(channel, busy);

        if (attempt == EXPIRE_LOCK_MAX_RETRIES) {
            LogError("Directory %s is still in use by nfexpire pid %d after %d seconds - giving up", busy->datadir, (int)holder,
                      EXPIRE_LOCK_MAX_RETRIES);
            return 0;
        }

        LogInfo("Directory %s is in use by nfexpire pid %d - retrying (%d/%d)", busy->datadir, (int)holder, attempt + 1,
                EXPIRE_LOCK_MAX_RETRIES);
        sleep(EXPIRE_LOCK_RETRY_SECONDS);
        if (ExpireStopRequested()) return -1;
    }

    return 0;
}  // End of AcquireChannelLocks

static void PrintBookKeeper(bookkeeper_t *bookkeeper) {
    if (!bookkeeper) {
        LogError("No bookkeeper record available");
        return;
    }

    printf("Collector pid   : %lu\n", (unsigned long)bookkeeper->nfcapd_pid);
    printf("Expire pid      : %lu\n", (unsigned long)bookkeeper->expire_pid);
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
    uint32_t low_water = 0;
    uint32_t limit_mask = 0;
    datadir = NULL;
    int dryrun = 0;
    int exit_status = EXIT_SUCCESS;
    int locks_claimed = 0;
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
                if (limit_mask & BOOK_LIMIT_MAXSIZE) {
                    LogError("Max size already set");
                    exit(EXIT_FAILURE);
                }
                if (ParseSizeDef(optarg, &maxsize) == 0) exit(250);
                limit_mask |= BOOK_LIMIT_MAXSIZE;
                break;
            case 't':
                CheckArgLen(optarg, 32);
                if (limit_mask & BOOK_LIMIT_LIFETIME) {
                    LogError("Max lifetime already set");
                    exit(EXIT_FAILURE);
                }
                if (ParseTimeDef(optarg, &maxlife) == 0) exit(250);
                limit_mask |= BOOK_LIMIT_LIFETIME;
                break;
            case 'u':
                if (TestPath(optarg, S_IFDIR) != PATH_OK) {
                    LogError("No such directory: %s", optarg);
                }
                datadir = optarg;
                do_update_param = 1;
                break;
            case 'w':
                if (limit_mask & BOOK_LIMIT_WATERMARK) {
                    LogError("Low water already set");
                    exit(EXIT_FAILURE);
                }
                errno = 0;
                char *end = NULL;
                unsigned long watermark = strtoul(optarg, &end, 10);
                if (errno == ERANGE || end == optarg || *end != '\0' || watermark > UINT32_MAX) {
                    LogError("Invalid low water mark: %s", optarg);
                    exit(EXIT_FAILURE);
                }
                low_water = (uint32_t)watermark;
                if (low_water <= 0 || low_water >= 100) {
                    LogError("Low water mark needs to be a 0 < value < 100%%");
                    exit(EXIT_FAILURE);
                }
                limit_mask |= BOOK_LIMIT_WATERMARK;
                break;
            case 'T':
                errno = 0;
                char *runtime_end = NULL;
                unsigned long runtime_value = strtoul(optarg, &runtime_end, 10);
                if (errno == ERANGE || runtime_end == optarg || *runtime_end != '\0' || runtime_value > 3600) {
                    LogError("Runtime must be an integer between 0 and 3600 seconds");
                    exit(250);
                }
                runtime = (uint32_t)runtime_value;
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

    if (dryrun && runtime) {
        LogInfo("Disable timeout for dryrun");
        runtime = 0;
    }

    // Install handlers before acquiring an expire lock or rescanning a dirty
    // book. The handler only sets a flag; normal control flow below releases
    // locks and, if deletion has started, ExpireDir() commits its partial book.
    // The optional -T timer therefore covers profile indexing as well as the
    // actual unlink loop.
    ExpireSetupSignalHandling(do_expire && !dryrun ? runtime : 0);

    channel = GetChannelList(datadir, is_profile);
    if (!channel) {
        LogError("Failed to get channel list");
        exit(EXIT_FAILURE);
    }

    if (ExpireStopRequested()) goto interrupted;

    // Claim every channel before touching anything - VerifyChannels() below
    // may rescan (it does so unconditionally whenever the book is dirty,
    // regardless of which option was given), and a rescan racing another
    // process' rescan or expire is exactly the corruption this guards
    // against. AcquireChannelLocks() has already logged the reason on failure.
    int lock_status = AcquireChannelLocks(channel);
    if (lock_status <= 0) {
        if (lock_status < 0) goto interrupted;
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }
    locks_claimed = 1;

    int verify_status = VerifyChannels(channel, do_rescan);
    if (verify_status <= 0) {
        if (verify_status < 0 || ExpireStopRequested()) goto interrupted;
        LogError("Failed to verify channels");
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }

    if (ExpireStopRequested()) goto interrupted;

    // now process do_expire if required
    if (do_expire) {
        uint64_t expired_files = 0;
        uint64_t expired_size = 0;
        time_t expired_time;

        // ExpireDir() handles both a single channel and a profile's channel
        // list uniformly - it sums to the same thing for a single channel.
        expire_status_t status = ExpireDir(channel, maxsize, maxlife, low_water, limit_mask, dryrun);
        for (channel_t *ch = channel; ch; ch = ch->next) {
            expired_files += ch->expired_files;
            expired_size += ch->expired_size;
        }
        expired_time = channel->expired_time;
        // A stopped run commits the files removed before the stop request and
        // retains the next valid slot as the new book head. A dirty book is
        // reserved for an actual filesystem or bookkeeping inconsistency.
        // TIMEOUT/ABORTED are not failures - the bookkeeping is guaranteed
        // consistent - but they are still logged via LogError(): both a -T
        // runtime limit and an operator-sent kill are events that need to
        // reach the user's attention, not scroll by at LogInfo level.
        switch (status) {
            case EXPIRE_OK:
                LogInfo("Expire %s: successfully terminated", datadir);
                break;
            case EXPIRE_TIMEOUT:
                LogError("Expire %s: stopped - -T runtime limit reached; partial bookkeeping committed", datadir);
                break;
            case EXPIRE_ABORTED:
                LogError("Expire %s: stopped by signal; partial bookkeeping committed", datadir);
                break;
            case EXPIRE_FAILED:
            default:
                LogError("Expire %s: failed", datadir);
                exit_status = EXIT_FAILURE;
                break;
        }
        LogInfo("Expired files:      %llu", (unsigned long long)(expired_files));
        char string[128];
        LogInfo("Expired file size:  %sB", ScaleByteValue(string, sizeof(string), expired_size, PRINT_SCALED, 0));
        LogInfo("Expired time range: %s", ScaleDuration(string, sizeof(string), expired_time, PRINT_SCALED, WIDTH_VAR));

        ExpireCancelTimeout();
        if (status == EXPIRE_TIMEOUT || status == EXPIRE_ABORTED || ExpireStopRequested()) goto cleanup;
    }

    if (ExpireStopRequested()) goto interrupted;

    if (do_update_param) {
        if (is_profile) {
            LogError("nfexpire cannot update profile parameters");
            exit_status = EXIT_FAILURE;
            goto cleanup;
        }
        // single flow directory
        LogInfo("Update expire settings for %s", channel->datadir);
        book_set_limits(channel->book_handle, maxlife, maxsize, low_water, limit_mask);
        print_stat = 1;
    }

    if (ExpireStopRequested()) goto interrupted;

cleanup:
    ExpireCancelTimeout();
    // Release as soon as the mutating work is done - print_stat below only
    // reads (book_get() is itself lock-protected), so there is no reason to
    // keep another waiting nfexpire blocked for it.
    if (locks_claimed) ReleaseChannelLocks(channel);

    if (print_stat && !ExpireStopRequested()) {
        bookkeeper_t bookkeeper;
        if (is_profile) {
            bookkeeper_t total_bookkeeper = {0};
            for (channel_t *ch = channel; ch; ch = ch->next) {
                book_get(ch->book_handle, &bookkeeper);
                total_bookkeeper.filesize += bookkeeper.filesize;
                total_bookkeeper.numfiles += bookkeeper.numfiles;
                if (total_bookkeeper.first == 0 || bookkeeper.first < total_bookkeeper.first) total_bookkeeper.first = bookkeeper.first;
                if (total_bookkeeper.last == 0 || bookkeeper.last > total_bookkeeper.last) total_bookkeeper.last = bookkeeper.last;
            }

            if (nfsen_format) {
                printf("Stat|%llu|%llu|%llu\n", (unsigned long long)total_bookkeeper.filesize, (unsigned long long)total_bookkeeper.first,
                       (unsigned long long)total_bookkeeper.last);
            } else
                PrintBookKeeper(&total_bookkeeper);
        } else if (nfsen_format) {
            book_get(channel->book_handle, &bookkeeper);
            printf("Stat|%llu|%llu|%llu\n", (unsigned long long)bookkeeper.filesize, (unsigned long long)bookkeeper.first,
                   (unsigned long long)bookkeeper.last);
        } else {
            book_get(channel->book_handle, &bookkeeper);
            PrintBookKeeper(&bookkeeper);
        }
    }

    current_channel = channel;
    while (current_channel) {
        // WriteStatInfo() reads the current bookkeeper via book_get()
        if (is_profile && !ExpireStopRequested())
            // write legacy .nfsts file
            WriteStatInfo(current_channel);
        book_close(current_channel->book_handle);

        current_channel = current_channel->next;
    }

    return exit_status;

interrupted:
    // If expiry itself had started, ExpireDir() has committed the partial
    // deletion before returning. Before that point no flow files have
    // changed, so releasing any acquired claims is sufficient. Same as the
    // do_expire status switch above: LogError(), not LogInfo() - a -T
    // runtime limit or an operator-sent kill needs to reach the user's
    // attention even when it happens before any deletion started.
    if (ExpireTerminationStatus() == EXPIRE_TIMEOUT)
        LogError("nfexpire stopped: -T runtime limit reached");
    else
        LogError("nfexpire stopped by signal");
    goto cleanup;
}
