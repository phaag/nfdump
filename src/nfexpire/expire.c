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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
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
#include "util.h"

static uint32_t timeout = 0;

#if defined __FreeBSD__
static int compare(const FTSENT *const *f1, const FTSENT *const *f2);
#else
static int compare(const FTSENT **f1, const FTSENT **f2);
#endif

static void IntHandler(int signal) {
    switch (signal) {
        case SIGALRM:
        case SIGHUP:
        case SIGINT:
        case SIGTERM:
            timeout = 1;
            break;
            break;
        default:
            // ignore everything we don't know
            break;
    }

} /* End of IntHandler */

static void SetupSignalHandler(void) {
    struct sigaction act;

    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = IntHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

}  // End of SetupSignalHandler

/*
 * Parses size string into uint64_t
 * supports
 * b,B: bytes, k,K: kilo, m,M: mega, g,G: giga, t,T: tera
 * example:
 * 10
 * 10K
 * 10KB
 * 1.5G
 * 2T
 * etc.
 */
int ParseSizeDef(const char *s, uint64_t *value) {
    if (!s || !*s) {
        LogError("Empty size definition");
        return 0;
    }

    errno = 0;
    char *end = NULL;

    double number = strtod(s, &end);

    if (end == s) {
        LogError("Missing number in '%s'", s);
        return 0;
    }

    if (errno == ERANGE || number < 0.0) {
        LogError("Invalid number in '%s'", s);
        return 0;
    }

    uint64_t factor = 1;

    if (*end) {
        switch (*end) {
            case 'b':
            case 'B':
                factor = 1;
                end++;
                break;

            case 'k':
            case 'K':
                factor = 1024ULL;
                end++;
                break;

            case 'm':
            case 'M':
                factor = 1024ULL * 1024ULL;
                end++;
                break;

            case 'g':
            case 'G':
                factor = 1024ULL * 1024ULL * 1024ULL;
                end++;
                break;

            case 't':
            case 'T':
                factor = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
                end++;
                break;

            default:
                LogError("Unknown size unit in '%s'", s);
                return 0;
        }

        /* Optional trailing 'B' */
        if (*end == 'B' || *end == 'b') end++;

        if (*end != '\0') {
            LogError("Garbage in '%s'", s);
            return 0;
        }
    }

    long double result = (long double)number * (long double)factor;

    if (result > (long double)UINT64_MAX) {
        LogError("Size overflow in '%s'", s);
        return 0;
    }

    *value = (uint64_t)result;
    return 1;
}  // End of ParseSizeDef

/*
 * Parses time string into time_t value
 * default is hours, otherwise:
 * w: weeks, d: days, M: minutes
 * 48   (default hours)
 * 7d
 * 24H
 * 60M
 * 1w2d3H15M
 */
int ParseTimeDef(const char *s, time_t *value) {
    if (!s || !*s) {
        LogError("Empty time definition");
        return 0;
    }

    uint64_t total = 0;
    const char *p = s;
    while (*p) {
        errno = 0;
        char *end = NULL;

        unsigned long long num = strtoull(p, &end, 10);

        if (end == p) {
            LogError("Missing number in '%s'", s);
            return 0;
        }

        if (errno == ERANGE) {
            LogError("Numeric overflow in '%s'", s);
            return 0;
        }

        uint64_t seconds = 0;

        switch (*end) {
            case 'w':
                seconds = num * 7ULL * 24ULL * 3600ULL;
                end++;
                break;

            case 'd':
                seconds = num * 24ULL * 3600ULL;
                end++;
                break;

            case 'H':
            case '\0':
                seconds = num * 3600ULL;
                if (*end) end++;
                break;

            case 'M':
                seconds = num * 60ULL;
                end++;
                break;

            default:
                LogError("Unknown time unit in '%s'", s);
                return 0;
        }

        if (UINT64_MAX - total < seconds) {
            LogError("Time overflow in '%s'", s);
            return 0;
        }

        total += seconds;
        p = end;
    }

    *value = total;
    return 1;
}  // End of ParseTimeDef

#if defined __FreeBSD__
static int compare(const FTSENT *const *f1, const FTSENT *const *f2) { return strcmp((*f1)->fts_name, (*f2)->fts_name); }  // End of compare
#else
static int compare(const FTSENT **f1, const FTSENT **f2) { return strcmp((*f1)->fts_name, (*f2)->fts_name); }  // End of compare
#endif

int RescanDir(const channel_t *channel) {
    FTS *fts;
    FTSENT *ent;

    char *const paths[] = {(char *)channel->datadir, NULL};

    char first_ts[16] = "99999999999999";
    char last_ts[16] = "00000000000000";

    bookkeeper_t bookkeeper;
    book_get(channel->book_handle, &bookkeeper);

    bookkeeper.filesize = 0;
    bookkeeper.numfiles = 0;
    bookkeeper.first = 0;
    bookkeeper.last = 0;

    fts = fts_open(paths, FTS_LOGICAL, compare);
    if (!fts) {
        LogError("fts_open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    while ((ent = fts_read(fts)) != NULL) {
        if (ent->fts_info == FTS_F) {
            if ((ent->fts_namelen == 19 || ent->fts_namelen == 21) && strncmp(ent->fts_name, "nfcapd.", 7) == 0) {
                const char *p = ent->fts_name + 7;
                size_t len = strlen(p);

                // validate timestamp length
                if (len == 12 || len == 14) {
                    // ensure all digits
                    int valid = 1;
                    for (size_t i = 0; i < len; i++) {
                        if (!isdigit((unsigned char)p[i])) {
                            valid = 0;
                            break;
                        }
                    }
                    if (!valid) continue;

                    // update first/last lexicographically
                    if (strcmp(p, first_ts) < 0) memcpy(first_ts, p, len + 1);
                    if (strcmp(p, last_ts) > 0) memcpy(last_ts, p, len + 1);

                    // accumulate disk usage
                    if (ent->fts_statp) {
                        bookkeeper.filesize += (uint64_t)ent->fts_statp->st_blocks * 512ULL;
                    }

                    bookkeeper.numfiles++;
                }
            }
        } else if (ent->fts_info == FTS_D && ent->fts_level > 0) {
            // skip directories
            if (ent->fts_name[0] == '.' || !isdigit((unsigned char)ent->fts_name[0])) {
                fts_set(fts, ent, FTS_SKIP);
            }
        }
    }

    if (errno != 0) {
        LogError("fts_read() error: %s", strerror(errno));
        return 0;
    }
    fts_close(fts);

    // successfully re-scanned
    // finalize timestamps
    if (bookkeeper.numfiles > 0) {
        bookkeeper.first = ISO2UNIX(first_ts);
        bookkeeper.last = ISO2UNIX(last_ts);
    }

    bookkeeper.dirty = 0;

    if (book_set(channel->book_handle, &bookkeeper) == 0) {
        return 0;
    }

    dbg_printf("Rescan dir - first: %s, last: %s\n", first_ts, last_ts);

    return 1;
}  // End of RescanDir

static int deleteFileAt(int dirfd, const char *base_dir, const char *rel, int dryrun) {
    if (dryrun) {
        LogInfo("Would delete file: %s/%s", base_dir, rel);
        return 0;
    } else {
        return unlinkat(dirfd, rel, 0);
    }
    // unreached
}  // End of deleteFileAt

static int deleteDir(const char *dirname, int dryrun) {
    if (dryrun) {
        LogInfo("Would delete dir: %s", dirname);
        return 0;
    } else {
        return rmdir(dirname);
    }
    // unreached
}  // End of deleteDir

static void CleanupChannels(const channel_t *channel) {
    for (const channel_t *ch = channel; ch; ch = ch->next) {
        if (ch->dirfd >= 0) close(ch->dirfd);
    }

}  // End of CleanupChannels

// Unified single-channel / profile expiry. A plain, non-profile expire is
// just this same lockstep algorithm with a channel list of length one -
// deleting a timeslot "from every channel in the list" trivially means
// "from the one channel" when there is only one. Keeping one implementation
// instead of two means a fix (or a bug) can no longer exist in one copy but
// not the other, which is exactly how two of this function's own past bugs
// happened: a lifetime-comparison off-by-one and an unlocked bookkeeper
// write were each fixed once here, but previously had to be fixed twice.
int ExpireDir(channel_t *channel, uint64_t maxsize, time_t maxlife, uint32_t low_water, time_t runtime, int dryrun) {
    if (!channel) return 0;

    // A single channel may fall back to its own persisted limits (nfexpire
    // -u); a multi-channel profile has no single channel a cross-channel
    // limit could sensibly live in, so -s/-t/-w must always be given
    // explicitly for -p - this is intentional, not a limitation to fix.
    int isSingle = (channel->next == NULL);
    const char *label = isSingle ? channel->datadir : "Profile";

    // Snapshot bookkeeping for every channel and derive combined totals.
    uint64_t total_size = 0;
    time_t first = 0;
    time_t last = 0;
    channel_t *reference_channel = channel;
    int failed = 0;
    for (channel_t *ch = channel; ch; ch = ch->next) {
        bookkeeper_t bookkeeper;
        book_get(ch->book_handle, &bookkeeper);

        total_size += bookkeeper.filesize;

        if (!first || bookkeeper.first < first) {
            first = bookkeeper.first;
            reference_channel = ch;
        }
        if (bookkeeper.last > last) last = bookkeeper.last;

        ch->expired_files = 0;
        ch->expired_size = 0;
        ch->expired_time = 0;

        if (isSingle) {
            if (maxsize == 0) maxsize = bookkeeper.max_filesize;
            if (maxlife == 0) maxlife = bookkeeper.max_lifetime;
            if (low_water == 0) low_water = bookkeeper.watermark;
        }

        ch->dirfd = open(ch->datadir, O_RDONLY | O_DIRECTORY);
        if (ch->dirfd < 0) {
            LogError("Failed to open directory %s: %s", ch->datadir, strerror(errno));
            failed = 1;
        }
    }
    if (low_water == 0) low_water = 95;

    if (failed) {
        CleanupChannels(channel);
        return 0;
    }

    if (maxsize == 0 && maxlife == 0) {
        LogInfo("No limits set for %s. Nothing to expire", label);
        CleanupChannels(channel);
        return 1;
    }

    time_t expire_start = first;
    time_t expire_end = 0;

    // trigger values
    int need_size_expire = (maxsize && total_size > maxsize);
    uint64_t target_size = need_size_expire ? (maxsize * low_water) / 100 : 0;

    int need_life_expire = 0;
    char timeLimitStr[32] = {0};
    time_t timeLimit = 0;
    if (maxlife && first && last && (last - first) > maxlife) {
        need_life_expire = 1;

        timeLimit = last - ((maxlife * low_water) / 100);
        strcpy(timeLimitStr, UNIX2ISO(timeLimit));
    }

    if (!need_size_expire && !need_life_expire) {
        LogInfo("Limits do not trigger for %s. Nothing to expire", label);
        CleanupChannels(channel);
        return 1;
    }

#ifdef DEVEL
    if (need_size_expire) printf("need_size_expire: %d from %" PRIu64 " down to %" PRIu64, need_size_expire, total_size, target_size);
    if (need_life_expire) printf("need_life_expire: %d from %s down to %s", need_life_expire, UNIX2ISO(first), timeLimitStr);
#endif

    if (dryrun == 0 && runtime) {
        SetupSignalHandler();
        alarm(runtime);
    }

    // Traverse the reference channel's timeline; for a single channel that
    // is trivially the only channel there is.
    char *const path[] = {reference_channel->datadir, NULL};
    FTS *fts = fts_open(path, FTS_PHYSICAL, compare);
    if (!fts) {
        LogError("fts_open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CleanupChannels(channel);
        return 0;
    }

    size_t base_len = strlen(reference_channel->datadir);
    uint64_t current_size = total_size;
    time_t new_first = 0;
    uint32_t numfiles = 0;
    int done = 0;
    FTSENT *ftsent;
    while (!done && (ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
            case FTS_D:
                // enter subdirectory - set file counter
                numfiles = 0;

                // skip all '.' entries
                if (ftsent->fts_level > 0 && (ftsent->fts_name[0] == '.' || !isdigit((unsigned char)ftsent->fts_name[0]))) {
                    dbg_printf("FTS: skip directory: %s\n", ftsent->fts_name);
                    fts_set(fts, ftsent, FTS_SKIP);
                }

                break;

            case FTS_F: {
                // check for valid nfcapd.xxxx file
                if ((ftsent->fts_namelen != 19 && ftsent->fts_namelen != 21) || strncmp(ftsent->fts_name, "nfcapd.", 7) != 0) break;

                // literal date string
                const char *timeString = ftsent->fts_name + 7;
                size_t len = strlen(timeString);
                if (len != 12 && len != 14) break;

                // date string need to be all numbers
                int invalid = 0;
                for (size_t i = 0; i < len; i++)
                    if (!isdigit((unsigned char)timeString[i])) invalid = 1;

                if (invalid) break;

                // valid file
                numfiles++;

                // check, if we are done and set new first value
                if (need_size_expire == 0 && need_life_expire == 0) {
                    done = 1;
                    // first remaining file
                    new_first = ISO2UNIX(timeString);
                    expire_end = new_first;
                    dbg_printf("Done - first: %s, size: %" PRIu64 "\n", timeString, current_size);
                    break;
                }

                int delete_slot = 0;
                // check for size expiration
                if (need_size_expire && current_size > target_size) delete_slot = 1;

                // check for lifetime expiration - compare parsed unix time, not
                // the raw filename strings: a 12-char "no seconds" filename
                // (the default for any rotation interval >= 60s) is a strict
                // prefix of timeLimitStr's 14-char "with seconds" form, and
                // strcmp() ranks any prefix as "less than" its longer
                // extension regardless of the actual moment in time - which
                // wrongly deleted a file exactly at the watermark boundary.
                time_t fileTime = ISO2UNIX(timeString);
                int timeCMP = (fileTime > timeLimit) - (fileTime < timeLimit);
                if (!delete_slot && need_life_expire && timeCMP < 0) delete_slot = 1;

                if (delete_slot) {
                    // delete the same timeslot in every channel
                    dbg_printf("Delete %s\n", ftsent->fts_name);
                    const char *rel = ftsent->fts_path + base_len + 1;

                    for (channel_t *ch = channel; ch; ch = ch->next) {
                        dbg_printf("Delete %s/%s\n", ch->datadir, rel);

                        struct stat st;
                        if (fstatat(ch->dirfd, rel, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                            uint64_t fileSize = (uint64_t)st.st_blocks * 512ULL;
                            if (deleteFileAt(ch->dirfd, ch->datadir, rel, dryrun) == 0) {
                                ch->expired_size += fileSize;
                                ch->expired_files++;
                                if (current_size >= fileSize)
                                    current_size -= fileSize;
                                else
                                    current_size = 0;
                            } else {
                                LogError("unlink() error for %s/%s: %s", ch->datadir, rel, strerror(errno));
                                if (!dryrun) book_mark_dirty(ch->book_handle);
                                // if unlink failes, abort expire process
                                done = 1;
                            }
                        } else {
                            // Expected for a profile channel legitimately missing this
                            // timeslot; for a single channel this branch is unreachable
                            // since the file we are looking at came from its own listing.
                            LogError("stat() error for %s/%s: %s", ch->datadir, rel, strerror(errno));
                        }
                    }
                }

                // stop condition
                // this does not yet terminte the while loop
                // as we need to get the next valid file for the new first timestamp
                if (timeout || (need_size_expire && current_size <= target_size)) need_size_expire = 0;
                if (timeout || (need_life_expire && timeCMP >= 0)) need_life_expire = 0;

                break;
            }

            case FTS_DP: {
                if (numfiles == 0 && ftsent->fts_level > 0) {
                    // directory is empty in the reference channel - remove it in every channel
                    size_t len = strlen(reference_channel->datadir);
                    for (channel_t *ch = channel; ch; ch = ch->next) {
                        char dirpath[MAXPATHLEN];
                        snprintf(dirpath, sizeof(dirpath), "%s/%s", ch->datadir, ftsent->fts_path + len + 1);
                        dbg_printf("Remove directory %s\n", dirpath);

                        if (deleteDir(dirpath, dryrun) != 0) {
                            LogError("rmdir() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
                        }
                    }
                }
            } break;

            default:
                break;
        }
    }

    if (runtime) alarm(0);
    fts_close(fts);

    if (expire_end) {
        time_t expire_time = expire_end - expire_start;
        for (channel_t *ch = channel; ch; ch = ch->next) ch->expired_time = expire_time;
    }

    for (channel_t *ch = channel; ch; ch = ch->next) {
        if (ch->dirfd >= 0) close(ch->dirfd);
    }

    if (dryrun) {
        // early exit without updating books or rescanning
        LogInfo("Dryrun expire %s ends", label);
        return 1;
    }

    int dirty = 0;
    if (ftsent == NULL) {
        // end of directory reached - most likely all files expired
        // make sure bookkeeper gets updated correctly
        dirty = 1;
        LogVerbose("Reached end of file list for %s", label);
    }
    if (new_first == 0) {
        dirty = 1;
        LogVerbose("Unclean expire for %s", label);
    }

    for (channel_t *ch = channel; ch; ch = ch->next) {
        if (dirty == 0) {
            // expire successfully completed - book_expire() itself rejects the
            // update (and leaves the book untouched) if the numbers don't add up
            if (!book_expire(ch->book_handle, new_first, ch->expired_files, ch->expired_size)) {
                LogError("book_update rejected - rescan channel %s", ch->datadir);
                book_mark_dirty(ch->book_handle);
            }
        } else {
            book_mark_dirty(ch->book_handle);
        }
    }

    if (timeout) {
        // leave channels dirty, if time runs out - picked up on the next run
        return 1;
    }

    int rescanFailed = 0;
    for (channel_t *ch = channel; ch; ch = ch->next) {
        if (book_is_dirty(ch->book_handle)) {
            LogVerbose("Expire %s: inconsistent data - rescan ..", label);
            int ok = 0;
            int maxTries = 3;
            do {
                ok = RescanDir(ch);
                maxTries--;
            } while (ok == 0 && maxTries > 0);

            if (ok == 0) {
                LogError("Failed to re-scan dirty channel %s", ch->datadir);
                rescanFailed = 1;
            }
        }
    }

    return rescanFailed == 0;
}  // End of ExpireDir
