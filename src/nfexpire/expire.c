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

// These are the only state variables touched by the signal handler. POSIX
// permits volatile sig_atomic_t accesses there; using an ordinary uint32_t
// lets an optimiser legally cache the value and miss a stop request.
static volatile sig_atomic_t stop_requested = 0;
// Which signal actually caused the abort - SIGALRM means the -T runtime ran
// out; SIGTERM/SIGINT/SIGHUP mean someone asked us to stop. The stop flag
// alone cannot tell those apart, and ExpireDir()'s caller needs to.
static volatile sig_atomic_t abort_signal = 0;

typedef struct {
    char *relpath;
    time_t timestamp;
} expire_slot_t;

typedef struct {
    expire_slot_t *slots;
    size_t used;
    size_t size;
} expire_slots_t;

#if defined __FreeBSD__
static int compare(const FTSENT *const *f1, const FTSENT *const *f2);
#else
static int compare(const FTSENT **f1, const FTSENT **f2);
#endif

static int ParseFlowFilename(const char *name, size_t name_len, time_t *timestamp);
static int DeleteFlowFile(const channel_t *channel, const char *relpath, int dryrun, uint64_t *file_size);
static int GetFlowFileSize(const channel_t *channel, const char *relpath, uint64_t *file_size);
static int RemoveEmptyDirectory(const channel_t *channel, const char *relpath, int dryrun);
static int CollectProfileSlots(const channel_t *channel, expire_slots_t *slots);
static void FreeExpireSlots(expire_slots_t *slots);

static void IntHandler(int signal) {
    switch (signal) {
        case SIGALRM:
        case SIGHUP:
        case SIGINT:
        case SIGTERM:
            stop_requested = 1;
            abort_signal = signal;
            break;
        default:
            // ignore everything we don't know
            break;
    }

} /* End of IntHandler */

void ExpireSetupSignalHandling(uint32_t runtime) {
    struct sigaction act;
    sigset_t signals;
    sigset_t oldmask;

    // Do not lose a termination signal in the small interval while handlers
    // are installed and their state is initialised. Pending signals are
    // delivered to IntHandler() once the prior mask is restored below.
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGHUP);
    sigaddset(&signals, SIGALRM);
    int mask_saved = sigprocmask(SIG_BLOCK, &signals, &oldmask) == 0;
    if (!mask_saved) {
        LogError("sigprocmask() failed while installing nfexpire signal handlers: %s", strerror(errno));
    }

    stop_requested = 0;
    abort_signal = 0;

    memset((void *)&act, 0, sizeof(struct sigaction));
    act.sa_handler = IntHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if (runtime) alarm(runtime);
    if (mask_saved && sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
        LogError("sigprocmask() failed while enabling nfexpire signal handlers: %s", strerror(errno));
    }

}  // End of ExpireSetupSignalHandling

void ExpireCancelTimeout(void) { alarm(0); }  // End of ExpireCancelTimeout

int ExpireStopRequested(void) { return stop_requested != 0; }  // End of ExpireStopRequested

// Resolve the outcome of a run into the status the caller sees. Every
// ExpireDir()/ExpireProfileSlots() return funnels through here, so the
// timeout/signal distinction only has to be made in one place.
static expire_status_t FinalStatus(int operationFailed) {
    if (operationFailed) return EXPIRE_FAILED;
    if (!stop_requested) return EXPIRE_OK;
    return abort_signal == SIGALRM ? EXPIRE_TIMEOUT : EXPIRE_ABORTED;
}  // End of FinalStatus

expire_status_t ExpireTerminationStatus(void) { return FinalStatus(0); }  // End of ExpireTerminationStatus

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

        uint64_t factor = 0;

        switch (*end) {
            case 'w':
                factor = 7ULL * 24ULL * 3600ULL;
                end++;
                break;

            case 'd':
                factor = 24ULL * 3600ULL;
                end++;
                break;

            case 'H':
            case '\0':
                factor = 3600ULL;
                if (*end) end++;
                break;

            case 'M':
                factor = 60ULL;
                end++;
                break;

            default:
                LogError("Unknown time unit in '%s'", s);
                return 0;
        }

        if (num > UINT64_MAX / factor) {
            LogError("Time overflow in '%s'", s);
            return 0;
        }
        uint64_t seconds = num * factor;

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

static int ParseFlowFilename(const char *name, size_t name_len, time_t *timestamp) {
    if ((name_len != 19 && name_len != 21) || strncmp(name, "nfcapd.", 7) != 0) return 0;

    const char *time_string = name + 7;
    size_t time_len = name_len - 7;
    if (time_len != 12 && time_len != 14) return 0;
    for (size_t i = 0; i < time_len; i++)
        if (!isdigit((unsigned char)time_string[i])) return 0;

    time_t parsed = ISO2UNIX(time_string);
    if (parsed == 0) return 0;
    if (timestamp) *timestamp = parsed;
    return 1;
}  // End of ParseFlowFilename

static int CompareExpireSlot(const void *a, const void *b) {
    const expire_slot_t *left = a;
    const expire_slot_t *right = b;
    if (left->timestamp < right->timestamp) return -1;
    if (left->timestamp > right->timestamp) return 1;
    return strcmp(left->relpath, right->relpath);
}  // End of CompareExpireSlot

static int InsertExpireSlot(expire_slots_t *slots, const char *relpath, time_t timestamp) {
    if (slots->used == slots->size) {
        size_t new_size = slots->size ? slots->size * 2 : 256;
        if (new_size < slots->size || new_size > SIZE_MAX / sizeof(expire_slot_t)) return 0;
        expire_slot_t *new_slots = realloc(slots->slots, new_size * sizeof(expire_slot_t));
        if (!new_slots) return 0;
        slots->slots = new_slots;
        slots->size = new_size;
    }

    slots->slots[slots->used].relpath = strdup(relpath);
    if (!slots->slots[slots->used].relpath) return 0;
    slots->slots[slots->used].timestamp = timestamp;
    slots->used++;
    return 1;
}  // End of InsertExpireSlot

static void FreeExpireSlots(expire_slots_t *slots) {
    if (!slots) return;
    for (size_t i = 0; i < slots->used; i++) free(slots->slots[i].relpath);
    free(slots->slots);
    memset(slots, 0, sizeof(*slots));
}  // End of FreeExpireSlots

static int CollectProfileSlots(const channel_t *channel, expire_slots_t *slots) {
    memset(slots, 0, sizeof(*slots));

    for (const channel_t *ch = channel; ch; ch = ch->next) {
        char *const paths[] = {(char *)ch->datadir, NULL};
        FTS *fts = fts_open(paths, FTS_PHYSICAL, compare);
        if (!fts) {
            LogError("fts_open() error for %s: %s", ch->datadir, strerror(errno));
            FreeExpireSlots(slots);
            return 0;
        }

        size_t base_len = strlen(ch->datadir);
        errno = 0;
        FTSENT *entry;
        while ((entry = fts_read(fts)) != NULL) {
            if (entry->fts_info == FTS_D && entry->fts_level > 0) {
                if (entry->fts_name[0] == '.' || !isdigit((unsigned char)entry->fts_name[0])) fts_set(fts, entry, FTS_SKIP);
                continue;
            }
            if (entry->fts_info != FTS_F) continue;

            time_t timestamp;
            if (!ParseFlowFilename(entry->fts_name, entry->fts_namelen, &timestamp)) continue;
            if (entry->fts_path[base_len] != '/') continue;
            if (!InsertExpireSlot(slots, entry->fts_path + base_len + 1, timestamp)) {
                LogError("Out of memory while indexing profile flow files");
                fts_close(fts);
                FreeExpireSlots(slots);
                return 0;
            }
        }
        if (errno != 0) {
            LogError("fts_read() error for %s: %s", ch->datadir, strerror(errno));
            fts_close(fts);
            FreeExpireSlots(slots);
            return 0;
        }
        fts_close(fts);
    }

    qsort(slots->slots, slots->used, sizeof(expire_slot_t), CompareExpireSlot);
    size_t unique = 0;
    for (size_t i = 0; i < slots->used; i++) {
        if (unique && strcmp(slots->slots[unique - 1].relpath, slots->slots[i].relpath) == 0) {
            free(slots->slots[i].relpath);
            continue;
        }
        if (unique != i) slots->slots[unique] = slots->slots[i];
        unique++;
    }
    slots->used = unique;
    return 1;
}  // End of CollectProfileSlots

int RescanDir(const channel_t *channel) {
    FTS *fts;
    FTSENT *ent;

    char *const paths[] = {(char *)channel->datadir, NULL};

    time_t first = 0;
    time_t last = 0;

    bookkeeper_t bookkeeper;
    book_get(channel->book_handle, &bookkeeper);

    bookkeeper.filesize = 0;
    bookkeeper.numfiles = 0;
    bookkeeper.first = 0;
    bookkeeper.last = 0;

    fts = fts_open(paths, FTS_PHYSICAL, compare);
    if (!fts) {
        LogError("fts_open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        return 0;
    }

    errno = 0;
    while ((ent = fts_read(fts)) != NULL) {
        // A full rescan can run long on a large directory, and is meant to
        // stay interruptible - a signal here (fresh, not one already
        // consumed by an earlier phase of this run; see RescanDirtyChannels())
        // simply leaves the channel dirty, to be picked up on the next
        // invocation. That is different from the deletion loop in
        // ExpireDir(), which always commits a clean, consistent partial
        // state before stopping.
        if (ExpireStopRequested()) {
            fts_close(fts);
            return 0;
        }
        if (ent->fts_info == FTS_F) {
            time_t timestamp;
            if (!ParseFlowFilename(ent->fts_name, ent->fts_namelen, &timestamp)) continue;

            if (first == 0 || timestamp < first) first = timestamp;
            if (timestamp > last) last = timestamp;

            // accumulate disk usage
            if (ent->fts_statp) bookkeeper.filesize += (uint64_t)ent->fts_statp->st_blocks * 512ULL;
            bookkeeper.numfiles++;
        } else if (ent->fts_info == FTS_D && ent->fts_level > 0) {
            // skip directories
            if (ent->fts_name[0] == '.' || !isdigit((unsigned char)ent->fts_name[0])) {
                fts_set(fts, ent, FTS_SKIP);
            }
        }
    }

    if (errno != 0) {
        LogError("fts_read() error: %s", strerror(errno));
        fts_close(fts);
        return 0;
    }
    fts_close(fts);

    // successfully re-scanned
    // finalize timestamps
    if (bookkeeper.numfiles > 0) {
        bookkeeper.first = first;
        bookkeeper.last = last;
    }

    bookkeeper.dirty = 0;

    if (book_set(channel->book_handle, &bookkeeper) == 0) {
        return 0;
    }

    dbg_printf("Rescan dir - first: %s, last: %s\n", UNIX2ISO(first), UNIX2ISO(last));

    return 1;
}  // End of RescanDir

// Open the parent directory of relpath below channel->dirfd without following
// any path component.  fstatat(AT_SYMLINK_NOFOLLOW) only protects the final
// component, so using it with an untrusted nested path is not sufficient.
static int OpenFlowParent(const channel_t *channel, const char *relpath, char *basename, size_t basename_len) {
    if (!channel || channel->dirfd < 0 || !relpath || !*relpath) {
        errno = EINVAL;
        return -1;
    }

    char path[MAXPATHLEN];
    size_t path_len = strlen(relpath);
    if (path_len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path, relpath, path_len + 1);

    char *last = strrchr(path, '/');
    char *name = path;
    int dirfd = dup(channel->dirfd);
    if (dirfd < 0) return -1;

    if (last) {
        *last = '\0';
        name = last + 1;
        char *part = path;
        while (*part) {
            char *next = strchr(part, '/');
            if (next) *next = '\0';
            if (*part == '\0' || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
                close(dirfd);
                errno = EINVAL;
                return -1;
            }
            int nextfd = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(dirfd);
            if (nextfd < 0) return -1;
            dirfd = nextfd;
            if (!next) break;
            part = next + 1;
        }
    }

    if (*name == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 || strlen(name) >= basename_len) {
        close(dirfd);
        errno = EINVAL;
        return -1;
    }
    strcpy(basename, name);
    return dirfd;
}  // End of OpenFlowParent

static int GetFlowFileSize(const channel_t *channel, const char *relpath, uint64_t *file_size) {
    char basename[NAME_MAX + 1];
    int parent = OpenFlowParent(channel, relpath, basename, sizeof(basename));
    if (parent < 0) return errno == ENOENT ? 0 : -1;

    struct stat st;
    int result = 0;
    if (fstatat(parent, basename, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISREG(st.st_mode)) {
            *file_size = (uint64_t)st.st_blocks * STAT_BLOCK_SIZE;
            result = 1;
        } else {
            errno = EINVAL;
            result = -1;
        }
    } else if (errno != ENOENT) {
        result = -1;
    }
    close(parent);
    return result;
}  // End of GetFlowFileSize

// Return 1 when a regular file was deleted (or would be deleted), 0 when it
// does not exist and -1 for any unsafe or failed operation.
static int DeleteFlowFile(const channel_t *channel, const char *relpath, int dryrun, uint64_t *file_size) {
    char basename[NAME_MAX + 1];
    int parent = OpenFlowParent(channel, relpath, basename, sizeof(basename));
    if (parent < 0) return errno == ENOENT ? 0 : -1;

    struct stat st;
    int result = 0;
    if (fstatat(parent, basename, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode)) {
            errno = EINVAL;
            result = -1;
        } else {
            *file_size = (uint64_t)st.st_blocks * STAT_BLOCK_SIZE;
            if (dryrun) {
                LogInfo("Would delete file: %s/%s", channel->datadir, relpath);
                result = 1;
            } else if (unlinkat(parent, basename, 0) == 0) {
                result = 1;
            } else if (errno != ENOENT) {
                result = -1;
            }
        }
    } else if (errno != ENOENT) {
        result = -1;
    }
    close(parent);
    return result;
}  // End of DeleteFlowFile

static int RemoveEmptyDirectory(const channel_t *channel, const char *relpath, int dryrun) {
    char basename[NAME_MAX + 1];
    int parent = OpenFlowParent(channel, relpath, basename, sizeof(basename));
    if (parent < 0) return errno == ENOENT ? 0 : -1;

    struct stat st;
    int result = 0;
    if (fstatat(parent, basename, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            errno = EINVAL;
            result = -1;
        } else if (dryrun) {
            result = 0;
        } else if (unlinkat(parent, basename, AT_REMOVEDIR) == 0 || errno == ENOTEMPTY || errno == EEXIST || errno == ENOENT) {
            result = 0;
        } else {
            result = -1;
        }
    } else if (errno != ENOENT) {
        result = -1;
    }
    close(parent);
    return result;
}  // End of RemoveEmptyDirectory

static void CleanupChannels(const channel_t *channel) {
    for (const channel_t *ch = channel; ch; ch = ch->next) {
        if (ch->dirfd >= 0) close(ch->dirfd);
    }

}  // End of CleanupChannels

// The last-resort pass that gets a channel out of the dirty state. A stop
// request already consumed by the deletion phase above must not also block
// this repair from ever starting - it is reset here for a clean slate, so
// the common case (an orderly stop with nothing left to repair) never even
// reaches this function with a leftover flag in the way. A *fresh* signal
// arriving once this pass is actually running is a different matter: a
// rescan can run long on a large directory, so it stays interruptible - the
// channel(s) not yet repaired simply stay dirty, to be picked up on the
// next invocation.
static int RescanDirtyChannels(channel_t *channel, const char *label) {
    stop_requested = 0;
    abort_signal = 0;

    int failed = 0;
    for (channel_t *ch = channel; ch; ch = ch->next) {
        if (!book_is_dirty(ch->book_handle)) continue;
        if (ExpireStopRequested()) {
            failed = 1;
            break;
        }
        LogVerbose("Expire %s: inconsistent data - rescan ..", label);
        int ok = 0;
        int maxTries = 3;
        do {
            ok = RescanDir(ch);
            maxTries--;
        } while (!ok && !ExpireStopRequested() && maxTries > 0);
        if (!ok) {
            LogError("Failed to re-scan dirty channel %s", ch->datadir);
            failed = 1;
        }
    }
    return !failed;
}  // End of RescanDirtyChannels

// Profile channels can legitimately have different sets of timeslots.  Walk
// their union rather than selecting one channel as a reference; otherwise an
// incomplete reference channel can leave the aggregate profile above limit.
static expire_status_t ExpireProfileSlots(channel_t *channel, uint64_t total_size, time_t first, time_t last, uint64_t maxsize,
                                          time_t maxlife, uint32_t low_water, int dryrun) {
    const char *label = "Profile";
    int need_size_expire = maxsize && total_size > maxsize;
    uint64_t target_size = (maxsize / 100) * low_water + ((maxsize % 100) * low_water) / 100;
    int need_life_expire = maxlife && first && last && (last - first) > maxlife;
    time_t time_limit = need_life_expire ? last - ((maxlife / 100) * low_water + ((maxlife % 100) * low_water) / 100) : 0;

    expire_slots_t slots;
    if (!CollectProfileSlots(channel, &slots)) {
        CleanupChannels(channel);
        return ExpireStopRequested() ? ExpireTerminationStatus() : EXPIRE_FAILED;
    }

    uint64_t current_size = total_size;
    size_t first_remaining = slots.used;
    int failed = 0;
    for (size_t i = 0; i < slots.used; i++) {
        // Never begin another lockstep slot after a stop request. If a signal
        // arrives while deleting a slot, the inner channel loop completes that
        // slot before reaching this check, so profiles remain symmetrical.
        if (ExpireStopRequested()) {
            // The current slot is the first retained one. Do not delete it.
            first_remaining = i;
            break;
        }
        if (!need_size_expire && !need_life_expire) {
            first_remaining = i;
            break;
        }

        int time_cmp = (slots.slots[i].timestamp > time_limit) - (slots.slots[i].timestamp < time_limit);
        int delete_slot = (need_size_expire && current_size > target_size) || (need_life_expire && time_cmp < 0);
        if (delete_slot) {
            // Validate every channel before changing any of them. This keeps
            // profile expiry lockstep even when a malicious or broken path
            // is encountered in one channel.
            for (channel_t *ch = channel; ch; ch = ch->next) {
                uint64_t ignored_size;
                int present = GetFlowFileSize(ch, slots.slots[i].relpath, &ignored_size);
                ch->slot_present = present > 0;
                if (present < 0) {
                    LogError("Failed to inspect %s/%s safely: %s", ch->datadir, slots.slots[i].relpath, strerror(errno));
                    failed = 1;
                    break;
                }
            }
            if (failed) break;

            for (channel_t *ch = channel; ch; ch = ch->next) {
                uint64_t file_size = 0;
                int deleted = DeleteFlowFile(ch, slots.slots[i].relpath, dryrun, &file_size);
                if (deleted > 0) {
                    ch->expired_files++;
                    ch->expired_size += file_size;
                    current_size = current_size >= file_size ? current_size - file_size : 0;
                } else if (deleted < 0) {
                    LogError("Failed to remove %s/%s safely: %s", ch->datadir, slots.slots[i].relpath, strerror(errno));
                    failed = 1;
                    break;
                } else if (ch->slot_present) {
                    LogError("Flow file disappeared during profile expiry: %s/%s", ch->datadir, slots.slots[i].relpath);
                    failed = 1;
                    break;
                }
            }
        }
        if (failed) break;

        if (stop_requested || (need_size_expire && current_size <= target_size)) need_size_expire = 0;
        if (stop_requested || (need_life_expire && time_cmp >= 0)) need_life_expire = 0;
    }

    if (dryrun) {
        CleanupChannels(channel);
        FreeExpireSlots(&slots);
        LogInfo("Dryrun expire %s ends", label);
        return FinalStatus(failed);
    }

    // An empty remaining union is valid: book_expire() records an empty
    // channel when its deleted-file count consumes its full book count.
    // Only a real failed operation needs a rebuild.
    if (failed) {
        CleanupChannels(channel);
        for (channel_t *ch = channel; ch; ch = ch->next) book_mark_dirty(ch->book_handle);
        FreeExpireSlots(&slots);
        int rescan_ok = RescanDirtyChannels(channel, label);
        return FinalStatus(failed || !rescan_ok);
    }

    time_t expired_time = first_remaining < slots.used ? slots.slots[first_remaining].timestamp - first : last - first;
    for (channel_t *ch = channel; ch; ch = ch->next) ch->expired_time = expired_time;

    for (channel_t *ch = channel; ch; ch = ch->next) {
        time_t channel_first = 0;
        for (size_t i = first_remaining; i < slots.used; i++) {
            uint64_t ignored_size;
            int exists = GetFlowFileSize(ch, slots.slots[i].relpath, &ignored_size);
            if (exists > 0) {
                channel_first = slots.slots[i].timestamp;
                break;
            }
            if (exists < 0) {
                LogError("Failed to inspect %s/%s safely: %s", ch->datadir, slots.slots[i].relpath, strerror(errno));
                failed = 1;
                break;
            }
        }
        if (failed || !book_expire(ch->book_handle, channel_first, ch->expired_files, ch->expired_size)) {
            book_mark_dirty(ch->book_handle);
        }
    }

    CleanupChannels(channel);
    FreeExpireSlots(&slots);
    // Capture the outcome of the deletion phase before RescanDirtyChannels()
    // runs: it resets the stop-request flags (see its own comment) so a
    // repair it does not even need to attempt cannot silently turn a real
    // EXPIRE_TIMEOUT/EXPIRE_ABORTED back into EXPIRE_OK.
    expire_status_t status = FinalStatus(0);
    return RescanDirtyChannels(channel, label) ? status : EXPIRE_FAILED;
}  // End of ExpireProfileSlots

// Unified single-channel / profile expiry. A plain, non-profile expire is
// just this same lockstep algorithm with a channel list of length one -
// deleting a timeslot "from every channel in the list" trivially means
// "from the one channel" when there is only one. Keeping one implementation
// instead of two means a fix (or a bug) can no longer exist in one copy but
// not the other, which is exactly how two of this function's own past bugs
// happened: a lifetime-comparison off-by-one and an unlocked bookkeeper
// write were each fixed once here, but previously had to be fixed twice.
expire_status_t ExpireDir(channel_t *channel, uint64_t maxsize, time_t maxlife, uint32_t low_water, uint32_t limit_mask, int dryrun) {
    if (!channel) return EXPIRE_FAILED;

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

        if (UINT64_MAX - total_size < bookkeeper.filesize) {
            LogError("Bookkeeping size overflow in %s", ch->datadir);
            failed = 1;
        } else {
            total_size += bookkeeper.filesize;
        }

        if (!first || bookkeeper.first < first) {
            first = bookkeeper.first;
            reference_channel = ch;
        }
        if (bookkeeper.last > last) last = bookkeeper.last;

        ch->expired_files = 0;
        ch->expired_size = 0;
        ch->expired_time = 0;

        if (isSingle) {
            if (!(limit_mask & BOOK_LIMIT_MAXSIZE)) maxsize = bookkeeper.max_filesize;
            if (!(limit_mask & BOOK_LIMIT_LIFETIME)) maxlife = bookkeeper.max_lifetime;
            if (!(limit_mask & BOOK_LIMIT_WATERMARK)) low_water = bookkeeper.watermark;
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
        return EXPIRE_FAILED;
    }

    if (maxsize == 0 && maxlife == 0) {
        LogInfo("No limits set for %s. Nothing to expire", label);
        CleanupChannels(channel);
        return EXPIRE_OK;
    }

    time_t expire_start = first;
    time_t expire_end = 0;

    // trigger values
    int need_size_expire = (maxsize && total_size > maxsize);
    uint64_t target_size = need_size_expire ? (maxsize / 100) * low_water + ((maxsize % 100) * low_water) / 100 : 0;

    int need_life_expire = 0;
    char timeLimitStr[32] = {0};
    time_t timeLimit = 0;
    if (maxlife && first && last && (last - first) > maxlife) {
        need_life_expire = 1;

        timeLimit = last - ((maxlife / 100) * low_water + ((maxlife % 100) * low_water) / 100);
        strcpy(timeLimitStr, UNIX2ISO(timeLimit));
    }

    if (!need_size_expire && !need_life_expire) {
        LogInfo("Limits do not trigger for %s. Nothing to expire", label);
        CleanupChannels(channel);
        return EXPIRE_OK;
    }

    if (!isSingle) return ExpireProfileSlots(channel, total_size, first, last, maxsize, maxlife, low_water, dryrun);

#ifdef DEVEL
    if (need_size_expire) printf("need_size_expire: %d from %" PRIu64 " down to %" PRIu64, need_size_expire, total_size, target_size);
    if (need_life_expire) printf("need_life_expire: %d from %s down to %s", need_life_expire, UNIX2ISO(first), timeLimitStr);
#endif

    // Traverse the reference channel's timeline; for a single channel that
    // is trivially the only channel there is.
    char *const path[] = {reference_channel->datadir, NULL};
    FTS *fts = fts_open(path, FTS_PHYSICAL, compare);
    if (!fts) {
        LogError("fts_open() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno));
        CleanupChannels(channel);
        return EXPIRE_FAILED;
    }

    size_t base_len = strlen(reference_channel->datadir);
    uint64_t current_size = total_size;
    time_t new_first = 0;
    int done = 0;
    FTSENT *ftsent;
    int stopping = 0;
    int fts_errno = 0;
    while (!done) {
        // fts_read() reports traversal errors through errno. Reset it for
        // this call: unlinkat()/rmdir() in the prior iteration may have set
        // errno even though their expected outcome was handled successfully.
        errno = 0;
        ftsent = fts_read(fts);
        if (ftsent == NULL) {
            fts_errno = errno;
            break;
        }
        // On a stop request, continue only until the next valid flow file.
        // That file is retained and supplies the exact new book head; no more
        // unlink operations are started.
        if (ExpireStopRequested()) stopping = 1;
        switch (ftsent->fts_info) {
            case FTS_D:
                // skip all '.' entries
                if (ftsent->fts_level > 0 && (ftsent->fts_name[0] == '.' || !isdigit((unsigned char)ftsent->fts_name[0]))) {
                    dbg_printf("FTS: skip directory: %s\n", ftsent->fts_name);
                    fts_set(fts, ftsent, FTS_SKIP);
                }

                break;

            case FTS_F: {
                time_t fileTime;
                if (!ParseFlowFilename(ftsent->fts_name, ftsent->fts_namelen, &fileTime)) break;

                if (stopping) {
                    done = 1;
                    new_first = fileTime;
                    expire_end = new_first;
                    break;
                }

                // check, if we are done and set new first value
                if (need_size_expire == 0 && need_life_expire == 0) {
                    done = 1;
                    // first remaining file
                    new_first = fileTime;
                    expire_end = new_first;
                    dbg_printf("Done - first: %s, size: %" PRIu64 "\n", UNIX2ISO(fileTime), current_size);
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
                int timeCMP = (fileTime > timeLimit) - (fileTime < timeLimit);
                if (!delete_slot && need_life_expire && timeCMP < 0) delete_slot = 1;

                if (delete_slot) {
                    // delete the same timeslot in every channel
                    dbg_printf("Delete %s\n", ftsent->fts_name);
                    const char *rel = ftsent->fts_path + base_len + 1;

                    for (channel_t *ch = channel; ch; ch = ch->next) {
                        dbg_printf("Delete %s/%s\n", ch->datadir, rel);

                        uint64_t fileSize = 0;
                        int deleted = DeleteFlowFile(ch, rel, dryrun, &fileSize);
                        if (deleted > 0) {
                            ch->expired_size += fileSize;
                            ch->expired_files++;
                            if (current_size >= fileSize)
                                current_size -= fileSize;
                            else
                                current_size = 0;
                        } else if (deleted < 0) {
                            LogError("Failed to remove %s/%s safely: %s", ch->datadir, rel, strerror(errno));
                            if (!dryrun) book_mark_dirty(ch->book_handle);
                            done = 1;
                        } else if (isSingle) {
                            LogError("Flow file disappeared during expiry: %s/%s", ch->datadir, rel);
                            if (!dryrun) book_mark_dirty(ch->book_handle);
                            done = 1;
                        }
                    }
                }

                // stop condition
                // this does not yet terminte the while loop
                // as we need to get the next valid file for the new first timestamp
                if (stop_requested || (need_size_expire && current_size <= target_size)) need_size_expire = 0;
                if (stop_requested || (need_life_expire && timeCMP >= 0)) need_life_expire = 0;

                break;
            }

            case FTS_DP:
                // Remove now-empty archive directories after their files have
                // been considered. Use the same no-follow traversal as file
                // deletion, so a replacement symlink cannot escape a channel.
                if (!stopping && ftsent->fts_level > 0) {
                    const char *rel = ftsent->fts_path + base_len + 1;
                    for (channel_t *ch = channel; ch; ch = ch->next) {
                        if (RemoveEmptyDirectory(ch, rel, dryrun) < 0) {
                            LogError("Failed to remove empty directory %s/%s safely: %s", ch->datadir, rel, strerror(errno));
                            if (!dryrun) book_mark_dirty(ch->book_handle);
                        }
                    }
                }
                break;

            default:
                break;
        }
    }

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
        return FinalStatus(0);
    }

    int dirty = fts_errno != 0;
    if (dirty) LogError("fts_read() error for %s: %s", label, strerror(fts_errno));

    for (channel_t *ch = channel; ch; ch = ch->next) {
        if (dirty == 0) {
            // This commits either the next retained file or a verified empty
            // archive. book_expire() rejects a concurrent/inconsistent state.
            if (!book_expire(ch->book_handle, new_first, ch->expired_files, ch->expired_size)) {
                LogError("book_update rejected - rescan channel %s", ch->datadir);
                book_mark_dirty(ch->book_handle);
            }
        } else {
            book_mark_dirty(ch->book_handle);
        }
    }

    // A timeout is an orderly partial completion: the deleted prefix and the
    // next retained file were committed above. Only a real filesystem or
    // concurrent-bookkeeping inconsistency needs a rebuild here - and that
    // repair (see RescanDirtyChannels()) is deliberately not gated on the
    // stop request that got us here, only on one that arrives fresh while
    // it is itself running.
    //
    // Capture the outcome of the deletion phase before calling it:
    // RescanDirtyChannels() resets the stop-request flags (see its own
    // comment) so a repair it does not even need to attempt cannot silently
    // turn a real EXPIRE_TIMEOUT/EXPIRE_ABORTED back into EXPIRE_OK.
    expire_status_t status = FinalStatus(0);
    return RescanDirtyChannels(channel, label) ? status : EXPIRE_FAILED;
}  // End of ExpireDir
