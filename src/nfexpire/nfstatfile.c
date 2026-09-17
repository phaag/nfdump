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

/* legacy code for NfSen */

#include "nfstatfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "bookkeeper.h"
#include "expire.h"
#include "logging.h"
#include "util.h"

// NfSen reads this file under flock(LOCK_SH). Take the matching lock before
// reading the book or truncating, so concurrent exporters cannot publish an
// older snapshot after a newer one.
int WriteStatInfo(channel_t *channel) {
    char path[MAXPATHLEN];
    if (!channel || !channel->datadir || !channel->book_handle) return 0;
    int len = snprintf(path, sizeof(path), "%s/.nfstat", channel->datadir);
    if (len < 0 || (size_t)len >= sizeof(path)) return 0;
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        LogError("open() error on '%s': %s", path, strerror(errno));
        return 0;
    }
    while (flock(fd, LOCK_EX) < 0) {
        if (errno == EINTR) continue;
        LogError("Lock failed on '%s': %s", path, strerror(errno));
        close(fd);
        return 0;
    }

    bookkeeper_t book;
    book_get(channel->book_handle, &book);
    char buffer[512];
    len = snprintf(buffer, sizeof(buffer),
                   "first=%llu\nlast=%llu\nsize=%llu\nmaxsize=%llu\nnumfiles=%llu\nlifetime=%llu\nwatermark=%u\nstatus=%u\n",
                   (unsigned long long)book.first, (unsigned long long)book.last, (unsigned long long)book.filesize,
                   (unsigned long long)book.max_filesize, (unsigned long long)book.numfiles,
                   (unsigned long long)book.max_lifetime, book.watermark, book.dirty ? 3U : 0U);
    int ok = len > 0 && (size_t)len < sizeof(buffer) && ftruncate(fd, 0) == 0;
    size_t offset = 0;
    while (ok && offset < (size_t)len) {
        ssize_t n = write(fd, buffer + offset, (size_t)len - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n == 0) errno = EIO;
            ok = 0;
        } else {
            offset += (size_t)n;
        }
    }
    if (!ok) LogError("Writing '%s' failed: %s", path, strerror(errno));
    // close releases the lock, including on errors.
    if (close(fd) < 0) {
        LogError("Closing '%s' failed: %s", path, strerror(errno));
        ok = 0;
    }
    return ok;
}

// Import only retention settings on first migration. Counts and timestamps
// are rebuilt from files, never trusted from the legacy statistics file.
int ImportStatLimits(const channel_t *channel) {
    char path[MAXPATHLEN];
    snprintf(path, sizeof(path), "%s/.nfstat", channel->datadir);
    FILE *file = fopen(path, "r");
    if (!file) {
        if (errno != ENOENT) return 0;
        book_set_limits(channel->book_handle, 0, 0, 95, BOOK_LIMIT_WATERMARK);
        return 1;
    }
    if (flock(fileno(file), LOCK_SH) < 0) {
        fclose(file);
        return 0;
    }
    bookkeeper_t book;
    book_get(channel->book_handle, &book);
    book.watermark = 95;  // legacy default
    char line[256], key[64], value[64];
    int ok = 1;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%63[^=]=%63s", key, value) != 2) continue;
        if (strcmp(key, "maxsize") && strcmp(key, "lifetime") && strcmp(key, "watermark")) continue;
        char *end;
        errno = 0;
        unsigned long long n = strtoull(value, &end, 10);
        if (errno || *end || value[0] == '-') {
            ok = 0;
            break;
        }
        if (strcmp(key, "maxsize") == 0) book.max_filesize = n;
        if (strcmp(key, "lifetime") == 0) {
            if ((time_t)n < 0 || (unsigned long long)(time_t)n != n) {
                ok = 0;
                break;
            }
            book.max_lifetime = (time_t)n;
        }
        if (strcmp(key, "watermark") == 0) {
            if (n > 100) {
                ok = 0;
                break;
            }
            book.watermark = (uint32_t)n;
        }
    }
    if (ferror(file)) ok = 0;
    fclose(file);
    return ok && book_set(channel->book_handle, &book);
}
